from typing import (
    List,
    Optional,
    Callable,
    Dict,
    Any,
    Tuple,
)
import traceback
import re

import binaryninja
from binaryninja import (
    BinaryView,
    Function,
    BackgroundTask,
    Symbol,
    SymbolType,
    DataVariable,
    Type,
    Logger,
    interaction,
)

from ..defs import LOGGER_NAME

from ..dsl import (
    DSLCommand,
    CommentCommand,
    FNameCommand,
    VNameCommand,
    DNameCommand,
    parse_bndsl,
)


# - dsl execution logic
class DSLExecutor:
    """
    handles the core logic of executing parsed bn-dsl commands.
    it interacts with the binaryview to apply changes and manages journaling of operations.
    this class is designed to be instantiated by a wrapper (like ExecuteBNDSLTask)
    and is not directly tied to ui components or background task management.
    """

    # - metadata keys for bndsl operation journaling
    # key for storing the total count of journaled bndsl operations.
    OP_COUNT_KEY = "moonanalyzer.bndsl_op_count"
    # prefix for keys storing individual journaled bndsl operation strings.
    OP_DATA_PREFIX = "moonanalyzer.bndsl_op_data_"

    def __init__(self, bv: BinaryView, logger: Logger):
        # the binary view instance on which operations will be performed.
        self.bv: BinaryView = bv
        # a logger instance for recording execution details and errors.
        self.log: Logger = logger

        # - command handler dispatch table
        # maps dsl command dataclass types to their corresponding handler methods within this class.
        # this allows for easy extension with new dsl commands.
        self.command_handlers: Dict[type, Callable[[Any], None]] = {
            CommentCommand: self._execute_comment_command,
            FNameCommand: self._execute_fname_command,
            VNameCommand: self._execute_vname_command,
            DNameCommand: self._execute_dname_command,
        }

    # - utility helper methods
    def _get_function_context(self, address: int) -> Optional[Function]:
        """
        attempts to find a function associated with the given address.
        it first checks if any function contains the address. if not, it checks
        if any function starts exactly at the address.
        returns the binaryninja.Function object or none if no function is found.
        """
        # check if the address falls within the body of any existing function.
        functions_containing_address = self.bv.get_functions_containing(address)
        if functions_containing_address:
            # if multiple functions contain the address (e.g., due to thunks or overlapping analysis),
            # we default to using the first one returned by the api.
            selected_func = functions_containing_address[0]
            self.log.log_debug(
                f"helper: address 0x{address:x} is within function '{selected_func.name}' (0x{selected_func.start:x})."
            )
            return selected_func

        # as a fallback, check if a function starts exactly at the given address.
        function_at_start_address = self.bv.get_function_at(address)
        if function_at_start_address:
            self.log.log_debug(
                f"helper: address 0x{address:x} is the start of function '{function_at_start_address.name}' (0x{function_at_start_address.start:x})."
            )
            return function_at_start_address

        # if no function is found by either method.
        self.log.log_debug(
            f"helper: no function context found for address 0x{address:x}."
        )
        return None

    def _parse_data_auto_name(self, name: str) -> Optional[int]:
        """
        parses an auto-generated data variable name (e.g., 'data_XXXXXXXX', 'data_123ab')
        and returns the hexadecimal address as an integer if the pattern matches.
        returns none if the name does not fit the expected auto-name pattern.
        the match is case-insensitive for the hexadecimal part.
        """
        # regex matches "data_" followed by one or more hexadecimal characters (0-9, a-f, A-F).
        match = re.fullmatch(r"data_([0-9a-fA-F]+)", name, re.IGNORECASE)
        if match:
            try:
                # extract the hexadecimal string (group 1) and convert it to an integer.
                return int(match.group(1), 16)
            except ValueError:
                # this should be rare if the regex matches, but handles malformed hex.
                self.log.log_error(
                    f"helper: invalid hex string '{match.group(1)}' encountered in auto-name '{name}'."
                )
        return None

    # - journaling implementation methods
    def _get_initial_journal_count(self) -> int:
        """
        retrieves the current total count of previously journaled bndsl operations
        from the binaryview's metadata.
        returns 0 if the count is not found or if an error occurs.
        """
        current_op_journal_count = 0
        try:
            # query_metadata can return various types or none if the key doesn't exist.
            queried_count = self.bv.query_metadata(self.OP_COUNT_KEY)
            if isinstance(queried_count, int):
                current_op_journal_count = queried_count
            elif queried_count is not None:
                # handle case where the key exists but stores an unexpected data type.
                self.log.log_warn(
                    f"journaling: metadata key '{self.OP_COUNT_KEY}' found but is not an integer (type: {type(queried_count)}). resetting journal count to 0."
                )
        except Exception as e:
            # catch any other exceptions during metadata query.
            self.log.log_error(
                f"journaling: error querying metadata key '{self.OP_COUNT_KEY}': {e}. defaulting journal count to 0."
            )
        return current_op_journal_count

    def _journal_single_op(
        self,
        command_obj: DSLCommand,
        base_journal_count: int,
        successful_ops_idx_this_run: int,
    ):
        """
        journals a single successfully executed dsl command to the binaryview's metadata.
        `base_journal_count` is the total count before this execution run.
        `successful_ops_idx_this_run` is the 0-based index of this successful operation within the current run.
        """
        try:
            # command objects must implement to_dsl_string() to be journalable.
            if not hasattr(command_obj, "to_dsl_string"):
                self.log.log_error(
                    f"journaling: command object of type {type(command_obj)} lacks 'to_dsl_string' method. cannot journal."
                )
                return

            command_dsl_str = command_obj.to_dsl_string()
            # calculate the global, persistent index for this journal entry.
            journal_total_index = base_journal_count + successful_ops_idx_this_run
            metadata_key_for_op = f"{self.OP_DATA_PREFIX}{journal_total_index}"

            self.bv.store_metadata(metadata_key_for_op, command_dsl_str)
            self.log.log_debug(
                f"journaling: stored operation to metadata key '{metadata_key_for_op}': {command_dsl_str}"
            )
        except Exception as journal_e:
            # log journaling errors but do not let them halt the entire process
            # if the command itself executed successfully.
            self.log.log_error(
                f"journaling: failed to journal command {command_obj}: {journal_e}"
            )
            self.log.log_error(
                traceback.format_exc()
            )  # include full traceback for debugging

    def _update_total_journal_count(self, final_total_count: int):
        """
        updates the master journal count (OP_COUNT_KEY) in the binaryview's metadata
        to reflect the new total number of journaled operations.
        """
        try:
            self.bv.store_metadata(self.OP_COUNT_KEY, final_total_count)
            self.log.log_info(
                f"journaling: updated total bndsl operation journal count in metadata to: {final_total_count}."
            )
        except Exception as e:
            self.log.log_error(
                f"journaling: failed to update metadata key '{self.OP_COUNT_KEY}' to {final_total_count}: {e}"
            )
            self.log.log_error(traceback.format_exc())

    # - individual dsl command execution handlers
    def _execute_comment_command(self, command: CommentCommand):
        """handles the COMMENT dsl command."""
        # determine if the comment should be function-local or global.
        target_func = self._get_function_context(command.address)
        # preview the comment for logging, truncated if too long.
        comment_preview = (
            f"{command.text[:60]}{'...' if len(command.text) > 60 else ''}"
        )

        if target_func:
            # comment address is within an existing function; make it a function-local comment.
            self.log.log_info(
                f"comment: setting in function '{target_func.name}' at 0x{command.address:x}: \"{comment_preview}\""
            )
            target_func.set_comment_at(command.address, command.text)
        else:
            # comment address is not within a known function; make it a global (address-based) comment.
            self.log.log_info(
                f'comment: setting global comment at 0x{command.address:x}: "{comment_preview}"'
            )
            self.bv.set_comment_at(command.address, command.text)

    def _execute_fname_command(self, command: FNameCommand):
        """handles the FNAME dsl command for renaming functions."""
        # fname command requires the address to be the exact start of a function.
        target_func = self.bv.get_function_at(command.address)
        if target_func:
            old_name = target_func.name
            try:
                target_func.name = command.new_name
                self.log.log_info(
                    f"fname: renamed function at 0x{command.address:x} from '{old_name}' to '{command.new_name}'."
                )
            except Exception as e:
                # catch errors that might occur during name assignment (e.g., invalid characters, though bn usually handles this).
                self.log.log_error(
                    f"fname: failed to rename function '{old_name}' (at 0x{command.address:x}) to '{command.new_name}': {e}"
                )
        else:
            self.log.log_warn(
                f"fname: no function found starting at address 0x{command.address:x}. cannot rename to '{command.new_name}'. command skipped."
            )

    def _execute_vname_command(self, command: VNameCommand):
        """handles the VNAME dsl command for renaming local variables within a function."""
        # use the helper to find the function context based on command.function_address.
        target_func = self._get_function_context(command.function_address)

        if not target_func:
            self.log.log_warn(
                f"vname: no function context found for address 0x{command.function_address:x}. "
                f"cannot process local variable rename for '{command.old_var_root}' -> '{command.new_var_root}'. command skipped."
            )
            return

        self.log.log_info(
            f"vname: processing local variables in function '{target_func.name}' (0x{target_func.start:x}) "
            f"for root rename: '{command.old_var_root}' -> '{command.new_var_root}'."
        )

        renamed_variables_count = 0
        # iterate through all variables (parameters, stack-based, register-based) associated with the function.
        for (
            var_to_rename
        ) in target_func.vars:  # var_to_rename is a binaryninja.Variable
            if var_to_rename.name.startswith(command.old_var_root):
                original_variable_name = var_to_rename.name
                # preserve any suffix that exists after the old_var_root (e.g., _1, _4_8 for struct fields part of var).
                suffix = original_variable_name[len(command.old_var_root) :]
                new_variable_name = command.new_var_root + suffix

                try:
                    # assigning to the .name property of a binaryninja.Variable object performs the rename.
                    var_to_rename.name = new_variable_name
                    self.log.log_info(
                        f"  vname: renamed local variable '{original_variable_name}' to '{new_variable_name}' in function '{target_func.name}'."
                    )
                    renamed_variables_count += 1
                except Exception as e:
                    self.log.log_error(
                        f"  vname: failed to rename local variable '{original_variable_name}' to '{new_variable_name}' "
                        f"in function '{target_func.name}': {e}\n{traceback.format_exc()}"
                    )

        if renamed_variables_count == 0:
            self.log.log_warn(
                f"  vname: no local variables found with root name '{command.old_var_root}' in function '{target_func.name}'."
            )

    def _execute_dname_command(self, command: DNameCommand):
        """handles the DNAME dsl command for naming or renaming global data entities."""
        self.log.log_info(
            f"dname: processing global data name assignment: '{command.old_global_name}' -> '{command.new_global_name}'."
        )

        # - mode 1: `command.old_global_name` is an auto-generated name like "data_ADDRESS"
        parsed_address = self._parse_data_auto_name(command.old_global_name)
        if parsed_address is not None:
            self.log.log_debug(
                f"dname: '{command.old_global_name}' interpreted as auto-name for address 0x{parsed_address:x}."
            )
            existing_data_variable = self.bv.get_data_var_at(parsed_address)

            type_to_use_for_define: Optional[binaryninja.Type] = None
            # default to void* if no existing data_var or its type is unsuitable
            default_type_string = "void* default_dname_ptr_type"

            if (
                existing_data_variable
                and existing_data_variable.type
                and existing_data_variable.type.width > 0
            ):
                # use the type of the existing data variable if it's valid (not void).
                type_to_use_for_define = existing_data_variable.type
                self.log.log_debug(
                    f"dname: using existing data_var type '{type_to_use_for_define}' at 0x{parsed_address:x}."
                )
            else:
                log_reason = (
                    "no data_var found"
                    if not existing_data_variable
                    else "existing data_var has void/invalid type"
                )
                self.log.log_warn(
                    f"dname: {log_reason} at 0x{parsed_address:x} (from auto-name '{command.old_global_name}'). trying to use default type '{default_type_string}'."
                )
                try:
                    # parse the default "void*" type string. the name part of the string is ignored by define_user_data_var when a name is provided.
                    parsed_default_type, _ = self.bv.parse_type_string(default_type_string)  # type: ignore
                    if parsed_default_type:
                        type_to_use_for_define = parsed_default_type
                    else:
                        # this indicates a failure in parsing even the basic "void*" string.
                        self.log.log_error(
                            f"dname: CRITICAL - failed to parse default type string '{default_type_string}'. cannot proceed for 0x{parsed_address:x}."
                        )
                        return
                except Exception as e:
                    self.log.log_error(
                        f"dname: CRITICAL - exception parsing default type string '{default_type_string}': {e}. cannot proceed for 0x{parsed_address:x}."
                    )
                    return

            if (
                type_to_use_for_define is None
            ):  # should not be reached if default type parsing is robust
                self.log.log_error(
                    f"dname: CRITICAL - type for 0x{parsed_address:x} is None after all checks. Aborting DNAME for this entry."
                )
                return

            try:
                # define_user_data_var creates or updates the data variable and its associated symbol.
                defined_dv = self.bv.define_user_data_var(
                    parsed_address, type_to_use_for_define, command.new_global_name
                )
                if defined_dv:
                    self.log.log_info(
                        f"dname: successfully defined/updated user data variable at 0x{parsed_address:x} "
                        f"(identified by auto-name '{command.old_global_name}') as '{command.new_global_name}' with type '{type_to_use_for_define}'."
                    )
                else:
                    self.log.log_error(
                        f"dname: call to define_user_data_var for 0x{parsed_address:x} as '{command.new_global_name}' returned None (operation failed)."
                    )
            except Exception as e:
                self.log.log_error(
                    f"dname: exception during define_user_data_var at 0x{parsed_address:x} for '{command.new_global_name}': {e}\n{traceback.format_exc()}"
                )
            # auto-name path is complete.
            return

        # - mode 2: `command.old_global_name` is treated as an existing symbol name (not an auto-name pattern).
        #   this mode specifically targets existing *data symbols* for renaming.
        self.log.log_debug(
            f"dname: '{command.old_global_name}' not an auto-name. searching for existing *data symbol* to rename."
        )
        try:
            # fetch all symbols (any type) that match the old_global_name.
            all_symbols_matching_old_name = self.bv.get_symbols_by_name(
                command.old_global_name
            )
        except Exception as e:
            self.log.log_error(
                f"dname: an error occurred while searching for symbol '{command.old_global_name}': {e}"
            )
            return

        # filter these symbols to include only those of type DataSymbol.
        data_symbols_matching_old_name: List[Symbol] = [
            s for s in all_symbols_matching_old_name if s.type == SymbolType.DataSymbol
        ]

        if not data_symbols_matching_old_name:
            self.log.log_warn(
                f"dname: no existing global *data symbol* found with name '{command.old_global_name}'. rename skipped. "
                "(if naming an unnamed data variable, use 'data_ADDRESS' as the old name)."
            )
            return

        if len(data_symbols_matching_old_name) > 1:
            self.log.log_warn(
                f"dname: found {len(data_symbols_matching_old_name)} global data symbols named '{command.old_global_name}'. "
                "rename skipped due to ambiguity. the old name must be unique among existing data symbols."
            )
            for i, sym_candidate in enumerate(data_symbols_matching_old_name):
                self.log.log_warn(
                    f"  candidate {i+1}: '{sym_candidate.name}' (type: {sym_candidate.type}) @ 0x{sym_candidate.address:x}"
                )
            return

        # exactly one matching existing data symbol was found.
        target_data_symbol = data_symbols_matching_old_name[0]
        target_address = target_data_symbol.address

        # a DataSymbol should ideally correspond to a DataVariable. log if not, but proceed with symbol rename.
        if not self.bv.get_data_var_at(target_address):
            self.log.log_warn(
                f"dname: renaming existing data symbol '{target_data_symbol.name}' at 0x{target_address:x}, "
                "but no corresponding data variable found at that address (this is unusual). proceeding with symbol rename."
            )

        try:
            # use define_user_symbol to update the name of the existing data symbol.
            # this does not change the type of any underlying data variable.
            self.bv.define_user_symbol(
                Symbol(SymbolType.DataSymbol, target_address, command.new_global_name)
            )
            self.log.log_info(
                f"dname: successfully renamed existing global data symbol '{target_data_symbol.name}' "
                f"(at 0x{target_address:x}) to '{command.new_global_name}'."
            )
        except Exception as e:
            self.log.log_error(
                f"dname: error renaming existing data symbol '{target_data_symbol.name}' "
                f"at 0x{target_address:x} to '{command.new_global_name}': {e}\n{traceback.format_exc()}"
            )

    # - main public execution method for a list of commands
    def execute_script_commands(
        self,
        commands: List[DSLCommand],
        cancellation_check: Callable[[], bool] = lambda: False,
    ) -> Tuple[int, int, List[str]]:
        """
        executes a list of parsed dsl commands and journals successful operations.
        this method orchestrates the execution within a single undo transaction.

        args:
            commands: a list of parsed dslcommand objects.
            cancellation_check: a callable that returns true if execution should be cancelled.

        returns:
            a tuple: (number_successful_and_journaled, number_failed_or_skipped, list_of_error_messages_for_failures)
        """
        if not commands:
            self.log.log_info("executor: no commands provided to execute.")
            return 0, 0, []  # successful_ops, failed_ops, error_messages

        initial_journal_count = self._get_initial_journal_count()
        self.log.log_info(
            f"executor: starting with initial journal count: {initial_journal_count}."
        )

        successful_ops_this_run = 0
        failed_ops_this_run = 0
        error_messages_for_failed_ops: List[str] = []

        # all commands in this batch are processed within a single undoable transaction.
        # if any command raises an unhandled exception that propagates out of this 'with' block,
        # all changes made by preceding commands in this batch would be reverted by binaryninja.
        # individual command failures handled within the loop do not cause a full revert unless they re-raise.
        with self.bv.undoable_transaction():
            for cmd_idx, command_obj in enumerate(commands):
                if cancellation_check():
                    # if cancellation is requested, log it and stop processing further commands.
                    cancellation_message = f"executor: cancellation requested. stopping after processing {cmd_idx} of {len(commands)} commands."
                    self.log.log_info(cancellation_message)
                    error_messages_for_failed_ops.append(
                        "execution was cancelled by user request."
                    )  # user-facing message
                    break  # exit the loop over commands

                self.log.log_debug(
                    f"executor: processing command {cmd_idx + 1}/{len(commands)}: {command_obj}"
                )
                command_executed_successfully_this_iteration = False
                try:
                    # dispatch to the appropriate handler based on the command object's type.
                    handler = self.command_handlers.get(type(command_obj))
                    if handler:
                        handler(command_obj)  # execute the specific command logic
                        command_executed_successfully_this_iteration = (
                            True  # assume success if handler doesn't raise
                        )
                    else:
                        # no handler is registered for this type of command.
                        err_msg = f"no handler registered for command type: {type(command_obj).__name__} (command: {command_obj}). this command was skipped."
                        self.log.log_error(err_msg)
                        error_messages_for_failed_ops.append(err_msg)
                        # this is considered a failure for this specific command.
                except Exception as exec_e:
                    # an exception occurred during the execution of the command's handler.
                    err_msg = (
                        f"error during execution of command {command_obj}: {exec_e}"
                    )
                    self.log.log_error(err_msg)
                    self.log.log_error(
                        traceback.format_exc()
                    )  # log full traceback for debugging
                    error_messages_for_failed_ops.append(err_msg)
                    # command execution failed.

                # - journal the command if its execution was successful.
                if command_executed_successfully_this_iteration:
                    # the index for journaling is based on the base count + how many successful ops we've had *so far in this run*.
                    self._journal_single_op(
                        command_obj, initial_journal_count, successful_ops_this_run
                    )
                    successful_ops_this_run += 1
                else:
                    failed_ops_this_run += (
                        1  # increment failed count if execution failed or no handler
                    )

        # after the loop (all commands processed or cancelled), update the total journal count in metadata.
        if successful_ops_this_run > 0:
            self._update_total_journal_count(
                initial_journal_count + successful_ops_this_run
            )

        self.log.log_info(
            f"executor: command execution run finished. "
            f"successful and journaled: {successful_ops_this_run}, failed or skipped: {failed_ops_this_run}."
        )
        return (
            successful_ops_this_run,
            failed_ops_this_run,
            error_messages_for_failed_ops,
        )


# - background task wrapper for dsl execution
class ExecuteBNDSLTask(BackgroundTask):
    """
    a binaryninja.BackgroundTask that wraps the DSLExecutor to run bn-dsl scripts
    asynchronously, handling script parsing, execution, and user feedback.
    """

    def __init__(self, bv: BinaryView, dsl_script: str):
        super().__init__("Executing BN-DSL Script...", can_cancel=True)  # task title
        self.bv: BinaryView = bv
        # logger for messages specifically related to the task's lifecycle (start, stop, cancel).
        self.task_logger = bv.create_logger(f"{LOGGER_NAME}.Task")
        self.raw_dsl_script: str = dsl_script

        # instantiate the dsl_executor, providing it with a namespaced logger for its internal operations.
        executor_logger = bv.create_logger(f"{LOGGER_NAME}.DSLExecutor")
        self.dsl_executor = DSLExecutor(self.bv, executor_logger)

    def _extract_bndsl_code_block(self, script_content: str) -> str:
        """
        extracts content from a markdown-style bndsl code block (e.g., ```bndsl ... ```).
        if no such block is found, returns the original script content, stripped.
        this allows users to paste llm output that might include surrounding text.
        """
        # regex to find a bndsl code block, case-insensitive for "bndsl" tag.
        # re.dotall allows '.' to match newlines, for multi-line code blocks.
        codeblock_pattern = r"```(?:bndsl|BNDSL)\s*\n(.*?)\n*```"
        match = re.search(codeblock_pattern, script_content, re.DOTALL | re.IGNORECASE)

        if match:
            # group(1) contains the content inside the code block.
            extracted_content = match.group(1).strip()
            self.task_logger.log_debug(
                f"extracted bndsl code block from markdown (original len: {len(script_content)}, extracted len: {len(extracted_content)})."
            )
            return extracted_content
        else:
            # no code block found, assume the entire input is the dsl script.
            self.task_logger.log_debug(
                "no bndsl markdown code block detected, using raw script content (stripped)."
            )
            return script_content.strip()

    def run(self):
        """
        main execution method for the background task.
        parses the dsl script, then uses dsl_executor to apply commands.
        provides final feedback to the user via logs and message boxes.
        """
        self.task_logger.log_info("bn-dsl execution task started.")

        # preprocess the script to extract only the bndsl code.
        final_dsl_script_to_parse = self._extract_bndsl_code_block(self.raw_dsl_script)

        if not final_dsl_script_to_parse:  # check after stripping and extraction
            self.task_logger.log_warn(
                "bn-dsl script is effectively empty. no actions will be performed."
            )
            interaction.show_message_box(
                "BN-DSL Execution",
                "The provided BN-DSL script is empty or contains no executable content.",
                icon=binaryninja.MessageBoxIcon.WarningIcon,
            )
            self.finish()  # ensure task status is updated
            return

        # - step 1: parse the dsl script string into command objects.
        parsed_commands: list[DSLCommand] = []
        try:
            parsed_commands = parse_bndsl(final_dsl_script_to_parse)
        except Exception as parse_err:
            # handle errors during the parsing phase.
            self.task_logger.log_error(f"failed to parse bn-dsl script: {parse_err}")
            self.task_logger.log_error(
                traceback.format_exc()
            )  # log full traceback for debugging
            # inform the user about the parsing failure.
            interaction.show_message_box(
                "BN-DSL Parse Error",
                f"Failed to parse the BN-DSL script:\n{parse_err}\n\n(See log for more details.)",
                icon=binaryninja.MessageBoxIcon.ErrorIcon,
            )
            self.finish()  # ensure task status is updated
            return

        # check if parsing resulted in commands, or if script was e.g. only comments.
        if (
            not parsed_commands and final_dsl_script_to_parse
        ):  # script had content, but no commands were parsed
            self.task_logger.log_info(
                "bn-dsl script parsed successfully but yielded zero commands (it might contain only comments or whitespace). no actions performed."
            )
            # this isn't an error, so a less alarming feedback or just log is fine.
            interaction.show_message_box(
                "BN-DSL Execution",
                "Script parsed, but no executable DSL commands were found (e.g., script might only contain comments).",
                icon=binaryninja.MessageBoxIcon.InformationIcon,
            )
            self.finish()
            return

        # - step 2: execute the parsed commands using the dsl_executor.
        #   the cancellation_check lambda allows the executor to periodically check if this task has been cancelled.
        num_successful, num_failed, error_detail_messages = (
            self.dsl_executor.execute_script_commands(
                parsed_commands,
                cancellation_check=lambda: self.cancelled,  # pass the task's cancelled status
            )
        )

        # - step 3: construct and show final summary feedback to the user.
        summary_message_parts = []
        if self.cancelled:  # check if task was cancelled by user during execution
            self.task_logger.log_info(
                f"bn-dsl execution task was cancelled by user during command processing."
            )
            summary_message_parts.append("Execution was cancelled by the user.")
        else:
            self.task_logger.log_info(
                f"bn-dsl execution task finished processing commands."
            )
            summary_message_parts.append("Execution finished.")

        summary_message_parts.append(
            f"{num_successful} command(s) processed successfully and were journaled."
        )
        if num_failed > 0:
            summary_message_parts.append(
                f"{num_failed} command(s) failed or were skipped due to errors."
            )

        final_user_summary_message = " ".join(summary_message_parts)

        # append specific error details to the summary if any occurred.
        if error_detail_messages:
            self.task_logger.log_warn(
                "details of errors/warnings encountered during bn-dsl command execution:"
            )
            error_details_for_dialog = "\n\nSpecific Errors/Warnings Encountered:\n"
            for i, error_msg_detail_item in enumerate(error_detail_messages):
                self.task_logger.log_warn(
                    f"  - {error_msg_detail_item}"
                )  # log all details
                if i < 5:  # limit number of errors shown in the dialog for brevity
                    error_details_for_dialog += f"- {error_msg_detail_item}\n"
            if len(error_detail_messages) > 5:
                error_details_for_dialog += f"...and {len(error_detail_messages) - 5} more (see log for full details)."

            final_user_summary_message += error_details_for_dialog

        # determine the appropriate icon for the message box based on the outcome.
        message_box_icon = binaryninja.MessageBoxIcon.InformationIcon  # default to info
        if self.cancelled or num_failed > 0:
            message_box_icon = binaryninja.MessageBoxIcon.WarningIcon

        # # show the summary message box to the user.
        # # disable message boxes for now cause they're annoying
        # if (
        #     num_successful > 0
        #     or num_failed > 0
        #     or self.cancelled
        #     or (not parsed_commands and final_dsl_script_to_parse)
        # ):  # ensures some feedback if script had content but no commands
        #     interaction.show_message_box(
        #         "BN-DSL Execution Summary",
        #         final_user_summary_message,
        #         icon=message_box_icon,
        #     )

        self.finish()
