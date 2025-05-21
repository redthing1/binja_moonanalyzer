from typing import List, Set, Optional, Deque
import collections
import traceback
import re

import binaryninja
from binaryninja import (
    BinaryView,
    Function,
    PluginCommand,
    BackgroundTask,
    Settings,
    Symbol,
    SymbolType,
    Type,
)


from ..defs import LOGGER_NAME
from ..settings import my_settings
from ..dsl import (
    DSLCommand,
    CommentCommand,
    FNameCommand,
    VNameCommand,
    DNameCommand,
    parse_bndsl,
)


class ExecuteBNDSLTask(BackgroundTask):
    # - metadata keys for journaling
    OP_COUNT_KEY = "moonanalyzer.bndsl_op_count"
    OP_DATA_PREFIX = "moonanalyzer.bndsl_op_data_"

    def __init__(self, bv: BinaryView, dsl_script: str):
        super().__init__("Executing BN-DSL...", can_cancel=True)
        self.bv: BinaryView = bv
        self.log = bv.create_logger(LOGGER_NAME)
        self.dsl_script: str = self._extract_bndsl_code_block(dsl_script)

    def _extract_bndsl_code_block(self, raw_dsl_script: str) -> str:
        codeblock_match = re.search(
            r"```(?:bndsl|BNDSL)\s*\n(.*?)```",
            raw_dsl_script,
            re.DOTALL | re.IGNORECASE,
        )
        if codeblock_match:
            # extract the content of the code block
            self.log.log_debug(
                f"extracted bndsl code block from markdown (len={len(codeblock_match.group(1))})"
            )
            return codeblock_match.group(1).strip()
        else:
            # if no code block is found, return the original script
            self.log.log_debug(
                "no bndsl code block found in markdown, using raw script."
            )
            return raw_dsl_script.strip()

    def run(self):
        # parse the dsl script
        self.log.log_debug(
            f"bndsl script to parse (len={len(self.dsl_script)}):\n{self.dsl_script[:500]}{'...' if len(self.dsl_script) > 500 else ''}"
        )
        try:
            commands: list[DSLCommand] = parse_bndsl(self.dsl_script)
        except Exception as parse_err:
            self.log.log_error(f"failed to parse bndsl script: {parse_err}")
            self.log.log_error(traceback.format_exc())
            self.bv.show_message_box(
                "BN-DSL Execution Error",
                f"Failed to parse BN-DSL script:\n{parse_err}",
                icon=binaryninja.MessageBoxIcon.ErrorIcon,
            )
            self.finish()
            return

        self.log.log_debug(f"parsed {len(commands)} bndsl commands")

        # - journaling setup
        # retrieve the current total count of journaled operations
        current_op_journal_count = 0
        try:
            # query_metadata returns the value or None if not found.
            # it can also raise if the type is incompatible, though less likely for simple int.
            queried_count = self.bv.query_metadata(self.OP_COUNT_KEY)
            if isinstance(queried_count, int):
                current_op_journal_count = queried_count
            elif queried_count is not None:
                # exists but not an int
                self.log.log_warn(
                    f"metadata key '{self.OP_COUNT_KEY}' exists but is not an integer (type: {type(queried_count)}). "
                    "resetting journal count to 0."
                )
            # if queried_count is None, current_op_journal_count remains 0
        except Exception as e:
            self.log.log_error(
                f"error querying metadata key '{self.OP_COUNT_KEY}': {e}. "
                "defaulting journal count to 0."
            )
        self.log.log_info(
            f"starting bndsl journal count at: {current_op_journal_count}"
        )

        # apply the changes within a transaction
        ops_successfully_journaled_this_run = 0
        with self.bv.undoable_transaction():
            for command_obj in commands:
                if self.cancelled:
                    self.log.log_info("task cancelled during command execution loop.")
                    break

                # run the command
                self.log.log_debug(f"executing command: {command_obj}")
                try:
                    self._execute_dsl_command(command_obj)

                    # - journal this successfully executed command
                    try:
                        # ensure the command object has the to_dsl_string method
                        if not hasattr(command_obj, "to_dsl_string"):
                            self.log.log_error(
                                f"command object {type(command_obj)} does not have 'to_dsl_string' method. skipping journal."
                            )
                            continue

                        command_dsl_str = command_obj.to_dsl_string()
                        journal_index = (
                            current_op_journal_count
                            + ops_successfully_journaled_this_run
                        )
                        metadata_key_for_op = f"{self.OP_DATA_PREFIX}{journal_index}"

                        self.bv.store_metadata(metadata_key_for_op, command_dsl_str)
                        self.log.log_debug(
                            f"journaled to '{metadata_key_for_op}': {command_dsl_str}"
                        )
                        ops_successfully_journaled_this_run += 1
                    except Exception as journal_e:
                        self.log.log_error(
                            f"failed to journal command {command_obj}: {journal_e}"
                        )
                        self.log.log_error(traceback.format_exc())
                        # continue execution even if journaling this one command fails

                except Exception as exec_e:
                    self.log.log_error(f"error executing command: {command_obj}")
                    self.log.log_error(traceback.format_exc())
                    # do not journal a command that failed to execute
                    continue

        # - update the total operation count in metadata if any commands were processed and journaled
        if ops_successfully_journaled_this_run > 0:
            new_total_op_journal_count = (
                current_op_journal_count + ops_successfully_journaled_this_run
            )
            try:
                self.bv.store_metadata(self.OP_COUNT_KEY, new_total_op_journal_count)
                self.log.log_info(
                    f"updated BNDSL operation journal count to: {new_total_op_journal_count}"
                )
            except Exception as e:
                self.log.log_error(
                    f"failed to update metadata '{self.OP_COUNT_KEY}': {e}"
                )
                self.log.log_error(traceback.format_exc())

        if not self.cancelled:
            self.log.log_info("bndsl script execution and journaling finished.")
        else:
            if ops_successfully_journaled_this_run > 0:
                self.log.log_info(
                    f"bndsl script execution cancelled after processing and journaling {ops_successfully_journaled_this_run} commands."
                )
            else:
                self.log.log_info(
                    "bndsl script execution cancelled before any commands were processed."
                )
        self.finish()

    def _execute_comment_command(self, command: CommentCommand):
        # try to get the function containing the address for the comment
        target_func_list = self.bv.get_functions_containing(command.address)
        if target_func_list:
            target_func = target_func_list[0]
            self.log.log_info(
                f"setting comment in function '{target_func.name}' at 0x{command.address:x}: \"{command.text[:60]}{'...' if len(command.text) > 60 else ''}\""
            )
            # set_comment_at is a method of the function object for function-specific comments
            target_func.set_comment_at(command.address, command.text)
        else:
            # if no function contains the address, set it as a global comment on the binary view
            self.log.log_info(
                f"setting global comment at 0x{command.address:x}: \"{command.text[:60]}{'...' if len(command.text) > 60 else ''}\""
            )
            self.bv.set_comment_at(command.address, command.text)

    def _execute_fname_command(self, command: FNameCommand):
        target_func: Optional[Function] = self.bv.get_function_at(command.address)
        if target_func:
            old_name = target_func.name
            target_func.name = command.new_name
            self.log.log_info(
                f"renamed function at 0x{command.address:x} from '{old_name}' to '{command.new_name}'"
            )
        else:
            self.log.log_warn(
                f"fname command: no function found at address 0x{command.address:x} to rename to '{command.new_name}'."
            )

    def _execute_vname_command(self, command: VNameCommand):
        # vname handles renaming of local variables (parameters, stack, register)
        # within a specific function. the command.function_address is used to
        # identify this function, either by being within its range or its start address.

        target_func: Optional[Function] = None

        # attempt to find the function if the address is within its body
        functions_containing_address = self.bv.get_functions_containing(
            command.function_address
        )
        if functions_containing_address:
            # if multiple functions contain the address (e.g., thunks, overlaps),
            # default to the first one returned by the api.
            target_func = functions_containing_address[0]
            self.log.log_debug(
                f"vname: command address 0x{command.function_address:x} is within function '{target_func.name}' (0x{target_func.start:x})."
            )
        else:
            # fallback: check if the address is the exact start of a function
            function_at_start_address = self.bv.get_function_at(
                command.function_address
            )
            if function_at_start_address:
                target_func = function_at_start_address
                self.log.log_debug(
                    f"vname: command address 0x{command.function_address:x} is the start of function '{target_func.name}' (0x{target_func.start:x})."
                )

        if target_func:
            self.log.log_info(
                f"vname: processing local variables in function '{target_func.name}' (0x{target_func.start:x}) "
                f"for root rename: '{command.old_var_root}' -> '{command.new_var_root}'."
            )

            renamed_variables_count = 0
            # iterate through all variables (parameters, stack, register) associated with the function.
            # `var_to_rename` is a `binaryninja.Variable` object.
            for var_to_rename in target_func.vars:
                if var_to_rename.name.startswith(command.old_var_root):
                    original_variable_name = var_to_rename.name

                    # preserve any suffix that exists after the old_var_root.
                    # this handles cases like `var_10` (root `var_`) or `buffer_a` (root `buffer_`).
                    suffix = original_variable_name[len(command.old_var_root) :]
                    new_variable_name = command.new_var_root + suffix

                    try:
                        # assigning to the .name property of a variable object performs the rename.
                        var_to_rename.name = new_variable_name
                        self.log.log_info(
                            f"  renamed local variable '{original_variable_name}' to '{new_variable_name}' in function '{target_func.name}'."
                        )
                        renamed_variables_count += 1
                    except Exception as e:
                        # log errors during individual variable renames (e.g., if a name collision
                        # isn't gracefully handled by the core for a specific edge case).
                        self.log.log_error(
                            f"  failed to rename local variable '{original_variable_name}' to '{new_variable_name}' "
                            f"in '{target_func.name}': {e}\n{traceback.format_exc()}"
                        )

            if renamed_variables_count == 0:
                self.log.log_warn(
                    f"  vname: no local variables found with root '{command.old_var_root}' in function '{target_func.name}'."
                )
        else:
            # this indicates that the provided function_address did not resolve to a function.
            self.log.log_warn(
                f"vname: no function found containing or starting at address 0x{command.function_address:x}. "
                f"cannot process local variable rename for '{command.old_var_root}' -> '{command.new_var_root}'."
            )

    def _execute_dname_command(self, command: DNameCommand):
        # dname is specifically for assigning or updating names for global *data* entities.
        # it operates in two main modes based on `command.old_global_name`:
        # 1. if `old_global_name` matches "data_ADDRESS" (an auto-name pattern):
        #    it targets the data variable at that address. if a data variable exists,
        #    it uses `define_user_data_var` to assign the new name, preserving the
        #    existing type. if no data variable exists (unusual for a valid auto-name),
        #    it attempts to define one with a default 'byte' type and the new name.
        # 2. if `old_global_name` is not an auto-name pattern:
        #    it's treated as an existing symbol name. the command will attempt to
        #    find a *unique existing data symbol* with this name. if found,
        #    `define_user_symbol` is used to rename it. this path does not
        #    create new data variables if the symbol doesn't exist or isn't a data symbol.

        self.log.log_info(
            f"dname: processing global data name assignment: '{command.old_global_name}' -> '{command.new_global_name}'."
        )

        # - mode 1: `command.old_global_name` is an auto-generated name like "data_XXXXXXXX"
        parsed_address_from_auto_name = self._parse_data_auto_name(
            command.old_global_name
        )

        if parsed_address_from_auto_name is not None:
            target_address = parsed_address_from_auto_name
            self.log.log_debug(
                f"dname: '{command.old_global_name}' interpreted as auto-name for address 0x{target_address:x}."
            )

            existing_data_var = self.bv.get_data_var_at(target_address)
            type_to_use_for_define: Optional[binaryninja.Type] = None

            if existing_data_var:
                # a data variable already exists at the address from the auto-name.
                # we will use its current type when calling define_user_data_var.
                type_to_use_for_define = existing_data_var.type
                self.log.log_debug(
                    f"dname: found existing data variable at 0x{target_address:x} with type '{type_to_use_for_define}'."
                )
            else:
                # no data variable currently exists at the address derived from the auto-name.
                # this is an unexpected situation if the auto-name was validly observed,
                # but we'll proceed by attempting to define a new data variable with a default type.
                self.log.log_warn(
                    f"dname: no data variable found at 0x{target_address:x} (from auto-name '{command.old_global_name}'). "
                    "will attempt to define a new data variable with default type 'byte'."
                )
                # use a default type (e.g., unsigned byte) since none is specified in dname.
                type_to_use_for_define = Type.void()

            if type_to_use_for_define is None:
                # this should not be reached if the logic above is correct (default type fallback).
                self.log.log_error(
                    f"dname: failed to determine or assign a type for data variable at 0x{target_address:x}. "
                    "cannot proceed with define_user_data_var."
                )
                return

            try:
                # define_user_data_var creates/updates the data variable and its associated symbol.
                # this makes it a "user" defined variable and assigns the name.
                defined_dv = self.bv.define_user_data_var(
                    target_address, type_to_use_for_define, command.new_global_name
                )
                if defined_dv:
                    self.log.log_info(
                        f"dname: successfully defined/updated user data variable at 0x{target_address:x} "
                        f"(from auto-name '{command.old_global_name}') as '{command.new_global_name}' with type '{type_to_use_for_define}'."
                    )
                else:
                    # this indicates define_user_data_var itself failed.
                    self.log.log_error(
                        f"dname: call to define_user_data_var for 0x{target_address:x} as '{command.new_global_name}' returned None (failed)."
                    )

            except Exception as e:
                self.log.log_error(
                    f"dname: exception during define_user_data_var at 0x{target_address:x} for '{command.new_global_name}' "
                    f"with type '{type_to_use_for_define}': {e}\n{traceback.format_exc()}"
                )
            # this path (auto-name processing) is complete.
            return

        # - mode 2: `command.old_global_name` is treated as an existing symbol name (not an auto-name pattern).
        #   this mode specifically targets existing *data symbols* for renaming.
        self.log.log_debug(
            f"dname: '{command.old_global_name}' not an auto-name pattern. searching for existing *data symbol* to rename."
        )

        try:
            # fetch all symbols that match the old_global_name.
            all_symbols_matching_old_name = self.bv.get_symbols_by_name(
                command.old_global_name
            )
        except Exception as e:  # general catch for robustness of symbol lookup
            self.log.log_error(
                f"dname: an error occurred while searching for symbol '{command.old_global_name}': {e}"
            )
            return

        # filter these symbols to include only those of type DataSymbol.
        data_symbols_matching_old_name: List[Symbol] = []
        for sym in all_symbols_matching_old_name:
            if sym.type == SymbolType.DataSymbol:
                data_symbols_matching_old_name.append(sym)

        if not data_symbols_matching_old_name:
            # no existing *data symbol* was found with this name.
            # dname in this mode does not create new data variables from arbitrary names;
            # that's handled by mode 1 if an auto-name like "data_ADDRESS" is used.
            self.log.log_warn(
                f"dname: no existing global *data symbol* found with name '{command.old_global_name}'. rename skipped. "
                "(if naming an unnamed data variable, use 'data_ADDRESS' as the old name)."
            )
            return

        if len(data_symbols_matching_old_name) > 1:
            # ambiguity: multiple data symbols share the same old_global_name.
            self.log.log_warn(
                f"dname: {len(data_symbols_matching_old_name)} global data symbols named '{command.old_global_name}' found. "
                "rename skipped due to ambiguity. the old name must be unique among existing data symbols to be renamed."
            )
            for i, sym in enumerate(data_symbols_matching_old_name):
                self.log.log_warn(
                    f"  candidate {i+1}: '{sym.name}' (type: {sym.type}) @ 0x{sym.address:x}"
                )
            return

        # exactly one matching existing data symbol was found.
        target_data_symbol = data_symbols_matching_old_name[0]
        target_address = target_data_symbol.address

        # a DataSymbol should ideally correspond to a DataVariable.
        # if not, it might be a symbol pointing to unanalyzed data or an unusual state.
        # we log this but proceed with the symbol rename as that's the primary action here.
        if not self.bv.get_data_var_at(target_address):
            self.log.log_warn(
                f"dname: renaming existing data symbol '{command.old_global_name}' at 0x{target_address:x}, "
                "but no corresponding data variable found at that address. this is unusual but proceeding with symbol rename."
            )

        try:
            # use define_user_symbol to update the name of the existing data symbol.
            # this does not change the type of any underlying data variable.
            self.bv.define_user_symbol(
                Symbol(SymbolType.DataSymbol, target_address, command.new_global_name)
            )
            self.log.log_info(
                f"dname: successfully renamed existing global data symbol '{command.old_global_name}' "
                f"(at 0x{target_address:x}) to '{command.new_global_name}'."
            )
        except Exception as e:
            self.log.log_error(
                f"dname: error renaming existing data symbol '{command.old_global_name}' "
                f"at 0x{target_address:x} to '{command.new_global_name}': {e}\n{traceback.format_exc()}"
            )

    def _parse_data_auto_name(self, name: str) -> Optional[int]:
        """
        parses an auto-generated data variable name like 'data_XXXXXXXX'
        and returns the address integer if successful, otherwise none.
        this is case-insensitive for the hex part.
        """
        # regex to match "data_" followed by one or more hexadecimal characters.
        # binaryninja auto-names do not have leading zeros in the hex address part
        # if they are generated via ui or typical api usage (e.g. data_1000, not data_00001000).
        # however, the llm might generate it with padding, so the regex is flexible.
        match = re.fullmatch(r"data_([0-9a-fA-F]+)", name, re.IGNORECASE)
        if match:
            try:
                return int(match.group(1), 16)
            except ValueError:
                self.log.log_error(
                    f"_parse_data_auto_name: invalid hex string '{match.group(1)}' in '{name}'."
                )
                return None
        return None

    def _execute_dsl_command(self, command: DSLCommand):
        if isinstance(command, CommentCommand):
            self._execute_comment_command(command)
        elif isinstance(command, FNameCommand):
            self._execute_fname_command(command)
        elif isinstance(command, VNameCommand):
            self._execute_vname_command(command)
        elif isinstance(command, DNameCommand):
            self._execute_dname_command(command)
        else:
            # this case should ideally be caught by the parser or earlier validation
            self.log.log_error(
                f"unknown or unhandled dsl command type: {type(command).__name__} for command: {command}"
            )
            raise NotImplementedError(
                f"unknown or unhandled dsl command type: {type(command).__name__} for command: {command}"
            )
