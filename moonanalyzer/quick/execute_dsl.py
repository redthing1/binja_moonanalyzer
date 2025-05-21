from typing import (
    List,
    Optional,
    Callable,
    Dict,
    Any,
    Tuple,
    Type,
    Union,
)
import traceback
import re
import json
import dataclasses

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
from ..util import get_or_create_tag_type

from ..dsl import (
    DSLCommand,
    CommentCommand,
    FNameCommand,
    VNameCommand,
    DNameCommand,
    VTypeCommand,
    PatchCommand,
    parse_bndsl,
)


# - helper functions for dataclass serialization
def serialize_command(command: DSLCommand) -> Dict[str, Any]:
    """
    converts a dsl command dataclass to a dictionary for storage.
    preserves the command type information for accurate deserialization.
    """
    # convert dataclass to dict
    command_dict = dataclasses.asdict(command)
    # store class name for reconstruction
    command_dict["command_class"] = command.__class__.__name__
    return command_dict


def deserialize_command(command_dict: Dict[str, Any]) -> Optional[DSLCommand]:
    """
    recreates a dsl command object from a dictionary representation.
    """
    command_class_name = command_dict.pop("command_class", None)
    if not command_class_name:
        return None

    # map command class names to actual classes
    command_classes = {
        "CommentCommand": CommentCommand,
        "FNameCommand": FNameCommand,
        "VNameCommand": VNameCommand,
        "DNameCommand": DNameCommand,
        "VTypeCommand": VTypeCommand,
        "PatchCommand": PatchCommand,
    }

    # get the appropriate class
    command_class = command_classes.get(command_class_name)
    if not command_class:
        return None

    # remove command_type from dict if present (it's a default in the dataclass)
    if "command_type" in command_dict:
        command_dict.pop("command_type")

    try:
        # instantiate the command class with the dict data
        return command_class(**command_dict)
    except Exception:
        return None


# - dsl execution logic
class DSLExecutor:
    """
    handles the core logic of executing parsed bn-dsl commands.
    it interacts with the binaryview to apply changes and manages journaling of operations.
    this class is designed to be instantiated by a wrapper (like ExecuteBNDSLTask)
    and is not directly tied to ui components or background task management.
    """

    # - metadata key for bndsl operation journaling
    # key for storing all journaled operations as a single JSON string
    BNDSL_JOURNAL_KEY = "moonanalyzer.bndsl_journal"
    # tag type for patches
    TAG_TYPE_PATCH = "Patch"

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
            VTypeCommand: self._execute_vtype_command,
            PatchCommand: self._execute_patch_command,
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
    def _get_journal(self) -> List[Dict[str, Any]]:
        """
        retrieves the current journal from the binaryview's metadata.

        returns:
            a list of dictionaries, each representing a journaled command
        """
        try:
            journal_json = self.bv.query_metadata(self.BNDSL_JOURNAL_KEY)
            if not journal_json:
                self.log.log_debug("journaling: no existing journal found.")
                return []

            return json.loads(journal_json)
        except Exception as e:
            self.log.log_error(f"journaling: failed to retrieve journal: {e}")
            return []

    def _journal_operations(self, successful_commands: List[DSLCommand]):
        """
        journals all successful dsl commands as a single JSON object in the binaryview's metadata.

        args:
            successful_commands: a list of successfully executed dslcommand objects
        """
        if not successful_commands:
            self.log.log_debug("journaling: no operations to journal.")
            return

        try:
            # get existing journal if any
            existing_journal = self._get_journal()

            # process new commands to journal
            new_entries = []
            for cmd in successful_commands:
                try:
                    # serialize the command to a dict
                    cmd_dict = serialize_command(cmd)
                    # store the dsl string for easy access
                    if hasattr(cmd, "to_dsl_string"):
                        cmd_dict["dsl_string"] = cmd.to_dsl_string()
                    else:
                        self.log.log_warn(
                            f"journaling: command object of type {type(cmd)} lacks 'to_dsl_string' method."
                        )
                    new_entries.append(cmd_dict)
                except Exception as e:
                    self.log.log_error(
                        f"journaling: failed to serialize command {cmd}: {e}"
                    )

            # combine existing journal with new entries
            journal_entries = existing_journal + new_entries

            # convert to json and store
            journal_json = json.dumps(journal_entries)
            self.bv.store_metadata(self.BNDSL_JOURNAL_KEY, journal_json)

            self.log.log_info(
                f"journaling: successfully journaled {len(new_entries)} new operations "
                f"(total journal now contains {len(journal_entries)} operations)."
            )
        except Exception as e:
            self.log.log_error(f"journaling: failed to journal operations: {e}")
            self.log.log_error(traceback.format_exc())

    def get_journaled_commands(self) -> List[DSLCommand]:
        """
        reconstructs and returns all journaled commands as DSLCommand objects.

        returns:
            a list of DSLCommand objects
        """
        journal = self._get_journal()
        commands = []

        for entry in journal:
            cmd = deserialize_command(entry)
            if cmd:
                commands.append(cmd)
            else:
                self.log.log_warn(f"Failed to deserialize command: {entry}")

        return commands

    def get_journaled_command_strings(self) -> List[str]:
        """
        retrieves all previously journaled dsl command strings from the binaryview's metadata.

        returns:
            a list of dsl command strings
        """
        journal = self._get_journal()
        return [
            entry.get("dsl_string", "") for entry in journal if "dsl_string" in entry
        ]

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
                    var_to_rename.set_name_async(new_variable_name)
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

        if renamed_variables_count > 0:
            target_func.reanalyze()

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

    def _execute_vtype_command(self, command: VTypeCommand):
        """handles the VTYPE dsl command for setting local variable types."""
        self.log.log_info(
            f"vtype: setting type for '{command.var_identifier}' in func 0x{command.function_address:x} to '{command.type_string}'."
        )

        target_func = self._get_function_context(command.function_address)
        if not target_func:
            self.log.log_warn(
                f"vtype: no function context for 0x{command.function_address:x}. "
                f"cannot type '{command.var_identifier}'. skipped."
            )
            return

        # attempt to parse the type string
        parsed_type_obj: Optional[binaryninja.Type] = None
        # name_from_string is usually not directly used for var.type assignment,
        # as the variable already has a name (command.var_identifier).
        # however, parse_type_string returns it, so we capture it.
        type_name_from_string: Optional[binaryninja.QualifiedName] = None
        try:
            parsed_type_obj, type_name_from_string = self.bv.parse_type_string(
                command.type_string
            )
            if parsed_type_obj is None:
                self.log.log_error(
                    f"vtype: failed to parse type string '{command.type_string}' for '{target_func.name}'. "
                    f"parsed_type_obj is None. command skipped."
                )
                return
            self.log.log_debug(
                f"vtype: parsed '{command.type_string}' to Type: {parsed_type_obj} (width: {parsed_type_obj.width if parsed_type_obj else 'N/A'}). "
                f"Name from string (if any): {type_name_from_string}."
            )

        except Exception as e:
            self.log.log_error(
                f"vtype: exception parsing type string '{command.type_string}' for '{target_func.name}': {e}\n{traceback.format_exc()}"
            )
            return

        variable_found_and_typed = False
        # iterate through variables in the function (parameters and local vars)
        for var_to_type in target_func.vars:  # var_to_type is a binaryninja.Variable
            # command.var_identifier should match the current name of the variable
            if var_to_type.name == command.var_identifier:
                original_var_type_str = (
                    str(var_to_type.type) if var_to_type.type else "None"
                )
                try:
                    # set the variable's type using the parsed Type object
                    var_to_type.set_type_async(parsed_type_obj)
                    self.log.log_info(
                        f"  vtype: successfully set type of '{var_to_type.name}' "
                        f"(was: {original_var_type_str}) to '{str(parsed_type_obj)}' (from: '{command.type_string}') in '{target_func.name}'."
                    )
                    variable_found_and_typed = True
                    break  # assume var_identifier is unique enough for this function
                except Exception as e:
                    self.log.log_error(
                        f"  vtype: failed to set type for '{var_to_type.name}' "
                        f"in '{target_func.name}' to '{command.type_string}': {e}\n{traceback.format_exc()}"
                    )
                    # an error here means this specific variable could not be typed.

        if not variable_found_and_typed:
            self.log.log_warn(
                f"  vtype: variable '{command.var_identifier}' not found in '{target_func.name}'. "
                f"cannot set type to '{command.type_string}'. "
                f"it might have been renamed, or does not exist."
            )

        if variable_found_and_typed:
            target_func.reanalyze()

    def _execute_patch_command(self, command: PatchCommand):
        """handles the PATCH dsl command for applying assembly code patches."""
        self.log.log_info(
            f"patch: attempting to apply patch at 0x{command.address:x} with assembly:\n{command.assembly_code[:100]}{'...' if len(command.assembly_code) > 100 else ''}"
        )

        if self.bv.arch is None:
            self.log.log_error(
                f"patch: cannot assemble, BinaryView architecture is not set. Command for 0x{command.address:x} skipped."
            )
            raise RuntimeError("BinaryView architecture not set for PATCH command")

        if not command.assembly_code.strip():
            self.log.log_warn(
                f"patch: assembly code is empty for address 0x{command.address:x}. No patch applied."
            )
            # this is a no-op, considered successful for journaling.
            return

        _ = get_or_create_tag_type(self.bv, self.TAG_TYPE_PATCH, "🩹")

        try:
            # assemble the code
            assembled_bytes: bytes = self.bv.arch.assemble(
                command.assembly_code, command.address
            )
            if not assembled_bytes:
                self.log.log_warn(
                    f"patch: assembly resulted in zero bytes for address 0x{command.address:x}. "
                    f'input assembly: "{command.assembly_code.strip()}". no patch written.'
                )
                # considered a successful no-op if assembly itself didn't error.
                return

            self.log.log_debug(
                f"patch: successfully assembled {len(assembled_bytes)} byte(s) for 0x{command.address:x}: {assembled_bytes.hex()}"
            )

            # write the assembled bytes to the BinaryView
            bytes_written = self.bv.write(command.address, assembled_bytes)
            if bytes_written != len(assembled_bytes):
                self.log.log_error(
                    f"patch: failed to write all assembled bytes at 0x{command.address:x}. "
                    f"expected to write {len(assembled_bytes)}, but wrote {bytes_written}."
                )
                raise RuntimeError(
                    f"partial write ({bytes_written}/{len(assembled_bytes)}) during patch application at 0x{command.address:x}"
                )

            self.log.log_info(
                f"patch: successfully applied {bytes_written} byte patch at 0x{command.address:x}."
            )

            # add a tag describing the patch
            self.bv.add_tag(
                addr=command.address,
                tag_type_name=self.TAG_TYPE_PATCH,
                data=f"PATCH@{command.address:x}:\n{command.assembly_code.strip()}",
                user=True,
            )

            # tell bn that data has changed so analysis can update if needed
            self.bv.notify_data_written(command.address, bytes_written)
            # request an analysis update for the function containing the patch
            func_context = self._get_function_context(command.address)
            if func_context:
                func_context.reanalyze()

        except ValueError as ve:
            self.log.log_error(
                f"patch: assembly error at 0x{command.address:x} - {ve}\nAssembly attempted:\n{command.assembly_code}"
            )
            raise
        except NotImplementedError:
            self.log.log_error(
                f"patch: architecture '{self.bv.arch.name}' does not support assembly. Command for 0x{command.address:x} failed."
            )
            raise
        except Exception as e:
            self.log.log_error(
                f"patch: unexpected error applying patch at 0x{command.address:x}: {e}\n{traceback.format_exc()}"
            )
            raise

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

        successful_ops = 0
        failed_ops = 0
        error_messages: List[str] = []

        # collect successful operations for journaling at the end
        successful_commands: List[DSLCommand] = []

        # all commands in this batch are processed within a single undoable transaction.
        with self.bv.undoable_transaction():
            for cmd_idx, command_obj in enumerate(commands):
                if cancellation_check():
                    # if cancellation is requested, log it and stop processing further commands.
                    cancellation_message = f"executor: cancellation requested. stopping after processing {cmd_idx} of {len(commands)} commands."
                    self.log.log_info(cancellation_message)
                    error_messages.append(
                        "execution was cancelled by user request."
                    )  # user-facing message
                    break  # exit the loop over commands

                self.log.log_debug(
                    f"executor: processing command {cmd_idx + 1}/{len(commands)}: {command_obj}"
                )
                command_executed_successfully = False
                try:
                    # dispatch to the appropriate handler based on the command object's type.
                    handler = self.command_handlers.get(type(command_obj))
                    if handler:
                        handler(command_obj)  # execute the specific command logic
                        command_executed_successfully = (
                            True  # assume success if handler doesn't raise
                        )
                    else:
                        # no handler is registered for this type of command.
                        err_msg = f"no handler registered for command type: {type(command_obj).__name__} (command: {command_obj}). this command was skipped."
                        self.log.log_error(err_msg)
                        error_messages.append(err_msg)
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
                    error_messages.append(err_msg)
                    # command execution failed.

                # collect successful operations for journaling at the end
                if command_executed_successfully:
                    successful_commands.append(command_obj)
                    successful_ops += 1
                else:
                    failed_ops += (
                        1  # increment failed count if execution failed or no handler
                    )

            # journal all successful operations at the end
            if successful_commands:
                self._journal_operations(successful_commands)

        self.log.log_info(
            f"executor: command execution run finished. "
            f"successful and journaled: {successful_ops}, failed or skipped: {failed_ops}."
        )
        return successful_ops, failed_ops, error_messages


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

        self.finish()
