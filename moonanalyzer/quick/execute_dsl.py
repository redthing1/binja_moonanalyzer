from typing import List, Set, Optional, Deque
import collections
import traceback
import re

import binaryninja
from binaryninja import BinaryView, Function, PluginCommand, BackgroundTask, Settings


from ..defs import LOGGER_NAME
from ..settings import my_settings
from ..dsl import DSLCommand, CommentCommand, FNameCommand, VNameCommand, parse_bndsl


class ExecuteBNDSLTask(BackgroundTask):
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
            return raw_dsl_script.strip()

    def run(self):
        # parse the dsl script
        self.log.log_debug(f"bndsl script: {self.dsl_script}")
        commands: list[DSLCommand] = parse_bndsl(self.dsl_script)
        self.log.log_debug(f"parsed bndsl commands: {commands}")

        # apply the changes within a transaction
        with self.bv.undoable_transaction():
            for command in commands:
                if self.cancelled:
                    self.log.log_info("Cancelled")
                    return

                # run the command
                self.log.log_debug(f"executing command: {command}")
                try:
                    self._execute_dsl_command(command)
                except Exception as e:
                    self.log.log_error(f"error executing command: {command}")
                    self.log.log_error(traceback.format_exc())
                    continue

        if not self.cancelled:
            self.log.log_info("bndsl script execution finished.")
            self.finish()
        else:
            self.log.log_info("bndsl script execution cancelled.")

    def _execute_comment_command(self, command: CommentCommand):
        # try to get the function containing the address for the comment
        target_func_list = self.bv.get_functions_containing(command.address)
        if target_func_list:
            target_func = target_func_list[0]
            self.log.log_info(
                f"setting comment in function '{target_func.name}' at 0x{command.address:x}: \"{command.text}\""
            )
            # set_comment_at is a method of the function object for function-specific comments
            target_func.set_comment_at(command.address, command.text)
        else:
            # if no function contains the address, set it as a global comment on the binary view
            self.log.log_info(
                f'setting global comment at 0x{command.address:x}: "{command.text}"'
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
        # the address in vnamecommand identifies the function scope
        target_func_list = self.bv.get_functions_containing(command.address)

        # fallback: check if the address is the start of a function if not found by containing
        if not target_func_list:
            func_at_start = self.bv.get_function_at(command.address)
            if func_at_start:
                target_func_list = [func_at_start]

        if target_func_list:
            target_func = target_func_list[0]
            self.log.log_info(
                f"vname command: processing variables in function '{target_func.name}' (0x{target_func.start:x}) for root '{command.old_var_root}' -> '{command.new_var_root}'."
            )
            renamed_count = 0
            # func.vars includes parameters, stack variables, and register variables
            # that are part of the function's analysis context.
            for var_to_rename in target_func.vars:
                if var_to_rename.name.startswith(command.old_var_root):
                    original_var_name = var_to_rename.name
                    # preserve any suffix after the old_var_root
                    suffix = original_var_name[len(command.old_var_root) :]
                    new_variable_name = command.new_var_root + suffix
                    try:
                        # setting the .name property on a variable object renames it
                        var_to_rename.name = new_variable_name
                        self.log.log_info(
                            f"  renamed variable '{original_var_name}' to '{new_variable_name}' in function '{target_func.name}'."
                        )
                        renamed_count += 1
                    except Exception as e:
                        # catch potential errors during rename (e.g., name collision if not robustly handled by bn core for specific cases)
                        self.log.log_error(
                            f"  failed to rename variable '{original_var_name}' to '{new_variable_name}' in '{target_func.name}': {e}"
                        )
            if renamed_count == 0:
                self.log.log_warn(
                    f"  vname command: no variables found starting with root '{command.old_var_root}' in function '{target_func.name}'."
                )
        else:
            self.log.log_warn(
                f"vname command: no function found containing or starting at address 0x{command.address:x} to process variables."
            )

    def _execute_dsl_command(self, command: DSLCommand):
        if isinstance(command, CommentCommand):
            self._execute_comment_command(command)
        elif isinstance(command, FNameCommand):
            self._execute_fname_command(command)
        elif isinstance(command, VNameCommand):
            self._execute_vname_command(command)
        else:
            # this case should ideally be caught by the parser or earlier validation
            raise NotImplementedError(
                f"unknown or unhandled dsl command type: {type(command).__name__} for command: {command}"
            )
