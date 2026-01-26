from __future__ import annotations

from typing import Iterable, List, Optional, TYPE_CHECKING

import binaryninja
from binaryninja import Symbol, SymbolType

from .journal import Journal
from .types import ExecutionOptions, ExecutionReport
from ..defs import LOGGER_NAME
from ..dsl.ast import (
    CommentCommand,
    DNameCommand,
    DSLCommand,
    FNameCommand,
    PatchCommand,
    VNameCommand,
    VTypeCommand,
)
from ..util import get_or_create_tag_type

if TYPE_CHECKING:
    from binaryninja import BinaryView, Function


class AnnotationExecutor:
    """Executes BNDSL commands against a BinaryView."""

    TAG_TYPE_PATCH = "Patch"

    def apply(
        self,
        bv: "BinaryView",
        commands: Iterable[DSLCommand],
        options: ExecutionOptions,
    ) -> ExecutionReport:
        logger = bv.create_logger(LOGGER_NAME)
        command_list = list(commands)
        if not command_list:
            return ExecutionReport(
                success=True,
                applied_count=0,
                failed_count=0,
                message="No commands to execute.",
            )

        journal = Journal(bv)
        applied: List[DSLCommand] = []
        errors: List[str] = []
        failed = 0

        def _get_function_context(address: int) -> Optional["Function"]:
            funcs = bv.get_functions_containing(address)
            if funcs:
                return funcs[0]
            return bv.get_function_at(address)

        def _parse_data_auto_name(name: str) -> Optional[int]:
            import re

            match = re.fullmatch(r"data_([0-9a-fA-F]+)", name, re.IGNORECASE)
            if not match:
                return None
            try:
                return int(match.group(1), 16)
            except ValueError:
                return None

        def _execute_comment(command: CommentCommand) -> None:
            target_func = _get_function_context(command.address)
            if target_func:
                target_func.set_comment_at(command.address, command.text)
            else:
                bv.set_comment_at(command.address, command.text)

        def _execute_fname(command: FNameCommand) -> None:
            target_func = bv.get_function_at(command.address)
            if not target_func:
                raise ValueError(f"No function at 0x{command.address:x}")
            target_func.name = command.new_name

        def _execute_vname(command: VNameCommand) -> None:
            target_func = _get_function_context(command.function_address)
            if not target_func:
                raise ValueError(f"No function for 0x{command.function_address:x}")
            renamed = 0
            for var in target_func.vars:
                if var.name.startswith(command.old_var_root):
                    suffix = var.name[len(command.old_var_root) :]
                    var.set_name_async(command.new_var_root + suffix)
                    renamed += 1
            if renamed:
                target_func.reanalyze()

        def _execute_dname(command: DNameCommand) -> None:
            parsed_address = _parse_data_auto_name(command.old_global_name)
            if parsed_address is not None:
                existing = bv.get_data_var_at(parsed_address)
                type_to_use: Optional[binaryninja.Type] = None
                default_type_string = "void* default_dname_ptr_type"

                if existing and existing.type and existing.type.width > 0:
                    type_to_use = existing.type
                else:
                    parsed_default, _ = bv.parse_type_string(default_type_string)
                    if parsed_default is None:
                        raise ValueError(
                            f"Failed to parse default type for 0x{parsed_address:x}"
                        )
                    type_to_use = parsed_default

                bv.define_user_data_var(parsed_address, type_to_use, command.new_global_name)
                return

            symbols = bv.get_symbols_by_name(command.old_global_name)
            data_symbols = [s for s in symbols if s.type == SymbolType.DataSymbol]
            if not data_symbols:
                raise ValueError(f"No data symbol named '{command.old_global_name}'")
            if len(data_symbols) > 1:
                raise ValueError(
                    f"Multiple data symbols named '{command.old_global_name}'"
                )
            sym = data_symbols[0]
            bv.define_user_symbol(
                Symbol(SymbolType.DataSymbol, sym.address, command.new_global_name)
            )

        def _execute_vtype(command: VTypeCommand) -> None:
            target_func = _get_function_context(command.function_address)
            if not target_func:
                raise ValueError(f"No function for 0x{command.function_address:x}")
            parsed_type, _ = bv.parse_type_string(command.type_string)
            if parsed_type is None:
                raise ValueError(f"Failed to parse type string '{command.type_string}'")

            for var in target_func.vars:
                if var.name == command.var_identifier:
                    var.set_type_async(parsed_type)
                    target_func.reanalyze()
                    return
            raise ValueError(
                f"Variable '{command.var_identifier}' not found in function"
            )

        def _execute_patch(command: PatchCommand) -> None:
            if bv.arch is None:
                raise RuntimeError("BinaryView architecture is not set")
            if not command.assembly_code.strip():
                return

            get_or_create_tag_type(bv, self.TAG_TYPE_PATCH, "P")
            assembled = bv.arch.assemble(command.assembly_code, command.address)
            if not assembled:
                return

            bytes_written = bv.write(command.address, assembled)
            if bytes_written != len(assembled):
                raise RuntimeError("Partial write during patch application")

            bv.add_tag(
                addr=command.address,
                tag_type_name=self.TAG_TYPE_PATCH,
                data=f"PATCH@{command.address:x}:\n{command.assembly_code.strip()}",
                user=True,
            )
            bv.notify_data_written(command.address, bytes_written)
            func_context = _get_function_context(command.address)
            if func_context:
                func_context.reanalyze()

        handler_map = {
            CommentCommand: _execute_comment,
            FNameCommand: _execute_fname,
            VNameCommand: _execute_vname,
            DNameCommand: _execute_dname,
            VTypeCommand: _execute_vtype,
            PatchCommand: _execute_patch,
        }

        with bv.undoable_transaction():
            for cmd in command_list:
                try:
                    if options.dry_run:
                        applied.append(cmd)
                        continue
                    handler = handler_map.get(type(cmd))
                    if not handler:
                        raise ValueError(f"No handler for command {type(cmd).__name__}")
                    handler(cmd)
                    applied.append(cmd)
                except Exception as exc:
                    failed += 1
                    errors.append(str(exc))
                    logger.log_error(f"BNDSL execution error: {exc}")
                    if options.strict:
                        break

        if applied and not options.dry_run:
            journal.append(applied)

        success = failed == 0
        message = f"Applied {len(applied)} command(s), failed {failed}."
        error = "\n".join(errors) if errors else None
        return ExecutionReport(
            success=success,
            applied_count=len(applied),
            failed_count=failed,
            message=message,
            error=error,
        )
