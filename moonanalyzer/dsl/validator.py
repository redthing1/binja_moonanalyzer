from __future__ import annotations

from typing import Iterable, List

from .ast import (
    CommentCommand,
    DNameCommand,
    DSLCommand,
    FNameCommand,
    PatchCommand,
    VNameCommand,
    VTypeCommand,
)
from .errors import ValidationIssue


def validate_bndsl(commands: Iterable[DSLCommand]) -> List[ValidationIssue]:
    issues: List[ValidationIssue] = []

    for idx, command in enumerate(commands):
        if isinstance(command, CommentCommand):
            if not command.text.strip():
                issues.append(
                    ValidationIssue(
                        severity="warning",
                        message="COMMENT has empty text; it will overwrite with blank.",
                        command_index=idx,
                    )
                )
        elif isinstance(command, FNameCommand):
            if not command.new_name.strip():
                issues.append(
                    ValidationIssue(
                        severity="error",
                        message="FNAME requires a non-empty new name.",
                        command_index=idx,
                    )
                )
        elif isinstance(command, VNameCommand):
            if not command.old_var_root.strip() or not command.new_var_root.strip():
                issues.append(
                    ValidationIssue(
                        severity="error",
                        message="VNAME requires non-empty old and new variable roots.",
                        command_index=idx,
                    )
                )
        elif isinstance(command, DNameCommand):
            if not command.old_global_name.strip() or not command.new_global_name.strip():
                issues.append(
                    ValidationIssue(
                        severity="error",
                        message="DNAME requires non-empty old and new global names.",
                        command_index=idx,
                    )
                )
        elif isinstance(command, VTypeCommand):
            if not command.var_identifier.strip() or not command.type_string.strip():
                issues.append(
                    ValidationIssue(
                        severity="error",
                        message="VTYPE requires a variable identifier and type string.",
                        command_index=idx,
                    )
                )
        elif isinstance(command, PatchCommand):
            if not command.assembly_code.strip():
                issues.append(
                    ValidationIssue(
                        severity="warning",
                        message="PATCH has empty assembly; it will be a no-op.",
                        command_index=idx,
                    )
                )

    return issues
