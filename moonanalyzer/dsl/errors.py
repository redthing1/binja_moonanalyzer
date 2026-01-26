from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


class BNDslError(Exception):
    """Base error for BNDSL parsing and validation."""


class BNDslParseError(BNDslError):
    """Raised when BNDSL parsing fails."""

    def __init__(self, message: str, line: Optional[int] = None, column: Optional[int] = None):
        super().__init__(message)
        self.line = line
        self.column = column


@dataclass(frozen=True)
class ValidationIssue:
    severity: str  # "error" or "warning"
    message: str
    command_index: Optional[int] = None
