from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class ExecutionOptions:
    dry_run: bool = False
    strict: bool = False


@dataclass
class ExecutionReport:
    success: bool
    applied_count: int
    failed_count: int
    message: str
    error: Optional[str] = None
