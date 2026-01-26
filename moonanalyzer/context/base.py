from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from binaryninja import BinaryView, Function


@dataclass(frozen=True)
class ContextParams:
    """Parameters that control context collection behavior."""

    max_depth: int = 1
    max_functions: int = 0  # 0 means unlimited
    include_entry: bool = True


@dataclass(frozen=True)
class ContextEdge:
    """Represents a relationship between two functions in the context graph."""

    source: "Function"
    target: "Function"
    reason: str
    source_address: Optional[int] = None


@dataclass
class ContextGraph:
    """Collected context graph with functions and discovery relationships."""

    functions: list["Function"]
    edges: list[ContextEdge]


class ContextStrategy(Protocol):
    """Strategy interface for collecting functions around an entry point."""

    id: str
    label: str

    def collect(
        self, bv: "BinaryView", entry_func: Optional["Function"], params: ContextParams
    ) -> ContextGraph:
        ...
