from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, TYPE_CHECKING

from .base import ContextEdge, ContextGraph

if TYPE_CHECKING:
    from binaryninja import Function


@dataclass
class ContextGraphBuilder:
    max_functions: int = 0

    def __post_init__(self) -> None:
        self._functions: list["Function"] = []
        self._edges: list[ContextEdge] = []
        self._seen_funcs: set[int] = set()
        self._seen_edges: set[tuple[int, int, str, Optional[int]]] = set()

    def can_add_more(self) -> bool:
        return self.max_functions <= 0 or len(self._functions) < self.max_functions

    def has_function(self, func: "Function") -> bool:
        return func.start in self._seen_funcs

    def add_function(self, func: "Function") -> bool:
        if func.start in self._seen_funcs:
            return False
        if not self.can_add_more():
            return False
        self._seen_funcs.add(func.start)
        self._functions.append(func)
        return True

    def add_edge(self, edge: ContextEdge) -> bool:
        if edge.source.start not in self._seen_funcs or edge.target.start not in self._seen_funcs:
            return False
        key = (edge.source.start, edge.target.start, edge.reason, edge.source_address)
        if key in self._seen_edges:
            return False
        self._seen_edges.add(key)
        self._edges.append(edge)
        return True

    def merge(self, graph: ContextGraph) -> None:
        for func in graph.functions:
            if not self.add_function(func) and not self.can_add_more():
                break
        for edge in graph.edges:
            self.add_edge(edge)

    def build(self) -> ContextGraph:
        return ContextGraph(functions=list(self._functions), edges=list(self._edges))
