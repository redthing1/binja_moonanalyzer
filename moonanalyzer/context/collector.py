from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from .base import ContextGraph, ContextParams, ContextStrategy
from .graph import ContextGraphBuilder

if TYPE_CHECKING:
    from binaryninja import BinaryView, Function


@dataclass
class ContextCollector:
    """Collects context by applying multiple strategies and merging results."""

    strategies: list[ContextStrategy]

    def collect(
        self, bv: "BinaryView", entry_func: "Function | None", params: ContextParams
    ) -> ContextGraph:
        builder = ContextGraphBuilder(max_functions=params.max_functions)
        for strategy in self.strategies:
            graph = strategy.collect(bv, entry_func, params)
            builder.merge(graph)
            if not builder.can_add_more():
                break
        return builder.build()
