from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from typing import Callable, Iterable, Optional, TYPE_CHECKING

from .base import ContextEdge, ContextGraph, ContextParams
from .graph import ContextGraphBuilder
from ..defs import LOGGER_NAME

if TYPE_CHECKING:
    from binaryninja import BinaryView, Function


@dataclass(frozen=True)
class Neighbor:
    next_func: "Function"
    edge_source: "Function"
    edge_target: "Function"
    reason: str
    source_address: Optional[int] = None


NeighborFn = Callable[["Function"], Iterable[Neighbor]]


def bfs_collect(
    bv: "BinaryView",
    entry_func: Optional["Function"],
    params: ContextParams,
    neighbor_fn: NeighborFn,
) -> ContextGraph:
    logger = bv.create_logger(LOGGER_NAME)
    builder = ContextGraphBuilder(max_functions=params.max_functions)

    if entry_func is None:
        logger.log_error("context collection failed: no entry function provided")
        return builder.build()

    if params.include_entry:
        builder.add_function(entry_func)

    queue = deque([(entry_func, 0)])
    while queue:
        func, depth = queue.popleft()
        if depth >= params.max_depth:
            continue

        try:
            neighbors = list(neighbor_fn(func))
        except Exception as exc:
            logger.log_error(
                f"context traversal error in neighbor_fn for {func.name} @ 0x{func.start:x}: {exc}"
            )
            continue

        for neighbor in neighbors:
            next_func = neighbor.next_func
            if builder.has_function(next_func):
                builder.add_edge(
                    ContextEdge(
                        source=neighbor.edge_source,
                        target=neighbor.edge_target,
                        reason=neighbor.reason,
                        source_address=neighbor.source_address,
                    )
                )
                continue

            if not builder.can_add_more():
                return builder.build()

            if builder.add_function(next_func):
                builder.add_edge(
                    ContextEdge(
                        source=neighbor.edge_source,
                        target=neighbor.edge_target,
                        reason=neighbor.reason,
                        source_address=neighbor.source_address,
                    )
                )
                queue.append((next_func, depth + 1))

    return builder.build()
