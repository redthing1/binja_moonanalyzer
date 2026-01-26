from __future__ import annotations

from typing import Iterable, Optional, TYPE_CHECKING

from ..base import ContextGraph, ContextParams, ContextStrategy
from ..traversal import Neighbor, bfs_collect
from ...defs import LOGGER_NAME

if TYPE_CHECKING:
    from binaryninja import BinaryView, Function


class CallersStrategy:
    id = "callers"
    label = "Callers"

    def collect(
        self, bv: "BinaryView", entry_func: Optional["Function"], params: ContextParams
    ) -> ContextGraph:
        logger = bv.create_logger(LOGGER_NAME)

        def neighbors(func: "Function") -> Iterable[Neighbor]:
            items: list[Neighbor] = []
            try:
                for caller in func.callers:
                    if caller is None or caller.start == func.start:
                        continue
                    items.append(
                        Neighbor(
                            next_func=caller,
                            edge_source=caller,
                            edge_target=func,
                            reason="caller",
                        )
                    )
            except Exception as exc:
                logger.log_error(
                    f"callers: error collecting callers for {func.name} @ 0x{func.start:x}: {exc}"
                )
            return items

        return bfs_collect(bv, entry_func, params, neighbors)
