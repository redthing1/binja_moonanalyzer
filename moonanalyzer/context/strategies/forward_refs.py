from __future__ import annotations

from typing import Iterable, Optional, TYPE_CHECKING

from ..base import ContextGraph, ContextParams, ContextStrategy
from ..traversal import Neighbor, bfs_collect
from ...defs import LOGGER_NAME

if TYPE_CHECKING:
    from binaryninja import BinaryView, Function


class ForwardReferencesStrategy:
    id = "forward_references"
    label = "Forward References"

    def collect(
        self, bv: "BinaryView", entry_func: Optional["Function"], params: ContextParams
    ) -> ContextGraph:
        logger = bv.create_logger(LOGGER_NAME)

        def neighbors(func: "Function") -> Iterable[Neighbor]:
            items: list[Neighbor] = []
            try:
                for callee in func.callees:
                    if callee is None or callee.start == func.start:
                        continue
                    items.append(
                        Neighbor(
                            next_func=callee,
                            edge_source=func,
                            edge_target=callee,
                            reason="callee",
                        )
                    )
            except Exception as exc:
                logger.log_error(
                    f"forward refs: error collecting callees for {func.name} @ 0x{func.start:x}: {exc}"
                )

            try:
                for _tokens, instr_addr in func.instructions:
                    refs = bv.get_code_refs_from(
                        addr=instr_addr, func=func, arch=func.arch
                    )
                    for target_addr in refs:
                        target_func = bv.get_function_at(
                            addr=target_addr, plat=func.platform
                        )
                        if target_func is None or target_func.start == func.start:
                            continue
                        items.append(
                            Neighbor(
                                next_func=target_func,
                                edge_source=func,
                                edge_target=target_func,
                                reason="xref",
                                source_address=instr_addr,
                            )
                        )
            except Exception as exc:
                logger.log_error(
                    f"forward refs: error collecting code xrefs for {func.name} @ 0x{func.start:x}: {exc}"
                )

            return items

        return bfs_collect(bv, entry_func, params, neighbors)
