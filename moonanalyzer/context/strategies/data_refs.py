from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from enum import Enum
from typing import Optional, TYPE_CHECKING

from binaryninja import SymbolType

from ..base import ContextEdge, ContextGraph, ContextParams, ContextStrategy
from ..graph import ContextGraphBuilder
from ...defs import LOGGER_NAME

if TYPE_CHECKING:
    from binaryninja import BinaryView, Function


class DataSeedMode(Enum):
    SMART = "smart"
    CURSOR_DATA = "cursor_data"
    ENTRY_FUNCTION = "entry_function"


@dataclass
class DataReferencesStrategy(ContextStrategy):
    id: str = "data_references"
    label: str = "Data References"
    seed_mode: DataSeedMode = DataSeedMode.SMART

    def collect(
        self, bv: "BinaryView", entry_func: Optional["Function"], params: ContextParams
    ) -> ContextGraph:
        logger = bv.create_logger(LOGGER_NAME)
        builder = ContextGraphBuilder(max_functions=params.max_functions)
        seen_data: set[int] = set()

        def is_data_address(addr: int) -> bool:
            if bv.get_data_var_at(addr) is not None:
                return True
            sym = bv.get_symbol_at(addr)
            return sym is not None and sym.type == SymbolType.DataSymbol

        def collect_data_from_function(func: "Function") -> set[int]:
            data_addrs: set[int] = set()
            try:
                for _tokens, instr_addr in func.instructions:
                    for target_addr in bv.get_data_refs_from(addr=instr_addr):
                        if is_data_address(target_addr):
                            data_addrs.add(target_addr)
            except Exception as exc:
                logger.log_error(
                    f"data refs: error collecting data refs from {func.name} @ 0x{func.start:x}: {exc}"
                )
            return data_addrs

        def add_functions_for_data(data_addr: int, origin: Optional["Function"]) -> list["Function"]:
            newly_added: list["Function"] = []
            try:
                for ref in bv.get_code_refs(data_addr):
                    func = ref.function
                    if func is None:
                        funcs = bv.get_functions_containing(ref.address)
                        func = funcs[0] if funcs else None
                    if func is None:
                        continue

                    was_added = builder.add_function(func)
                    if was_added:
                        newly_added.append(func)

                    if origin is not None and builder.has_function(origin) and builder.has_function(func):
                        builder.add_edge(
                            ContextEdge(
                                source=origin,
                                target=func,
                                reason="data_ref",
                                source_address=data_addr,
                            )
                        )

                    if not builder.can_add_more():
                        break
            except Exception as exc:
                logger.log_error(
                    f"data refs: error collecting code refs for data @ 0x{data_addr:x}: {exc}"
                )
            return newly_added

        seed_data: set[int] = set()
        data_var = bv.get_data_var_at(bv.offset)
        symbol = bv.get_symbol_at(bv.offset)
        cursor_has_data = data_var is not None or (
            symbol is not None and symbol.type == SymbolType.DataSymbol
        )

        if self.seed_mode == DataSeedMode.CURSOR_DATA:
            if data_var is not None:
                seed_data.add(data_var.address)
            elif symbol is not None and symbol.type == SymbolType.DataSymbol:
                seed_data.add(symbol.address)
            else:
                logger.log_error("data refs: cursor is not on a data variable")
        elif self.seed_mode == DataSeedMode.ENTRY_FUNCTION:
            if entry_func is None:
                logger.log_error("data refs: entry function required but missing")
            else:
                seed_data.update(collect_data_from_function(entry_func))
        else:
            if cursor_has_data:
                if data_var is not None:
                    seed_data.add(data_var.address)
                elif symbol is not None and symbol.type == SymbolType.DataSymbol:
                    seed_data.add(symbol.address)
            elif entry_func is not None:
                logger.log_info(
                    "data refs: no cursor data; using data referenced by entry function"
                )
                seed_data.update(collect_data_from_function(entry_func))

        if params.include_entry and entry_func is not None:
            builder.add_function(entry_func)

        if not seed_data:
            logger.log_error("data refs: no seed data found")
            return builder.build()

        queue = deque([(seed_data, 0, entry_func)])
        while queue:
            data_addrs, depth, origin_func = queue.popleft()
            next_funcs: list["Function"] = []
            for data_addr in data_addrs:
                if data_addr in seen_data:
                    continue
                seen_data.add(data_addr)
                next_funcs.extend(add_functions_for_data(data_addr, origin_func))
                if not builder.can_add_more():
                    return builder.build()

            if depth >= params.max_depth:
                continue

            next_data: set[int] = set()
            for func in next_funcs:
                next_data.update(collect_data_from_function(func))
                if not builder.can_add_more():
                    break

            if next_data:
                queue.append((next_data, depth + 1, None))

        return builder.build()
