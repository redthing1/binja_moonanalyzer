from __future__ import annotations

from typing import TYPE_CHECKING

from ...defs import LOGGER_NAME
from ..base import Listing, ListingParams, ListingRenderer
from ..linear import CodeDisplayType, format_listing_lines, get_function_code_lines, truncate_lines

if TYPE_CHECKING:
    from binaryninja import BinaryView, Function


class HLILListingRenderer:
    id = "hlil"
    label = "HLIL"

    def render(self, bv: "BinaryView", func: "Function", params: ListingParams) -> Listing:
        logger = bv.create_logger(LOGGER_NAME)
        if not func:
            return Listing(text="error: invalid function for HLIL listing.", line_count=0, truncated=False)

        address_width = params.address_width
        if address_width <= 0:
            address_width = func.arch.address_size * 2 if func.arch else 8

        raw_lines = get_function_code_lines(func, CodeDisplayType.HLIL, logger)
        formatted = format_listing_lines(
            raw_lines,
            include_addresses=params.include_addresses,
            hex_address_width=address_width,
        )
        truncated_lines, truncated = truncate_lines(formatted, params.max_lines)
        text = "\n".join(truncated_lines) if truncated_lines else "-- no HLIL lines --"
        return Listing(text=text, line_count=len(truncated_lines), truncated=truncated)
