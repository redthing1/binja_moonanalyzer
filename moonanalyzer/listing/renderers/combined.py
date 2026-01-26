from __future__ import annotations

from typing import TYPE_CHECKING

from ..base import Listing, ListingParams, ListingRenderer
from .hlil import HLILListingRenderer
from .disassembly import DisassemblyListingRenderer

if TYPE_CHECKING:
    from binaryninja import BinaryView, Function


class CombinedListingRenderer:
    id = "hlil_disassembly"
    label = "HLIL + Disassembly"

    def __init__(self) -> None:
        self._hlil = HLILListingRenderer()
        self._disasm = DisassemblyListingRenderer()

    def render(self, bv: "BinaryView", func: "Function", params: ListingParams) -> Listing:
        hlil_listing = self._hlil.render(bv, func, params)
        disasm_listing = self._disasm.render(bv, func, params)

        parts = [
            "// HLIL",
            hlil_listing.text,
            "",
            "// Disassembly",
            disasm_listing.text,
        ]
        text = "\n".join(parts).strip()
        line_count = text.count("\n") + (1 if text else 0)
        truncated = hlil_listing.truncated or disasm_listing.truncated
        return Listing(text=text, line_count=line_count, truncated=truncated)
