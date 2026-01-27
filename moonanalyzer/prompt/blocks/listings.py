from __future__ import annotations

from typing import List

from ..base import ListingBundle
from ...context.base import ContextGraph


def build_listing_block(context: ContextGraph, listings: ListingBundle) -> str:
    blocks: List[str] = []
    for func in context.functions:
        listing = listings.listings.get(func.start)
        header = f"// Function: {func.name} @ 0x{func.start:x}"
        blocks.append(header)
        if listing:
            blocks.append(listing.text)
        else:
            blocks.append("-- listing missing --")
        blocks.append("")
    body = "\n".join(blocks).strip()
    if not body:
        body = "-- listing missing --"
    return f"```\n{body}\n```"
