from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from ..context.base import ContextParams
from ..context.collector import ContextCollector
from ..listing.base import ListingParams, ListingRenderer
from ..prompt.blocks.listings import build_listing_block
from ..prompt.base import ListingBundle

if TYPE_CHECKING:
    from binaryninja import BinaryView, Function


@dataclass
class ListingContextService:
    """Builds listing-only context (no prompt)."""

    context_collector: ContextCollector
    listing_renderer: ListingRenderer

    def build_listing(
        self,
        bv: "BinaryView",
        entry_func: "Function",
        context_params: ContextParams,
        listing_params: ListingParams,
    ) -> str:
        context = self.context_collector.collect(bv, entry_func, context_params)
        listings = {
            func.start: self.listing_renderer.render(bv, func, listing_params)
            for func in context.functions
        }
        bundle = ListingBundle(listings=listings)
        return build_listing_block(context, bundle)
