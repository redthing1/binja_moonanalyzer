from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from ..context.base import ContextParams
from ..context.collector import ContextCollector
from ..listing.base import ListingParams, ListingRenderer
from ..prompt.base import ListingBundle, Prompt, PromptInstructions, PromptPolicy, PromptRecipe

if TYPE_CHECKING:
    from binaryninja import BinaryView, Function


@dataclass
class AnalysisService:
    """Orchestrates context collection, listings, and prompt construction."""

    context_collector: ContextCollector
    prompt_recipe: PromptRecipe
    listing_renderer: ListingRenderer

    def build_prompt(
        self,
        bv: "BinaryView",
        entry_func: "Function | None",
        context_params: ContextParams,
        listing_params: ListingParams,
        instructions: PromptInstructions,
        policy: PromptPolicy,
    ) -> Prompt:
        context = self.context_collector.collect(bv, entry_func, context_params)
        if not context.functions:
            return Prompt(text="No functions collected for analysis.", truncated=False)
        listings = {
            func.start: self.listing_renderer.render(bv, func, listing_params)
            for func in context.functions
        }
        listing_bundle = ListingBundle(listings=listings)
        return self.prompt_recipe.build(
            bv=bv,
            context=context,
            listings=listing_bundle,
            instructions=instructions,
            policy=policy,
        )
