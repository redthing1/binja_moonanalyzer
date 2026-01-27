from __future__ import annotations

from ..base import ListingBundle, Prompt, PromptInstructions, PromptPolicy, PromptRecipe
from ...context.base import ContextGraph
from ..blocks.instructions import build_instructions_block
from ..blocks.metadata import build_metadata_block
from ..blocks.listings import build_listing_block
from ..blocks.dsl_spec import build_dsl_spec_block
from ..blocks.analysis_policy import build_analysis_policy_block


class AnalysisV1Recipe:
    id = "analysis_v1"
    label = "Analysis v1"

    def build(
        self,
        bv,
        context: ContextGraph,
        listings: ListingBundle,
        instructions: PromptInstructions,
        policy: PromptPolicy,
    ) -> Prompt:
        parts = [
            "You are an expert reverse-engineering assistant.",
            "Output exactly one fenced `bndsl` block AFTER the analysis.",
            build_instructions_block(instructions),
            build_analysis_policy_block(),
            build_dsl_spec_block(),
            build_metadata_block(bv),
            "LISTINGS:",
            build_listing_block(context, listings),
        ]
        text = "\n\n".join(p for p in parts if p)
        truncated = False
        if policy.max_chars and len(text) > policy.max_chars:
            text = text[: policy.max_chars].rstrip() + "\n\n// ... prompt truncated ..."
            truncated = True
        return Prompt(text=text, truncated=truncated)
