from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from ..annotate.executor import AnnotationExecutor
from ..context.collector import ContextCollector
from ..context.strategies.forward_refs import ForwardReferencesStrategy
from ..context.strategies.data_refs import DataReferencesStrategy
from ..context.strategies.callers import CallersStrategy
from ..context.strategies.code_xrefs import CodeXrefsStrategy
from ..listing.renderers.hlil import HLILListingRenderer
from ..prompt.recipes.analysis_v1 import AnalysisV1Recipe
from .analysis_service import AnalysisService


@dataclass
class AppServices:
    """
    Container for services wired by the composition root.

    Services are intentionally explicit to keep the architecture modular.
    """

    context_collector: ContextCollector
    analysis_service: AnalysisService
    dsl_executor: AnnotationExecutor


_services: Optional[AppServices] = None


def get_services() -> AppServices:
    """Return a singleton service container for the plugin instance."""
    global _services
    if _services is None:
        context_collector = ContextCollector(
            strategies=[
                ForwardReferencesStrategy(),
                CallersStrategy(),
                CodeXrefsStrategy(),
                DataReferencesStrategy(),
            ]
        )
        analysis_service = AnalysisService(
            context_collector=context_collector,
            prompt_recipe=AnalysisV1Recipe(),
            listing_renderer=HLILListingRenderer(),
        )
        _services = AppServices(
            context_collector=context_collector,
            analysis_service=analysis_service,
            dsl_executor=AnnotationExecutor(),
        )
    return _services
