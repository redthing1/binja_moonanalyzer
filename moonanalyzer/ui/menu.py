from __future__ import annotations

from binaryninja import BinaryView, PluginCommand, execute_on_main_thread

from ..app.analysis_service import AnalysisService
from ..app.services import get_services
from ..context.base import ContextParams
from ..context.collector import ContextCollector
from ..context.strategies.forward_refs import ForwardReferencesStrategy
from ..listing.base import ListingParams
from ..listing.renderers.hlil import HLILListingRenderer
from ..prompt.base import PromptInstructions, PromptPolicy
from ..settings import settings
from ..util import get_current_function
from .dialogs.execute_bndsl import ExecuteBNDslDialog
from .dialogs.custom_analysis import CustomAnalysisDialog
from .dialogs.listing_context import ListingContextDialog
from .dialogs.prompt_output import PromptOutputDialog
from .qt import get_main_window


def _quick_analysis_action(bv: BinaryView) -> None:
    services = get_services()
    log = bv.create_logger("MoonAnalyzer")
    entry_func = get_current_function(bv, None, log)
    if not entry_func:
        return

    context_params = ContextParams(
        max_depth=max(0, settings.get_integer("moonanalyzer.quick_analysis_context_depth", bv)),
        max_functions=max(0, settings.get_integer("moonanalyzer.quick_analysis_max_function_count", bv)),
    )
    listing_params = ListingParams(
        max_lines=max(0, settings.get_integer("moonanalyzer.analysis_max_function_lines", bv))
    )
    instructions = PromptInstructions(
        project_context=settings.get_string("moonanalyzer.analysis_project_context", bv),
        focus_instructions=settings.get_string("moonanalyzer.custom_prompt_additions", bv),
        detail_level=settings.get_string("moonanalyzer.level_of_detail_instructions", bv),
    )
    policy = PromptPolicy(max_chars=0)

    analysis_service = AnalysisService(
        context_collector=ContextCollector(strategies=[ForwardReferencesStrategy()]),
        prompt_recipe=services.analysis_service.prompt_recipe,
        listing_renderer=HLILListingRenderer(),
    )

    prompt = analysis_service.build_prompt(
        bv=bv,
        entry_func=entry_func,
        context_params=context_params,
        listing_params=listing_params,
        instructions=instructions,
        policy=policy,
    )

    def _show() -> None:
        dialog = PromptOutputDialog(
            prompt.text,
            title="Quick Analysis",
            parent=get_main_window(),
        )
        dialog.exec()

    execute_on_main_thread(_show)


def _custom_analysis_action(bv: BinaryView) -> None:
    services = get_services()

    def _show() -> None:
        dialog = CustomAnalysisDialog(bv, services, parent=get_main_window())
        dialog.exec()

    execute_on_main_thread(_show)


def _listing_context_action(bv: BinaryView) -> None:
    services = get_services()

    def _show() -> None:
        dialog = ListingContextDialog(bv, services, parent=get_main_window())
        dialog.exec()

    execute_on_main_thread(_show)


def _execute_bndsl_action(bv: BinaryView) -> None:
    services = get_services()

    def _show() -> None:
        dialog = ExecuteBNDslDialog(bv, services, parent=get_main_window())
        dialog.exec()

    execute_on_main_thread(_show)


def register() -> None:
    """Register MoonAnalyzer menu commands."""
    PluginCommand.register(
        "MoonAnalyzer\\Analysis Context (Quick)",
        "Generate prompt using default quick analysis settings",
        _quick_analysis_action,
    )
    PluginCommand.register(
        "MoonAnalyzer\\Analysis Context (Custom)",
        "Generate prompt using custom analysis settings",
        _custom_analysis_action,
    )
    PluginCommand.register(
        "MoonAnalyzer\\Listing Context",
        "Gather listing-only context for the current function",
        _listing_context_action,
    )
    PluginCommand.register(
        "MoonAnalyzer\\Execute BNDSL",
        "Execute BNDSL using MoonAnalyzer",
        _execute_bndsl_action,
    )
