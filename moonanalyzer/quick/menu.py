import binaryninja
from binaryninja import BinaryView, PluginCommand


from ..defs import LOGGER_NAME
from .gather_context import GatherQuickAnalysisContextTask


def quick_analysis_menu(bv: BinaryView):
    # run gather context
    gather_task = GatherQuickAnalysisContextTask(bv)
    gather_task.run()

    # check if canceled
    if gather_task.cancelled:
        # too bad
        return

    # show dialog with context
    prompt_title = "Quick Analysis"

    context_val = gather_task.result_string
    context_text_field = binaryninja.interaction.MultilineTextField(
        prompt="", default=context_val
    )
    if binaryninja.interaction.get_form_input([context_text_field], prompt_title):
        # clicked ok
        return context_text_field.result
    else:
        # canceled
        return None

    pass


PluginCommand.register(
    "MoonAnalyzer\\Quick Analysis",
    "Begin quick analysis of the current function",
    quick_analysis_menu,
)
