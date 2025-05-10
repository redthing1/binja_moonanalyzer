import binaryninja
from binaryninja import BinaryView, PluginCommand

from ..defs import LOGGER_NAME

from .gather_context import GatherQuickAnalysisContextTask
from .execute_dsl import ExecuteBNDSLTask


def menu_quick_analysis_begin(bv: BinaryView):
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


def menu_execute_dsl(bv: BinaryView):
    # show dialog asking for the DSL script
    prompt_title = "Execute BN-DSL Script"

    dsl_text_field = binaryninja.interaction.MultilineTextField(prompt="", default="")

    dsl_script = None
    if binaryninja.interaction.get_form_input([dsl_text_field], prompt_title):
        # clicked ok
        dsl_script = dsl_text_field.result
    else:
        # canceled
        return None
    
    # run task to execute the DSL script
    dsl_task = ExecuteBNDSLTask(bv, dsl_script)
    dsl_task.run()

    # check if canceled
    if dsl_task.cancelled:
        # too bad
        return


PluginCommand.register(
    "MoonAnalyzer\\Quick Analysis",
    "Begin quick analysis of the current function",
    menu_quick_analysis_begin,
)

PluginCommand.register(
    "MoonAnalyzer\\Execute DSL",
    "Execute BN-DSL script to annotate functions",
    menu_execute_dsl,
)
