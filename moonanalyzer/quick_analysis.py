import binaryninja
from binaryninja import BinaryView, PluginCommand, BackgroundTask

from .defs import LOGGER_NAME

from .listing import (
    get_function_code_lines,
    create_formatted_code_listing_string,
    CodeDisplayType,
    LinearListingLine,
)


class GatherQuickAnalysisContextTask(BackgroundTask):
    def __init__(self, bv: BinaryView):
        BackgroundTask.__init__(self, "Gathering context...", can_cancel=True)
        self.bv = bv
        self.log = bv.create_logger(LOGGER_NAME)

    def run(self):
        # get current functions here
        curr_funcs = self.bv.get_functions_containing(addr=self.bv.offset)

        # make sure exactly one function is selected
        if len(curr_funcs) != 1:
            self.log.log_error(
                f"expected exactly one function at {hex(self.bv.offset)}, got {len(curr_funcs)} functions"
            )
            # fail
            self.cancel()
            return
        curr_func = curr_funcs[0]

        # grab hlil listing
        hlil_listing_str = create_formatted_code_listing_string(
            func=curr_func,
            display_type=CodeDisplayType.HLIL,
        )

        # set result
        self.result = hlil_listing_str

        # mark finished
        self.finish()


def quick_analysis_cmd(bv: BinaryView):
    # run gather context
    gather_task = GatherQuickAnalysisContextTask(bv)
    gather_task.run()

    # check if canceled
    if gather_task.is_canceled():
        # too bad
        return

    # show dialog with context
    prompt_title = "Quick Analysis"

    context_val = gather_task.result
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
    quick_analysis_cmd,
)
