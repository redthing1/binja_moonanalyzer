import binaryninja
from binaryninja import BinaryView, PluginCommand, BackgroundTask

from .defs import LOGGER_NAME

from .listing import (
    get_function_code_lines,
    format_code_listing,
    CodeDisplayType,
    LinearListingLine,
)


class GatherQuickAnalysisContextTask(BackgroundTask):
    def __init__(self, bv: BinaryView):
        BackgroundTask.__init__(self, "Gathering context...", can_cancel=True)
        self.bv = bv
        self.log = bv.create_logger(LOGGER_NAME)

    def make_function_context_block(self, func):
        # get function hlil listing
        hlil_listing = format_code_listing(
            func=func,
            display_type=CodeDisplayType.HLIL,
        )

        # format function chunk
        func_chunk_header = f"// Function: {func.name} @ {hex(func.start)}\n"
        func_chunk_str = func_chunk_header + hlil_listing
        return func_chunk_str

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

        # get context block for current function
        curr_func_chunk = self.make_function_context_block(curr_func)

        # set result
        self.result = curr_func_chunk

        # mark finished
        self.finish()


def quick_analysis_cmd(bv: BinaryView):
    # run gather context
    gather_task = GatherQuickAnalysisContextTask(bv)
    gather_task.run()

    # check if canceled
    if gather_task.cancelled:
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
