from typing import Optional

import binaryninja
from binaryninja import (
    BinaryView,
    PluginCommand,
    Function,
    interaction,
)

from ..defs import LOGGER_NAME
from ..settings import my_settings
from ..util import get_current_function
from .gather_context import (
    GatherAnalysisContextTask,
    AnalysisParameters,
    ContextCodeType,
)
from .execute_dsl import ExecuteBNDSLTask
from .smart_patch import SmartPatchContextTask


# - ui interaction helper
def _show_analysis_result_dialog(
    bv: BinaryView, task: GatherAnalysisContextTask, mode_name_for_title: str
):
    """
    displays the analysis result from the completed (or cancelled) task.
    """
    if (
        task.cancelled and not task.result_string
    ):  # cancelled before any result could be set
        bv.show_message_box(
            f"{mode_name_for_title} Analysis",
            "Context gathering was cancelled by user or an early error.",
            buttons=binaryninja.interaction.MessageBoxButtonSet.OKButtonSet,
            icon=binaryninja.interaction.MessageBoxIcon.WarningIcon,
        )
        return

    # if result_string is empty or indicates an error, show a specific message
    if not task.result_string or task.result_string.startswith("Error:"):
        error_message = (
            task.result_string
            if task.result_string
            else "Failed to gather context or no context was produced."
        )
        bv.show_message_box(
            f"{mode_name_for_title} Analysis",
            error_message,
            buttons=binaryninja.interaction.MessageBoxButtonSet.OKButtonSet,
            icon=binaryninja.interaction.MessageBoxIcon.ErrorIcon,
        )
        return

    prompt_title = f"Analysis Context"
    context_text_field = binaryninja.interaction.MultilineTextField(
        prompt="", default=task.result_string
    )

    # show results in an editable multiline text field
    binaryninja.interaction.get_form_input([context_text_field], prompt_title)


# - menu command functions
def menu_quick_analysis_begin(bv: BinaryView):
    log = bv.create_logger(LOGGER_NAME)  # logger for menu-specific actions
    log.log_info("quick analysis command triggered.")

    raw_max_depth = my_settings.get_integer(
        "moonanalyzer.quick_analysis_context_depth", bv
    )
    clamped_max_depth = max(0, min(raw_max_depth, 3))
    max_func_count = max(
        0, my_settings.get_integer("moonanalyzer.quick_analysis_max_function_count", bv)
    )

    params = AnalysisParameters(
        max_depth=clamped_max_depth,
        max_function_count=max_func_count,
        initial_func_addr=bv.offset,
    )

    gather_task = GatherAnalysisContextTask(bv, params)
    gather_task.run()

    _show_analysis_result_dialog(bv, gather_task, "Quick")


def menu_custom_analysis_begin(bv: BinaryView):
    log = bv.create_logger(LOGGER_NAME)
    log.log_info("custom analysis command triggered.")

    default_raw_max_depth = my_settings.get_integer(
        "moonanalyzer.quick_analysis_context_depth", bv
    )
    # default_clamped_max_depth = max(0, min(default_raw_max_depth, 3))
    default_clamped_max_depth = max(0, default_raw_max_depth)
    default_max_func_count = max(
        0, my_settings.get_integer("moonanalyzer.quick_analysis_max_function_count", bv)
    )

    default_project_context = my_settings.get_string(
        "moonanalyzer.analysis_project_context", bv
    )
    default_custom_prompt_additions = my_settings.get_string(
        "moonanalyzer.custom_prompt_additions", bv
    )
    default_level_of_detail_instructions = my_settings.get_string(
        "moonanalyzer.level_of_detail_instructions", bv
    )

    project_context_field = interaction.MultilineTextField(
        "Project Context:",
        default=default_project_context,
    )
    custom_prompt_field = interaction.MultilineTextField(
        "Focus Instructions:",
        default=default_custom_prompt_additions,
    )
    detail_level_field = interaction.MultilineTextField(
        f"Level of Detail:",
        default=default_level_of_detail_instructions,
    )
    code_type_choices = [str(ct) for ct in ContextCodeType]
    code_type_field = interaction.ChoiceField(
        "Code Listing Type:",
        choices=code_type_choices,
        # default=str(ContextCodeType.HLIL),
        default=0,  # bug: binja says str but expects int
    )
    depth_field = interaction.IntegerField(
        "Max Traversal Depth:",
        default=default_clamped_max_depth,
    )
    count_field = interaction.IntegerField(
        "Max Functions:",
        default=default_max_func_count,
    )

    form_fields = [
        project_context_field,
        custom_prompt_field,
        detail_level_field,
        code_type_field,
        depth_field,
        count_field,
    ]

    if interaction.get_form_input(form_fields, "Custom Analysis Parameters"):
        # user_depth = max(0, min(depth_field.result, 3))
        user_depth = max(0, depth_field.result)
        user_count = max(0, count_field.result)
        user_project_context = project_context_field.result.strip()
        user_custom_prompt = custom_prompt_field.result.strip()
        user_detail_level = detail_level_field.result.strip()
        user_code_type = ContextCodeType(code_type_choices[code_type_field.result])

        params = AnalysisParameters(
            max_depth=user_depth,
            max_function_count=user_count,
            project_context=user_project_context,
            custom_prompt_additions=user_custom_prompt,
            level_of_detail_instructions=user_detail_level,
            code_type=user_code_type,
            initial_func_addr=bv.offset,
        )

        gather_task = GatherAnalysisContextTask(bv, params)
        gather_task.run()

        _show_analysis_result_dialog(bv, gather_task, "Custom")


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


def menu_gather_listing_context(bv: BinaryView):
    # just gather hlil listing info without the promt
    log = bv.create_logger(LOGGER_NAME)
    log.log_info("listing context command triggered.")

    default_max_depth = max(
        0, my_settings.get_integer("moonanalyzer.quick_analysis_context_depth", bv)
    )
    default_max_func_count = max(
        0, my_settings.get_integer("moonanalyzer.quick_analysis_max_function_count", bv)
    )

    code_type_choices = [str(ct) for ct in ContextCodeType]
    code_type_field = interaction.ChoiceField(
        "Code Listing Type:",
        choices=code_type_choices,
        # default=str(ContextCodeType.HLIL),
        default=0,  # bug: binja says str but expects int
    )
    depth_field = interaction.IntegerField(
        "Max Traversal Depth:",
        default=default_max_depth,
    )
    count_field = interaction.IntegerField(
        "Max Functions:",
        default=default_max_func_count,
    )

    form_fields = [code_type_field, depth_field, count_field]

    if interaction.get_form_input(form_fields, "Listing Context Parameters"):
        user_depth = max(0, depth_field.result)
        user_count = max(0, count_field.result)
        user_code_type = ContextCodeType(code_type_choices[code_type_field.result])

        params = AnalysisParameters(
            max_depth=user_depth,
            max_function_count=user_count,
            initial_func_addr=bv.offset,
            code_type=user_code_type,
            listing_only=True,
        )

        gather_task = GatherAnalysisContextTask(bv, params)
        gather_task.run()

        # check if cancelled
        if gather_task.cancelled:
            # too bad
            return

        # show results in an editable multiline text field
        prompt_title = f"Listing Context"
        context_text_field = binaryninja.interaction.MultilineTextField(
            prompt="", default=gather_task.result_string
        )
        binaryninja.interaction.get_form_input([context_text_field], prompt_title)


def menu_smart_patch_begin(bv: BinaryView):
    log = bv.create_logger(LOGGER_NAME)
    log.log_info("smart patch command triggered.")

    current_function: Optional[Function] = get_current_function(
        bv=bv, addr=None, log=log
    )
    if not current_function:
        interaction.show_message_box(
            "Smart Patch Error",
            "no current function selected. please navigate to a function.",
            icon=binaryninja.interaction.MessageBoxIcon.ErrorIcon,
        )
        log.log_error("smart patch attempted without a current function.")
        return

    patch_objective_text_field = interaction.MultilineTextField(
        "Objective:"
    )

    if interaction.get_form_input(
        [patch_objective_text_field], "Smart Patch Objective"
    ):
        patch_objective = patch_objective_text_field.result.strip()
        if not patch_objective:
            interaction.show_message_box(
                "Smart Patch Error",
                "Objective cannot be empty.",
                icon=binaryninja.interaction.MessageBoxIcon.ErrorIcon,
            )
            log.log_warn("user provided an empty patch objective.")
            return

        log_objective = patch_objective[:100].replace("\n", " ") + (
            "..." if len(patch_objective) > 100 else ""
        )
        log.log_info(
            f"user entered patch objective for function '{current_function.name}': {log_objective}"
        )

        patch_context_task = SmartPatchContextTask(
            bv, current_function, patch_objective
        )
        patch_context_task.run()

        _show_analysis_result_dialog(
            bv,
            patch_context_task,
            "Smart Patch",
        )
    else:
        log.log_info("user cancelled smart patch objective input.")


PluginCommand.register(
    "MoonAnalyzer\\Analysis Context (Quick)",
    "Gather context for the current function and its callees using default setting",
    menu_quick_analysis_begin,
)

PluginCommand.register(
    "MoonAnalyzer\\Analysis Context (Custom)",
    "Gather context for the current function and its callees using custom settings",
    menu_custom_analysis_begin,
)

PluginCommand.register(
    "MoonAnalyzer\\Execute BN-DSL",
    "Execute BN-DSL script to annotate functions",
    menu_execute_dsl,
)

PluginCommand.register(
    "MoonAnalyzer\\Listing Context",
    "Gather context for the current function and its callees using custom settings",
    menu_gather_listing_context,
)

PluginCommand.register(
    "MoonAnalyzer\\Smart Patch",
    "Generate an prompt to suggest patches for the current function",
    menu_smart_patch_begin,
)
