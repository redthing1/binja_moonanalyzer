from typing import Optional
import traceback

import binaryninja
from binaryninja import (
    BinaryView,
    Function,
    BackgroundTask,
    interaction,
)  # Added interaction for consistency

from ..defs import LOGGER_NAME
from ..listing import (
    format_code_listing,
    CodeDisplayType,
)

# - prompt template for smart patch
SMART_PATCH_PROMPT_TEMPLATE = """You are an expert reverse-engineering assistant with extensive experience in binary patching. Your task is to devise precise assembly patches for the provided function to meet a specific objective.

PATCH OBJECTIVE:
{patch_objective}

YOUR TASK:

1.  DEEP ANALYSIS AND REASONING (MANDATORY PRE-STEP):
    First, thoroughly analyze the provided HLIL and Disassembly listings for the target function: {function_name} at {function_address_hex} (Architecture: {architecture_name}).
    Critically evaluate how the current code behaves concerning the PATCH OBJECTIVE.
    Brainstorm potential patching strategies. This may involve one or more patch locations and corresponding assembly sequences.
    For each considered patch or set of coordinated patches, meticulously assess:
    - Effectiveness: Does it (or do they collectively) fully and correctly achieve the PATCH OBJECTIVE?
    - Correctness: Is the assembly valid for the {architecture_name} architecture? Will it assemble without errors?
    - Safety: What are the potential side effects? Could it introduce new bugs, crashes, or vulnerabilities (e.g., register clobbering, stack imbalance, unintended control flow changes, breaking other functionality)?
    - Conciseness and Precision: Are the patches as small and targeted as possible while still being effective? Avoid overly broad changes.
    - Alternatives: Briefly note why you discarded other considered approaches or individual patch ideas.

2.  DETAILED EXPLANATION OF CHOSEN PATCH(ES):
    Based on your deep analysis, select the best patching strategy, which may involve one or more PATCH commands.
    Clearly explain your reasoning for the chosen patch(es) *before* providing the BN-DSL commands. Your explanation *must* cover for each patch, or for the set of patches as a whole where appropriate:
    - Chosen Patch Location(s) (`<patch_addr>`): Why was each specific address selected?
    - Proposed Assembly Code: How does each specific sequence of instructions (or the set of them) directly achieve the PATCH OBJECTIVE?
    - Interdependencies (if multiple patches): If you propose multiple patches, explain how they work together.
    - Impact and Side Effects: Explicitly state any anticipated side effects (even minor ones) and how your patches mitigate them if possible. Confirm that you've considered register usage and stack state.
    - Justification: Why is this the optimal solution (or set of solutions) compared to alternatives you considered?

3.  BN-DSL CODE BLOCK WITH PATCH COMMAND(S):
    After your detailed explanation, output exactly one fenced BNDSL block with the necessary PATCH command(s).
    Each `<patch_addr>` must be an address within the provided function.
    The `assembly_instructions` can be multi-line. Ensure newlines are correctly formatted within the @"..." string if needed (e.g., by literally including newlines).
    Do NOT use any other BN-DSL commands (like FNAME, VNAME, COMMENT, VTYPE) in your response for this patching task. Focus solely on the PATCH command(s).

IMPORTANT CONSIDERATIONS FOR YOUR PATCH(ES):
- No Crashes: The primary goal after achieving the objective is stability. Your patches must not introduce crashes.
- Architecture Specifics: The assembly must be valid for {architecture_name}.
- Existing Code: Patches will overwrite existing instructions at their respective `<patch_addr>`. Be mindful of the length of your patches and what they replace.
- Clarity: Your reasoning should be clear enough for a human reverse engineer to understand and verify your proposed patches.

SAMPLE OUTPUT FORMAT:
```bndsl
PATCH <patch_addr_1> @"
ins_1 op1, op2
ins_2 op1, op2
"
PATCH <patch_addr_2> @"
ins_3 op1, op2
"
```

FILE METADATA:
{file_metadata}

FUNCTION UNDER ANALYSIS:
Name: {function_name}
Address: {function_address_hex}
Architecture: {architecture_name}

HLIL LISTING (Current Function Only):
```hlil
{hlil_listing}
```

DISASSEMBLY LISTING (Current Function Only):
```asm
{disassembly_listing}
```

Begin your response with your detailed reasoning, followed by the BN-DSL PATCH command(s).
"""


class SmartPatchContextTask(BackgroundTask):
    """
    generates a prompt for an llm to suggest assembly patches for a given function
    based on a user-provided objective.
    """

    def __init__(
        self,
        bv: BinaryView,
        current_function: Function,
        patch_objective: str,
    ):
        super().__init__("gathering context for smart patch...", can_cancel=True)
        self.bv: BinaryView = bv
        self.log = bv.create_logger(LOGGER_NAME)
        self.current_function: Function = current_function
        self.patch_objective: str = patch_objective
        self.result_string: str = ""

        self.log.log_info(
            f"smart patch context task initialized for function: '{current_function.name}' (0x{current_function.start:x}), "
            f"objective: '{patch_objective[:100].replace(chr(10), ' ')}{'...' if len(patch_objective) > 100 else ''}'"  # ensure objective is clean for logging
        )

    def _build_file_metadata_prompt(self) -> str:
        bv_name = self.bv.file.original_filename if self.bv.file else "unknown_binary"
        bv_arch_name = "unknown"
        if self.bv.arch:
            bv_arch_name = self.bv.arch.name
        return f'binary: name="{bv_name}", architecture: {bv_arch_name}'

    def run(self):
        try:
            self.progress = f"generating listings for {self.current_function.name}..."

            if self.cancelled:
                self.result_string = "smart patch context generation cancelled."
                return

            # generate hlil listing for the current function
            self.log.log_debug(f"generating hlil for '{self.current_function.name}'.")
            hlil_listing = format_code_listing(
                func=self.current_function,
                display_type=CodeDisplayType.HLIL,
            )
            if self.cancelled:
                return

            # generate disassembly listing for the current function
            self.log.log_debug(
                f"generating disassembly for '{self.current_function.name}'."
            )
            disassembly_listing = format_code_listing(
                func=self.current_function,
                display_type=CodeDisplayType.DISASSEMBLY,
            )
            if self.cancelled:
                return

            file_metadata_str = self._build_file_metadata_prompt()
            arch_name = self.bv.arch.name if self.bv.arch else "unknown"
            func_name = self.current_function.name
            func_addr_hex = hex(self.current_function.start)

            self.progress = "formatting prompt for llm..."
            self.result_string = SMART_PATCH_PROMPT_TEMPLATE.format(
                patch_objective=self.patch_objective,
                architecture_name=arch_name,
                file_metadata=file_metadata_str,
                function_name=func_name,
                function_address_hex=func_addr_hex,
                hlil_listing=hlil_listing,
                disassembly_listing=disassembly_listing,
            )
            self.log.log_info(
                f"smart patch prompt generated successfully for '{func_name}'."
            )

        except Exception as e:
            self.log.log_error(
                f"unexpected error during smart patch context generation: {e}\n{traceback.format_exc()}"
            )
            self.result_string = f"error during smart patch context generation: {e}"
        finally:
            self.finish()
