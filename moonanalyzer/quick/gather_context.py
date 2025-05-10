from typing import List, Set, Optional, Deque
import collections
import traceback
from dataclasses import dataclass
from typing import Callable

import binaryninja
from binaryninja import BinaryView, Function, PluginCommand, BackgroundTask, Settings


from ..defs import LOGGER_NAME
from ..listing import (
    get_function_code_lines,
    format_code_listing,
    CodeDisplayType,
    LinearListingLine,
)


# - dataclass for analysis parameters
@dataclass
class AnalysisParameters:
    """
    holds all parameters for a context gathering operation.
    these parameters control the scope of function collection and provide
    custom instructions for the llm.
    """

    max_depth: int
    max_function_count: int
    custom_prompt_additions: str = ""  # for additional instructions to the llm
    level_of_detail_instructions: str = ""  # for llm focus on detail
    initial_func_addr: Optional[int] = None


# - prompt template
# this template is formatted with llm_instructions, analysis_scope, and the code listing.
# the llm_instructions section is built dynamically based on user input.
GATHER_CONTEXT_PROMPT_TEMPLATE = """You are a reverse-engineering assistant.

{llm_instructions}

TASK:
1. For each function in the listing, write a focused explanation (up to 200 words) covering:
   - Overall purpose  
   - Inputs & outputs  
   - Control flow highlights (branches, loops)  
   - Major data operations (buffers, copies)  
   - Side effects, error paths, security notes  

2. After all explanations, output exactly one fenced bndsl block.
   In that block, include only these statements, one per line:

     COMMENT <addr> @"any text, may span lines; the @ means it can be multiline"
     FNAME   <addr> <new_function_name>
     VNAME   <addr> <old_var_root> <new_var_root>

   **BN-DSL EXPECTATIONS**
   - **FNAME:** Try to rename every function whose name is generic (e.g. sub_XXXXX) or unclear.
   - **VNAME:** Try to rename any local or parameter whose root name is non-descriptive (e.g. var_123, buf, ptr) to something meaningful.
   - **COMMENT:** Add some comments per interesting function at the *most important* spots, such as:
     - Function entry (summarize the purpose)  
     - Key branch or loop heads  
     - Before/after major memory ops (memcpy, alloc, free)  
     - On early-exit or error-handling paths  
   - Strive for breadth: each function should have at least one FNAME, one VNAME, and one COMMENT where it adds clarity.
   - Acknowledge uncertainty or unclear cases with comments, to make it clear something needs further analysis.
   - Use the exact 0x-addresses from the listing margin.
   - Rename only the *root* of cascaded locals (e.g. rename buf, not buf_1).
   - Use snake_case, verb-style names (≤ 40 chars).
   - Multi-line comments must use triple quotes.

BN-DSL EXAMPLES:
```bndsl
# Function rename + entry comment
FNAME   0x006ebf00 check_and_load_license
COMMENT 0x006ebf00 @"Entry: verify or load license blob."

# Early-exit comment
COMMENT 0x006ebf58 @"Early-out if license already validated."

# Memory op comment
COMMENT 0x006ebf64 @"Copy user_buf into local buffer without length check."

# Variable rename (propagates to buffers)
VNAME   0x006ebf64 user_buf license_env

# Rename a generic flag variable
VNAME   0x006ed104 var_3d9  license_status_flag
```

ANALYSIS SCOPE:
{analysis_scope}

LISTING
```hlil
{listing}
```
"""

# default level of detail if none is provided by the user in custom mode.
DEFAULT_LEVEL_OF_DETAIL = "Standard: Explain overall purpose, inputs/outputs, control flow, major data operations, and side effects for each function."


# - background task for gathering context
class GatherAnalysisContextTask(BackgroundTask):
    def __init__(
        self,
        bv: BinaryView,
        params: AnalysisParameters,
    ):
        super().__init__("Gathering function context (BFS)...", can_cancel=True)
        self.bv: BinaryView = bv
        self.log = bv.create_logger(LOGGER_NAME)
        self.params: AnalysisParameters = params
        self.result_string: str = ""  # stores the final prompt string

        # log the parameters being used for this task instance for easier debugging
        # newlines in string parameters are replaced for cleaner single-line logging
        self.log.log_info(
            f"context gathering task initialized with settings: "
            f"max_depth={self.params.max_depth}, "
            f"max_function_count={self.params.max_function_count if self.params.max_function_count > 0 else 'unlimited'}, "
            f"initial_addr={hex(self.params.initial_func_addr) if self.params.initial_func_addr is not None else 'current_offset'}, "
            f"custom_prompt_additions='{self.params.custom_prompt_additions[:50].replace(chr(10), ' ')}...', "
            f"level_of_detail='{self.params.level_of_detail_instructions[:50].replace(chr(10), ' ')}...'"
        )

    def _make_function_context_block(self, func: Function) -> str:
        """
        creates a formatted string block for a single function, including its
        hlil listing.
        """
        # uses the imported 'format_code_listing' function from the 'listing' module.
        # this function is expected to return a string.
        try:
            hlil_listing = format_code_listing(
                func=func,
                display_type=CodeDisplayType.HLIL,
            )
            func_chunk_header = f"// Function: {func.name} @ {hex(func.start)}\n"
            return func_chunk_header + hlil_listing
        except Exception as e:
            self.log.log_error(
                f"error generating listing for function {func.name} (0x{func.start:x}): {e}\n{traceback.format_exc()}"
            )
            return f"// Error generating listing for function: {func.name} @ {hex(func.start)}\n// Details: {e}\n"

    def _collect_functions_bfs(self, start_function: Function) -> List[Function]:
        """
        collects functions using breadth-first search (bfs) starting from start_function,
        respecting the depth and count limits defined in self.params.
        """
        collected_functions: List[Function] = []
        # queue stores tuples of (function_object, current_depth)
        queue: Deque[tuple[Function, int]] = collections.deque()
        visited_function_addresses: Set[int] = set()

        if start_function:
            queue.append((start_function, 0))
            visited_function_addresses.add(start_function.start)

        while queue:
            if self.cancelled:
                self.log.log_info("bfs function collection cancelled by user request.")
                break

            if (
                self.params.max_function_count > 0
                and len(collected_functions) >= self.params.max_function_count
            ):
                self.log.log_info(
                    f"reached max function count ({self.params.max_function_count}). stopping collection."
                )
                break

            current_func, current_depth = queue.popleft()
            collected_functions.append(current_func)

            if current_depth < self.params.max_depth:
                try:
                    for callee_func in current_func.callees:
                        if self.cancelled:
                            break
                        if callee_func.start not in visited_function_addresses:
                            if (
                                self.params.max_function_count > 0
                                and (len(collected_functions) + len(queue))
                                >= self.params.max_function_count
                                and len(collected_functions)
                                < self.params.max_function_count
                            ):
                                self.log.log_info(
                                    f"approaching max function count ({self.params.max_function_count}) while adding callees to queue for {current_func.name}."
                                )

                            visited_function_addresses.add(callee_func.start)
                            queue.append((callee_func, current_depth + 1))
                except Exception as e:
                    self.log.log_error(
                        f"error processing callees for function {current_func.name} (0x{current_func.start:x}): {e}\n{traceback.format_exc()}"
                    )
            if self.cancelled:
                break

        if (
            self.params.max_function_count > 0
            and len(collected_functions) > self.params.max_function_count
        ):
            collected_functions = collected_functions[: self.params.max_function_count]
            self.log.log_info(
                f"function collection truncated to ensure max count of {self.params.max_function_count} functions."
            )

        return collected_functions

    def _determine_entry_function(self) -> Optional[Function]:
        """
        determines the initial function for analysis based on task parameters
        and current binary view state (e.g., cursor position).
        """
        start_addr: Optional[int] = self.params.initial_func_addr

        if start_addr is None:
            if hasattr(self.bv, "offset") and self.bv.offset is not None:
                start_addr = self.bv.offset
                self.log.log_debug(
                    f"using bv.offset 0x{start_addr:x} as starting address."
                )
            else:
                current_func_from_view = self.bv.current_function
                if current_func_from_view:
                    start_addr = current_func_from_view.start
                    self.log.log_debug(
                        f"using bv.current_function '{current_func_from_view.name}' (0x{start_addr:x}) as starting point."
                    )
                else:
                    self.log.log_error(
                        "could not determine a starting address: initial_func_addr was not provided, and bv.offset and bv.current_function are unavailable."
                    )
                    return None

        if start_addr is None:
            self.log.log_error(
                "failed to determine a valid starting address after all checks."
            )
            return None

        initial_funcs: List[Function] = self.bv.get_functions_containing(
            addr=start_addr
        )
        if not initial_funcs:
            func_at_start = self.bv.get_function_at(start_addr)
            if func_at_start:
                initial_funcs = [func_at_start]
            else:
                self.log.log_error(
                    f"no function found containing or starting at address {hex(start_addr)}."
                )
                return None

        if len(initial_funcs) > 1:
            self.log.log_warn(
                f"multiple functions found at {hex(start_addr)} ({len(initial_funcs)} functions). using the first one: {initial_funcs[0].name}."
            )

        return initial_funcs[0]

    def _build_llm_instructions_section(self) -> str:
        """
        constructs the instructional part of the prompt for the llm,
        including level of detail and any custom focus instructions.
        this section appears at the top of the prompt.
        """
        instruction_lines = []

        detail_to_use = self.params.level_of_detail_instructions.strip()
        if not detail_to_use:
            detail_to_use = DEFAULT_LEVEL_OF_DETAIL
        instruction_lines.append(f"GUIDANCE ON LEVEL OF DETAIL:\n{detail_to_use}")

        if self.params.custom_prompt_additions:
            instruction_lines.append(
                f"\nADDITIONAL FOCUS AREAS:\n{self.params.custom_prompt_additions}"
            )

        return "\n\n".join(instruction_lines)

    def _build_analysis_scope_section(self) -> str:
        """
        constructs the 'analysis scope' part of the prompt, detailing depth and count limits.
        this informs the llm about the extent of the provided code listing.
        """
        scope_lines = [
            f"Max Traversal Depth for Callees: {self.params.max_depth}",  # e.g., 0 means only the initial function
            f"Max Functions Included in Listing: {self.params.max_function_count if self.params.max_function_count > 0 else 'Unlimited'}",
        ]
        return "\n".join(scope_lines)

    def _build_final_prompt(self, listing_str: str) -> str:
        """
        assembles the complete prompt string using the main template and dynamic sections.
        """
        llm_instructions = self._build_llm_instructions_section()
        analysis_scope = self._build_analysis_scope_section()

        return GATHER_CONTEXT_PROMPT_TEMPLATE.format(
            llm_instructions=llm_instructions,
            analysis_scope=analysis_scope,
            listing=listing_str,
        )

    def run(self):
        try:
            entry_function = self._determine_entry_function()
            if not entry_function:
                self.result_string = (
                    "Error: Could not determine an entry function for analysis."
                )
                self.cancel()  # mark as cancelled due to error
                return

            self.log.log_info(
                f"context gathering initiated for function: {entry_function.name} at {hex(entry_function.start)}"
            )

            all_functions_to_process: List[Function] = self._collect_functions_bfs(
                entry_function
            )

            if self.cancelled:
                self.log.log_info("task cancelled during function collection phase.")
                self.result_string = "Analysis cancelled during function collection."
                return

            self.log.log_info(
                f"collected {len(all_functions_to_process)} unique functions for context generation."
            )

            all_context_blocks: List[str] = []
            total_functions_to_render = len(all_functions_to_process)
            for i, func_to_analyze in enumerate(all_functions_to_process):
                if self.cancelled:
                    self.log.log_info(
                        "task cancelled during context block generation phase."
                    )
                    self.result_string = (
                        "Analysis cancelled during context block generation."
                    )
                    break

                self.progress = f"generating listing for function {i+1}/{total_functions_to_render}: {func_to_analyze.name}"
                block = self._make_function_context_block(func_to_analyze)
                all_context_blocks.append(block)

            if not self.cancelled:
                listing_str = "\n\n".join(
                    all_context_blocks
                )  # join with two newlines for separation
                self.result_string = self._build_final_prompt(listing_str)
                self.log.log_info(
                    "context gathering and prompt generation finished successfully."
                )

        except Exception as e:
            self.log.log_error(
                f"unexpected error during context gathering: {e}\n{traceback.format_exc()}"
            )
            self.result_string = f"Error during context gathering: {e}"
            self.cancel()
        finally:
            self.finish()
