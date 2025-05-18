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
    project_context: str = ""  # project context for the llm
    custom_prompt_additions: str = ""  # additional instructions to the llm
    level_of_detail_instructions: str = ""  # llm focus on detail
    initial_func_addr: Optional[int] = None


# - prompt template
# this template is formatted with llm_instructions, analysis_scope, and the code listing.
# the llm_instructions section is built dynamically based on user input.
GATHER_CONTEXT_PROMPT_TEMPLATE = """You are a reverse-engineering assistant.

{llm_instructions}

TASK:
1. For each function in the listing, write an explanation covering:
   - Overall purpose  
   - Inputs & outputs  
   - Control flow highlights (branches, loops)  
   - Major data operations (buffers, copies)  
   - Side effects, error paths

   For longer and more complex functions, first give a high-level overview, then explain each part of the function in more detail.
   When you clearly identify simple standard library functions, name them and their arguments to aid understanding, but skip details.

2. After all explanations, output exactly one fenced bndsl block.
   In that block, include only these statements, one per line:

     COMMENT <addr> @"any text, may span lines; the @ means it can be multiline"
     FNAME   <func_addr> <new_function_name>
     VNAME   <func_addr> <old_var_root> <new_var_root>

   **BN-DSL EXPECTATIONS**
   - **FNAME:** Try to rename every function whose name is generic (e.g. sub_XXXXX) or unclear.
   - **VNAME:** Try to rename any local or parameter whose root name is non-descriptive (e.g. var_123, buf, ptr) to something meaningful.
   - **COMMENT:** Add some comments per interesting function at the *most important* spots, such as:
     - Function entry (summarize the purpose)  
     - Key branch or loop heads  
     - Before/after major memory ops (memcpy, alloc, free)  
     - On early-exit or error-handling paths  
   - Strive for breadth: each function should have at least one FNAME, one VNAME, and one COMMENT where it adds clarity.
   - Rename important variables that are used in functions to help explain their purpose.
   - Acknowledge uncertainty or unclear cases with comments, to make it clear something needs further analysis.
   - Use the exact 0x-addresses from the listing margin.
   - Rename only the *root* of cascaded locals (e.g. rename buf, not buf_1).
   - Use snake_case, verb-style names (≤ 40 chars).
   - Multi-line comments must use triple quotes.
   - Note that COMMENT overwrites existing comments, so you can use it to modify existing comments.

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

FILE METADATA:
{file_metadata}

ANALYSIS SCOPE:
{analysis_scope}

LISTING
```hlil
{listing}
```
"""

# default level of detail if none is provided by the user in custom mode.
LEVEL_OF_DETAIL_STANDARD = """
Explain overall purpose, inputs/outputs, control flow, major data operations, and side effects for each function.
Try to rename as much as needed to make the code clearer.
For complex functions, you should try to rename as much as possible to make the code clearer.
Use comments to explain high level flow and important details, but also to note uncertainties.
Please be sure to provide explanations of the functions before the BN-DSL block.
""".strip()


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
            f"project_context='{self.params.project_context[:50].replace(chr(10), ' ')}...', "
            f"custom_prompt_additions='{self.params.custom_prompt_additions[:50].replace(chr(10), ' ')}...', "
            f"level_of_detail='{self.params.level_of_detail_instructions[:50].replace(chr(10), ' ')}...'"
        )

    def _make_function_context_block(self, func: Function) -> str:
        """
        creates a formatted string block for a single function, including its
        hlil listing.
        """
        try:
            hlil_listing = format_code_listing(
                func=func,
                display_type=CodeDisplayType.HLIL,
            )
            func_chunk_header = (
                f"// Function: {func.name} @ {hex(func.start)}\n"
            )
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
        traversal includes direct callees and functions targeted by code cross-references
        originating from instructions within the visited functions.
        """
        collected_functions: List[Function] = []
        # queue stores tuples of (function_object, current_depth)
        queue: Deque[tuple[Function, int]] = collections.deque()
        # visited_function_addresses stores addresses of functions already added to queue or collected_functions
        visited_function_addresses: Set[int] = set()

        if start_function:
            queue.append((start_function, 0))
            visited_function_addresses.add(start_function.start)
        else:
            # this case should ideally be prevented by _determine_entry_function returning none earlier
            self.log.log_error("bfs collection started without a valid start_function.")
            return []

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

            # if max_depth is reached for current_func, do not explore its neighbors (callees or xrefs)
            if current_depth >= self.params.max_depth:
                continue

            # use a temporary set to gather all potential distinct neighbors for this current_func
            # before checking against the global visited_function_addresses and adding to queue.
            # this avoids redundant checks if a function is both a callee and an xref target.
            potential_neighbors_for_current_func: Set[Function] = set()

            # - 1. collect direct callees
            try:
                for callee_func in current_func.callees:
                    if self.cancelled:
                        break
                    # avoid self-reference and ensure the callee_func object is valid
                    if callee_func and callee_func.start != current_func.start:
                        potential_neighbors_for_current_func.add(callee_func)
            except Exception as e:
                self.log.log_error(
                    f"error processing callees for function {current_func.name} (0x{current_func.start:x}): {e}\n{traceback.format_exc()}"
                )
            # check cancellation after processing all callees for current_func
            if self.cancelled:
                break

            # - 2. collect functions targeted by code xrefs from instructions within current_func
            try:
                # function.instructions yields tuples of (list_of_tokens, instruction_address)
                for _instruction_tokens, instr_addr in current_func.instructions:
                    if self.cancelled:
                        break

                    # get code references *from* this specific instruction's address.
                    # `func` and `arch` parameters scope the interpretation of the instruction at `instr_addr`.
                    # `get_code_refs_from` returns a list[int] of target addresses.
                    refs_from_instr: List[int] = self.bv.get_code_refs_from(
                        addr=instr_addr, func=current_func, arch=current_func.arch
                    )

                    for target_addr in refs_from_instr:
                        if self.cancelled:
                            break

                        # `get_function_at` checks if a function *starts* at target_addr.
                        # `current_func.platform` is used as a hint if multiple platforms might exist for the target address.
                        target_func_at_xref = self.bv.get_function_at(
                            addr=target_addr, plat=current_func.platform
                        )

                        # ensure it's a valid function (which `get_function_at` ensures by returning a function object)
                        # and that it's not a self-reference.
                        if (
                            target_func_at_xref
                            and target_func_at_xref.start != current_func.start
                        ):
                            potential_neighbors_for_current_func.add(
                                target_func_at_xref
                            )

                    # check after processing all targets for one instruction
                    if self.cancelled:
                        break
            except Exception as e:
                self.log.log_error(
                    f"error processing code xrefs for function {current_func.name} (0x{current_func.start:x}): {e}\n{traceback.format_exc()}"
                )
            # check after processing all instructions for current_func
            if self.cancelled:
                break

            # add unique, unvisited neighbors to the main queue
            for neighbor_func in potential_neighbors_for_current_func:
                if self.cancelled:
                    break

                if neighbor_func.start not in visited_function_addresses:
                    # this logging informs if the sum of (collected_functions + current_queue_length)
                    # is already at or exceeding max_function_count, but the function hasn't
                    # strictly been collected yet. the actual hard limit is checked at the start of the loop.
                    if (
                        self.params.max_function_count > 0
                        and (len(collected_functions) + len(queue))
                        >= self.params.max_function_count
                        and len(collected_functions) < self.params.max_function_count
                    ):
                        self.log.log_info(
                            f"approaching max function count ({self.params.max_function_count}) while adding neighbor "
                            f"{neighbor_func.name} (0x{neighbor_func.start:x}) from {current_func.name} to queue."
                        )

                    visited_function_addresses.add(neighbor_func.start)
                    queue.append((neighbor_func, current_depth + 1))

            # final check for this iteration of the main while loop
            if self.cancelled:
                break

        # final truncation: although the loop entry check handles most cases,
        # this ensures strict adherence if the last batch of neighbors pushed the count over.
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
            # `bv.offset` is not a standard public api attribute.
            # it is checked here for compatibility if it was part of the user's original environment.
            # `bv.current_function` is the more standard way to get contextually relevant function.
            if hasattr(self.bv, "offset") and self.bv.offset is not None:  # type: ignore [attr-defined]
                start_addr = self.bv.offset  # type: ignore [attr-defined]
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

        # this check should be redundant if the logic above is complete, but serves as a safeguard.
        if start_addr is None:
            self.log.log_error(
                "failed to determine a valid starting address after all checks."
            )
            return None

        # try to find functions containing the start_addr first.
        # this handles cases where start_addr might be in the middle of a function.
        initial_funcs: List[Function] = self.bv.get_functions_containing(
            addr=start_addr
        )
        if not initial_funcs:
            # if no function *contains* start_addr, check if a function *starts* at start_addr.
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
                f"multiple functions found at/containing {hex(start_addr)} ({len(initial_funcs)} functions). using the first one: {initial_funcs[0].name}."
            )

        self.log.log_info(
            f"determined entry function: {initial_funcs[0].name} at {hex(initial_funcs[0].start)}"
        )
        return initial_funcs[0]

    def _build_llm_instructions_prompt(self) -> str:
        instruction_lines = []
        if self.params.project_context:
            instruction_lines.append(
                f"\nPROJECT CONTEXT:\n{self.params.project_context}"
            )
        if self.params.custom_prompt_additions:
            instruction_lines.append(
                f"\nADDITIONAL FOCUS AREAS:\n{self.params.custom_prompt_additions}"
            )
        detail_to_use = self.params.level_of_detail_instructions.strip()
        if not detail_to_use:
            detail_to_use = LEVEL_OF_DETAIL_STANDARD
        instruction_lines.append(f"GUIDANCE ON LEVEL OF DETAIL:\n{detail_to_use}")
        return "\n\n".join(instruction_lines)

    def _build_analysis_scope_prompt(self) -> str:
        """
        constructs the 'analysis scope' part of the prompt, detailing depth and count limits.
        this informs the llm about the extent of the provided code listing.
        """
        scope_lines = [
            f"Max Traversal Depth for Callees/Xrefs: {self.params.max_depth}",
            f"Max Functions Included in Listing: {self.params.max_function_count if self.params.max_function_count > 0 else 'Unlimited'}",
        ]
        return "\n".join(scope_lines)

    def _build_file_metadata_prompt(self) -> str:
        bv_name = self.bv.file.original_filename
        bv_arch_name = "Unknown"
        # self.bv.arch can sometimes be none, especially for unanalyzed or raw views
        if self.bv.arch:
            bv_arch_name = self.bv.arch.name
        return f'Binary: Name="{bv_name}", Architecture: {bv_arch_name}'

    def _build_final_prompt(self, listing_str: str) -> str:
        return GATHER_CONTEXT_PROMPT_TEMPLATE.format(
            llm_instructions=self._build_llm_instructions_prompt(),
            analysis_scope=self._build_analysis_scope_prompt(),
            file_metadata=self._build_file_metadata_prompt(),
            listing=listing_str,
        )

    def run(self):
        try:
            entry_function = self._determine_entry_function()
            if not entry_function:
                self.result_string = (
                    "Error: Could not determine an entry function for analysis."
                )
                self.cancel()
                return

            self.log.log_info(
                f"context gathering initiated for function: {entry_function.name} at {hex(entry_function.start)}"
            )

            all_functions_to_process: List[Function] = self._collect_functions_bfs(
                entry_function
            )

            # check if cancelled during bfs
            if self.cancelled:
                self.log.log_info("task cancelled during function collection phase.")
                self.result_string = "Analysis cancelled during function collection."
                return

            # if not cancelled, but bfs returned empty (e.g. start func has no neighbors or limits too restrictive)
            if not all_functions_to_process:
                self.log.log_warn(
                    "no functions were collected for analysis (bfs returned empty)."
                )
                self.result_string = "No functions collected. Start function may have no neighbors or limits are too restrictive."
                # continue to prompt generation, which will then be empty or show this message.

            self.log.log_info(
                f"collected {len(all_functions_to_process)} unique functions for context generation."
            )

            all_context_blocks: List[str] = []
            total_functions_to_render = len(all_functions_to_process)
            for i, func_to_analyze in enumerate(all_functions_to_process):
                # check if cancelled during context block generation phase
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

            # only build prompt if not cancelled
            if not self.cancelled:
                # if no blocks were generated and no prior error/warning message exists
                if not all_context_blocks and not self.result_string:
                    self.result_string = (
                        "No function listings generated to create a prompt."
                    )
                    self.log.log_info(
                        "prompt generation skipped as no listings were created."
                    )
                # if blocks exist, build the prompt
                elif all_context_blocks:
                    listing_str = "\n\n".join(all_context_blocks)
                    self.result_string = self._build_final_prompt(listing_str)
                    self.log.log_info(
                        "context gathering and prompt generation finished successfully."
                    )
                # if result_string was already set (e.g., by empty bfs), that message will be used.

        except Exception as e:
            self.log.log_error(
                f"unexpected error during context gathering: {e}\n{traceback.format_exc()}"
            )
            self.result_string = f"Error during context gathering: {e}"
            self.cancel()
        finally:
            self.finish()
