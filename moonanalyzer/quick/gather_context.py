from typing import List, Set, Optional, Deque, Dict
import collections
import traceback
from dataclasses import dataclass
from typing import Callable
from enum import Enum

import binaryninja
from binaryninja import BinaryView, Function, PluginCommand, BackgroundTask, Settings


from ..defs import LOGGER_NAME
from ..listing import (
    get_function_code_lines,
    format_code_listing,
    CodeDisplayType,
    LinearListingLine,
)


# - enum for context listing code type
class ContextCodeType(Enum):
    HLIL = "HLIL"
    DISASSEMBLY = "Disassembly"
    HLIL_AND_DISASSEMBLY = "HLIL + Disassembly"

    def __str__(self):
        return self.value


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
    code_type: ContextCodeType = ContextCodeType.HLIL  # default to hlil
    initial_func_addr: Optional[int] = None
    listing_only: bool = (
        False  # if true, only generate hlil listings without the prompt
    )


# - dataclasses for managing function discovery context
@dataclass(
    frozen=True
)  # frozen=True makes instances hashable for sets if needed, and immutable
class DiscoveredFunctionInfo:
    """
    holds a function and the context of its discovery.
    """

    func: Function
    reason_type: str  # e.g., "initial", "callee", "xref"
    source_function: Optional[Function] = (
        None  # function from which this one was discovered
    )
    source_address: Optional[int] = (
        None  # specific address in source_function (e.g., xref location)
    )


@dataclass
class QueueEntry:
    """
    represents an entry in the bfs queue.
    """

    discovered_info: DiscoveredFunctionInfo
    depth: int


# - prompt template
# this template is formatted with llm_instructions, analysis_scope, and the code listing.
# the llm_instructions section is built dynamically based on user input.
GATHER_CONTEXT_PROMPT_TEMPLATE = """You are an expert reverse-engineering assistant with deep knowledge of binary analysis, with a meticulous and thorough approach.

{llm_instructions}

ANALYSIS APPROACH:
1. First scan all functions to identify patterns, relationships, and overall program flow
2. Form hypotheses about each function's purpose and how they work together
3. Analyze individual functions carefully, showing your reasoning step-by-step
4. Look for security implications, common algorithms, and data structure patterns
5. Document your findings with clear explanations before generating any commands

TASK:
1. For each function in the listing, write a detailed explanation covering:
   - Overall purpose and role in the program
   - Inputs & outputs (parameters, return values)
   - Control flow highlights (branches, loops, conditional jumps)
   - Major data operations (buffers, copies, allocations)
   - Side effects and error paths
   - Your reasoning about how you determined the function's purpose
   
   For longer and more complex functions, first give a high-level overview, then explain each part of the function in more detail.
   When you clearly identify simple standard library functions, name them and their arguments to aid understanding, but skip details.

2. After all explanations, output exactly one fenced bndsl block.
   In that block, include these statements, one per line:

     COMMENT <addr> @"any text, may span lines; the @ means it can be multiline"
     FNAME   <func_addr> <new_function_name>
     VNAME   <func_addr> <old_var_root> <new_var_root>
     DNAME   <old_global_name> <new_global_name>
     VTYPE   <func_addr> <var_identifier> "type_string"

   **BN-DSL EXPECTATIONS**
   - **FNAME:** Try to rename every function whose name is generic (e.g. sub_XXXXX) or unclear.
   - **VNAME:** Try to rename any local or parameter whose root name is non-descriptive (e.g. var_123, buf, ptr) to something meaningful.
   - **DNAME:** Rename global data variables from auto-generated names (data_XXXXXX) or unclear names to indicate their purpose.
   - **VTYPE:** Set types for local variables when you can determine them with reasonable confidence.
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
   - Multi-line comments must use @" " syntax.
   - Note that COMMENT overwrites existing comments, so you can use it to modify existing comments.

BN-DSL EXAMPLES:
```bndsl
# Function rename + entry comment
FNAME   0x006ebf00 check_and_load_license
COMMENT 0x006ebf00 @"Entry: verify or load license blob from environment variable."

# Early-exit comment
COMMENT 0x006ebf58 @"Early-out if license already validated."

# Memory op comment
COMMENT 0x006ebf64 @"Copy user_buf into local buffer without length check - potential buffer overflow."

# Variable rename (propagates to related variables)
VNAME   0x006ebf64 user_buf license_env
VTYPE   0x006ebf64 license_env "char*"
VTYPE   0x006ebf7c launch_counter "int32_t"

# Rename a generic flag variable
VNAME   0x006ed104 var_3d9 license_status_flag

# Global data rename
DNAME   data_00a5b200 g_license_config
DNAME   g_unknown_state g_connection_state
```

FILE METADATA:
{file_metadata}

ANALYSIS SCOPE:
{analysis_scope}

LISTING
```
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
            f"listing_only={self.params.listing_only}"
        )

    def _make_function_context_block(
        self, discovered_info: DiscoveredFunctionInfo
    ) -> str:
        func = discovered_info.func
        reason_comment_suffix = ""
        if discovered_info.reason_type == "callee" and discovered_info.source_function:
            reason_comment_suffix = f"    // (called by {discovered_info.source_function.name} @ {hex(discovered_info.source_function.start)})"
        elif (
            discovered_info.reason_type == "xref"
            and discovered_info.source_function
            and discovered_info.source_address is not None
        ):
            reason_comment_suffix = f"    // (code xref from {discovered_info.source_function.name} @ {hex(discovered_info.source_address)})"

        listing_parts: List[str] = []
        error_messages_for_this_block: List[str] = []

        # helper to generate and append a specific listing type, now simpler
        def _try_append_complete_block(
            display_type: CodeDisplayType,
            content_type_indicator: str,
        ):
            # construct the specific header for this block
            block_header = f"// Function ({content_type_indicator}): {func.name} @ {hex(func.start)}{reason_comment_suffix}"
            current_block_parts: List[str] = [block_header]

            try:
                code_str = format_code_listing(
                    func=func,
                    display_type=display_type,
                )
                if code_str:
                    current_block_parts.append(code_str)

                # if successfully generated, add to the main listing_parts
                # add a newline separator if this isn't the first block being added
                if (
                    listing_parts
                ):  # check if listing_parts already has content (e.g. previous HLIL block)
                    listing_parts.append("\n")
                listing_parts.extend(current_block_parts)

            except Exception as e_gen:
                # if generation fails, log error and append an error message instead of the block
                error_msg = f"// Error generating {content_type_indicator.lower()} listing for function: {func.name} @ {hex(func.start)}\n// (Header: {block_header.strip()})\n// Details: {e_gen}\n"
                self.log.log_error(
                    f"exception generating {content_type_indicator.lower()} listing for function {func.name} (0x{func.start:x}): {e_gen}\n{traceback.format_exc()}"
                )
                error_messages_for_this_block.append(error_msg)

        # determine which listings to generate
        should_generate_hlil = self.params.code_type in [
            ContextCodeType.HLIL,
            ContextCodeType.HLIL_AND_DISASSEMBLY,
        ]
        should_generate_disassembly = self.params.code_type in [
            ContextCodeType.DISASSEMBLY,
            ContextCodeType.HLIL_AND_DISASSEMBLY,
        ]

        # generate hlil block if requested
        if should_generate_hlil:
            _try_append_complete_block(CodeDisplayType.HLIL, "HLIL")

        # generate disassembly block if requested
        if should_generate_disassembly:
            _try_append_complete_block(CodeDisplayType.DISASSEMBLY, "Disassembly")

        # if any errors occurred during attempts to generate blocks, append them at the very end
        if error_messages_for_this_block:
            if listing_parts:  # add separator if other content exists
                listing_parts.append("\n")
            listing_parts.append(
                "// encountered errors during listing generation for this function:"
            )
            listing_parts.extend(error_messages_for_this_block)

        return "\n".join(listing_parts)

    def _collect_functions_bfs(
        self, start_function: Function
    ) -> List[DiscoveredFunctionInfo]:
        """
        collects functions using breadth-first search (bfs) starting from start_function,
        respecting the depth and count limits defined in self.params.
        traversal includes direct callees and functions targeted by code cross-references
        originating from instructions within the visited functions.
        returns a list of DiscoveredFunctionInfo objects.
        """
        collected_functions_info: List[DiscoveredFunctionInfo] = []
        queue: Deque[QueueEntry] = collections.deque()
        # visited_function_addresses stores addresses of functions already added to queue or collected_functions
        visited_function_addresses: Set[int] = set()

        if start_function:
            initial_discovery = DiscoveredFunctionInfo(
                func=start_function, reason_type="initial"
            )
            queue.append(QueueEntry(discovered_info=initial_discovery, depth=0))
            visited_function_addresses.add(start_function.start)
        else:
            self.log.log_error("bfs collection started without a valid start_function.")
            return []

        while queue:
            if self.cancelled:
                self.log.log_info("bfs function collection cancelled by user request.")
                break

            if (
                self.params.max_function_count > 0
                and len(collected_functions_info) >= self.params.max_function_count
            ):
                self.log.log_info(
                    f"reached max function count ({self.params.max_function_count}). stopping collection."
                )
                break

            current_queue_entry = queue.popleft()
            current_discovered_info = current_queue_entry.discovered_info
            current_func = current_discovered_info.func
            current_depth = current_queue_entry.depth

            collected_functions_info.append(current_discovered_info)

            if current_depth >= self.params.max_depth:
                continue

            # this list will store DiscoveredFunctionInfo objects for neighbors to be added to the queue
            neighbors_to_consider: List[DiscoveredFunctionInfo] = []

            # - 1. collect direct callees
            try:
                for callee_func in current_func.callees:
                    if self.cancelled:
                        break
                    if callee_func and callee_func.start != current_func.start:
                        # for callees, source_address is not the call site, but the start of the callee itself for simplicity
                        # the source_function is current_func.
                        discovery_info = DiscoveredFunctionInfo(
                            func=callee_func,
                            reason_type="callee",
                            source_function=current_func,
                        )
                        neighbors_to_consider.append(discovery_info)
            except Exception as e:
                self.log.log_error(
                    f"error processing callees for function {current_func.name} (0x{current_func.start:x}): {e}\n{traceback.format_exc()}"
                )
            if self.cancelled:
                break

            # - 2. collect functions targeted by code xrefs
            try:
                for _instruction_tokens, instr_addr in current_func.instructions:
                    if self.cancelled:
                        break
                    refs_from_instr: List[int] = self.bv.get_code_refs_from(
                        addr=instr_addr, func=current_func, arch=current_func.arch
                    )
                    for target_addr in refs_from_instr:
                        if self.cancelled:
                            break
                        target_func_at_xref = self.bv.get_function_at(
                            addr=target_addr, plat=current_func.platform
                        )
                        if (
                            target_func_at_xref
                            and target_func_at_xref.start != current_func.start
                        ):
                            discovery_info = DiscoveredFunctionInfo(
                                func=target_func_at_xref,
                                reason_type="xref",
                                source_function=current_func,
                                source_address=instr_addr,  # this is the address of the instruction *containing* the xref
                            )
                            neighbors_to_consider.append(discovery_info)
                    if self.cancelled:
                        break
            except Exception as e:
                self.log.log_error(
                    f"error processing code xrefs for function {current_func.name} (0x{current_func.start:x}): {e}\n{traceback.format_exc()}"
                )
            if self.cancelled:
                break

            # add unique, unvisited neighbors to the main queue
            # use a set to track neighbors added in this iteration to avoid duplicates from neighbors_to_consider
            # (e.g. if a function is both a callee and xref target from the same current_func)
            processed_neighbor_starts_this_iteration: Set[int] = set()
            for neighbor_discovered_info in neighbors_to_consider:
                if self.cancelled:
                    break

                neighbor_func = neighbor_discovered_info.func
                if neighbor_func.start in processed_neighbor_starts_this_iteration:
                    continue
                processed_neighbor_starts_this_iteration.add(neighbor_func.start)

                if neighbor_func.start not in visited_function_addresses:
                    if (
                        self.params.max_function_count > 0
                        and (len(collected_functions_info) + len(queue))
                        >= self.params.max_function_count
                        and len(collected_functions_info)
                        < self.params.max_function_count
                    ):
                        self.log.log_info(
                            f"approaching max function count ({self.params.max_function_count}) while adding neighbor "
                            f"{neighbor_func.name} (0x{neighbor_func.start:x}) from {current_func.name} to queue."
                        )

                    visited_function_addresses.add(neighbor_func.start)
                    queue.append(
                        QueueEntry(
                            discovered_info=neighbor_discovered_info,
                            depth=current_depth + 1,
                        )
                    )

            if self.cancelled:
                break

        if (
            self.params.max_function_count > 0
            and len(collected_functions_info) > self.params.max_function_count
        ):
            collected_functions_info = collected_functions_info[
                : self.params.max_function_count
            ]
            self.log.log_info(
                f"function collection truncated to ensure max count of {self.params.max_function_count} functions."
            )

        return collected_functions_info

    def _determine_entry_function(self) -> Optional[Function]:
        """
        determines the initial function for analysis based on task parameters
        and current binary view state (e.g., cursor position).
        """
        start_addr: Optional[int] = self.params.initial_func_addr

        if start_addr is None:
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
        scope_lines = [
            f"Max Traversal Depth for Callees/Xrefs: {self.params.max_depth}",
            f"Max Functions Included in Listing: {self.params.max_function_count if self.params.max_function_count > 0 else 'Unlimited'}",
        ]
        return "\n".join(scope_lines)

    def _build_file_metadata_prompt(self) -> str:
        bv_name = self.bv.file.original_filename
        bv_arch_name = "Unknown"
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

            # _collect_functions_bfs now returns List[DiscoveredFunctionInfo]
            all_discovered_functions_info: List[DiscoveredFunctionInfo] = (
                self._collect_functions_bfs(entry_function)
            )

            if self.cancelled:
                self.log.log_info("task cancelled during function collection phase.")
                self.result_string = "Analysis cancelled during function collection."
                return

            if not all_discovered_functions_info and not self.cancelled:
                self.log.log_warn(
                    "no functions were collected for analysis (bfs returned empty)."
                )
                self.result_string = "No functions collected. Start function may have no neighbors or limits are too restrictive."

            self.log.log_info(
                f"collected {len(all_discovered_functions_info)} unique functions with reasons for context generation."
            )

            all_context_blocks: List[str] = []
            total_functions_to_render = len(all_discovered_functions_info)
            # iterate over the collected DiscoveredFunctionInfo objects
            for i, discovered_info in enumerate(all_discovered_functions_info):
                if self.cancelled:
                    self.log.log_info(
                        "task cancelled during context block generation phase."
                    )
                    self.result_string = (
                        "Analysis cancelled during context block generation."
                    )
                    break

                self.progress = f"generating listing for function {i+1}/{total_functions_to_render}: {discovered_info.func.name}"
                # pass the entire DiscoveredFunctionInfo object
                block = self._make_function_context_block(discovered_info)
                all_context_blocks.append(block)

            if not self.cancelled:
                if not all_context_blocks and not self.result_string:
                    self.result_string = (
                        "No function listings generated to create a prompt."
                    )
                    self.log.log_info(
                        "prompt generation skipped as no listings were created."
                    )
                elif all_context_blocks:
                    listing_str = "\n\n".join(all_context_blocks)
                    if self.params.listing_only:
                        # if listing_only is True, only return the hlil listings
                        self.result_string = listing_str
                        self.log.log_info(
                            "listing-only mode enabled. returning hlil listings only."
                        )
                    else:
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
