from typing import List, Set, Optional, Deque
import collections
import traceback

import binaryninja
from binaryninja import BinaryView, Function, PluginCommand, BackgroundTask, Settings


from ..defs import LOGGER_NAME
from ..settings import my_settings
from ..listing import (
    get_function_code_lines,
    format_code_listing,
    CodeDisplayType,
    LinearListingLine,
)

GATHER_CONTEXT_PROMPT_TEMPLATE = '''You are a reverse-engineering assistant.
You will be given a listing of decompilation outputs of some functions of interest from a binary analysis tool.
Carefully analyze the functions to understand them properly, thinking hard to analyze in depth.
After reading the listing, you will have to explain each function's logic and workings.
After analyzing the functions, you will output a fenced DSL code block to rename things and add comments based on your analysis.

TASK
1. Think carefully and analyze each function.
2. Explain the logic and workings of each function.
3. After explaining all the functions, emit one fenced ```bn-dsl marakdown code block containing COMMENT / FNAME / VNAME statements.
   - Use the exact 0x-addresses shown in the listing.
   - Rename only the *root* of cascaded locals (e.g. rename `buf`, not `buf_1`).
   - Prefer verb-style snake_case for function names.
   - Multi-line comments welcome: COMMENT <addr> """ ... """

LISTING
```hlil
{listing}
```
'''


class GatherQuickAnalysisContextTask(BackgroundTask):
    def __init__(self, bv: BinaryView, initial_func_addr: Optional[int] = None):
        super().__init__("Gathering function context (BFS)...", can_cancel=True)
        self.bv: BinaryView = bv
        self.log = bv.create_logger(LOGGER_NAME)
        self.initial_func_addr: Optional[int] = initial_func_addr
        self.result_string: str = ""

        # get max_context_depth, clamp between 0 and 3
        # 0: initial function only
        # 1: initial function + direct callees
        # ...
        # 3: initial function + 3 levels of callees
        raw_max_depth = my_settings.get_integer(
            "moonanalyzer.quick_analysis_context_depth", self.bv
        )
        self.max_depth: int = max(0, min(raw_max_depth, 3))  # clamp depth to 0-3

        # get max_function_count; 0 means no limit
        self.max_function_count: int = my_settings.get_integer(
            "moonanalyzer.quick_analysis_max_function_count", self.bv
        )

        self.log.log_info(
            f"context gathering settings: max_depth={self.max_depth}, max_function_count={self.max_function_count if self.max_function_count > 0 else 'unlimited'}"
        )

    def _make_function_context_block(self, func: Function) -> str:
        # get function hlil listing using the listing utility
        hlil_listing = format_code_listing(
            func=func,
            display_type=CodeDisplayType.HLIL,
        )

        # format function chunk
        func_chunk_header = f"// Function: {func.name} @ {hex(func.start)}\n"
        func_chunk_str = func_chunk_header + hlil_listing
        return func_chunk_str

    def _collect_functions_bfs(self, start_function: Function) -> List[Function]:
        """
        collects functions using breadth-first search (bfs) starting from start_function,
        respecting self.max_depth and self.max_function_count.
        """
        collected_functions: List[Function] = []
        # queue stores tuples of (function_object, current_depth)
        queue: Deque[tuple[Function, int]] = collections.deque()
        visited_function_addresses: Set[int] = set()

        # enqueue the starting function at depth 0
        if start_function:
            queue.append((start_function, 0))
            visited_function_addresses.add(start_function.start)

        while queue:
            if self.cancelled:
                self.log.log_info("bfs function collection cancelled.")
                break

            # check if max function count is reached (if limit is set)
            if (
                self.max_function_count > 0
                and len(collected_functions) >= self.max_function_count
            ):
                self.log.log_info(
                    f"reached max function count ({self.max_function_count}). stopping collection."
                )
                break

            current_func, current_depth = queue.popleft()
            collected_functions.append(current_func)

            # explore callees if current depth is less than max_depth
            if current_depth < self.max_depth:
                try:
                    for callee_func in current_func.callees:
                        if (
                            self.cancelled
                        ):  # check for cancellation during callee processing
                            break
                        if callee_func.start not in visited_function_addresses:
                            # check again for max function count before adding to queue
                            # this is a soft limit, as we might exceed it slightly by adding all callees at the current level
                            if (
                                self.max_function_count > 0
                                and (len(collected_functions) + len(queue))
                                >= self.max_function_count
                            ):
                                # log a message if we are about to exceed due to queue additions
                                if len(collected_functions) < self.max_function_count:
                                    self.log.log_info(
                                        f"approaching max function count ({self.max_function_count}) while adding callees to queue."
                                    )
                                # we could break here, or let this level of callees be added and then the main loop will break.
                                # for simplicity, we'll let them be added and the main check will catch it.

                            visited_function_addresses.add(callee_func.start)
                            queue.append((callee_func, current_depth + 1))
                except Exception as e:
                    self.log.log_error(
                        f"error processing callees for function {current_func.name}: {e}\n{traceback.format_exc()}"
                    )
            if self.cancelled:  # check again after processing callees
                break

        # if max_function_count was exceeded, truncate the list if necessary
        # this ensures the hard limit is respected if the queue additions pushed it over
        if (
            self.max_function_count > 0
            and len(collected_functions) > self.max_function_count
        ):
            collected_functions = collected_functions[: self.max_function_count]
            self.log.log_info(
                f"function collection truncated to {self.max_function_count} functions."
            )

        return collected_functions

    def run(self):
        start_addr: Optional[int] = self.initial_func_addr
        if start_addr is None:
            # bv.offset is the current cursor address in the ui, if available
            if hasattr(self.bv, "offset") and self.bv.offset is not None:
                start_addr = self.bv.offset
            else:  # fallback if bv.offset is not set or available
                current_func_from_view = self.bv.current_function
                if current_func_from_view:
                    start_addr = current_func_from_view.start
                else:
                    self.log.log_error(
                        "could not determine a starting address (bv.offset and bv.current_function are unavailable)."
                    )
                    self.cancel()
                    return

        if start_addr is None:  # should be caught by above, but as a safeguard
            self.log.log_error("failed to determine a valid starting address.")
            self.cancel()
            return

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
                self.cancel()
                return

        if len(initial_funcs) > 1:
            self.log.log_warn(
                f"expected one function at {hex(start_addr)}, but found {len(initial_funcs)}. using the first one: {initial_funcs[0].name}."
            )

        entry_function: Function = initial_funcs[0]
        self.log.log_info(
            f"starting analysis with function: {entry_function.name} at {hex(entry_function.start)}"
        )

        all_functions_to_process: List[Function] = self._collect_functions_bfs(
            entry_function
        )

        if self.cancelled:
            self.log.log_info("task cancelled during function collection.")
            return

        self.log.log_info(
            f"collected {len(all_functions_to_process)} unique functions for context."
        )

        all_context_blocks: List[str] = []
        total_functions_to_render = len(all_functions_to_process)
        for i, func_to_analyze in enumerate(all_functions_to_process):
            if self.cancelled:
                self.log.log_info("task cancelled during context block generation.")
                break

            self.progress = f"processing function {i+1}/{total_functions_to_render}: {func_to_analyze.name}"
            try:
                block = self._make_function_context_block(func_to_analyze)
                all_context_blocks.append(block)
            except Exception as e:
                self.log.log_error(
                    f"failed to create context block for {func_to_analyze.name}: {e}\n{traceback.format_exc()}"
                )

        # # use a clear separator between function blocks
        # separator = "\n\n" + "=" * 10 + "\n\n"
        # self.result_string = separator + separator.join(all_context_blocks)

        # format the listing
        listing_str = "\n\n".join(all_context_blocks)

        # let's format it all into a neat result string/prompt
        self.result_string = GATHER_CONTEXT_PROMPT_TEMPLATE.format(listing=listing_str)

        if not self.cancelled:
            self.log.log_info("context gathering finished.")
            self.finish()
        else:
            self.log.log_info("context gathering cancelled before completion.")
