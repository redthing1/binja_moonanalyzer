# this module provides utilities for generating textual listings of disassembly
# and high-level intermediate language (hlil) for functions in binary ninja.
# it defines data structures for representing lines of code and offers
# functions to retrieve and format these listings.

from dataclasses import dataclass
from enum import Enum, auto
from typing import Iterator, Optional, List, Union

from binaryninja import (
    Function,
    DisassemblySettings,
    log_info,
    log_error,
    log_warn,
    BinaryView,  # kept for type hinting if these utilities are used in a bv context
    HighLevelILFunction,
    InstructionTextToken,
)
from binaryninja.lineardisassembly import (
    LinearViewObject,
    LinearViewCursor,
    LinearDisassemblyLine,
)
from binaryninja.function import DisassemblyTextLine
from binaryninja.enums import DisassemblyOption
import traceback


# - Definitions
class CodeDisplayType(Enum):
    """
    specifies the type of code representation to retrieve for a function's linear listing.
    """

    DISASSEMBLY = auto()
    HLIL = auto()


@dataclass
class LinearListingLine:
    """
    represents a single line from a function's linear listing (disassembly or
    decompiled il). it includes the address, textual representation, and the
    type of display (e.g., disassembly, hlil) that generated this line.
    """

    address: int
    text: str
    display_type: CodeDisplayType


# - Core Logic
def get_function_code_lines(
    func: Function, display_type: CodeDisplayType
) -> Iterator[LinearListingLine]:
    """
    provides an iterator yielding linearlistingline objects for a given function
    and display type (disassembly or hlil).
    """
    if not func:
        log_error(
            f"[{display_type.name}] invalid function object provided to get_function_code_lines."
        )
        return

    settings = DisassemblySettings()  # use default settings

    if display_type == CodeDisplayType.HLIL:
        settings.set_option(DisassemblyOption.WaitForIL, True)
        linear_view_object: Optional[LinearViewObject] = None
        lvo_lines_yielded = 0

        try:
            linear_view_object = LinearViewObject.single_function_hlil(func, settings)

            if linear_view_object is not None:
                cursor = LinearViewCursor(linear_view_object)
                if cursor is not None and cursor.valid:
                    # log_info(f"[{display_type.name}] lvo cursor created for '{func.name}'. OrderTotal: {cursor.ordering_index_total if hasattr(cursor, 'ordering_index_total') else 'N/A'}")

                    collected_raw_lvo_lines: List[LinearDisassemblyLine] = []
                    processed_line_hashes = (
                        set()
                    )  # used to deduplicate lines from lvo iteration

                    # attempt to get initial lines at the cursor's starting position
                    current_chunk = list(cursor.lines)
                    for line in current_chunk:
                        collected_raw_lvo_lines.append(line)

                    # loop by advancing the cursor to try and gather all lines from the linear view object.
                    # this is necessary because a single call to list(cursor.lines) often
                    # only returns a small initial portion of the view.
                    MAX_LVO_ITERATIONS = 1000  # safety break to prevent infinite loops
                    iterations = 0
                    while iterations < MAX_LVO_ITERATIONS:
                        if (
                            not cursor.next()
                        ):  # advance cursor to the next item/object in the linear view
                            break
                        new_chunk = list(
                            cursor.lines
                        )  # get lines at the new cursor position
                        if not new_chunk:  # no more lines available
                            break
                        collected_raw_lvo_lines.extend(new_chunk)
                        iterations += 1

                    if iterations >= MAX_LVO_ITERATIONS:
                        log_warn(
                            f"[{display_type.name}] hit max lvo iterations ({MAX_LVO_ITERATIONS}) for '{func.name}'. hlil listing might be truncated."
                        )

                    for linear_disassembly_line in collected_raw_lvo_lines:
                        if isinstance(
                            linear_disassembly_line.contents, DisassemblyTextLine
                        ):
                            disassembly_text_line = linear_disassembly_line.contents
                            # create a hashable key to detect and skip duplicate lines
                            line_hash_key = (
                                disassembly_text_line.address,
                                str(disassembly_text_line),
                            )
                            if line_hash_key not in processed_line_hashes:
                                yield LinearListingLine(
                                    address=disassembly_text_line.address,
                                    text=str(disassembly_text_line),
                                    display_type=display_type,
                                )
                                lvo_lines_yielded += 1
                                processed_line_hashes.add(line_hash_key)
                    # log_info(f"[{display_type.name}] lvo approach yielded {lvo_lines_yielded} unique lines for '{func.name}'.")
                else:
                    log_warn(
                        f"[{display_type.name}] hlil lvo cursor for '{func.name}' was none or invalid."
                    )
            else:
                log_warn(
                    f"[{display_type.name}] hlil lvo for '{func.name}' was none after creation attempt."
                )
        except Exception as e:
            log_error(
                f"[{display_type.name}] exception during hlil lvo processing for '{func.name}':\n{traceback.format_exc()}"
            )

        # if the lvo approach yields very few lines, it might indicate it only got the signature.
        # a more robust way to get full hlil text would be ast traversal, which is complex.
        if (
            lvo_lines_yielded <= 3
            and func.hlil is not None
            and func.hlil.root is not None
        ):  # heuristic check
            log_warn(
                f"[{display_type.name}] lvo for '{func.name}' yielded only {lvo_lines_yielded} lines. "
                f"this might only be the function signature. full hlil body via lvo "
                f"iteration seems incomplete. for a guaranteed complete hlil textual "
                f"representation, a more complex ast traversal and pretty-printing would be needed."
            )
        return

    elif display_type == CodeDisplayType.DISASSEMBLY:
        lvo_header_lines_yielded = 0
        # first, try to get header/signature lines using the linear view object.
        # this often provides a well-formatted function signature.
        try:
            linear_view_object = LinearViewObject.single_function_disassembly(
                func, settings
            )
            if linear_view_object is not None:
                cursor = LinearViewCursor(linear_view_object)
                if cursor is not None and cursor.valid:
                    # list(cursor.lines) is expected to yield only a few lines here (e.g., signature)
                    for linear_disassembly_line in list(cursor.lines):
                        if isinstance(
                            linear_disassembly_line.contents, DisassemblyTextLine
                        ):
                            disassembly_text_line = linear_disassembly_line.contents
                            yield LinearListingLine(
                                address=disassembly_text_line.address,
                                text=str(disassembly_text_line),
                                display_type=display_type,
                            )
                            lvo_header_lines_yielded += 1
                    # log_info(f"[{display_type.name}] lvo approach yielded {lvo_header_lines_yielded} header/signature lines for '{func.name}'.")
        except Exception as e:
            log_error(
                f"[{display_type.name}] exception during lvo disassembly header retrieval for '{func.name}':\n{traceback.format_exc()}"
            )

        # then, get the actual instruction lines directly from the function object.
        # this is a reliable way to get the body of the disassembly.
        instruction_lines_yielded = 0
        try:
            for tokens, addr in func.instructions:
                text = "".join(t.text for t in tokens)
                yield LinearListingLine(
                    address=addr, text=text, display_type=display_type
                )
                instruction_lines_yielded += 1
            # log_info(f"[{display_type.name}] func.instructions iteration yielded {instruction_lines_yielded} instruction lines for '{func.name}'.")
        except Exception as e:
            log_error(
                f"[{display_type.name}] exception during func.instructions iteration for '{func.name}':\n{traceback.format_exc()}"
            )

        return
    else:
        log_error(
            f"[{display_type.name}] unknown display type encountered in get_function_code_lines: {display_type}"
        )
        return


# - Formatting
def format_listing_lines(
    linear_listing_lines: Iterator[LinearListingLine], hex_address_width: int = 8
) -> Iterator[str]:
    """
    formats an iterator of linearlistingline objects into a neat,
    ui-like string representation (address<tab>text).
    the input listing_line.text is expected to already contain its own
    necessary indentation (e.g., for nested code blocks).
    """
    for listing_line in linear_listing_lines:
        formatted_address = f"0x{listing_line.address:0{hex_address_width}x}"
        yield f"{formatted_address}\t{listing_line.text}"


def create_formatted_code_listing_string(
    func: Function,
    display_type: CodeDisplayType,
    hex_address_width: Optional[int] = None,
) -> str:
    """
    generates a single multi-line string representing the formatted code listing
    for a given function and display type.

    args:
        func: the binary ninja function object.
        display_type: the type of code representation to retrieve.
        hex_address_width: optional width for formatting the hex address.
                           if none, it's derived from the function's architecture.

    returns:
        a string containing the formatted code listing, with lines separated by newlines.
        returns an error message string if the function is invalid or no lines are generated.
    """
    if not func:
        return f"error: invalid function provided for {display_type.name} listing."

    if hex_address_width is None:
        # default to 8 hex characters (32-bit address) if arch info is missing
        hex_address_width = func.arch.address_size * 2 if func.arch else 8

    linear_listing_lines_iterator = get_function_code_lines(func, display_type)
    formatted_lines_list = list(
        format_listing_lines(
            linear_listing_lines_iterator, hex_address_width=hex_address_width
        )
    )

    if not formatted_lines_list:
        # this message indicates that get_function_code_lines yielded nothing,
        # or an error prevented line generation.
        return f"-- no {display_type.name} lines available for {func.name} (or an error occurred during generation) --"

    return "\n".join(formatted_lines_list)
