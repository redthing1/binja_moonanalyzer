from __future__ import annotations

from dataclasses import dataclass
from enum import Enum, auto
from typing import Iterator, List

from binaryninja import (
    Function,
    DisassemblySettings,
)
from binaryninja.lineardisassembly import (
    LinearViewObject,
    LinearViewCursor,
    LinearDisassemblyLine,
)
from binaryninja.function import DisassemblyTextLine
from binaryninja.enums import DisassemblyOption


class CodeDisplayType(Enum):
    DISASSEMBLY = auto()
    HLIL = auto()


@dataclass
class LinearListingLine:
    address: int
    text: str
    display_type: CodeDisplayType


def get_function_code_lines(
    func: Function, display_type: CodeDisplayType, logger
) -> Iterator[LinearListingLine]:
    if not func:
        logger.log_error(f"[{display_type.name}] invalid function provided.")
        return

    settings = DisassemblySettings()

    if display_type == CodeDisplayType.HLIL:
        settings.set_option(DisassemblyOption.WaitForIL, True)
        lvo_lines_yielded = 0
        try:
            linear_view_object = LinearViewObject.single_function_hlil(func, settings)
            if linear_view_object is None:
                logger.log_warn(
                    f"[{display_type.name}] hlil lvo for '{func.name}' was none after creation."
                )
                return

            cursor = LinearViewCursor(linear_view_object)
            if cursor is None or not cursor.valid:
                logger.log_warn(
                    f"[{display_type.name}] hlil lvo cursor for '{func.name}' was none or invalid."
                )
                return

            collected_raw_lines: List[LinearDisassemblyLine] = []
            processed_line_hashes = set()

            collected_raw_lines.extend(list(cursor.lines))

            max_iterations = 1000
            iterations = 0
            while iterations < max_iterations:
                if not cursor.next():
                    break
                new_chunk = list(cursor.lines)
                if not new_chunk:
                    break
                collected_raw_lines.extend(new_chunk)
                iterations += 1

            if iterations >= max_iterations:
                logger.log_warn(
                    f"[{display_type.name}] hit max lvo iterations ({max_iterations}) for '{func.name}'."
                )

            for linear_disassembly_line in collected_raw_lines:
                if isinstance(linear_disassembly_line.contents, DisassemblyTextLine):
                    disassembly_text_line = linear_disassembly_line.contents
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
        except Exception as exc:
            logger.log_error(
                f"[{display_type.name}] exception during hlil lvo processing for '{func.name}': {exc}"
            )
        return

    if display_type == CodeDisplayType.DISASSEMBLY:
        try:
            linear_view_object = LinearViewObject.single_function_disassembly(
                func, settings
            )
            if linear_view_object is not None:
                cursor = LinearViewCursor(linear_view_object)
                if cursor is not None and cursor.valid:
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
        except Exception as exc:
            logger.log_error(
                f"[{display_type.name}] exception during disassembly header retrieval for '{func.name}': {exc}"
            )

        try:
            for tokens, addr in func.instructions:
                text = "".join(t.text for t in tokens)
                yield LinearListingLine(
                    address=addr, text=text, display_type=display_type
                )
        except Exception as exc:
            logger.log_error(
                f"[{display_type.name}] exception during instruction iteration for '{func.name}': {exc}"
            )
        return

    logger.log_error(
        f"[{display_type.name}] unknown display type in get_function_code_lines: {display_type}"
    )


def format_listing_lines(
    linear_listing_lines: Iterator[LinearListingLine],
    include_addresses: bool,
    hex_address_width: int,
) -> List[str]:
    formatted: List[str] = []
    for listing_line in linear_listing_lines:
        if include_addresses:
            formatted_address = f"0x{listing_line.address:0{hex_address_width}x}"
            formatted.append(f"{formatted_address}\t{listing_line.text}")
        else:
            formatted.append(listing_line.text)
    return formatted


def truncate_lines(lines: List[str], max_lines: int) -> tuple[List[str], bool]:
    if max_lines <= 0 or len(lines) <= max_lines:
        return lines, False
    head_count = max_lines // 2
    tail_count = max_lines - head_count
    omitted = len(lines) - max_lines
    omission_line = f"// ... omitting {omitted} lines ..."
    return lines[:head_count] + [omission_line] + lines[-tail_count:], True
