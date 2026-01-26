from __future__ import annotations

from typing import Optional

import binaryninja
from binaryninja import BinaryView, Function, Logger


def get_current_function(bv: BinaryView, addr: Optional[int], log: Logger) -> Optional[Function]:
    if addr is None:
        addr = bv.offset

    funcs = bv.get_functions_containing(addr=addr)
    if not funcs:
        log.log_error(f"no functions found at address: 0x{addr:x}")
        return None

    if len(funcs) > 1:
        log.log_warn(
            f"multiple functions found at address: 0x{addr:x}, using first one."
        )

    return funcs[0]


def get_or_create_tag_type(
    bv: BinaryView, name: str, icon: str
) -> binaryninja.TagType:
    tag_type = bv.get_tag_type(name)
    if tag_type is None:
        tag_type = bv.create_tag_type(name, icon)
        if tag_type is None:
            raise ValueError(f"Failed to create tag type: {name}")
    return tag_type
