from typing import List, Optional, Tuple

import binaryninja
from binaryninja import BinaryView, Function, Logger


def get_current_function(bv: BinaryView, addr: Optional[int], log: Logger):
    if addr is None:
        addr = bv.offset

    # get functions at current address
    initial_funcs: List[Function] = bv.get_functions_containing(addr=addr)

    if not initial_funcs:
        log.log_error(f"no functions found at address: 0x{addr:x}")
        return None

    if len(initial_funcs) > 1:
        log.log_warn(
            f"multiple functions found at address: 0x{addr:x}, using first one."
        )

    selected_func: Function = initial_funcs[0]

    return selected_func


def get_or_create_tag_type(
    bv: BinaryView, name: str, icon: str
) -> Optional[binaryninja.TagType]:
    t = bv.get_tag_type(name)
    if t is None:
        t = bv.create_tag_type(name, icon)
        if t is None:
            raise ValueError(f"Failed to create tag type: {name}")
    return t
