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
