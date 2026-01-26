from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from binaryninja import BinaryView


def build_metadata_block(bv: "BinaryView") -> str:
    name = "unknown"
    if bv.file and bv.file.original_filename:
        name = bv.file.original_filename
    arch = bv.arch.name if bv.arch else "unknown"
    return f'FILE METADATA:\nBinary: "{name}", Architecture: {arch}'
