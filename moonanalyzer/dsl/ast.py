from __future__ import annotations

from dataclasses import dataclass
from typing import Union


@dataclass
class CommentCommand:
    address: int
    text: str
    command_type: str = "COMMENT"


@dataclass
class FNameCommand:
    address: int
    new_name: str
    command_type: str = "FNAME"


@dataclass
class VNameCommand:
    function_address: int
    old_var_root: str
    new_var_root: str
    command_type: str = "VNAME"


@dataclass
class DNameCommand:
    old_global_name: str
    new_global_name: str
    command_type: str = "DNAME"


@dataclass
class VTypeCommand:
    function_address: int
    var_identifier: str
    type_string: str
    command_type: str = "VTYPE"


@dataclass
class PatchCommand:
    address: int
    assembly_code: str
    command_type: str = "PATCH"


DSLCommand = Union[
    CommentCommand,
    FNameCommand,
    VNameCommand,
    DNameCommand,
    VTypeCommand,
    PatchCommand,
]
