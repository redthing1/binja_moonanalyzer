from __future__ import annotations

from typing import List

from .ast import (
    CommentCommand,
    DNameCommand,
    DSLCommand,
    FNameCommand,
    PatchCommand,
    VNameCommand,
    VTypeCommand,
)
from .errors import BNDslParseError

try:
    from lark import Lark, Transformer, v_args, Token
    from lark.exceptions import LarkError, UnexpectedInput
except ImportError as exc:  # pragma: no cover - handled at runtime
    Lark = None  # type: ignore
    Transformer = object  # type: ignore
    v_args = lambda *args, **kwargs: lambda f: f  # type: ignore
    Token = None  # type: ignore
    LarkError = Exception  # type: ignore
    UnexpectedInput = Exception  # type: ignore


_BNDSL_LARK_GRAMMAR = r"""
    ?start: command*

    command: comment_stmt
           | fname_stmt
           | vname_stmt
           | dname_stmt
           | vtype_stmt
           | patch_stmt

    comment_stmt : "COMMENT"i HEX_ADDRESS (AT_STRING | NORMAL_STRING)
    fname_stmt   : "FNAME"i HEX_ADDRESS IDENTIFIER
    vname_stmt   : "VNAME"i HEX_ADDRESS IDENTIFIER IDENTIFIER
    dname_stmt   : "DNAME"i IDENTIFIER IDENTIFIER
    vtype_stmt   : "VTYPE"i HEX_ADDRESS IDENTIFIER (AT_STRING | NORMAL_STRING)
    patch_stmt   : "PATCH"i HEX_ADDRESS (AT_STRING | NORMAL_STRING)

    HEX_ADDRESS: /0x[0-9a-fA-F]+/
    IDENTIFIER: /[a-zA-Z_$][a-zA-Z0-9_.$:\-<>?]*/
    AT_STRING : /@"(?:[^"\\]|\\.)*"/
    NORMAL_STRING : /"(?:[^"\\]|\\.)*"/

    %import common.WS
    %ignore WS
    %ignore /#[^\n]*/
    %ignore /\/\/[^\n]*/
"""


class _DslTransformer(Transformer):
    def HEX_ADDRESS(self, token: Token) -> int:
        return int(token.value, 16)

    def IDENTIFIER(self, token: Token) -> str:
        return str(token.value)

    def AT_STRING(self, token: Token) -> str:
        return token.value[2:-1].replace('\\"', '"')

    def NORMAL_STRING(self, token: Token) -> str:
        return token.value[1:-1].replace('\\"', '"')

    @v_args(inline=True)
    def comment_stmt(self, address: int, text: str) -> CommentCommand:
        return CommentCommand(address=address, text=text)

    @v_args(inline=True)
    def fname_stmt(self, address: int, new_name: str) -> FNameCommand:
        return FNameCommand(address=address, new_name=new_name)

    @v_args(inline=True)
    def vname_stmt(self, function_address: int, old_var_root: str, new_var_root: str) -> VNameCommand:
        return VNameCommand(
            function_address=function_address,
            old_var_root=old_var_root,
            new_var_root=new_var_root,
        )

    @v_args(inline=True)
    def dname_stmt(self, old_global_name: str, new_global_name: str) -> DNameCommand:
        return DNameCommand(old_global_name=old_global_name, new_global_name=new_global_name)

    @v_args(inline=True)
    def vtype_stmt(self, function_address: int, var_identifier: str, type_string: str) -> VTypeCommand:
        return VTypeCommand(
            function_address=function_address,
            var_identifier=var_identifier,
            type_string=type_string,
        )

    @v_args(inline=True)
    def patch_stmt(self, address: int, assembly_code: str) -> PatchCommand:
        return PatchCommand(address=address, assembly_code=assembly_code)

    @v_args(inline=True)
    def command(self, command_instance: DSLCommand) -> DSLCommand:
        return command_instance

    def start(self, items: list) -> List[DSLCommand]:
        if items is None:
            return []
        if isinstance(items, list):
            return items
        return [items]


_parser_instance: Lark | None = None
_transformer_instance: _DslTransformer | None = None


def _get_parser_and_transformer() -> tuple[Lark, _DslTransformer]:
    global _parser_instance, _transformer_instance
    if Lark is None:
        raise BNDslParseError("Lark is not installed; BNDSL parsing is unavailable.")
    if _parser_instance is None:
        _parser_instance = Lark(
            _BNDSL_LARK_GRAMMAR,
            parser="earley",
            propagate_positions=True,
            lexer="dynamic",
        )
    if _transformer_instance is None:
        _transformer_instance = _DslTransformer()
    return _parser_instance, _transformer_instance


def parse_bndsl(text: str) -> List[DSLCommand]:
    if not isinstance(text, str):
        raise BNDslParseError("BNDSL input must be a string.")
    parser, transformer = _get_parser_and_transformer()
    try:
        parse_tree = parser.parse(text)
        commands = transformer.transform(parse_tree)
        if commands is None:
            return []
        if isinstance(commands, list):
            return commands
        return [commands]
    except UnexpectedInput as exc:
        raise BNDslParseError(str(exc), line=getattr(exc, "line", None), column=getattr(exc, "column", None))
    except LarkError as exc:
        raise BNDslParseError(str(exc))
