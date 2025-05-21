#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.9"
# dependencies = [
#   "lark"
# ]
# ///
# run with: uv run --script ./moonanalyzer/dsl.py

# bndsl_parser.py
"""
A self-contained module for parsing the BN-DSL (BinaryNinja Domain Specific Language).

This module uses the Lark parsing library to parse a textual DSL into structured
Python objects (dataclasses). The DSL is designed for representing reverse
engineering annotations like function renames, variable renames, and comments
at specific addresses.

The DSL supports:
- FNAME <func_addr> <new_function_name>
- VNAME <func_addr> <old_var_root> <new_var_root>
- COMMENT <addr> @" any text, may span lines and include \"escaped quotes\" "
- DNAME <old_global_name> <new_global_name>
- Line comments starting with '#' or '//' within the DSL itself.

Requires the 'lark' library: pip install lark
"""

import dataclasses
from typing import List, Union

# lark-specific imports
try:
    from lark import Lark, Transformer, v_args, Token
    from lark.exceptions import LarkError
except ImportError:
    # this allows the module to be imported even if lark isn't immediately available,
    # though parsing will fail. in a plugin, ensure lark is a dependency.
    print("Lark library not found. Please install it using: pip install lark")
    Lark = None  # type: ignore
    Transformer = object
    v_args = lambda *args, **kwargs: lambda f: f  # type: ignore
    Token = None  # type: ignore
    LarkError = Exception  # type: ignore


# - dataclass definitions for DSL commands
@dataclasses.dataclass
class CommentCommand:
    """
    Represents a COMMENT command in the DSL.
    """

    address: int
    text: str
    command_type: str = "COMMENT"

    def to_dsl_string(self) -> str:
        # escape backslashes first, then double quotes, to correctly form the @"" string
        processed_text = self.text.replace("\\", "\\\\")
        processed_text = processed_text.replace('"', '\\"')
        return f'COMMENT 0x{self.address:x} @"{processed_text}"'


@dataclasses.dataclass
class FNameCommand:
    """
    Represents an FNAME (function rename) command in the DSL.
    """

    address: int
    new_name: str
    command_type: str = "FNAME"

    def to_dsl_string(self) -> str:
        return f"FNAME 0x{self.address:x} {self.new_name}"


@dataclasses.dataclass
class VNameCommand:
    """
    Represents a VNAME (local variable rename) command in the DSL.
    """

    function_address: int
    old_var_root: str
    new_var_root: str
    command_type: str = "VNAME"

    def to_dsl_string(self) -> str:
        return (
            f"VNAME 0x{self.function_address:x} {self.old_var_root} {self.new_var_root}"
        )


@dataclasses.dataclass
class DNameCommand:
    """
    Represents a DNAME (global data variable rename) command in the DSL.
    """

    old_global_name: str
    new_global_name: str
    command_type: str = "DNAME"

    def to_dsl_string(self) -> str:
        return f"DNAME {self.old_global_name} {self.new_global_name}"


# union type for type hinting a list of any command
DSLCommand = Union[CommentCommand, FNameCommand, VNameCommand, DNameCommand]


# - Lark grammar definition
_BNDSL_LARK_GRAMMAR = r"""
    ?start: command*

    command: comment_stmt
           | fname_stmt
           | vname_stmt
           | dname_stmt

    comment_stmt : "COMMENT"i HEX_ADDRESS AT_STRING
    fname_stmt   : "FNAME"i HEX_ADDRESS IDENTIFIER
    vname_stmt   : "VNAME"i HEX_ADDRESS IDENTIFIER IDENTIFIER
    dname_stmt   : "DNAME"i IDENTIFIER IDENTIFIER

    HEX_ADDRESS: /0x[0-9a-fA-F]+/
    IDENTIFIER: /[a-zA-Z_][a-zA-Z0-9_]*/
    AT_STRING : /@"(?:\\.|[^"\\]|\n)*"/

    %import common.WS
    %ignore WS
    %ignore /#[^\n]*/       // ignore hash comments
    %ignore /\/\/[^\n]*/   // ignore C++ style comments
"""


# - Lark transformer
class DSLToDataclasses(Transformer):  # Renamed from DslToDataclasses
    """
    Transforms the Lark parse tree into a list of DSLCommand dataclass instances.
    """

    def HEX_ADDRESS(self, token: Token) -> int:
        # convert hex string to an integer
        return int(token.value, 16)

    def IDENTIFIER(self, token: Token) -> str:
        # return the identifier string as is
        return str(token.value)

    def AT_STRING(self, token: Token) -> str:
        # strip leading @" and trailing " from the captured string
        return token.value[2:-1]

    @v_args(inline=True)
    def comment_stmt(self, address: int, text: str) -> CommentCommand:
        return CommentCommand(address=address, text=text)

    @v_args(inline=True)
    def fname_stmt(self, address: int, new_name: str) -> FNameCommand:
        return FNameCommand(address=address, new_name=new_name)

    @v_args(inline=True)
    def vname_stmt(
        self, function_address: int, old_var_root: str, new_var_root: str
    ) -> VNameCommand:
        return VNameCommand(
            function_address=function_address,
            old_var_root=old_var_root,
            new_var_root=new_var_root,
        )

    @v_args(inline=True)
    def dname_stmt(self, old_global_name: str, new_global_name: str) -> DNameCommand:
        return DNameCommand(
            old_global_name=old_global_name, new_global_name=new_global_name
        )

    @v_args(inline=True)
    def command(self, dsl_command_instance: DSLCommand) -> DSLCommand:
        return dsl_command_instance

    def start(self, items: list) -> List[DSLCommand]:
        # 'items' will be a list of the results from the 'command' rule.
        # if there's only one command, 'items' might be a list containing one element.
        # this method just needs to return that list.
        # the type hint for items is already 'list' from Lark's perspective if command* is matched.
        # the key is that 'command*' should always produce a list for its parent rule.
        # if Lark sometimes returns a single item when `command*` matches only one `command`,
        # we can explicitly check and wrap.
        if not isinstance(items, list):
            # this case *shouldn't* happen if 'command*' correctly yields a list of one,
            # but as a safeguard:
            if items is None:  # e.g. empty input
                return []
            return [items]  # wrap a single item into a list
        return items  # items should already be List[DSLCommand]


# - main parsing function
_parser_instance = None
_transformer_instance = None


def _get_parser_and_transformer():
    global _parser_instance, _transformer_instance
    if Lark is None:
        raise RuntimeError(
            "Lark library is not available. Please install it: pip install lark"
        )
    if _parser_instance is None:
        _parser_instance = Lark(
            _BNDSL_LARK_GRAMMAR,
            parser="earley",
            propagate_positions=True,
            lexer="dynamic",
        )
    if _transformer_instance is None:
        _transformer_instance = DSLToDataclasses()
    return _parser_instance, _transformer_instance


def parse_bndsl(dsl_string: str) -> List[DSLCommand]:
    if not isinstance(dsl_string, str):
        raise TypeError("Input dsl_string must be a string.")
    parser, transformer = _get_parser_and_transformer()
    try:
        parse_tree = parser.parse(dsl_string)
        transformed_commands: List[DSLCommand] = transformer.transform(parse_tree)

        if transformed_commands is None:
            # this case shouldn't happen, but as a safeguard:
            return []

        if not isinstance(transformed_commands, list):
            # if the transformer returns a single command instead of a list,
            # wrap it in a list for consistency
            transformed_commands = [transformed_commands]

        return transformed_commands
    except LarkError as e:
        raise e


# - example usage (when run as a script)
if __name__ == "__main__":
    print("BN-DSL Parser Module - Example Usage (with DNAME)")
    print("----------------------------------------------")

    if Lark is None:
        print("Cannot run example: Lark library is not installed (pip install lark).")
    else:
        example_dsl_with_dname = """
        FNAME   0x006ebf00 check_and_load_license
        COMMENT 0x006ebf00 @"Entry: verify or load license blob."
        VNAME   0x006ebf00 user_buf license_env_buffer
        DNAME   g_license_status_flag g_is_license_valid
        """
        test_cases = [
            ("DSL with DNAME", example_dsl_with_dname),
        ]
        for name, dsl_content in test_cases:
            print(f"\n--- Testing: {name} ---")
            print("Input DSL:")
            dsl_snippet = dsl_content.strip()
            print(f"```\n{dsl_snippet}\n```")
            try:
                parsed_commands = parse_bndsl(dsl_content)
                print("\nParsed Commands:")
                for cmd_idx, cmd in enumerate(parsed_commands):
                    print(f"  {cmd_idx}: {cmd}")
            except LarkError as e:
                print(f"\nError parsing DSL: {e}")
            except Exception as e:
                print(f"\nAn unexpected error occurred: {e}")
        print("\n--- End of Examples ---")
