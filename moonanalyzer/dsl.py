#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.9"
# dependencies = [
#   "lark"
# ]
# ///

# bndsl_parser.py (or dsl.py)
"""
A self-contained module for parsing the BN-DSL (BinaryNinja Domain Specific Language).

This module uses the Lark parsing library to parse a textual DSL into structured
Python objects (dataclasses). The DSL is designed for representing reverse
engineering annotations like function renames, variable renames, and comments
at specific addresses.

The DSL supports:
- FNAME <addr> <new_function_name>
- VNAME <addr> <old_var_root> <new_var_root>
- COMMENT <addr> @" any text, may span lines and include \"escaped quotes\" "
- Line comments starting with '#' within the DSL itself.

Requires the 'lark' library: pip install lark
"""

import dataclasses
from typing import List, Union, Any

# Lark-specific imports
try:
    from lark import Lark, Transformer, v_args, Token
    from lark.exceptions import LarkError
except ImportError:
    # This allows the module to be imported even if Lark isn't immediately available,
    # though parsing will fail. In a plugin, ensure Lark is a dependency.
    print("Lark library not found. Please install it using: pip install lark")
    Lark = None
    Transformer = object  # type: ignore
    v_args = lambda *args, **kwargs: lambda f: f  # type: ignore
    Token = None  # type: ignore
    LarkError = Exception  # type: ignore


# --- Dataclass Definitions for DSL Commands ---
@dataclasses.dataclass
class CommentCommand:
    """Represents a COMMENT command in the DSL."""

    address: int
    text: str
    command_type: str = "COMMENT"


@dataclasses.dataclass
class FNameCommand:
    """Represents an FNAME (function rename) command in the DSL."""

    address: int
    new_name: str
    command_type: str = "FNAME"


@dataclasses.dataclass
class VNameCommand:
    """Represents a VNAME (variable rename) command in the DSL."""

    address: int
    old_var_root: str
    new_var_root: str
    command_type: str = "VNAME"


# Union type for type hinting a list of any command
DSLCommand = Union[CommentCommand, FNameCommand, VNameCommand]


# --- Lark Grammar Definition ---
_BNDSL_LARK_GRAMMAR = r"""
    ?start: command*

    command: comment_stmt
           | fname_stmt
           | vname_stmt

    comment_stmt : "COMMENT"i HEX_ADDRESS AT_STRING
    fname_stmt   : "FNAME"i HEX_ADDRESS IDENTIFIER
    vname_stmt   : "VNAME"i HEX_ADDRESS IDENTIFIER IDENTIFIER

    HEX_ADDRESS: /0x[0-9a-fA-F]+/
    IDENTIFIER: /[a-zA-Z_][a-zA-Z0-9_]*/
    AT_STRING : /@"(?:\\.|[^"\\]|\n)*"/

    %import common.WS
    %ignore WS
    %ignore /#[^\n]*/
"""


# --- Lark Transformer ---
class DslToDataclasses(Transformer):
    """
    Transforms the Lark parse tree into a list of DSLCommand dataclass instances.
    """

    def HEX_ADDRESS(self, token: Token) -> int:
        return int(token.value, 16)

    def IDENTIFIER(self, token: Token) -> str:
        return str(token.value)

    def AT_STRING(self, token: Token) -> str:
        return token.value[2:-1]  # Strip leading @" and trailing "

    # --- Rule transformers ---
    # These methods correspond to rules in the grammar.
    # @v_args(inline=True) unpacks children directly as arguments.

    @v_args(inline=True)
    def comment_stmt(self, address: int, text: str) -> CommentCommand:
        return CommentCommand(address=address, text=text)

    @v_args(inline=True)
    def fname_stmt(self, address: int, new_name: str) -> FNameCommand:
        return FNameCommand(address=address, new_name=new_name)

    @v_args(inline=True)
    def vname_stmt(
        self, address: int, old_var_root: str, new_var_root: str
    ) -> VNameCommand:
        return VNameCommand(
            address=address, old_var_root=old_var_root, new_var_root=new_var_root
        )

    # This is the crucial addition:
    # It ensures that the 'command' rule resolves to its child (which is already a DSLCommand instance)
    # rather than being wrapped in a Tree('command', [...]).
    @v_args(inline=True)
    def command(self, dsl_command_instance: DSLCommand) -> DSLCommand:
        """
        Passes through the already transformed DSLCommand instance
        (CommentCommand, FNameCommand, or VNameCommand).
        """
        return dsl_command_instance

    # The 'start' rule by default will collect the results of its children ('command*' rules).
    # Since 'command' now returns a DSLCommand directly, 'start' will collect a list of DSLCommands.
    # An explicit 'start' method like `def start(self, items): return items` is often not needed
    # if the default behavior of collecting children is sufficient.
    # For clarity, we can keep it or remove it. If kept, it should look like:
    def start(self, items: List[DSLCommand]) -> List[DSLCommand]:
        return items


# --- Main Parsing Function ---
_parser_instance = None
_transformer_instance = None


def _get_parser_and_transformer():
    """Initializes and returns the Lark parser and transformer instances (singleton)."""
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
        _transformer_instance = DslToDataclasses()
    return _parser_instance, _transformer_instance


def parse_bndsl(dsl_string: str) -> List[DSLCommand]:  # Renamed to parse_bndsl
    """
    Parses a BN-DSL string and returns a list of DSLCommand objects.

    Args:
        dsl_string: The string containing the BN-DSL to parse.

    Returns:
        A list of DSLCommand dataclass instances representing the parsed commands.

    Raises:
        LarkError: If there's a syntax error or other parsing issue in the dsl_string.
        RuntimeError: If the Lark library is not installed/available.
    """
    if not isinstance(dsl_string, str):
        raise TypeError("Input dsl_string must be a string.")

    parser, transformer = _get_parser_and_transformer()

    try:
        parse_tree = parser.parse(dsl_string)
        # The transformer.transform call will now produce a direct list of DSLCommand objects
        transformed_commands: List[DSLCommand] = transformer.transform(parse_tree)
        return transformed_commands
    except LarkError as e:
        # Consider logging the error or adding more context before re-raising
        # print(f"Lark parsing error: Line {e.line}, Column {e.column}. Context: {e.get_context(dsl_string)}")
        raise e


# --- Example Usage (when run as a script) ---
if __name__ == "__main__":
    print("BN-DSL Parser Module - Example Usage (with @-string comments)")
    print("----------------------------------------------------------")

    if Lark is None:
        print("Cannot run example: Lark library is not installed (pip install lark).")
    else:
        example_dsl = """
        # This is a DSL comment and should be ignored by the parser.
        FNAME   0x006ebf00 check_and_load_license
        COMMENT 0x006ebf00 @"Entry: verify or load license blob.
        This can span multiple lines."

        # Another DSL comment
        COMMENT 0x006ebf58 @"Early-out if license already validated."
        VNAME   0x006ebf64 user_buf license_env_buffer # Inline DSL comment, also ignored

        # Test case sensitivity for keywords (should still work)
        fname   0x12345 TestFunction
        CoMmEnT 0xABCDE @"Testing case insensitivity for keywords."
        """

        empty_dsl = ""
        comments_only_dsl = """
        # Comment 1
        # Comment 2
        """
        malformed_dsl = """
        FNAME 0x1000 # Missing name
        COMMENT not_an_address @"text"
        INVALID_COMMAND 0x2000
        COMMENT 0x3000 @Unclosed string
        """

        test_cases = [
            ("Valid DSL", example_dsl),
            ("Empty DSL", empty_dsl),
            ("Comments Only DSL", comments_only_dsl),
        ]

        for name, dsl_content in test_cases:
            print(f"\n--- Testing: {name} ---")
            print("Input DSL:")
            print(f"```\n{dsl_content.strip()}\n```")
            try:
                parsed_commands = parse_bndsl(dsl_content)  # Use the renamed function
                if parsed_commands:
                    print("\nParsed Commands:")
                    for cmd_idx, cmd in enumerate(parsed_commands):
                        # Check if cmd is already a DSLCommand dataclass instance
                        if isinstance(
                            cmd, (CommentCommand, FNameCommand, VNameCommand)
                        ):
                            print(f"  {cmd_idx}: {cmd}")
                        else:
                            # This case should ideally not be hit with the fix
                            print(
                                f"  {cmd_idx}: Unexpected type: {type(cmd)}, value: {cmd}"
                            )
                else:
                    print(
                        "\nNo commands parsed (input might be empty or comments only)."
                    )
            except LarkError as e:
                print(f"\nError parsing DSL: {e}")
            except Exception as e:
                print(f"\nAn unexpected error occurred: {e}")

        print(f"\n--- Testing: Malformed DSL (expecting errors) ---")
        print("Input DSL:")
        print(f"```\n{malformed_dsl.strip()}\n```")
        try:
            parsed_commands = parse_bndsl(malformed_dsl)  # Use the renamed function
            print("\nParsed Commands (should not happen for malformed):")
            for cmd in parsed_commands:
                print(f"  {cmd}")
        except LarkError as e:
            print(f"\nSuccessfully caught LarkError as expected:")
            print(f"  Error: {e}")
        except Exception as e:
            print(f"\nAn unexpected error occurred: {e}")

        print("\n--- End of Examples ---")
