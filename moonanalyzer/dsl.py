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
- FNAME <addr> <new_function_name>
- VNAME <addr> <old_var_root> <new_var_root>
- COMMENT <addr> @" any text, may span lines and include \"escaped quotes\" "
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


# - Dataclass definitions for DSL commands
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


# union type for type hinting a list of any command
DSLCommand = Union[CommentCommand, FNameCommand, VNameCommand]


# - Lark grammar definition
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

    #   - Rule transformers
    # these methods correspond to rules in the grammar.
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

    @v_args(inline=True)
    def command(self, dsl_command_instance: DSLCommand) -> DSLCommand:
        """
        Passes through the already transformed DSLCommand instance
        (CommentCommand, FNameCommand, or VNameCommand).
        """
        # this ensures that the 'command' rule resolves to its child
        # (which is already a DSLCommand instance)
        return dsl_command_instance

    def start(self, items: List[DSLCommand]) -> List[DSLCommand]:
        # the 'start' rule collects the results of its children ('command*' rules).
        # since 'command' now returns a DSLCommand directly, 'start' will collect a list of DSLCommands.
        return items


# - Main parsing function
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
            parser="earley",  # earley parser is good for complex grammars
            propagate_positions=True,  # useful for error reporting
            lexer="dynamic",  # dynamic lexer adapts to ambiguities
        )
    if _transformer_instance is None:
        _transformer_instance = DSLToDataclasses()
    return _parser_instance, _transformer_instance


def parse_bndsl(dsl_string: str) -> List[DSLCommand]:
    """
    Parses a BN-DSL string and returns a list of DSLCommand objects.

    Args:
        dsl_string: The string containing the BN-DSL to parse.

    Returns:
        A list of DSLCommand dataclass instances representing the parsed commands.

    Raises:
        LarkError: If there's a syntax error or other parsing issue in the dsl_string.
        RuntimeError: If the Lark library is not installed/available.
        TypeError: If dsl_string is not a string.
    """
    if not isinstance(dsl_string, str):
        raise TypeError("Input dsl_string must be a string.")

    parser, transformer = _get_parser_and_transformer()

    try:
        parse_tree = parser.parse(dsl_string)
        transformed_commands: List[DSLCommand] = transformer.transform(parse_tree)
        return transformed_commands
    except LarkError as e:
        # for more detailed error context, one might use:
        # error_context = e.get_context(dsl_string, context_lines=2)
        # print(f"Lark parsing error: Line {e.line}, Column {e.column}.\nContext:\n{error_context}")
        raise e


# - Example usage (when run as a script)
if __name__ == "__main__":
    print("BN-DSL Parser Module - Example Usage")
    print("------------------------------------")

    if Lark is None:
        print("Cannot run example: Lark library is not installed (pip install lark).")
    else:
        example_dsl_basic = """
        # This is a DSL comment and should be ignored by the parser.
        FNAME   0x006ebf00 check_and_load_license
        COMMENT 0x006ebf00 @"Entry: verify or load license blob.
        This can span multiple lines."

        // Another DSL comment, C++ style
        COMMENT 0x006ebf58 @"Early-out if license already validated."
        VNAME   0x006ebf64 user_buf license_env_buffer // Inline C++ comment, also ignored

        # Test case insensitivity for keywords (should still work)
        fname   0x12345 TestFunction
        CoMmEnT 0xABCDE @"Testing case insensitivity for keywords."
        """

        empty_dsl = ""
        comments_only_dsl = """
        # Hash Comment 1
        // C++ Style Comment 1
        # Hash Comment 2
        // C++ Style Comment 2
        """

        cpp_style_comments_dsl = """
        // This is a C++ style comment at the beginning of the file
        FNAME   0x1000 func_with_cpp_comment // Another C++ comment at end of line
        // COMMENT 0x2000 @"This is commented out using C++ style"
        # Hash comment still works in conjunction
        VNAME   0x3000 old_var new_var // Mix and match comments
        COMMENT 0x4000 @"Text after C++ comment." // This should be parsed
        // Trailing C++ comment
        """

        adjacent_commands_dsl = """
        FNAME 0x1000 first_func VNAME 0x1001 old_v new_v COMMENT 0x1002 @"text for 1002"
        FNAME 0x2000 second_func//comment for second_func
        COMMENT 0x3000 @"another text"FNAME 0x4000 third_func
        """

        leading_trailing_whitespace_dsl = """
            FNAME   0x5000   spaced_func_leading_spaces
          COMMENT    0x6000    @"  Text with leading and trailing spaces in content  "
        VNAME 0x7000 old_spaced    new_spaced    // trailing spaces after command
        """

        complex_at_string_dsl = r"""
        // Test various AT_STRING features
        COMMENT 0x7A00 @"This string contains \"escaped quotes\" and an escaped backslash \\. It also spans
        multiple lines directly in the DSL source."
        COMMENT 0x7A01 @"" // Empty AT_STRING, should result in an empty text field
        COMMENT 0x7A02 @"One line\nstill one line in content, with literal backslash-n"
        COMMENT 0x7A03 @"This is an @ sign inside, and a # hash, and a // slash pair, all literal."
        COMMENT 0x7A04 @"Final line."
        """

        various_address_formats_dsl = """
        FNAME 0x0 func_at_zero
        COMMENT 0x0000000000000000 @"Zero address, potentially long form"
        VNAME 0xDEADBEEF old_hex_val new_hex_val
        FNAME 0x1a2b3c4d simple_hex
        """

        mixed_case_keywords_explicit_dsl = """
        fNaMe 0x9000 MixedCaseFuncKeyword
        cOmMeNt 0x9001 @"Mixed case CoMmEnT keyword."
        vNaMe 0x9002 oLdVaRnAmE nEwVaRnAmE // Mixed case VNAME
        """

        malformed_dsl = """
        FNAME 0x1000 // Missing name, Lark will error: Unexpected token Token('COMMENT_CPP', '// Missing name...')
        COMMENT not_an_address @"text"
        INVALID_COMMAND 0x2000
        COMMENT 0x3000 @Unclosed string "
        FNAME 0x4000 name_ok but_too_many_identifiers
        VNAME 0x5000 missing_one_identifier
        """

        test_cases = [
            ("Basic Valid DSL", example_dsl_basic),
            ("C++ Style Comments DSL", cpp_style_comments_dsl),
            ("Adjacent Commands DSL", adjacent_commands_dsl),
            ("Leading/Trailing Whitespace DSL", leading_trailing_whitespace_dsl),
            ("Complex AT_STRING DSL", complex_at_string_dsl),
            ("Various Address Formats DSL", various_address_formats_dsl),
            ("Mixed Case Keywords DSL", mixed_case_keywords_explicit_dsl),
            ("Empty DSL", empty_dsl),
            ("Comments Only DSL", comments_only_dsl),
        ]

        for name, dsl_content in test_cases:
            print(f"\n--- Testing: {name} ---")
            print("Input DSL:")
            # print a snippet for brevity if too long
            dsl_snippet = dsl_content.strip()
            if len(dsl_snippet) > 200:
                dsl_snippet = dsl_snippet[:200] + "\n..."
            if not dsl_snippet:
                dsl_snippet = "[EMPTY]"

            print(f"```\n{dsl_snippet}\n```")
            try:
                parsed_commands = parse_bndsl(dsl_content)
                if parsed_commands:
                    print("\nParsed Commands:")
                    for cmd_idx, cmd in enumerate(parsed_commands):
                        print(f"  {cmd_idx}: {cmd}")
                else:
                    print(
                        "\nNo commands parsed (input might be empty or comments only)."
                    )
            except LarkError as e:
                print(f"\nError parsing DSL: {e}")
                # For more detailed error location:
                # print(f"  Line: {e.line}, Column: {e.column}, Expected: {e.expected}")
                # print(f"  Context:\n{e.get_context(dsl_content)}")
            except Exception as e:
                print(f"\nAn unexpected error occurred: {e}")

        print(f"\n--- Testing: Malformed DSL (expecting errors) ---")
        print("Input DSL:")
        print(f"```\n{malformed_dsl.strip()}\n```")
        try:
            # we expect this to fail
            parsed_commands = parse_bndsl(malformed_dsl)
            print("\nParsed Commands (should not happen for malformed):")
            for cmd_idx, cmd in enumerate(parsed_commands):
                print(f"  {cmd_idx}: {cmd}")
        except LarkError as e:
            print(f"\nSuccessfully caught LarkError as expected:")
            print(f"  Error type: {type(e).__name__}")
            print(f"  Details: {e}")
            # you can get more detailed info from e.line, e.column, e.expected etc.
            # print(f"  Line: {e.line}, Column: {e.column}")
            # print(f"  Context: {e.get_context(malformed_dsl, 2)}") # show 2 lines of context
        except Exception as e:
            # catch any other unexpected errors during malformed test
            print(f"\nAn unexpected error occurred during malformed DSL test: {e}")

        print("\n--- End of Examples ---")
