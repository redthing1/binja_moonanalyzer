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
engineering annotations like function renames, variable renames, comments,
and assembly patches.

The DSL supports:
- FNAME <func_addr> <new_function_name>
- VNAME <func_addr> <old_var_root> <new_var_root>
- COMMENT <addr> @" any text, may span lines and include \"escaped quotes\" "
- DNAME <old_global_name> <new_global_name>
- VTYPE <func_addr> <var_identifier> "type_string"
- PATCH <addr> @"assembly_code_string"

Line comments starting with '#' or '//' within the DSL itself are ignored.

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
        if "\n" in self.text or '"' in self.text:
            # multiline string: use @"..." format
            escaped_text = self.text.replace('"', '\\"')
            return f'COMMENT 0x{self.address:x} @"{escaped_text}"'
        else:
            # normal string: use regular quotes
            return f'COMMENT 0x{self.address:x} "{self.text}"'


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


@dataclasses.dataclass
class VTypeCommand:
    """
    represents a VTYPE (local variable type) command in the dsl.
    """

    function_address: int
    var_identifier: str
    type_string: str
    command_type: str = "VTYPE"

    def to_dsl_string(self) -> str:
        if "\n" in self.type_string or '"' in self.type_string:
            escaped_type_string = self.type_string.replace('"', '\\"')
            return f'VTYPE 0x{self.function_address:x} {self.var_identifier} @"{escaped_type_string}"'
        else:
            return f'VTYPE 0x{self.function_address:x} {self.var_identifier} "{self.type_string}"'


@dataclasses.dataclass
class PatchCommand:
    """
    Represents a PATCH command in the DSL for applying assembly patches.
    """

    address: int
    assembly_code: str
    command_type: str = "PATCH"

    def to_dsl_string(self) -> str:
        escaped_assembly_code = self.assembly_code.replace('"', '\\"')
        return f'PATCH 0x{self.address:x} @"{escaped_assembly_code}"'


# union type for type hinting a list of any command
DSLCommand = Union[
    CommentCommand, FNameCommand, VNameCommand, DNameCommand, VTypeCommand, PatchCommand
]


# - Lark grammar definition
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
    IDENTIFIER: /[a-zA-Z_][a-zA-Z0-9_.:\-<>?]*/  // Expanded IDENTIFIER to allow more chars often found in symbols
    AT_STRING : /@"(?:[^"\\]|\\.)*"/             // Allows escaped quotes \" inside @"..."
    NORMAL_STRING : /"(?:[^"\\]|\\.)*"/         // Allows escaped quotes \" inside "..."

    %import common.WS
    %ignore WS
    %ignore /#[^\n]*/       // ignore hash comments
    %ignore /\/\/[^\n]*/   // ignore C++ style comments
"""


# - Lark transformer
class DSLToDataclasses(Transformer):
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
        # strip leading @" and trailing " and unescape internal quotes
        return token.value[2:-1].replace('\\"', '"')

    def NORMAL_STRING(self, token: Token) -> str:
        # strip leading " and trailing " and unescape internal quotes
        return token.value[1:-1].replace('\\"', '"')

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
    def vtype_stmt(
        self, function_address: int, var_identifier: str, type_string: str
    ) -> VTypeCommand:
        return VTypeCommand(
            function_address=function_address,
            var_identifier=var_identifier,
            type_string=type_string,
        )

    @v_args(inline=True)
    def patch_stmt(self, address: int, assembly_code: str) -> PatchCommand:
        return PatchCommand(address=address, assembly_code=assembly_code)

    @v_args(inline=True)
    def command(self, dsl_command_instance: DSLCommand) -> DSLCommand:
        return dsl_command_instance

    def start(self, items: list) -> List[DSLCommand]:
        if items is None:
            return []
        if not isinstance(items, list):
            return [items]
        return items


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
            return []
        # the 'start' rule in the transformer should already ensure a list.
        # if it's a single item not in a list, it's unexpected but we can wrap it.
        if not isinstance(transformed_commands, list):
            return [transformed_commands]

        return transformed_commands
    except LarkError as e:
        raise e


if __name__ == "__main__":
    print("bn-dsl parser module - example usage with various string formats")
    print("-------------------------------------------------")

    if Lark is None:
        print("cannot run example: lark library is not installed (pip install lark).")
    else:
        sample_dsl_1 = """
        # example function and variable modifications with multiline strings
        FNAME   0x1000 process_input
        VNAME   0x1000 arg_1 input_buffer
        VTYPE   0x1000 input_buffer @"char*" // type the renamed local var
        
        COMMENT 0x1000 @"entry point for processing user input."
        
        VNAME   0x1000 var_24 loop_counter
        VTYPE   0x1000 loop_counter @"int"     // type another local var

        VTYPE   0x1000 var_30 @"CustomStruct* my_struct_ptr" // type an auto-var with a custom type
        """

        sample_dsl_2 = """
        # example using regular string literals
        FNAME   0x2000 handle_request
        VNAME   0x2000 arg_8 request_buffer
        VTYPE   0x2000 request_buffer "char*"  // normal string
        
        COMMENT 0x2000 "Main entry point for HTTP requests"  // normal string
        
        VNAME   0x2000 var_10 status_code
        VTYPE   0x2000 status_code "int"
        """

        sample_dsl_3 = """
        # example mixing both string types
        FNAME   0x3000 parse_config
        
        # multiline comment with @"..." syntax
        COMMENT 0x3000 @"This function parses the configuration file.
        It handles multiple sections and validates entries."
        
        # single line comment with "..." syntax
        COMMENT 0x3010 "Configuration validation routine"
        
        VTYPE   0x3000 config_ptr "ConfigStruct*"  // normal string
        VTYPE   0x3000 complex_type @"struct {
            int id;
            char* name;
        }*"  // multiline type with @"..." syntax
        """

        sample_dsl_4 = """
        # Test for roundtrip serialization 
        COMMENT 0x4000 "Single line comment with quotes"
        COMMENT 0x4010 @"Multiline comment
        with quotes \"escaped\"
        and multiple lines"
        VTYPE 0x4000 var1 "Simple type"
        VTYPE 0x4010 var2 @"Complex type
        spanning multiple lines"
        """

        sample_dsl_patch = """
        # Test PATCH commands
        PATCH 0x5000 @"mov eax, 1\\nnop\\nret" // Escaped newline
        PATCH 0x5010 @"jmp 0x6000" // Single line assembly
        PATCH 0x5020 @"push ebp
        mov ebp, esp
        sub esp, 0x10
        ; a comment in assembly
        mov dword [ebp-4], 0xcafebabe
        leave
        ret" // Direct newlines
        PATCH 0x5030 @"call some_func ; call external"
        PATCH 0x5040 @" // This is an empty patch effectively
        "
        PATCH 0x5050 @"mov rbx, qword ptr [rax+0x20]"
        PATCH 0x5060 "nop" // Using normal string for single instruction
        """

        test_cases = [
            ("Multiline strings", sample_dsl_1),
            ("Regular strings", sample_dsl_2),
            ("Mixed string types", sample_dsl_3),
            ("Roundtrip", sample_dsl_4),
            ("Patch Commands", sample_dsl_patch),
        ]

        for name, dsl_content in test_cases:
            print(f"\n--- testing: {name} ---")
            print("input dsl:")
            dsl_snippet = dsl_content.strip()  # show a snippet for brevity
            print(f"```bndsl\n{dsl_snippet}\n```")
            try:
                parsed_commands = parse_bndsl(dsl_content)
                if parsed_commands:
                    print("\nparsed commands:")
                    for cmd_idx, cmd in enumerate(parsed_commands):
                        print(f"  {cmd_idx + 1}: {cmd}")
                        print(f"     to_dsl_string(): {cmd.to_dsl_string()}")
                else:
                    print(
                        "\nno commands parsed (input might be empty or comments only)."
                    )
            except LarkError as e:
                print(f"\nerror parsing dsl: {e}")
            except Exception as e:  # catch any other unexpected errors
                print(f"\nan unexpected error occurred during parsing: {e}")

        print("\n--- end of examples ---")
