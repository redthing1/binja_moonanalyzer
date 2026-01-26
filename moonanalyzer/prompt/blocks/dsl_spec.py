from __future__ import annotations


def build_dsl_spec_block() -> str:
    return """BN-DSL OUTPUT REQUIREMENTS:
- Output exactly one fenced `bndsl` code block.
- Each command must be on its own line.
- Supported commands:
  COMMENT <addr> @"..."
  FNAME <func_addr> <new_function_name>
  VNAME <func_addr> <old_var_root> <new_var_root>
  DNAME <old_global_name> <new_global_name>
  VTYPE <func_addr> <var_identifier> "type_string"
  PATCH <addr> @"assembly_code"
"""
