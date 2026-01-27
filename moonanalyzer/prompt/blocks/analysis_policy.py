from __future__ import annotations


def build_analysis_policy_block() -> str:
    return (
        "ANALYSIS REQUIREMENTS:\n"
        "For each function in the listing, write a detailed analysis covering:\n"
        "- Purpose\n"
        "- Inputs/Outputs\n"
        "- Control Flow\n"
        "- Data & State\n"
        "- External Calls / Side Effects\n"
        "- Uncertainty / Open Questions\n\n"
        "Provide the breakdowns BEFORE the BNDSL block.\n"
        "ANNOTATION POLICY:\n"
        "- Goal: annotate as much as possible to improve readability and digestibility.\n"
        "- Rename generic/unnamed functions and variables to improve clarity.\n"
        "- Prioritize sub_*, var_*, arg_*, buf, ptr, tmp, or ambiguous names.\n"
        "- Add entry comments and comments at branch/loop heads, memory ops, and error exits.\n"
        "- Apply types only when high-confidence.\n"
        "- If uncertain, keep names and add a comment describing the uncertainty."
    )
