from __future__ import annotations

from ..base import PromptInstructions


DEFAULT_DETAIL_LEVEL = (
    "Explain the purpose, inputs/outputs, control flow, and major data operations. "
    "Rename unclear functions/variables and add comments at key points."
)


def build_instructions_block(instructions: PromptInstructions) -> str:
    parts: list[str] = []
    if instructions.project_context:
        parts.append(f"PROJECT CONTEXT:\n{instructions.project_context}")
    if instructions.focus_instructions:
        parts.append(f"FOCUS AREAS:\n{instructions.focus_instructions}")

    detail = instructions.detail_level.strip() if instructions.detail_level else ""
    if not detail:
        detail = DEFAULT_DETAIL_LEVEL
    parts.append(f"DETAIL LEVEL:\n{detail}")

    return "\n\n".join(parts)
