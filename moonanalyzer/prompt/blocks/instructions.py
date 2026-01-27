from __future__ import annotations

from ..base import PromptInstructions
from ..presets import get_focus_preset


def build_instructions_block(instructions: PromptInstructions) -> str:
    parts: list[str] = []
    if instructions.project_context:
        parts.append(f"PROJECT CONTEXT:\n{instructions.project_context}")

    focus = get_focus_preset(instructions.focus_preset)
    parts.append(focus.text)

    return "\n\n".join(parts)
