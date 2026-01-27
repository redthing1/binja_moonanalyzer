from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class FocusPreset:
    id: str
    label: str
    text: str


FOCUS_PRESETS: dict[str, FocusPreset] = {
    "general": FocusPreset(
        id="general",
        label="General Analysis",
        text=(
            "FOCUS PRESET: General Analysis\n"
            "- Build a full and detailed understanding of each function.\n"
            "- Explain intent, control flow, and data transformations clearly.\n"
            "- Aggressively rename unnamed/generic symbols and add clarifying comments.\n"
            "- Provide as many high-confidence annotations as possible."
        ),
    ),
    "deep": FocusPreset(
        id="deep",
        label="Deep Analysis",
        text=(
            "FOCUS PRESET: Deep Analysis\n"
            "- Exhaustively analyze and annotate a small set of functions.\n"
            "- Maximize clarity: rename aggressively and add comments throughout.\n"
            "- Explain invariants, state transitions, data structures, and edge cases.\n"
            "- Identify standard library patterns, semantics, and side effects."
        ),
    ),
}


def get_focus_preset(preset_id: str) -> FocusPreset:
    return FOCUS_PRESETS.get(preset_id, FOCUS_PRESETS["general"])
