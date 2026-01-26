from __future__ import annotations

import json

from binaryninja.settings import Settings

settings = Settings()
settings.register_group("moonanalyzer", "MoonAnalyzer")

settings.register_setting(
    "moonanalyzer.quick_analysis_context_depth",
    json.dumps(
        {
            "title": "Quick Analysis Context Depth",
            "description": "Call graph traversal depth for quick analysis context.",
            "default": 1,
            "type": "number",
        }
    ),
)

settings.register_setting(
    "moonanalyzer.quick_analysis_max_function_count",
    json.dumps(
        {
            "title": "Quick Analysis Max Function Count",
            "description": "Maximum number of functions to add to quick analysis context.",
            "default": 0,
            "type": "number",
        }
    ),
)

settings.register_setting(
    "moonanalyzer.analysis_project_context",
    json.dumps(
        {
            "title": "Analysis Project Context",
            "description": "Project context for analysis context.",
            "default": "",
            "type": "string",
            "ignore": ["SettingsUserScope"],
        }
    ),
)

settings.register_setting(
    "moonanalyzer.custom_prompt_additions",
    json.dumps(
        {
            "title": "Custom Prompt Additions",
            "description": "Custom prompt additions for analysis context.",
            "default": "",
            "type": "string",
            "ignore": ["SettingsUserScope"],
        }
    ),
)

settings.register_setting(
    "moonanalyzer.level_of_detail_instructions",
    json.dumps(
        {
            "title": "Level of Detail Instructions",
            "description": "Level of detail instructions for analysis context.",
            "default": "",
            "type": "string",
            "ignore": ["SettingsUserScope"],
        }
    ),
)

settings.register_setting(
    "moonanalyzer.analysis_max_function_lines",
    json.dumps(
        {
            "title": "Analysis Max Function Lines (HLIL)",
            "description": "Maximum HLIL lines per function before truncation (0 = unlimited).",
            "default": 0,
            "type": "number",
        }
    ),
)
