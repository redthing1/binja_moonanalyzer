import json

from binaryninja.settings import Settings

my_settings = Settings()
my_settings.register_group("moonanalyzer", "MoonAnalyzer")

# int: quick analysis context depth
my_settings.register_setting(
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

# bool: quick analysis max function count
my_settings.register_setting(
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

# string: custom analysis project context
my_settings.register_setting(
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

# string: custom prompt additions
my_settings.register_setting(
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

# string: level of detail instructions
my_settings.register_setting(
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
