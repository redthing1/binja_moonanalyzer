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
