from __future__ import annotations

from binaryninja import log_info

from .. import settings as _settings
from ..ui import menu


def init() -> None:
    """Plugin entrypoint for MoonAnalyzer."""
    menu.register()
    log_info("MoonAnalyzer loaded.")
