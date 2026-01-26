from __future__ import annotations

from PySide6.QtGui import QFontDatabase

from binaryninjaui import UIContext


def get_main_window():
    ctx = UIContext.activeContext()
    if ctx is None:
        contexts = UIContext.allContexts()
        ctx = contexts[0] if contexts else None
    return ctx.mainWindow() if ctx else None


def get_monospace_font():
    return QFontDatabase.systemFont(QFontDatabase.FixedFont)
