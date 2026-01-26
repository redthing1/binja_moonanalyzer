from __future__ import annotations

from PySide6.QtWidgets import QDialog, QPlainTextEdit, QVBoxLayout

from ..qt import get_monospace_font


class PromptOutputDialog(QDialog):
    def __init__(self, text: str, title: str, parent=None):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setMinimumSize(700, 500)

        layout = QVBoxLayout()
        output = QPlainTextEdit()
        output.setReadOnly(True)
        output.setFont(get_monospace_font())
        output.setPlainText(text)
        layout.addWidget(output)
        self.setLayout(layout)
