from __future__ import annotations

from typing import List

from PySide6.QtWidgets import (
    QDialog,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QPlainTextEdit,
    QVBoxLayout,
)

from ...app.services import AppServices
from ...dsl.parser import parse_bndsl
from ...dsl.validator import validate_bndsl
from ...dsl.errors import BNDslParseError
from ...annotate.types import ExecutionOptions
from ...dsl.ast import DSLCommand
from ..qt import get_monospace_font


class ExecuteBNDslDialog(QDialog):
    def __init__(self, bv, services: AppServices, parent=None):
        super().__init__(parent)
        self._bv = bv
        self._services = services
        self._commands: List[DSLCommand] = []

        self.setWindowTitle("Execute BNDSL")
        self.setMinimumSize(700, 500)

        layout = QVBoxLayout()

        self.editor = QPlainTextEdit()
        self.editor.setFont(get_monospace_font())
        self.editor.setPlaceholderText("Paste BNDSL here...")
        self.editor.setLineWrapMode(QPlainTextEdit.NoWrap)
        layout.addWidget(self.editor)

        self.status_label = QLabel("")
        self.status_label.setWordWrap(True)
        layout.addWidget(self.status_label)

        button_row = QHBoxLayout()
        self.apply_button = QPushButton("Apply")
        button_row.addWidget(self.apply_button)
        layout.addLayout(button_row)

        self.setLayout(layout)

        self.apply_button.clicked.connect(self._on_apply)

    def _set_status(self, text: str, is_error: bool = False) -> None:
        self.status_label.setText(text)
        if is_error:
            self.status_label.setStyleSheet("color: #c62828;")
        else:
            self.status_label.setStyleSheet("")

    def _validate(self) -> List[DSLCommand]:
        text = self.editor.toPlainText()
        self._commands = []

        if not text.strip():
            self._set_status("BNDSL is empty.", is_error=True)
            return []

        try:
            commands = parse_bndsl(text)
        except BNDslParseError as exc:
            location = ""
            if exc.line is not None and exc.column is not None:
                location = f" (line {exc.line}, col {exc.column})"
            self._set_status(f"Parse error{location}: {exc}", is_error=True)
            return []

        issues = validate_bndsl(commands)
        errors = [i for i in issues if i.severity == "error"]
        warnings = [i for i in issues if i.severity == "warning"]

        self._commands = commands

        if errors:
            self._set_status(
                f"Validation failed: {len(errors)} error(s), {len(warnings)} warning(s).",
                is_error=True,
            )
            return []

        if warnings:
            self._set_status(f"{len(warnings)} warning(s).")
        else:
            self._set_status("")
        return commands

    def _on_apply(self) -> None:
        commands = self._validate()
        if not commands:
            return

        report = self._services.dsl_executor.apply(
            self._bv, commands, ExecutionOptions(dry_run=False, strict=False)
        )
        if report.success:
            self._set_status(report.message)
            self.accept()
        else:
            detail = report.error or "Execution failed."
            self._set_status(f"{report.message}\n{detail}", is_error=True)
