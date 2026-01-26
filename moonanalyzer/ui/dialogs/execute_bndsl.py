from __future__ import annotations

from typing import List

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QDialog,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QPushButton,
    QTextEdit,
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

        self.editor = QTextEdit()
        self.editor.setFont(get_monospace_font())
        self.editor.setPlaceholderText("Paste BNDSL here...")
        layout.addWidget(self.editor)

        button_row = QHBoxLayout()
        self.check_button = QPushButton("Check Syntax")
        self.apply_button = QPushButton("Apply")
        self.apply_button.setEnabled(False)
        button_row.addWidget(self.check_button)
        button_row.addWidget(self.apply_button)
        layout.addLayout(button_row)

        self.status_label = QLabel("Ready.")
        self.status_label.setWordWrap(True)
        layout.addWidget(self.status_label)

        self.preview_list = QListWidget()
        self.preview_list.setSelectionMode(QListWidget.NoSelection)
        layout.addWidget(self.preview_list)

        self.setLayout(layout)

        self.check_button.clicked.connect(self._on_check)
        self.apply_button.clicked.connect(self._on_apply)

    def _set_status(self, text: str, is_error: bool = False) -> None:
        self.status_label.setText(text)
        if is_error:
            self.status_label.setStyleSheet("color: #c62828;")
        else:
            self.status_label.setStyleSheet("")

    def _render_preview(self, commands: List[DSLCommand]) -> None:
        self.preview_list.clear()
        for idx, cmd in enumerate(commands):
            item = QListWidgetItem(f"{idx + 1}. {cmd.command_type} {cmd}")
            item.setFlags(Qt.ItemIsEnabled)
            self.preview_list.addItem(item)

    def _on_check(self) -> None:
        text = self.editor.toPlainText()
        self._commands = []
        self.apply_button.setEnabled(False)

        if not text.strip():
            self._set_status("BNDSL is empty.", is_error=True)
            self.preview_list.clear()
            return

        try:
            commands = parse_bndsl(text)
        except BNDslParseError as exc:
            location = ""
            if exc.line is not None and exc.column is not None:
                location = f" (line {exc.line}, col {exc.column})"
            self._set_status(f"Parse error{location}: {exc}", is_error=True)
            self.preview_list.clear()
            return

        issues = validate_bndsl(commands)
        errors = [i for i in issues if i.severity == "error"]
        warnings = [i for i in issues if i.severity == "warning"]

        self._commands = commands
        self._render_preview(commands)

        if errors:
            self._set_status(
                f"Validation failed: {len(errors)} error(s), {len(warnings)} warning(s).",
                is_error=True,
            )
            self.apply_button.setEnabled(False)
            return

        status = f"Syntax OK: {len(commands)} command(s)"
        if warnings:
            status += f" ({len(warnings)} warning(s))"
        self._set_status(status)
        self.apply_button.setEnabled(True)

    def _on_apply(self) -> None:
        if not self._commands:
            self._on_check()
        if not self._commands:
            return

        report = self._services.dsl_executor.apply(
            self._bv, self._commands, ExecutionOptions(dry_run=False, strict=False)
        )
        if report.success:
            self._set_status(report.message)
        else:
            detail = report.error or "Execution failed."
            self._set_status(f"{report.message}\n{detail}", is_error=True)
