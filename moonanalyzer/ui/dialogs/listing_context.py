from __future__ import annotations

from PySide6.QtWidgets import (
    QComboBox,
    QDialog,
    QHBoxLayout,
    QLabel,
    QPlainTextEdit,
    QPushButton,
    QSpinBox,
    QVBoxLayout,
)

from ...app.listing_service import ListingContextService
from ...app.services import AppServices
from ...context.base import ContextParams
from ...context.collector import ContextCollector
from ...context.strategies.forward_refs import ForwardReferencesStrategy
from ...listing.base import ListingParams
from ...listing.renderers.hlil import HLILListingRenderer
from ...listing.renderers.disassembly import DisassemblyListingRenderer
from ...listing.renderers.combined import CombinedListingRenderer
from ...settings import settings
from ...util import get_current_function
from ..qt import get_monospace_font


class ListingContextDialog(QDialog):
    def __init__(self, bv, services: AppServices, parent=None):
        super().__init__(parent)
        self._bv = bv
        self._services = services
        self.setWindowTitle("Listing Context")
        self.setMinimumSize(800, 600)

        layout = QVBoxLayout()

        settings_row = QHBoxLayout()
        self.depth_spin = QSpinBox()
        self.depth_spin.setMinimum(0)
        self.depth_spin.setMaximum(10)
        self.depth_spin.setValue(
            max(0, settings.get_integer("moonanalyzer.quick_analysis_context_depth", bv))
        )
        settings_row.addWidget(QLabel("Max depth"))
        settings_row.addWidget(self.depth_spin)

        self.max_funcs_spin = QSpinBox()
        self.max_funcs_spin.setMinimum(0)
        self.max_funcs_spin.setMaximum(2000)
        self.max_funcs_spin.setValue(
            max(0, settings.get_integer("moonanalyzer.quick_analysis_max_function_count", bv))
        )
        settings_row.addWidget(QLabel("Max functions"))
        settings_row.addWidget(self.max_funcs_spin)

        self.max_lines_spin = QSpinBox()
        self.max_lines_spin.setMinimum(0)
        self.max_lines_spin.setMaximum(4000)
        self.max_lines_spin.setValue(
            max(0, settings.get_integer("moonanalyzer.analysis_max_function_lines", bv))
        )
        settings_row.addWidget(QLabel("Max lines"))
        settings_row.addWidget(self.max_lines_spin)

        self.listing_type = QComboBox()
        self.listing_type.addItems(["HLIL", "Disassembly", "HLIL + Disassembly"])
        settings_row.addWidget(QLabel("Listing"))
        settings_row.addWidget(self.listing_type)

        layout.addLayout(settings_row)

        self.generate_button = QPushButton("Generate Listing")
        layout.addWidget(self.generate_button)

        layout.addWidget(QLabel("Listing output"))
        self.output = QPlainTextEdit()
        self.output.setReadOnly(True)
        self.output.setFont(get_monospace_font())
        layout.addWidget(self.output)

        self.setLayout(layout)

        self.generate_button.clicked.connect(self._on_generate)

    def _make_listing_renderer(self):
        choice = self.listing_type.currentText()
        if choice == "Disassembly":
            return DisassemblyListingRenderer()
        if choice == "HLIL + Disassembly":
            return CombinedListingRenderer()
        return HLILListingRenderer()

    def _on_generate(self) -> None:
        log = self._bv.create_logger("MoonAnalyzer")
        entry_func = get_current_function(self._bv, None, log)
        if not entry_func:
            self.output.setPlainText("No function at current cursor.")
            return

        context_params = ContextParams(
            max_depth=self.depth_spin.value(),
            max_functions=self.max_funcs_spin.value(),
        )
        listing_params = ListingParams(max_lines=self.max_lines_spin.value())

        listing_service = ListingContextService(
            context_collector=ContextCollector(strategies=[ForwardReferencesStrategy()]),
            listing_renderer=self._make_listing_renderer(),
        )

        listing_text = listing_service.build_listing(
            bv=self._bv,
            entry_func=entry_func,
            context_params=context_params,
            listing_params=listing_params,
        )
        self.output.setPlainText(listing_text)
