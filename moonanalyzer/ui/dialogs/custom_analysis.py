from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from PySide6.QtWidgets import (
    QComboBox,
    QDialog,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QPlainTextEdit,
    QPushButton,
    QSpinBox,
    QSplitter,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
    QCheckBox,
)

from binaryninja import SymbolType

from ...app.analysis_service import AnalysisService
from ...app.services import AppServices
from ...context.base import ContextParams
from ...context.collector import ContextCollector
from ...context.strategies.forward_refs import ForwardReferencesStrategy
from ...context.strategies.callers import CallersStrategy
from ...context.strategies.code_xrefs import CodeXrefsStrategy
from ...context.strategies.data_refs import DataReferencesStrategy, DataSeedMode
from ...listing.base import ListingParams
from ...listing.renderers.hlil import HLILListingRenderer
from ...listing.renderers.disassembly import DisassemblyListingRenderer
from ...listing.renderers.combined import CombinedListingRenderer
from ...prompt.base import PromptInstructions, PromptPolicy
from ...settings import settings
from ...util import get_current_function
from ..qt import get_monospace_font


@dataclass
class StrategySpec:
    label: str
    description: str
    build_strategy: Callable[[], object]
    build_params: Callable[[], ContextParams]
    requires_function: bool
    widget: QWidget


class CustomAnalysisDialog(QDialog):
    def __init__(self, bv, services: AppServices, parent=None):
        super().__init__(parent)
        self._bv = bv
        self._services = services
        self.setWindowTitle("Custom Analysis")
        self.setMinimumSize(900, 650)

        layout = QVBoxLayout()

        splitter = QSplitter()
        splitter.setStretchFactor(0, 0)
        splitter.setStretchFactor(1, 1)

        config_widget = QWidget()
        config_layout = QVBoxLayout()

        strategy_group = QGroupBox("Context Strategy")
        strategy_layout = QVBoxLayout()
        self.strategy_combo = QComboBox()
        self.strategy_description = QLabel()
        self.strategy_description.setWordWrap(True)

        self.strategy_stack = QStackedWidget()
        self._strategy_specs: list[StrategySpec] = []
        self._init_strategies()

        for spec in self._strategy_specs:
            self.strategy_combo.addItem(spec.label)
            self.strategy_stack.addWidget(spec.widget)

        self.strategy_combo.currentIndexChanged.connect(self._on_strategy_changed)
        self._on_strategy_changed(0)

        strategy_layout.addWidget(self.strategy_combo)
        strategy_layout.addWidget(self.strategy_description)
        strategy_layout.addWidget(self.strategy_stack)
        strategy_group.setLayout(strategy_layout)
        config_layout.addWidget(strategy_group)

        limits_group = QGroupBox("Global Limits")
        limits_layout = QFormLayout()
        self.max_funcs_spin = QSpinBox()
        self.max_funcs_spin.setMinimum(0)
        self.max_funcs_spin.setMaximum(5000)
        self.max_funcs_spin.setValue(
            max(0, settings.get_integer("moonanalyzer.quick_analysis_max_function_count", bv))
        )
        self.max_lines_spin = QSpinBox()
        self.max_lines_spin.setMinimum(0)
        self.max_lines_spin.setMaximum(4000)
        self.max_lines_spin.setValue(
            max(0, settings.get_integer("moonanalyzer.analysis_max_function_lines", bv))
        )

        self.listing_type = QComboBox()
        self.listing_type.addItems(["HLIL", "Disassembly", "HLIL + Disassembly"])

        limits_layout.addRow("Max functions", self.max_funcs_spin)
        limits_layout.addRow("Max lines", self.max_lines_spin)
        limits_layout.addRow("Listing", self.listing_type)
        limits_group.setLayout(limits_layout)
        config_layout.addWidget(limits_group)

        prompt_group = QGroupBox("Prompt Instructions")
        prompt_layout = QFormLayout()
        self.project_context = QPlainTextEdit()
        self.project_context.setFont(get_monospace_font())
        self.project_context.setPlainText(
            settings.get_string("moonanalyzer.analysis_project_context", bv)
        )

        self.focus_instructions = QPlainTextEdit()
        self.focus_instructions.setFont(get_monospace_font())
        self.focus_instructions.setPlainText(
            settings.get_string("moonanalyzer.custom_prompt_additions", bv)
        )

        self.detail_level = QPlainTextEdit()
        self.detail_level.setFont(get_monospace_font())
        self.detail_level.setPlainText(
            settings.get_string("moonanalyzer.level_of_detail_instructions", bv)
        )

        prompt_layout.addRow("Project context", self.project_context)
        prompt_layout.addRow("Focus", self.focus_instructions)
        prompt_layout.addRow("Detail level", self.detail_level)
        prompt_group.setLayout(prompt_layout)
        config_layout.addWidget(prompt_group)

        self.generate_button = QPushButton("Generate Prompt")
        config_layout.addWidget(self.generate_button)

        config_widget.setLayout(config_layout)
        splitter.addWidget(config_widget)

        output_widget = QWidget()
        output_layout = QVBoxLayout()
        output_layout.addWidget(QLabel("Prompt Output"))
        self.output = QPlainTextEdit()
        self.output.setReadOnly(True)
        self.output.setFont(get_monospace_font())
        output_layout.addWidget(self.output)
        output_widget.setLayout(output_layout)
        splitter.addWidget(output_widget)

        layout.addWidget(splitter)
        self.setLayout(layout)

        self.generate_button.clicked.connect(self._on_generate)

    def _init_strategies(self) -> None:
        self._strategy_specs = [
            self._make_forward_strategy(),
            self._make_reverse_strategy(),
            self._make_xref_strategy(),
            self._make_data_refs_strategy(),
        ]

    def _make_forward_strategy(self) -> StrategySpec:
        widget = QWidget()
        form = QFormLayout()
        depth_spin = QSpinBox()
        depth_spin.setMinimum(0)
        depth_spin.setMaximum(10)
        depth_spin.setValue(
            max(0, settings.get_integer("moonanalyzer.quick_analysis_context_depth", self._bv))
        )
        include_entry = QCheckBox("Include entry function")
        include_entry.setChecked(True)
        form.addRow("Depth", depth_spin)
        form.addRow("", include_entry)
        widget.setLayout(form)

        def build_params() -> ContextParams:
            return ContextParams(
                max_depth=depth_spin.value(),
                max_functions=self.max_funcs_spin.value(),
                include_entry=include_entry.isChecked(),
            )

        return StrategySpec(
            label="Forward References",
            description="Traverse callees and code xrefs forward from the entry function.",
            build_strategy=ForwardReferencesStrategy,
            build_params=build_params,
            requires_function=True,
            widget=widget,
        )

    def _make_reverse_strategy(self) -> StrategySpec:
        widget = QWidget()
        form = QFormLayout()
        depth_spin = QSpinBox()
        depth_spin.setMinimum(0)
        depth_spin.setMaximum(10)
        depth_spin.setValue(
            max(0, settings.get_integer("moonanalyzer.quick_analysis_context_depth", self._bv))
        )
        include_entry = QCheckBox("Include entry function")
        include_entry.setChecked(True)
        form.addRow("Depth", depth_spin)
        form.addRow("", include_entry)
        widget.setLayout(form)

        def build_params() -> ContextParams:
            return ContextParams(
                max_depth=depth_spin.value(),
                max_functions=self.max_funcs_spin.value(),
                include_entry=include_entry.isChecked(),
            )

        return StrategySpec(
            label="Reverse References",
            description="Traverse callers backward toward the entry function.",
            build_strategy=CallersStrategy,
            build_params=build_params,
            requires_function=True,
            widget=widget,
        )

    def _make_xref_strategy(self) -> StrategySpec:
        widget = QWidget()
        form = QFormLayout()
        depth_spin = QSpinBox()
        depth_spin.setMinimum(0)
        depth_spin.setMaximum(10)
        depth_spin.setValue(
            max(0, settings.get_integer("moonanalyzer.quick_analysis_context_depth", self._bv))
        )
        include_entry = QCheckBox("Include entry function")
        include_entry.setChecked(True)
        form.addRow("Depth", depth_spin)
        form.addRow("", include_entry)
        widget.setLayout(form)

        def build_params() -> ContextParams:
            return ContextParams(
                max_depth=depth_spin.value(),
                max_functions=self.max_funcs_spin.value(),
                include_entry=include_entry.isChecked(),
            )

        return StrategySpec(
            label="Code Xrefs",
            description="Traverse code cross-references from each function.",
            build_strategy=CodeXrefsStrategy,
            build_params=build_params,
            requires_function=True,
            widget=widget,
        )

    def _make_data_refs_strategy(self) -> StrategySpec:
        widget = QWidget()
        form = QFormLayout()
        depth_spin = QSpinBox()
        depth_spin.setMinimum(0)
        depth_spin.setMaximum(10)
        depth_spin.setValue(
            max(0, settings.get_integer("moonanalyzer.quick_analysis_context_depth", self._bv))
        )
        include_entry = QCheckBox("Include entry function when present")
        include_entry.setChecked(True)

        seed_combo = QComboBox()
        seed_combo.addItem("Smart (cursor data, else entry function)", DataSeedMode.SMART)
        seed_combo.addItem("Cursor data only", DataSeedMode.CURSOR_DATA)
        seed_combo.addItem("Entry function data only", DataSeedMode.ENTRY_FUNCTION)

        hint = QLabel(
            "Data References collects functions that reference the same data."
        )
        hint.setWordWrap(True)
        form.addRow("Depth", depth_spin)
        form.addRow("Seed", seed_combo)
        form.addRow("", include_entry)
        form.addRow("", hint)
        widget.setLayout(form)

        def build_params() -> ContextParams:
            return ContextParams(
                max_depth=depth_spin.value(),
                max_functions=self.max_funcs_spin.value(),
                include_entry=include_entry.isChecked(),
            )

        def build_strategy() -> object:
            mode = seed_combo.currentData()
            return DataReferencesStrategy(seed_mode=mode)

        return StrategySpec(
            label="Data References",
            description="Find functions that reference data tied to the cursor or entry function.",
            build_strategy=build_strategy,
            build_params=build_params,
            requires_function=False,
            widget=widget,
        )

    def _on_strategy_changed(self, index: int) -> None:
        spec = self._strategy_specs[index]
        self.strategy_description.setText(spec.description)
        self.strategy_stack.setCurrentIndex(index)

    def _make_listing_renderer(self):
        choice = self.listing_type.currentText()
        if choice == "Disassembly":
            return DisassemblyListingRenderer()
        if choice == "HLIL + Disassembly":
            return CombinedListingRenderer()
        return HLILListingRenderer()

    def _on_generate(self) -> None:
        spec = self._strategy_specs[self.strategy_combo.currentIndex()]
        log = self._bv.create_logger("MoonAnalyzer")

        entry_func = None
        if spec.requires_function:
            entry_func = get_current_function(self._bv, None, log)
            if entry_func is None:
                self.output.setPlainText("No function at current cursor.")
                return
        else:
            entry_func = get_current_function(self._bv, None, log)
            data_var = self._bv.get_data_var_at(self._bv.offset)
            symbol = self._bv.get_symbol_at(self._bv.offset)
            if entry_func is None and data_var is None and (
                symbol is None or symbol.type != SymbolType.DataSymbol
            ):
                self.output.setPlainText("No function or data variable at current cursor.")
                return

        context_params = spec.build_params()
        listing_params = ListingParams(max_lines=self.max_lines_spin.value())
        instructions = PromptInstructions(
            project_context=self.project_context.toPlainText().strip(),
            focus_instructions=self.focus_instructions.toPlainText().strip(),
            detail_level=self.detail_level.toPlainText().strip(),
        )
        policy = PromptPolicy(max_chars=0)

        analysis_service = AnalysisService(
            context_collector=ContextCollector(strategies=[spec.build_strategy()]),
            prompt_recipe=self._services.analysis_service.prompt_recipe,
            listing_renderer=self._make_listing_renderer(),
        )

        prompt = analysis_service.build_prompt(
            bv=self._bv,
            entry_func=entry_func,
            context_params=context_params,
            listing_params=listing_params,
            instructions=instructions,
            policy=policy,
        )
        self.output.setPlainText(prompt.text)
