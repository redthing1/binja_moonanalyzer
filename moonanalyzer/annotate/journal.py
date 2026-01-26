from __future__ import annotations

import dataclasses
import json
from typing import Any, Dict, Iterable

from ..defs import LOGGER_NAME
from ..dsl.ast import DSLCommand


JOURNAL_KEY = "moonanalyzer.bndsl_journal"


def serialize_command(command: DSLCommand) -> Dict[str, Any]:
    data = dataclasses.asdict(command)
    data["command_type"] = command.command_type
    return data


class Journal:
    """Stores executed BNDSL commands in BinaryView metadata."""

    def __init__(self, bv):
        self._bv = bv
        self._logger = bv.create_logger(LOGGER_NAME)

    def load(self) -> list[dict[str, Any]]:
        raw = self._bv.query_metadata(JOURNAL_KEY)
        if not raw:
            return []
        try:
            return json.loads(raw)
        except Exception as exc:
            self._logger.log_error(f"journal: failed to parse stored entries: {exc}")
            return []

    def append(self, commands: Iterable[DSLCommand]) -> None:
        entries = self.load()
        entries.extend(serialize_command(cmd) for cmd in commands)
        self._bv.store_metadata(JOURNAL_KEY, json.dumps(entries))
