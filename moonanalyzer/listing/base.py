from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, TYPE_CHECKING

if TYPE_CHECKING:
    from binaryninja import BinaryView, Function


@dataclass(frozen=True)
class ListingParams:
    """Parameters for rendering function listings."""

    max_lines: int = 0  # 0 means unlimited
    include_addresses: bool = True
    address_width: int = 0  # 0 means auto


@dataclass(frozen=True)
class Listing:
    """Rendered listing text plus metadata."""

    text: str
    line_count: int
    truncated: bool


class ListingRenderer(Protocol):
    """Strategy interface for rendering a function listing."""

    id: str
    label: str

    def render(self, bv: "BinaryView", func: "Function", params: ListingParams) -> Listing:
        ...
