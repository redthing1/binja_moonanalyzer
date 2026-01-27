from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, TYPE_CHECKING

from ..context.base import ContextGraph
from ..listing.base import Listing

if TYPE_CHECKING:
    from binaryninja import BinaryView, Function


@dataclass(frozen=True)
class PromptInstructions:
    """High-level guidance to include in prompt construction."""

    project_context: str = ""
    focus_preset: str = "general"


@dataclass(frozen=True)
class PromptPolicy:
    """Policy hints for prompt construction."""

    max_chars: int = 0  # 0 means unlimited


@dataclass(frozen=True)
class ListingBundle:
    """Listing output keyed by function start address."""

    listings: dict[int, Listing]


@dataclass(frozen=True)
class Prompt:
    """Final prompt text plus metadata for UI/display."""

    text: str
    truncated: bool


class PromptRecipe(Protocol):
    """Strategy interface for building prompt text."""

    id: str
    label: str

    def build(
        self,
        bv: "BinaryView",
        context: ContextGraph,
        listings: ListingBundle,
        instructions: PromptInstructions,
        policy: PromptPolicy,
    ) -> Prompt:
        ...
