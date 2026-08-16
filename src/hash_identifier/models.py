"""
Data shapes shared by the detection engine and the CLI.

Kept separate from engine.py so the "what a result looks like" question
is answered in one place, independent of "how we find results."
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum


class Confidence(IntEnum):
    """
    How sure a single detector is about its guess.

    IntEnum (rather than a plain str Enum) so findings sort naturally —
    HIGH > MEDIUM > LOW — without a separate sort-key lookup table.
    """

    LOW = 1
    MEDIUM = 2
    HIGH = 3

    def label(self) -> str:
        return self.name.title()

    def style(self) -> str:
        """Rich console color for this confidence tier."""
        return {
            Confidence.HIGH: "bold green",
            Confidence.MEDIUM: "bold yellow",
            Confidence.LOW: "bold red",
        }[self]


@dataclass(frozen=True, slots=True)
class Finding:
    """One candidate identification produced by a single detector."""

    algorithm: str
    confidence: Confidence
    reason: str
    is_hash: bool = True


@dataclass(slots=True)
class ScanReport:
    """
    The full result of scanning one sample.

    `findings` is kept pre-sorted (highest confidence first) so
    presentation layers never need to think about ordering.
    """

    sample: str
    findings: list[Finding] = field(default_factory=list)

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)
        self.findings.sort(key=lambda f: f.confidence, reverse=True)

    @property
    def best(self) -> Finding | None:
        return self.findings[0] if self.findings else None

    @property
    def is_empty(self) -> bool:
        return not self.findings
