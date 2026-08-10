"""Arithmetic that refuses to report a default as a measurement.

Two failure modes motivate this module, both observed in practice: a reported
0.946 that was the identity (s - c) / (s - c), and a reported 0.00 that was
mean([]). Both are what a naive expression evaluates to when the input set is
empty or degenerate, and both read as findings.

The rule enforced here: an aggregation over nothing prints NA, never 0, and
every quoted quantity carries its n. `Rate` and `mean` are the only division
and averaging primitives in this codebase. Nothing else divides.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Iterable, Sequence

NA = "NA"


@dataclass(frozen=True)
class Rate:
    """A fraction that knows its own denominator and refuses to hide an empty one.

    `value` is None when the denominator is zero. It is never 0.0, because 0.0
    is a legitimate measurement (nothing was killed) and must stay
    distinguishable from "there was nothing to measure".
    """

    numerator: int
    denominator: int
    label: str = ""

    def __post_init__(self) -> None:
        if self.numerator < 0 or self.denominator < 0:
            raise ValueError(f"Rate takes non-negative counts, got {self!r}")
        if self.denominator and self.numerator > self.denominator:
            raise ValueError(
                f"Rate numerator exceeds denominator: {self.numerator}/{self.denominator}"
                f"{' for ' + self.label if self.label else ''}"
            )

    @property
    def defined(self) -> bool:
        return self.denominator > 0

    @property
    def value(self) -> float | None:
        """The ratio, or None when there was nothing to divide into."""
        if not self.defined:
            return None
        return self.numerator / self.denominator

    @property
    def n(self) -> int:
        """The denominator, which is the n that must travel with the number."""
        return self.denominator

    def percent(self, places: int = 1) -> str:
        v = self.value
        if v is None:
            return NA
        return f"{v * 100:.{places}f}%"

    def render(self, places: int = 1) -> str:
        """Human-readable form. Always carries n. Prints NA when undefined."""
        head = f"{self.label}: " if self.label else ""
        if not self.defined:
            return f"{head}{NA} (n=0)"
        return f"{head}{self.numerator}/{self.denominator} = {self.percent(places)} (n={self.denominator})"

    def as_record(self) -> dict:
        """Serialisable form. `value` is null rather than 0 when undefined."""
        return {
            "label": self.label,
            "numerator": self.numerator,
            "denominator": self.denominator,
            "n": self.denominator,
            "value": self.value,
            "defined": self.defined,
        }

    def __str__(self) -> str:
        return self.render()


def mean(values: Sequence[float] | Iterable[float], label: str = "") -> "Mean":
    vals = list(values)
    return Mean(values=vals, label=label)


@dataclass(frozen=True)
class Mean:
    """An average that reports NA over an empty sequence rather than 0.00."""

    values: Sequence[float]
    label: str = ""

    @property
    def defined(self) -> bool:
        return len(self.values) > 0

    @property
    def value(self) -> float | None:
        if not self.defined:
            return None
        return math.fsum(self.values) / len(self.values)

    @property
    def n(self) -> int:
        return len(self.values)

    def render(self, places: int = 3) -> str:
        head = f"{self.label}: " if self.label else ""
        if not self.defined:
            return f"{head}{NA} (n=0)"
        return f"{head}{self.value:.{places}f} (n={self.n})"

    def as_record(self) -> dict:
        return {
            "label": self.label,
            "n": self.n,
            "value": self.value,
            "defined": self.defined,
        }

    def __str__(self) -> str:
        return self.render()


def count(label: str, n: int) -> str:
    """Render a bare count. Counts are always defined, but keep the shape uniform."""
    return f"{label}: {n} (n={n})"
