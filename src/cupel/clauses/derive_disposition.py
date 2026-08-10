"""Derivation D3: the structural bound, read from the generator's own enums.

Every negative ACVP test case is produced by selecting one value from a
disposition enum in the vector generator's source. The enums are finite,
public and enumerable, so the set of KINDS of negative case is bounded by their
cardinality no matter how many cases the production database emits.

This is what lifts an empirical result about the committed sample files into a
claim about any generated vector set. Sample size is irrelevant to a statement
about a taxonomy: a production run with ten thousand cases per group draws from
the same enum as a sample with fifteen.

The bound is on kinds, not on clauses. One disposition can in principle violate
several clauses at once, and whether it does is empirical, which is what the
violation matrix supplies. What the bound establishes on its own is the
ceiling: a standard mandating more distinct checks than its disposition enum
has negative members has clauses no generated set can exercise in isolation.

`MLDSASignatureDisposition.cs` additionally carries a committed comment naming
three checks its authors intended to add and recording the assumption that the
existing dispositions already cover them. That comment is captured as
`planned_but_absent`, because it is an upstream-authored statement of exactly
the coverage claim this project measures.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

ENUM_RE = re.compile(r"public\s+enum\s+(\w+)")
MEMBER_RE = re.compile(r'\[EnumMember\(Value\s*=\s*"([^"]*)"\)\]\s*(?:\r?\n\s*)([A-Za-z_]\w*)')
TODO_RE = re.compile(r"//\s*TODO\s+add\s+([^\n(]+)(?:\(([^)]*)\))?", re.IGNORECASE)

# Which enum governs which algorithm and vector-set function.
ENUM_SCOPE = {
    "MLDSASignatureDisposition": ("ML-DSA", "sigVer"),
    "MLKEMDecapsulationDisposition": ("ML-KEM", "decapsulation"),
    "MLKEMDecapsulationKeyDisposition": ("ML-KEM", "decapsulationKeyCheck"),
    "MLKEMEncapsulationKeyDisposition": ("ML-KEM", "encapsulationKeyCheck"),
    "SLHDSASignatureDisposition": ("SLH-DSA", "sigVer"),
}

VALID_PREFIXES = ("valid ",)


@dataclass(frozen=True)
class Member:
    enum: str
    name: str
    label: str
    algorithm: str
    function: str
    is_valid: bool
    planned_but_absent: bool
    note: str

    def as_record(self) -> dict:
        return {
            "schema": "disposition/1",
            "derivation": "D3",
            "enum": self.enum,
            "name": self.name,
            "label": self.label,
            "algorithm": self.algorithm,
            "function": self.function,
            "is_valid": self.is_valid,
            "planned_but_absent": self.planned_but_absent,
            "note": self.note,
        }


def parse(source: str, filename: str) -> list[Member]:
    m = ENUM_RE.search(source)
    if not m:
        raise ValueError(f"{filename}: no enum declaration found")
    enum_name = m.group(1)
    algorithm, function = ENUM_SCOPE.get(enum_name, ("", ""))

    planned: list[Member] = []
    for todo in TODO_RE.finditer(source):
        names = [n.strip() for n in todo.group(1).replace(" and ", ",").split(",") if n.strip()]
        note = (todo.group(2) or "").strip()
        for name in names:
            planned.append(Member(
                enum=enum_name, name=name, label="", algorithm=algorithm,
                function=function, is_valid=False, planned_but_absent=True,
                note=f"named in an upstream TODO; upstream states: {note}" if note else
                     "named in an upstream TODO comment",
            ))

    members = []
    for label, name in MEMBER_RE.findall(source):
        members.append(Member(
            enum=enum_name, name=name, label=label, algorithm=algorithm,
            function=function,
            is_valid=label.startswith(VALID_PREFIXES),
            planned_but_absent=False, note="",
        ))
    if not members:
        raise ValueError(f"{filename}: enum {enum_name} parsed to zero members")
    return members + planned


@dataclass
class Bound:
    enum: str
    algorithm: str
    function: str
    n_members: int
    n_negative: int
    n_planned_absent: int
    labels: list[str]

    def as_record(self) -> dict:
        return {
            "schema": "bound/1",
            "enum": self.enum,
            "algorithm": self.algorithm,
            "function": self.function,
            "n_members": self.n_members,
            "n_negative": self.n_negative,
            "n_planned_absent": self.n_planned_absent,
            "labels": self.labels,
        }


def bounds(members: list[Member]) -> list[Bound]:
    by_enum: dict[str, list[Member]] = {}
    for m in members:
        by_enum.setdefault(m.enum, []).append(m)
    out = []
    for enum, ms in sorted(by_enum.items()):
        real = [m for m in ms if not m.planned_but_absent]
        negative = [m for m in real if not m.is_valid]
        out.append(Bound(
            enum=enum,
            algorithm=ms[0].algorithm,
            function=ms[0].function,
            n_members=len(real),
            n_negative=len(negative),
            n_planned_absent=sum(1 for m in ms if m.planned_but_absent),
            labels=[m.label for m in negative],
        ))
    return out
