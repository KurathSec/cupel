"""Does each negative vector violate the clause its own label names?

A negative test case carries a `reason` string asserting why it should be
rejected. That assertion is testable: evaluate the clause the label names
against the case, independently of every other clause, and see whether it is
actually violated.

Four outcomes, and the distinction between the last two matters:

  attributed     the case violates the clause its label names
  misattributed  it does not. The case cannot fail for the stated reason, and
                 whatever does reject it is some other check
  unmapped-label the (algorithm, reason) pair is absent from the mapping
  no-predicate   the label maps to a clause this battery cannot evaluate, so
                 nothing is claimed either way

Reporting misattribution requires the label mapping to be right, so the last two
are kept apart: a label absent from the mapping is a gap in the mapping, while a
label naming a clause the battery cannot evaluate is a gap in the battery. Only
the first two are scored.
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass
from pathlib import Path

from ..vectors.pins import REPO

MAPPING = REPO / "data" / "mappings" / "reason_to_clause.toml"


@dataclass(frozen=True)
class Label:
    reason: str
    algorithm: str
    clause: str
    also_permitted: tuple[str, ...]
    is_valid: bool
    expects_rejection: bool
    note: str

    @property
    def accepts(self) -> frozenset[str]:
        return frozenset((self.clause,) + self.also_permitted) - {""}


def load_labels(path: str | Path = MAPPING) -> dict[tuple[str, str], Label]:
    data = tomllib.loads(Path(path).read_text(encoding="utf-8"))
    out = {}
    for row in data.get("label", []):
        lab = Label(
            reason=row["reason"],
            algorithm=row["algorithm"],
            clause=row.get("clause", ""),
            also_permitted=tuple(row.get("also_permitted", [])),
            is_valid=bool(row.get("is_valid", False)),
            expects_rejection=bool(row.get("expects_rejection", True)),
            note=row.get("note", ""),
        )
        out[(lab.algorithm, lab.reason)] = lab
    return out


@dataclass
class Finding:
    vdir: str
    tc_id: int
    algorithm: str
    reason: str
    claimed: str
    violated: list[str]
    status: str

    @property
    def misattributed(self) -> bool:
        return self.status == "misattributed"

    def as_record(self) -> dict:
        return {
            "schema": "misattribution/1",
            "dir": self.vdir,
            "tc_id": self.tc_id,
            "algorithm": self.algorithm,
            "reason": self.reason,
            "claimed_clause": self.claimed,
            "violated": sorted(self.violated),
            "status": self.status,
            "misattributed": self.misattributed,
        }


def check(rows, labels: dict[tuple[str, str], Label], known_clauses: set[str]) -> list[Finding]:
    findings = []
    for row in rows:
        if row.reason is None:
            continue
        lab = labels.get((row.algorithm, row.reason))
        if lab is None:
            findings.append(Finding(row.vdir, row.tc_id, row.algorithm, row.reason,
                                    "", list(row.violated), "unmapped-label"))
            continue
        if lab.is_valid or not lab.expects_rejection:
            continue
        accepts = lab.accepts
        if not accepts or not (accepts & known_clauses):
            # The label names a clause this battery cannot yet evaluate. Saying
            # nothing is the only honest option; scoring it either way would be
            # a claim about a predicate that does not exist.
            findings.append(Finding(row.vdir, row.tc_id, row.algorithm, row.reason,
                                    lab.clause, list(row.violated), "no-predicate"))
            continue
        hit = accepts & set(row.violated)
        findings.append(Finding(
            row.vdir, row.tc_id, row.algorithm, row.reason, lab.clause,
            list(row.violated), "attributed" if hit else "misattributed",
        ))
    return findings
