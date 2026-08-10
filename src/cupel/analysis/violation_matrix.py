"""Build V[case][clause] and run the three joins over it.

The matrix is the instrument. Each row is a test case, each column a normative
clause, each cell says whether that case violates that clause, evaluated with
no short-circuiting. From it:

  zero column      no case in the corpus violates the clause. Nothing that
                   deletes this check can be caught. A surviving mutant is
                   guaranteed without compiling anything.

  masked column    the clause is violated, but never alone. Every case that
                   violates it also violates something else, and whether the
                   check is reached depends on the implementation's ordering.
                   This is ACVP-Server #460.

  misattribution   the case's own `reason` label names a clause the case does
                   not violate. The vector cannot fail for the reason it
                   claims. This is ACVP-Server #462.

Only the first is a statement about the vector set alone. The second is a
statement about the vector set that becomes a statement about an implementation
once check ordering is known, which is what the mutation spine supplies.

WHAT A COVERED COLUMN DOES AND DOES NOT PREDICT
-----------------------------------------------
An ABSENT column is decisive: no case violates the clause, so nothing that
deletes the check can be caught, and the mutant survives necessarily.

A COVERED column is NOT decisive in the other direction, and assuming it was
produced a wrong prediction here. `fips204.alg21.hint-trailing-zeros` shows 20
isolated violations at r2026-07-31, so deleting the check was predicted to be
caught. The mutant survived.

The reason is that "isolated" means isolated among the clauses this battery
MODELS, and the FIPS 204 commitment hash is deliberately not modelled because
computing it needs the whole verification path. That check is a universal
backstop for signature verification: any perturbation of a signature changes w1
and therefore changes c-tilde, so every malformed-signature case is rejected by
it regardless of which structural clause is deleted upstream. Removing the
trailing-zeros check does not make those 20 cases verify; it just moves where
they are rejected.

So the matrix predicts survival soundly and predicts death only conditionally.
A clause whose violations are all subsumed by a downstream check cannot be
exercised in the sense that matters, however many cases violate it, and the
mutation is what settles that. The two disagreeing is the instrument working,
not the instrument breaking.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..predicates import mldsa as mldsa_predicates
from ..predicates import slhdsa as slhdsa_predicates
from ..predicates import mlkem as mlkem_predicates
from ..util.na import Rate

BATTERIES = {
    "ML-KEM": mlkem_predicates.PREDICATES,
    "ML-DSA": mldsa_predicates.PREDICATES,
    "SLH-DSA": slhdsa_predicates.PREDICATES,
}


@dataclass
class Row:
    vdir: str
    tg_id: int
    tc_id: int
    algorithm: str
    mode: str
    function: str
    param_set: str
    reason: str | None
    expected: bool | None
    violated: list[str] = field(default_factory=list)
    not_applicable: list[str] = field(default_factory=list)

    @property
    def n_violated(self) -> int:
        return len(self.violated)

    def as_record(self) -> dict:
        return {
            "schema": "violation/1",
            "dir": self.vdir,
            "tg_id": self.tg_id,
            "tc_id": self.tc_id,
            "algorithm": self.algorithm,
            "mode": self.mode,
            "function": self.function,
            "param_set": self.param_set,
            "reason": self.reason,
            "expected_pass": self.expected,
            "violated": sorted(self.violated),
            "n_violated": self.n_violated,
            "n_not_applicable": len(self.not_applicable),
        }


def build(doc: dict, vdir: str, algorithm: str, mode: str) -> list[Row]:
    battery = BATTERIES.get(algorithm)
    if battery is None:
        return []
    rows = []
    for group in doc.get("testGroups", []):
        for test in group.get("tests", []):
            row = Row(
                vdir=vdir,
                tg_id=group.get("tgId", -1),
                tc_id=test.get("tcId", -1),
                algorithm=algorithm,
                mode=mode,
                function=group.get("function", "") or "",
                param_set=group.get("parameterSet", "") or "",
                reason=test.get("reason"),
                expected=test.get("testPassed"),
            )
            for pred in battery:
                verdict = pred(test, group)
                if verdict is None:
                    row.not_applicable.append(pred.clause_id)
                elif verdict:
                    row.violated.append(pred.clause_id)
            rows.append(row)
    return rows


# ---------------------------------------------------------------------------
# joins
# ---------------------------------------------------------------------------

@dataclass
class ColumnSummary:
    clause_id: str
    n_applicable: int = 0
    n_violating: int = 0
    n_isolated: int = 0
    co_violated_with: dict[str, int] = field(default_factory=dict)

    @property
    def status(self) -> str:
        if self.n_violating == 0:
            return "ABSENT"
        if self.n_isolated == 0:
            return "MASKED"
        return "COVERED"

    def as_record(self) -> dict:
        return {
            "schema": "column/1",
            "clause_id": self.clause_id,
            "status": self.status,
            "n_applicable": self.n_applicable,
            "n_violating": self.n_violating,
            "n_isolated": self.n_isolated,
            "co_violated_with": self.co_violated_with,
        }


def columns(rows: list[Row], clause_ids: list[str]) -> list[ColumnSummary]:
    out = {cid: ColumnSummary(cid) for cid in clause_ids}
    for row in rows:
        violated = set(row.violated)
        for cid in clause_ids:
            col = out[cid]
            if cid in row.not_applicable:
                continue
            col.n_applicable += 1
            if cid not in violated:
                continue
            col.n_violating += 1
            others = violated - {cid}
            if not others:
                col.n_isolated += 1
            for other in others:
                col.co_violated_with[other] = col.co_violated_with.get(other, 0) + 1
    return [out[cid] for cid in clause_ids]


def coverage(cols: list[ColumnSummary]) -> Rate:
    """Clauses a negative case can actually exercise in isolation."""
    return Rate(
        sum(1 for c in cols if c.status == "COVERED"),
        len(cols),
        "clauses exercised in isolation",
    )
