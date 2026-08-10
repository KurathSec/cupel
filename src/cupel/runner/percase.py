"""Per-case verdicts, so a kill can be told apart from a degeneracy.

The upstream harness reports one pass or fail for a whole vector file. That is
enough to say a mutant died and not enough to say why, and the difference
matters: deleting a check can only WIDEN acceptance, so a well-formed
check-deletion mutant must never break a case the standard says is valid. If it
does, the mutant is malformed and belongs nowhere near the numerator.

  kill witness       a case expected to be REJECTED is now accepted
  degeneracy witness a case expected to be ACCEPTED is now rejected

A mutant with a degeneracy witness is MALFORMED_MUTANT, not KILLED, however
loudly the suite failed.
"""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from ..targets import native

BINARIES = {
    "ML-DSA-44": "test/build/mldsa44/bin/acvp_mldsa44",
    "ML-DSA-65": "test/build/mldsa65/bin/acvp_mldsa65",
    "ML-DSA-87": "test/build/mldsa87/bin/acvp_mldsa87",
}


@dataclass
class CaseOutcome:
    tc_id: int
    param_set: str
    reason: str | None
    expected_pass: bool | None
    observed_pass: bool

    @property
    def correct(self) -> bool:
        return self.expected_pass is None or self.observed_pass == self.expected_pass


@dataclass
class FlipReport:
    kill_witnesses: list[dict] = field(default_factory=list)
    degeneracy_witnesses: list[dict] = field(default_factory=list)
    n_cases: int = 0

    @property
    def verdict(self) -> str:
        if self.degeneracy_witnesses:
            return "MALFORMED_MUTANT"
        return "KILLED" if self.kill_witnesses else "SURVIVED"

    def as_record(self) -> dict:
        return {
            "n_cases": self.n_cases,
            "verdict": self.verdict,
            "n_kill_witnesses": len(self.kill_witnesses),
            "n_degeneracy_witnesses": len(self.degeneracy_witnesses),
            "kill_witnesses": self.kill_witnesses[:12],
            "degeneracy_witnesses": self.degeneracy_witnesses[:12],
        }


def _sigver(binary: Path, case: dict) -> bool:
    """True when the implementation accepts. The driver exits non-zero on reject."""
    proc = subprocess.run(
        [str(binary), "sigVer",
         f"message={case.get('message', '')}",
         f"context={case.get('context', '')}",
         f"signature={case['signature']}",
         f"pk={case['pk']}"],
        capture_output=True, text=True,
    )
    return proc.returncode == 0


def run_sigver(target: str, doc: dict) -> list[CaseOutcome]:
    tree = native.tree(target)
    out = []
    for group in doc.get("testGroups", []):
        ps = group.get("parameterSet")
        rel = BINARIES.get(ps)
        if not rel:
            continue
        binary = tree / rel
        # The driver has three sigVer entry points: sigVer for the external
        # interface, sigVerPreHash for pre-hashed messages, and sigVerInternal
        # for the internal one. Only the first is implemented here; the others
        # are SKIPPED rather than invoked through the wrong door. Driving them
        # with the wrong argument list made eighteen valid cases look rejected
        # at baseline, which would have poisoned every mutant verdict computed
        # against it. The covered subset carries its own n.
        if group.get("externalMu"):
            continue
        if group.get("signatureInterface") != "external":
            continue
        if group.get("preHash") == "preHash":
            continue
        for test in group.get("tests", []):
            if not test.get("signature") or not test.get("pk"):
                continue
            out.append(CaseOutcome(
                tc_id=test.get("tcId", -1), param_set=ps,
                reason=test.get("reason"), expected_pass=test.get("testPassed"),
                observed_pass=_sigver(binary, test),
            ))
    return out


def compare(before: list[CaseOutcome], after: list[CaseOutcome]) -> FlipReport:
    """Which cases changed verdict, and in which direction."""
    rep = FlipReport(n_cases=len(before))
    idx = {c.tc_id: c for c in after}
    for b in before:
        a = idx.get(b.tc_id)
        if a is None or a.observed_pass == b.observed_pass:
            continue
        row = {"tc_id": b.tc_id, "param_set": b.param_set, "reason": b.reason,
               "expected_pass": b.expected_pass,
               "was": b.observed_pass, "now": a.observed_pass}
        if b.expected_pass is False and a.observed_pass:
            rep.kill_witnesses.append(row)
        elif b.expected_pass is True and not a.observed_pass:
            rep.degeneracy_witnesses.append(row)
        else:
            rep.degeneracy_witnesses.append(row | {"note": "unexpected direction"})
    return rep


def load_sigver(release: str, entries: dict) -> dict:
    from ..vectors import lock as lockmod
    from ..vectors import pins as pinsmod
    return json.loads(lockmod.ensure(
        release, pinsmod.vector_path("ML-DSA-sigVer-FIPS204", pinsmod.REASON_FILE), entries))
