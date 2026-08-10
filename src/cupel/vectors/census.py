"""Corpus census: what is actually in the mandated vector set.

This is the first table of the paper and it is deliberately dumb: it counts,
it does not interpret. Two counts are kept separate on purpose.

  n_expected_fail    cases carrying testPassed = false
  n_labelled_negative cases whose `reason` is not a valid-case label

They are not the same. ML-KEM `decapsulation` cases carry a `reason` of
"modified ciphertext" but no `testPassed` at all, because the expected answer is
the implicit-rejection shared secret rather than a rejection. Collapsing the two
would either hide 45 negative cases or invent 45 expectations: 15 in
ML-KEM-encapDecap-FIPS203 and 30 in the tr1 set.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field

from . import lock as lockmod
from . import pins as pinsmod

# A case is a positive control when its label says so. NIST spells these out
# per algorithm rather than using a flag, so the prefixes are matched rather
# than guessed, and an unrecognised label is reported instead of assumed.
VALID_LABEL_PREFIXES = (
    "valid signature and message",
    "valid decapsulation",
    "valid encapsulation key",
)


def is_valid_label(reason: str) -> bool:
    return any(reason.startswith(p) for p in VALID_LABEL_PREFIXES)


@dataclass
class DirCensus:
    release: str
    dir: str
    algorithm: str
    mode: str
    n_groups: int = 0
    n_cases: int = 0
    n_expected_fail: int = 0
    n_expected_pass: int = 0
    n_no_expectation: int = 0
    n_labelled_negative: int = 0
    n_unlabelled: int = 0
    reasons: dict[str, int] = field(default_factory=dict)
    unknown_labels: list[str] = field(default_factory=list)
    functions: dict[str, int] = field(default_factory=dict)
    param_sets: list[str] = field(default_factory=list)

    @property
    def n_negative(self) -> int:
        """The count Table 1 quotes. Labelled-negative is the honest denominator
        for coverage questions, since it counts cases meant to be rejected
        whether or not the schema gives them a testPassed."""
        return self.n_labelled_negative

    def as_record(self) -> dict:
        return {
            "schema": "census/1",
            "release": self.release,
            "dir": self.dir,
            "algorithm": self.algorithm,
            "mode": self.mode,
            "n_groups": self.n_groups,
            "n_cases": self.n_cases,
            "n_negative": self.n_negative,
            "n_expected_fail": self.n_expected_fail,
            "n_expected_pass": self.n_expected_pass,
            "n_no_expectation": self.n_no_expectation,
            "n_labelled_negative": self.n_labelled_negative,
            "n_unlabelled": self.n_unlabelled,
            "n_distinct_reasons": len(self.reasons),
            "functions": self.functions,
            "param_sets": sorted(self.param_sets),
            "unknown_labels": sorted(set(self.unknown_labels)),
        }


def census_dir(release_id: str, vdir: pinsmod.VectorDir, entries: dict) -> DirCensus:
    """Count one vector directory at one pinned release."""
    ip_path = pinsmod.vector_path(vdir.dir, pinsmod.REASON_FILE)
    raw = lockmod.ensure(release_id, ip_path, entries)
    doc = json.loads(raw)

    c = DirCensus(release=release_id, dir=vdir.dir, algorithm=vdir.algorithm, mode=vdir.mode)
    param_sets: set[str] = set()
    for group in doc.get("testGroups", []):
        c.n_groups += 1
        fn = group.get("function")
        if fn:
            c.functions[fn] = c.functions.get(fn, 0) + len(group.get("tests", []))
        ps = group.get("parameterSet")
        if ps:
            param_sets.add(ps)
        for test in group.get("tests", []):
            c.n_cases += 1

            passed = test.get("testPassed")
            if passed is True:
                c.n_expected_pass += 1
            elif passed is False:
                c.n_expected_fail += 1
            else:
                c.n_no_expectation += 1

            reason = test.get("reason")
            if reason is None:
                c.n_unlabelled += 1
            else:
                c.reasons[reason] = c.reasons.get(reason, 0) + 1
                if not is_valid_label(reason):
                    c.n_labelled_negative += 1
    c.param_sets = sorted(param_sets)
    return c


def run(release_id: str, entries: dict) -> tuple[list[DirCensus], list[dict]]:
    """Census every pinned vector directory at one release."""
    censuses = [census_dir(release_id, vd, entries) for vd in pinsmod.vector_dirs()]
    histogram = []
    for c in censuses:
        for reason, n in sorted(c.reasons.items()):
            histogram.append(
                {
                    "schema": "reason/1",
                    "release": release_id,
                    "algorithm": c.algorithm,
                    "dir": c.dir,
                    "mode": c.mode,
                    "reason": reason,
                    "n": n,
                    "is_valid_label": is_valid_label(reason),
                }
            )
    return censuses, histogram
