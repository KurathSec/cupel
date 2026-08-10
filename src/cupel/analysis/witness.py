"""Construct an input that violates exactly one clause.

An ABSENT column says no case in the corpus violates the clause, so a mutant
deleting that check survives. A reviewer's next question is whether the check is
deletable because it is unreachable, in which case the mutant is equivalent and
the finding is empty. The answer is an input, not an argument.

Two ways to build one, and the cheap one covers most of them:

  direct       take a valid case and perturb it minimally so that exactly one
               clause is violated. Length clauses fall out immediately: truncate
               or extend a valid encoding by one byte and nothing else changes.

  dual mutant  for clauses no direct edit can isolate, strip the corresponding
               bound from the PRODUCER and let it emit the input as a matter of
               course. That is how the z infinity-norm witness was built, since
               forging a signature with oversized z and a correct commitment
               hash is not something one can do by editing bytes.

Every witness is checked against the full predicate battery before it counts. A
candidate that violates two clauses is not a witness for either, and one that
violates none is a bug in the constructor.
"""

from __future__ import annotations

import pathlib
from dataclasses import dataclass, field
from typing import Callable

from ..predicates import mldsa as mldsa_p
from ..predicates import mlkem as mlkem_p
from ..predicates import slhdsa as slhdsa_p
from ..vectors.pins import REPO

# Artifacts are written under the repository root, never relative to the
# process working directory. A run that shells into a vendored tree leaves cwd
# there, and a relative path then writes the artifact inside vendor/, which is
# gitignored. That happened to the z-norm witness: the commit claimed an
# artifact the repository did not contain.
WITNESS_DIR = REPO / "witness"


def witness_path(name: str) -> "pathlib.Path":
    WITNESS_DIR.mkdir(parents=True, exist_ok=True)
    return WITNESS_DIR / name

BATTERIES = {
    "ML-KEM": mlkem_p.PREDICATES,
    "ML-DSA": mldsa_p.PREDICATES,
    "SLH-DSA": slhdsa_p.PREDICATES,
}


@dataclass
class Witness:
    clause_id: str
    algorithm: str
    param_set: str
    field_name: str
    method: str
    derived_from: str
    case: dict
    group: dict
    violates: list[str] = field(default_factory=list)

    @property
    def isolates(self) -> bool:
        return self.violates == [self.clause_id]

    def as_record(self) -> dict:
        return {
            "schema": "witness/2",
            "clause_id": self.clause_id,
            "algorithm": self.algorithm,
            "param_set": self.param_set,
            "field": self.field_name,
            "method": self.method,
            "derived_from": self.derived_from,
            "violates": sorted(self.violates),
            "isolates_clause": self.isolates,
            "case": self.case,
        }


def evaluate(case: dict, group: dict, algorithm: str) -> list[str]:
    """Which clauses does this input violate, evaluated independently."""
    return [p.clause_id for p in BATTERIES[algorithm] if p(case, group) is True]


# ---------------------------------------------------------------------------
# direct constructors
# ---------------------------------------------------------------------------

def _truncate(hexstr: str) -> str:
    return hexstr[:-2]


def _extend(hexstr: str) -> str:
    return hexstr + "aa"


# clause -> (field it perturbs, how)
DIRECT: dict[str, tuple[str, str, Callable[[str], str]]] = {
    "fips203.s7.2.ek-length": ("ek", "truncate one byte", _truncate),
    "fips203.s7.3.dk-length": ("dk", "truncate one byte", _truncate),
    "fips203.s7.3.ct-length": ("c", "truncate one byte", _truncate),
    "fips204.alg08.sig-length": ("signature", "truncate one byte", _truncate),
    "fips205.s3.1.pk-length": ("pk", "extend one byte", _extend),
}


def construct_direct(clause_id: str, case: dict, group: dict,
                     algorithm: str, source: str) -> Witness | None:
    """Perturb one field of a valid case so exactly this clause is violated."""
    spec = DIRECT.get(clause_id)
    if spec is None:
        return None
    field_name, method, fn = spec
    if not case.get(field_name):
        return None
    built = dict(case)
    built[field_name] = fn(case[field_name])
    w = Witness(clause_id=clause_id, algorithm=algorithm,
                param_set=group.get("parameterSet", ""), field_name=field_name,
                method=method, derived_from=source, case=built, group=group)
    w.violates = evaluate(built, group, algorithm)
    return w


def construct_hint_weight(case: dict, group: dict, source: str) -> Witness | None:
    """Declare more hints than omega permits.

    FIPS 204 Algorithm 21 rejects when the running tally exceeds omega. The
    tally lives in the last k bytes of the signature, so setting the final one
    above omega violates the weight bound. The hint indices themselves are left
    alone, so the ordering and trailing-zero sub-clauses are unaffected.
    """
    sig = case.get("signature")
    if not sig:
        return None
    p = mldsa_p.params_of(group)
    raw = bytearray(bytes.fromhex(sig))
    if len(raw) != p.sig_bytes:
        return None
    raw[-1] = p.omega + 1
    built = dict(case)
    built["signature"] = raw.hex()
    w = Witness(clause_id="fips204.alg15.hint-weight", algorithm="ML-DSA",
                param_set=group.get("parameterSet", ""), field_name="signature",
                method="set the hint tally above omega", derived_from=source,
                case=built, group=group)
    w.violates = evaluate(built, group, "ML-DSA")
    return w


def construct_dk_embedded_modulus(case: dict, group: dict, source: str) -> Witness | None:
    """Raise one coefficient of the encapsulation key embedded inside dk.

    The embedded key must satisfy the modulus check, and the hash check covers
    the same bytes, so this necessarily violates both. It is recorded as a
    non-isolating candidate rather than suppressed, because the fact that the
    clause CANNOT be isolated is itself the finding: no input violates it alone.
    """
    dk = case.get("dk")
    if not dk:
        return None
    k = mlkem_p.k_of(group)
    raw = bytearray(bytes.fromhex(dk))
    # 12-bit field zero of the embedded key, set to q, which is out of range.
    off = 384 * k
    raw[off] = 0x01
    raw[off + 1] = (raw[off + 1] & 0xF0) | 0x0D     # 0x0D01 = 3329 = q
    built = dict(case)
    built["dk"] = raw.hex()
    w = Witness(clause_id="fips203.s7.3.dk-embedded-ek-modulus", algorithm="ML-KEM",
                param_set=group.get("parameterSet", ""), field_name="dk",
                method="raise embedded coefficient to q", derived_from=source,
                case=built, group=group)
    w.violates = evaluate(built, group, "ML-KEM")
    return w
