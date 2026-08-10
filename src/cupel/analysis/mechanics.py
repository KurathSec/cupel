"""What a disposition can detect, as opposed to what its label says it detects.

The violation matrix answers "did any case in this corpus violate this clause".
This module answers the stronger question: "can the mechanism that produces
these cases violate this clause at all, and how often".

The difference matters because it decides what the finding is about. An empty
column is a fact about a particular vector file, and a reviewer can reasonably
ask whether a production file with more cases would fill it. A deterministic
perturbation of bounded magnitude is a fact about the generator's source, and
sample size cannot argue with it.

The worked case is ML-DSA ModifyZ. Its label names the z infinity-norm bound.
Its implementation flips bit 2*lambda + 1 of the signature, which lands one bit
past c_tilde and therefore alters the first z coefficient by plus or minus 64.
The bound is gamma1 - beta. So the case violates the clause it is labelled for
only when that single coefficient already lies within 64 of the bound, which is
a window of about 1.2e-4 to 4.9e-4 of the coefficient range. The disposition is
not failing to cover the clause by accident. It cannot cover it except by
coincidence.
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from ..predicates import mldsa as M
from ..util.na import Rate
from ..vectors.pins import REPO

MECHANISMS = REPO / "data" / "mechanisms.toml"


@dataclass(frozen=True)
class Mechanism:
    id: str
    algorithm: str
    disposition: str
    label: str
    claims_clause: str
    source: str
    expression: str
    kind: str
    deterministic: bool
    bit_index_expr: str
    bit_order: str
    note: str
    verify: dict


def load(path: str | Path = MECHANISMS) -> list[Mechanism]:
    data = tomllib.loads(Path(path).read_text(encoding="utf-8"))
    return [
        Mechanism(
            id=m["id"], algorithm=m["algorithm"], disposition=m["disposition"],
            label=m["label"], claims_clause=m.get("claims_clause", ""),
            source=m["source"], expression=m["expression"], kind=m["kind"],
            deterministic=bool(m.get("deterministic", False)),
            bit_index_expr=m.get("bit_index_expr", ""),
            bit_order=m.get("bit_order", "msb_first"),
            note=m.get("note", ""), verify=m.get("verify", {}),
        )
        for m in data.get("mechanism", [])
    ]


def flip_bit(data: bytes, index: int, order: str = "msb_first") -> bytes:
    out = bytearray(data)
    if order == "msb_first":
        out[index // 8] ^= 0x80 >> (index % 8)
    else:
        out[index // 8] ^= 1 << (index % 8)
    return bytes(out)


def zbit_index(p: M.ParamSet) -> int:
    """The literal expression from the generator: (Lambda * 2) + 1."""
    return 2 * p.lam + 1


@dataclass
class Reach:
    """Whether a mechanism can breach the clause it claims, over a corpus."""

    mechanism_id: str
    param_set: str
    n_cases: int = 0
    n_could_breach: int = 0
    n_coeffs_changed: set[int] = field(default_factory=set)
    deltas: set[int] = field(default_factory=set)
    min_headroom: int | None = None
    window: int = 0
    coeff_range: int = 0

    @property
    def rate(self) -> Rate:
        return Rate(self.n_could_breach, self.n_cases, f"{self.mechanism_id} {self.param_set}")

    @property
    def window_fraction(self) -> float | None:
        if not self.coeff_range:
            return None
        return self.window / self.coeff_range

    def as_record(self) -> dict:
        return {
            "schema": "mechanism/1",
            "mechanism_id": self.mechanism_id,
            "param_set": self.param_set,
            "n_cases": self.n_cases,
            "n_could_breach": self.n_could_breach,
            "coeffs_changed": sorted(self.n_coeffs_changed),
            "abs_deltas": sorted({abs(d) for d in self.deltas}),
            "min_headroom": self.min_headroom,
            "window": self.window,
            "coeff_range": self.coeff_range,
            "window_fraction": self.window_fraction,
        }


def analyse_modify_z(cases: list[tuple[str, bytes]], mech: Mechanism) -> dict[str, Reach]:
    """Measure ModifyZ against every signature in the corpus.

    Two things are established per parameter set. First, the transcription: the
    flip must alter exactly the number of coefficients and by the magnitude the
    mechanism record claims, or the record is wrong and this fails. Second, the
    reach: how many signatures sit close enough to the bound that the
    perturbation could carry them over it.

    Every signature is used, not only the ones labelled ModifyZ, because the
    question is what the mechanism could do to any signature the generator might
    perturb, not what it happened to do to thirty-six of them.
    """
    out: dict[str, Reach] = {}
    for param_set, sig in cases:
        p = M.PARAMS.get(param_set)
        if p is None or len(sig) != p.sig_bytes:
            continue
        r = out.setdefault(param_set, Reach(mech.id, param_set))
        bit = zbit_index(p)
        z0 = M.decode_z(sig, p)
        z1 = M.decode_z(flip_bit(sig, bit, mech.bit_order), p)
        changed = [i for i, (a, b) in enumerate(zip(z0, z1)) if a != b]
        r.n_cases += 1
        r.n_coeffs_changed.add(len(changed))
        for i in changed:
            r.deltas.add(z1[i] - z0[i])

        bound = p.gamma1 - p.beta
        delta = max((abs(z1[i] - z0[i]) for i in changed), default=0)
        r.window = 2 * delta
        r.coeff_range = 2 * p.gamma1
        # Could a perturbation of this magnitude, on the coefficient this
        # mechanism reaches, carry the signature past the bound?
        touched = changed[0] if changed else 0
        c0 = z0[touched]
        headroom = bound - max(abs(c0 + delta), abs(c0 - delta))
        if headroom <= 0:
            r.n_could_breach += 1
        r.min_headroom = headroom if r.min_headroom is None else min(r.min_headroom, headroom)
    return out


def verify_transcription(reach: Reach, mech: Mechanism) -> list[str]:
    """The record claims what the code does. Check it against the corpus."""
    problems = []
    want_coeffs = mech.verify.get("coeffs_changed")
    if want_coeffs is not None and reach.n_coeffs_changed != {want_coeffs}:
        problems.append(
            f"{reach.param_set}: record says {want_coeffs} coefficient(s) change, "
            f"corpus shows {sorted(reach.n_coeffs_changed)}"
        )
    want_delta = mech.verify.get("abs_delta")
    if want_delta is not None:
        seen = {abs(d) for d in reach.deltas}
        if seen != {want_delta}:
            problems.append(
                f"{reach.param_set}: record says magnitude {want_delta}, corpus shows {sorted(seen)}"
            )
    return problems
