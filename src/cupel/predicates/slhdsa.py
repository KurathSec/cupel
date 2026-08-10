"""FIPS 205 (SLH-DSA) verification checks.

SLH-DSA verification has very little that is separately checkable at the API
boundary. Algorithm 20 checks the signature length, then recomputes the FORS
public key and the hypertree root and compares against PK.root. That is close to
the whole of it.

Which makes the disposition set interesting. Six negative labels ship, and four
of them (modified message, modified signature R, SIGFORS, SIGHT) can only ever
be caught by the same root comparison. Distinct labels do not imply distinct
clauses, and here four of six collapse onto one.

The root comparison is deliberately not implemented. It needs WOTS+, FORS, XMSS
and the hypertree, and an approximation of it would silently corrupt every
attribution that depends on it. Cases whose label maps to it are reported as
not-scored. The length clause is implemented exactly, and it is the only clause
in this algorithm any vector can isolate.
"""

from __future__ import annotations

import math
from dataclasses import dataclass

from .base import Predicate, hexbytes


@dataclass(frozen=True)
class ParamSet:
    n: int
    h: int
    d: int
    hp: int   # h'
    a: int
    k: int
    lg_w: int
    m: int

    @property
    def w(self) -> int:
        return 1 << self.lg_w

    @property
    def len1(self) -> int:
        return math.ceil(8 * self.n / self.lg_w)

    @property
    def len2(self) -> int:
        return math.floor(math.log2(self.len1 * (self.w - 1)) / self.lg_w) + 1

    @property
    def wots_len(self) -> int:
        return self.len1 + self.len2

    @property
    def sig_bytes(self) -> int:
        """FIPS 205: |SIG| = (1 + k(1 + a) + h + d*len) * n."""
        return (1 + self.k * (1 + self.a) + self.h + self.d * self.wots_len) * self.n

    @property
    def pk_bytes(self) -> int:
        return 2 * self.n

    # Signature layout, as byte offsets: R, then SIG_FORS, then SIG_HT.
    @property
    def r_bytes(self) -> int:
        return self.n

    @property
    def sig_fors_bytes(self) -> int:
        return self.k * (1 + self.a) * self.n

    @property
    def sig_ht_bytes(self) -> int:
        return (self.h + self.d * self.wots_len) * self.n


# FIPS 205 Table 2. The SHAKE sets take the same structural parameters as their
# SHA2 counterparts, so they are generated rather than repeated.
_BASE = {
    "128s": ParamSet(n=16, h=63, d=7, hp=9, a=12, k=14, lg_w=4, m=30),
    "128f": ParamSet(n=16, h=66, d=22, hp=3, a=6, k=33, lg_w=4, m=34),
    "192s": ParamSet(n=24, h=63, d=7, hp=9, a=14, k=17, lg_w=4, m=39),
    "192f": ParamSet(n=24, h=66, d=22, hp=3, a=8, k=33, lg_w=4, m=42),
    "256s": ParamSet(n=32, h=64, d=8, hp=8, a=14, k=22, lg_w=4, m=47),
    "256f": ParamSet(n=32, h=68, d=17, hp=4, a=9, k=35, lg_w=4, m=49),
}

PARAMS = {
    f"SLH-DSA-{fam}-{size}": ps
    for size, ps in _BASE.items()
    for fam in ("SHA2", "SHAKE")
}


def params_of(group: dict) -> ParamSet:
    ps = group.get("parameterSet")
    if ps not in PARAMS:
        raise ValueError(f"unknown parameter set {ps!r}")
    return PARAMS[ps]


def _sig_length(case, group):
    """FIPS 205 Algorithm 20 line 1: the signature must be exactly |SIG| bytes."""
    sig = hexbytes(case.get("signature"))
    if sig is None:
        return None
    return len(sig) != params_of(group).sig_bytes


def _pk_length(case, group):
    """SP 800-89 key validation: the public key is 2n bytes.

    Deliberately NOT anchored to Algorithm 20. FIPS 205 Section 3.1 states that
    where public-key validation is required, implementations shall verify the
    public key is 2n bytes. That is a key-validation obligation, not part of the
    signature verification path, and citing it as Algorithm 20 would overstate
    what that algorithm mandates.
    """
    pk = hexbytes(case.get("pk"))
    if pk is None:
        return None
    return len(pk) != params_of(group).pk_bytes


def _ctx_length(case, group):
    """FIPS 205 Algorithms 24 and 25 line 1: reject when |ctx| > 255.

    External signature interface only. The internal interface takes no context,
    so the clause does not apply there rather than being satisfied by it.
    """
    if group.get("signatureInterface") == "internal":
        return None
    ctx = case.get("context")
    if ctx is None:
        return None
    return len(ctx) // 2 > 255


PREDICATES = [
    Predicate(
        clause_id="fips205.alg20.sig-length",
        algorithm="SLH-DSA", doc="FIPS-205", anchor="Section 10.3, Algorithm 20 line 1",
        title="signature is exactly (1 + k(1+a) + h + d*len) * n bytes",
        fn=_sig_length,
    ),
    Predicate(
        clause_id="fips205.s3.1.pk-length",
        algorithm="SLH-DSA", doc="FIPS-205", anchor="Section 3.1, key checks (SP 800-89)",
        title="public key is 2n bytes",
        fn=_pk_length,
    ),
    Predicate(
        clause_id="fips205.alg24.ctx-length",
        algorithm="SLH-DSA", doc="FIPS-205", anchor="Section 10.2, Algorithms 24 and 25 line 1",
        title="context string is at most 255 bytes",
        fn=_ctx_length,
    ),
]

# Not implemented, deliberately: fips205.alg20.root-compare. It requires the full
# WOTS+/FORS/XMSS/hypertree recomputation, and four of the six negative
# dispositions map onto it, so an approximation would corrupt two thirds of the
# attributions rather than a corner of them.
