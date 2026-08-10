"""FIPS 204 (ML-DSA) verification checks, each evaluated independently.

The clause this file exists for is the z infinity-norm bound in Algorithm 8
line 3. Two independent reporters have written publicly that deleting it from a
verifier causes no test vector to fail, one against Wycheproof and one against
ACVP. Neither measured it. This evaluates the predicate directly against every
case in the corpus, so the claim becomes a column in a table with its n.

Answering it does not require implementing verification. Whether a case
violates the z bound is a property of the signature bytes alone. What rejects
the case instead is a separate question, and the commitment hash comparison is
deliberately not implemented here rather than being approximated.
"""

from __future__ import annotations

from dataclasses import dataclass

from .base import Predicate, hexbytes

Q = 8380417


@dataclass(frozen=True)
class ParamSet:
    k: int
    ell: int
    gamma1: int
    gamma2: int
    tau: int
    eta: int
    omega: int
    lam: int          # lambda, the collision strength in bits

    @property
    def beta(self) -> int:
        return self.tau * self.eta

    @property
    def c_tilde_bytes(self) -> int:
        return self.lam // 4

    @property
    def z_bits(self) -> int:
        """BitPack width for z, whose coefficients lie in (-gamma1, gamma1]."""
        return (2 * self.gamma1 - 1).bit_length()

    @property
    def z_bytes(self) -> int:
        return self.ell * 32 * self.z_bits

    @property
    def hint_bytes(self) -> int:
        return self.omega + self.k

    @property
    def sig_bytes(self) -> int:
        return self.c_tilde_bytes + self.z_bytes + self.hint_bytes


# FIPS 204 Section 4, Table 1.
PARAMS = {
    "ML-DSA-44": ParamSet(k=4, ell=4, gamma1=1 << 17, gamma2=(Q - 1) // 88,
                          tau=39, eta=2, omega=80, lam=128),
    "ML-DSA-65": ParamSet(k=6, ell=5, gamma1=1 << 19, gamma2=(Q - 1) // 32,
                          tau=49, eta=4, omega=55, lam=192),
    "ML-DSA-87": ParamSet(k=8, ell=7, gamma1=1 << 19, gamma2=(Q - 1) // 32,
                          tau=60, eta=2, omega=75, lam=256),
}


def params_of(group: dict) -> ParamSet:
    ps = group.get("parameterSet")
    if ps not in PARAMS:
        raise ValueError(f"unknown parameter set {ps!r}")
    return PARAMS[ps]


def unpack_bits(data: bytes, width: int, count: int) -> list[int]:
    """Little-endian bit unpacking, as FIPS 204 BitPack stores coefficients."""
    out = []
    acc = 0
    nbits = 0
    idx = 0
    mask = (1 << width) - 1
    for _ in range(count):
        while nbits < width:
            if idx >= len(data):
                raise ValueError("ran out of bytes while unpacking")
            acc |= data[idx] << nbits
            nbits += 8
            idx += 1
        out.append(acc & mask)
        acc >>= width
        nbits -= width
    return out


def decode_z(sig: bytes, p: ParamSet) -> list[int]:
    """Recover the signed coefficients of z. FIPS 204 Algorithm 28, sigDecode."""
    start = p.c_tilde_bytes
    raw = sig[start: start + p.z_bytes]
    if len(raw) < p.z_bytes:
        raise ValueError("signature too short to contain z")
    coeffs = []
    per_poly = 32 * p.z_bits
    for i in range(p.ell):
        chunk = raw[i * per_poly:(i + 1) * per_poly]
        # BitPack stored gamma1 - coefficient, so invert to get the signed value.
        coeffs += [p.gamma1 - w for w in unpack_bits(chunk, p.z_bits, 256)]
    return coeffs


def hint_region(sig: bytes, p: ParamSet) -> bytes:
    start = p.c_tilde_bytes + p.z_bytes
    return sig[start: start + p.hint_bytes]


# ---------------------------------------------------------------------------
# predicates
# ---------------------------------------------------------------------------

def _sig_length(case, group):
    sig = hexbytes(case.get("signature"))
    if sig is None:
        return None
    return len(sig) != params_of(group).sig_bytes


def _z_inf_norm(case, group):
    """FIPS 204 Algorithm 8 line 3: the signature is valid only if the infinity
    norm of z is strictly below gamma1 - beta.

    Evaluated on whatever z can be decoded, independently of whether any other
    check would reject the signature first.
    """
    sig = hexbytes(case.get("signature"))
    if sig is None:
        return None
    p = params_of(group)
    if len(sig) != p.sig_bytes:
        return None
    bound = p.gamma1 - p.beta
    return any(abs(c) >= bound for c in decode_z(sig, p))


def _hint_weight(case, group):
    """FIPS 204 Algorithm 21 HintBitUnpack, the monotone tally and omega bound."""
    sig = hexbytes(case.get("signature"))
    if sig is None:
        return None
    p = params_of(group)
    if len(sig) != p.sig_bytes:
        return None
    y = hint_region(sig, p)
    index = 0
    for i in range(p.k):
        limit = y[p.omega + i]
        if limit < index or limit > p.omega:
            return True
        index = limit
    return False


def _hint_ordering(case, group):
    """HintBitUnpack: indices within a polynomial must strictly increase."""
    sig = hexbytes(case.get("signature"))
    if sig is None:
        return None
    p = params_of(group)
    if len(sig) != p.sig_bytes:
        return None
    y = hint_region(sig, p)
    index = 0
    for i in range(p.k):
        limit = y[p.omega + i]
        if limit < index or limit > p.omega:
            return None  # the tally clause governs this case, not this one
        for j in range(index, limit):
            if j > index and y[j] <= y[j - 1]:
                return True
        index = limit
    return False


def _hint_trailing_zeros(case, group):
    """HintBitUnpack: slots beyond the declared hints must all be zero."""
    sig = hexbytes(case.get("signature"))
    if sig is None:
        return None
    p = params_of(group)
    if len(sig) != p.sig_bytes:
        return None
    y = hint_region(sig, p)
    index = 0
    for i in range(p.k):
        limit = y[p.omega + i]
        if limit < index or limit > p.omega:
            return None
        index = limit
    return any(y[i] != 0 for i in range(index, p.omega))


PREDICATES = [
    Predicate(
        clause_id="fips204.alg08.sig-length",
        algorithm="ML-DSA", doc="FIPS-204", anchor="Section 7.2, Algorithm 28",
        title="signature is lambda/4 + 32*l*bitlen(2*gamma1-1) + omega + k bytes",
        fn=_sig_length,
    ),
    Predicate(
        clause_id="fips204.alg08.z-inf-norm",
        algorithm="ML-DSA", doc="FIPS-204", anchor="Section 7.2, Algorithm 8 line 3",
        title="infinity norm of z is below gamma1 - beta",
        fn=_z_inf_norm,
    ),
    Predicate(
        clause_id="fips204.alg21.hint-weight",
        algorithm="ML-DSA", doc="FIPS-204", anchor="Section 7.4, Algorithm 21",
        title="hint tally is monotone and at most omega",
        fn=_hint_weight,
    ),
    Predicate(
        clause_id="fips204.alg21.hint-ordering",
        algorithm="ML-DSA", doc="FIPS-204", anchor="Section 7.4, Algorithm 21",
        title="hint indices strictly increase within each polynomial",
        fn=_hint_ordering,
    ),
    Predicate(
        clause_id="fips204.alg21.hint-trailing-zeros",
        algorithm="ML-DSA", doc="FIPS-204", anchor="Section 7.4, Algorithm 21",
        title="hint slots beyond the declared count are zero",
        fn=_hint_trailing_zeros,
    ),
]

# Deliberately absent: the commitment hash comparison (Algorithm 8 line 4).
# Evaluating it requires the full verification path, and approximating it would
# make every attribution that depends on it unreliable. Cases whose label maps
# to it are reported as not-scored rather than being guessed at, and the
# mutation spine supplies the answer instead.
