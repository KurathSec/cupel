"""FIPS 203 (ML-KEM) normative checks, each evaluated independently.

Clause anchors cite FIPS 203 sections. The two input-validation clauses named
by the standard are the encapsulation key check (Section 7.2) and the
decapsulation key check (Section 7.3), and each decomposes into a type or
length part and a substantive part. Keeping those parts separate is the whole
point: the length part is what masked the modulus part in ACVP-Server #460.
"""

from __future__ import annotations

import hashlib

from .base import Predicate, bits12, hexbytes

Q = 3329

# k, and the derived byte lengths, per parameter set. FIPS 203 Section 8.
PARAMS = {
    "ML-KEM-512": 2,
    "ML-KEM-768": 3,
    "ML-KEM-1024": 4,
}


def k_of(group: dict) -> int:
    ps = group.get("parameterSet")
    if ps not in PARAMS:
        raise ValueError(f"unknown parameter set {ps!r}")
    return PARAMS[ps]


def ek_len(k: int) -> int:
    return 384 * k + 32


def dk_len(k: int) -> int:
    return 768 * k + 96


def ct_len(k: int) -> int:
    du, dv = (10, 4) if k in (2, 3) else (11, 5)
    return 32 * (du * k + dv)


# ---------------------------------------------------------------------------
# Encapsulation key
# ---------------------------------------------------------------------------

def _ek_length(case, group):
    ek = hexbytes(case.get("ek"))
    if ek is None:
        return None
    return len(ek) != ek_len(k_of(group))


def _ek_modulus(case, group):
    """FIPS 203 Section 7.2, the modulus check.

    The standard states it as a re-encoding round trip: ByteEncode_12 applied to
    ByteDecode_12(ek) must reproduce ek. That holds exactly when every packed
    12-bit field is already less than q, since ByteDecode_12 reduces mod q.
    Testing the coefficients directly is the same predicate and says why it
    failed.

    Note this is evaluated even when the length is wrong, on whatever whole
    coefficients are present. That is deliberate: asking whether a malformed key
    would ALSO have failed the modulus check is exactly the question #460 turned
    on, and short-circuiting on length is what hid the answer for a year.
    """
    ek = hexbytes(case.get("ek"))
    if ek is None:
        return None
    k = k_of(group)
    body = ek[: 384 * k]
    if len(body) < 3:
        return None
    return any(c >= Q for c in bits12(body))


# ---------------------------------------------------------------------------
# Decapsulation key
# ---------------------------------------------------------------------------

def _dk_length(case, group):
    dk = hexbytes(case.get("dk"))
    if dk is None:
        return None
    return len(dk) != dk_len(k_of(group))


def _dk_hash(case, group):
    """FIPS 203 Section 7.3, the hash check.

    dk = dk_PKE || ek || H(ek) || z, so the embedded digest sits at
    dk[768k+32 : 768k+64] and the encapsulation key it must digest is
    dk[384k : 768k+32].
    """
    dk = hexbytes(case.get("dk"))
    if dk is None:
        return None
    k = k_of(group)
    if len(dk) < dk_len(k):
        return None
    ek = dk[384 * k: 768 * k + 32]
    embedded = dk[768 * k + 32: 768 * k + 64]
    return hashlib.sha3_256(ek).digest() != embedded


def _dk_embedded_ek_modulus(case, group):
    """The encapsulation key embedded inside dk must itself satisfy the modulus
    check. FIPS 203 requires the pair to be consistent, and a dk carrying an
    out-of-range embedded ek is not a valid decapsulation key.
    """
    dk = hexbytes(case.get("dk"))
    if dk is None:
        return None
    k = k_of(group)
    if len(dk) < 768 * k + 32:
        return None
    return any(c >= Q for c in bits12(dk[384 * k: 768 * k]))


def _ct_length(case, group):
    c = hexbytes(case.get("c"))
    if c is None:
        return None
    return len(c) != ct_len(k_of(group))


PREDICATES = [
    Predicate(
        clause_id="fips203.s7.2.ek-length",
        algorithm="ML-KEM", doc="FIPS-203", anchor="Section 7.2, encapsulation input check 1",
        title="encapsulation key is 384k + 32 bytes",
        fn=_ek_length,
    ),
    Predicate(
        clause_id="fips203.s7.2.ek-modulus",
        algorithm="ML-KEM", doc="FIPS-203", anchor="Section 7.2, encapsulation input check 2",
        title="encapsulation key re-encodes, so every coefficient is below q",
        fn=_ek_modulus,
    ),
    Predicate(
        clause_id="fips203.s7.3.dk-length",
        algorithm="ML-KEM", doc="FIPS-203", anchor="Section 7.3, decapsulation input check 2",
        title="decapsulation key is 768k + 96 bytes",
        fn=_dk_length,
    ),
    Predicate(
        clause_id="fips203.s7.3.dk-hash",
        algorithm="ML-KEM", doc="FIPS-203", anchor="Section 7.3, decapsulation input check 3",
        title="hash embedded in the decapsulation key matches H(ek)",
        fn=_dk_hash,
    ),
    Predicate(
        clause_id="fips203.s7.3.dk-embedded-ek-modulus",
        algorithm="ML-KEM", doc="FIPS-203", anchor="Section 7.3, consistency of the embedded key",
        title="encapsulation key embedded in dk has every coefficient below q",
        fn=_dk_embedded_ek_modulus,
    ),
    Predicate(
        clause_id="fips203.s7.3.ct-length",
        algorithm="ML-KEM", doc="FIPS-203", anchor="Section 7.3, decapsulation input check 1",
        title="ciphertext is 32(du*k + dv) bytes",
        fn=_ct_length,
    ),
]
