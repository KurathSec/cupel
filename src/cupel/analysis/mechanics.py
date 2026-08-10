"""Where a disposition's perturbation actually lands, resolved from source.

A disposition label is a claim about which normative check a case exercises. The
code realising it is public, and in every case examined it is a deterministic
perturbation at a computed index. So the claim is checkable without running the
generator: resolve the index to a byte offset, see which region of the artifact
it falls in, and compare that against the clause the label names.

The whole difficulty is the index convention, and getting it wrong is not a
hypothetical. ACVP-Server issue #462 was exactly that mistake made by the
generator's own author, and this module got it wrong too on first writing, by
assuming MSB-first ordering and then "verifying" the assumption against
arithmetic that could not contradict it. Flipping any bit in the z region alters
exactly one coefficient, so finding that it did confirmed nothing.

The convention is documented and is resolved here from source rather than
assumed:

    BitString(byte[] msBytes)
        _bits = MostSignificantByteArrayToLeastSignificantBitArray(msBytes)

    MostSignificantByteArrayToLeastSignificantBitArray(msBytes)
        leastSignificantByteArray = ReverseByteOrder(msBytes)
        return new BitArray(leastSignificantByteArray)

and the BitString.Bits property carries the comment "In LSb". So the byte order
is reversed and .NET's BitArray then indexes LSb-first within each byte:

    Bits[i]  ==  bit (i mod 8), counted from the least significant bit,
                 of original byte (n_bytes - 1 - i div 8)

Everything below follows from that one mapping.
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass
from pathlib import Path

from ..predicates import mldsa as M
from ..vectors.pins import REPO

MECHANISMS = REPO / "data" / "mechanisms.toml"


@dataclass(frozen=True)
class BitTarget:
    """A BitString bit index resolved against a concrete artifact length."""

    bit_index: int
    n_bytes: int
    byte_offset: int
    mask: int

    @property
    def describes(self) -> str:
        return f"byte {self.byte_offset} of {self.n_bytes}, XOR 0x{self.mask:02x}"


def resolve_lsb(bit_index: int, n_bytes: int) -> BitTarget:
    """Map a BitString.Bits index onto the original byte array.

    Byte order is reversed before the BitArray is built, so index i addresses
    the byte that many positions from the END of the artifact.
    """
    byte_offset = n_bytes - 1 - (bit_index // 8)
    return BitTarget(bit_index, n_bytes, byte_offset, 1 << (bit_index % 8))


def resolve_msb(bit_index: int, n_bytes: int) -> BitTarget:
    """The convention this module wrongly assumed at first. Kept so the
    comparison can be shown rather than asserted."""
    return BitTarget(bit_index, n_bytes, bit_index // 8, 0x80 >> (bit_index % 8))


@dataclass(frozen=True)
class Region:
    name: str
    start: int
    end: int

    def contains(self, offset: int) -> bool:
        return self.start <= offset < self.end


def mldsa_regions(p: M.ParamSet) -> list[Region]:
    """FIPS 204 signature layout: c_tilde, then z, then the hint block."""
    a = p.c_tilde_bytes
    b = a + p.z_bytes
    return [
        Region("c_tilde", 0, a),
        Region("z", a, b),
        Region("hint", b, b + p.hint_bytes),
    ]


def region_of(offset: int, regions: list[Region]) -> str:
    for r in regions:
        if r.contains(offset):
            return r.name
    return "out_of_range"


def flip(data: bytes, target: BitTarget) -> bytes:
    out = bytearray(data)
    out[target.byte_offset] ^= target.mask
    return bytes(out)


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
            bit_order=m.get("bit_order", "lsb"),
            note=m.get("note", ""), verify=m.get("verify", {}),
        )
        for m in data.get("mechanism", [])
    ]


# The index expressions, transcribed from the grain source. Each is a function
# of the parameter set, matching the C# literally.
MLDSA_BIT_INDEX = {
    "ModifyZ": lambda p: 2 * p.lam + 1,          # var zBit = (Lambda * 2) + 1
    "ModifyHint": lambda p: 0,                    # Bits.Set(0, ...)
    "ModifySignature": lambda p: 8 * p.sig_bytes - 1,   # Bits.Count - 1
}


@dataclass
class Landing:
    """Where a mechanism's perturbation lands, per parameter set."""

    mechanism_id: str
    param_set: str
    bit_index: int
    lsb_offset: int
    lsb_region: str
    lsb_slot: int | None
    msb_offset: int
    msb_region: str
    claims_clause: str
    reaches_claim: bool

    def as_record(self) -> dict:
        return {
            "schema": "landing/1",
            "mechanism_id": self.mechanism_id,
            "param_set": self.param_set,
            "bit_index": self.bit_index,
            "byte_offset": self.lsb_offset,
            "region": self.lsb_region,
            "slot_within_region": self.lsb_slot,
            "claims_clause": self.claims_clause,
            "reaches_claimed_region": self.reaches_claim,
            "msb_would_be_offset": self.msb_offset,
            "msb_would_be_region": self.msb_region,
        }


# Which signature region a clause is decided by. A perturbation that never
# touches the region cannot make its clause fire.
CLAUSE_REGION = {
    "fips204.alg08.z-inf-norm": "z",
    "fips204.alg15.hint-decode": "hint",
    "fips204.alg15.hint-weight": "hint",
    "fips204.alg15.hint-ordering": "hint",
    "fips204.alg15.hint-trailing-zeros": "hint",
    # The commitment hash is computed over the whole signature, so any region
    # reaches it. That is why it absorbs every perturbation that fails to hit
    # the clause its label names.
    "fips204.alg08.commitment-hash": "*",
}


def land_mldsa(mech: Mechanism) -> list[Landing]:
    expr = MLDSA_BIT_INDEX.get(mech.disposition)
    if expr is None:
        return []
    out = []
    for name, p in sorted(M.PARAMS.items()):
        idx = expr(p)
        regions = mldsa_regions(p)
        lsb = resolve_lsb(idx, p.sig_bytes)
        msb = resolve_msb(idx, p.sig_bytes)
        lsb_region = region_of(lsb.byte_offset, regions)
        want = CLAUSE_REGION.get(mech.claims_clause, "?")
        slot = None
        for r in regions:
            if r.name == lsb_region:
                slot = lsb.byte_offset - r.start
        out.append(Landing(
            mechanism_id=mech.id, param_set=name, bit_index=idx,
            lsb_offset=lsb.byte_offset, lsb_region=lsb_region, lsb_slot=slot,
            msb_offset=msb.byte_offset, msb_region=region_of(msb.byte_offset, regions),
            claims_clause=mech.claims_clause,
            reaches_claim=(want == "*" or want == lsb_region),
        ))
    return out
