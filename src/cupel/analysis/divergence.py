"""Does the published generator produce the published vectors?

The two are pinned separately and can be compared. For each pinned release we
take the invalid encapsulation keys the corpus ships for the FIPS 203 section
7.2 check, and we measure two properties the generator's own source determines:
how long the key is against the standard length for its parameter set, and how
many of its coefficients lie outside the range ByteDecode is allowed to produce.
Alongside that we record the digest of the manipulator source at the same
commit.

A manipulator whose bytes never change, across a range of releases in which the
vectors it is supposed to produce change twice, did not produce them.

Nothing here executes the generator. The source is read for its digest and, in
one place, quoted; every quantity is measured from the vector data.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

# FIPS 203, Table 2. An encapsulation key is 384k bytes of ByteEncode(12) output
# followed by the 32-byte seed rho, and coefficients are integers modulo q.
Q = 3329
K_BY_PARAM_SET = {"ML-KEM-512": 2, "ML-KEM-768": 3, "ML-KEM-1024": 4}


def standard_ek_length(param_set: str) -> int:
    return 384 * K_BY_PARAM_SET[param_set] + 32


def decode12(body: bytes) -> list[int]:
    """ByteDecode(12) without the reduction modulo q.

    The reduction is exactly what is being tested for, so applying it here would
    destroy the measurement: a key whose coefficient is q+1 decodes to 1 under a
    reducing decoder and the violation disappears.
    """
    if len(body) % 3:
        raise ValueError(f"12-bit body must be a multiple of 3 bytes, got {len(body)}")
    out: list[int] = []
    for i in range(0, len(body), 3):
        word = body[i] | body[i + 1] << 8 | body[i + 2] << 16
        out.append(word & 0xFFF)
        out.append((word >> 12) & 0xFFF)
    return out


@dataclass
class KeyMeasurement:
    release: str
    param_set: str
    tc_id: int
    reason: str
    n_bytes: int
    standard_bytes: int
    n_coefficients: int
    out_of_range_indices: list[int] = field(default_factory=list)
    out_of_range_values: list[int] = field(default_factory=list)

    @property
    def length_delta(self) -> int:
        return self.n_bytes - self.standard_bytes

    def as_record(self) -> dict:
        return {
            "schema": "divergence-key/1",
            "release": self.release,
            "param_set": self.param_set,
            "tc_id": self.tc_id,
            "reason": self.reason,
            "n_bytes": self.n_bytes,
            "standard_bytes": self.standard_bytes,
            "length_delta": self.length_delta,
            "n_coefficients": self.n_coefficients,
            "n_out_of_range": len(self.out_of_range_indices),
            "out_of_range_indices": self.out_of_range_indices,
            "out_of_range_values": self.out_of_range_values,
        }


def measure_key(release: str, param_set: str, tc_id: int, reason: str,
                ek: bytes) -> KeyMeasurement:
    k = K_BY_PARAM_SET[param_set]
    # Only the first 384k bytes are the encoded polynomial vector. A key longer
    # than the standard carries whatever the producer appended after rho, and
    # decoding that as coefficients would invent violations that are not there.
    body = ek[: 384 * k]
    coeffs = decode12(body)
    bad = [(i, c) for i, c in enumerate(coeffs) if c >= Q]
    return KeyMeasurement(
        release=release, param_set=param_set, tc_id=tc_id, reason=reason,
        n_bytes=len(ek), standard_bytes=standard_ek_length(param_set),
        n_coefficients=len(coeffs),
        out_of_range_indices=[i for i, _ in bad],
        out_of_range_values=sorted({c for _, c in bad}),
    )


def measure_release(release: str, projection: dict) -> list[KeyMeasurement]:
    """Every negative encapsulationKeyCheck case in one release's tr1 set."""
    out = []
    for group in projection.get("testGroups", []):
        if group.get("function") != "encapsulationKeyCheck":
            continue
        param_set = group.get("parameterSet")
        if param_set not in K_BY_PARAM_SET:
            raise ValueError(f"unknown parameter set {param_set!r}")
        for test in group.get("tests", []):
            # testPassed is the corpus's own verdict field. A case it marks as
            # passing is a valid key and belongs in no measurement of what the
            # invalid ones look like.
            if test.get("testPassed"):
                continue
            out.append(measure_key(
                release, param_set, test.get("tcId", -1),
                test.get("reason", ""), bytes.fromhex(test["ek"]),
            ))
    return out


@dataclass
class SourceDigest:
    release: str
    commit: str
    path: str
    digest: str
    n_bytes: int

    def as_record(self) -> dict:
        return {
            "schema": "divergence-source/1",
            "release": self.release,
            "commit": self.commit,
            "path": self.path,
            "digest": self.digest,
            "n_bytes": self.n_bytes,
        }


def digest_source(release: str, commit: str, path: str, data: bytes) -> SourceDigest:
    return SourceDigest(release=release, commit=commit, path=path,
                        digest="sha256:" + hashlib.sha256(data).hexdigest(),
                        n_bytes=len(data))


def summarise(keys: list[KeyMeasurement],
              sources: list[SourceDigest]) -> list[dict]:
    """Per release: what the data looks like, and what the source was.

    The two halves are kept in one record because the finding is their
    disagreement, and separating them would let one be quoted without the other.
    """
    by_release: dict[str, list[KeyMeasurement]] = {}
    for k in keys:
        by_release.setdefault(k.release, []).append(k)

    src_by_release: dict[str, list[SourceDigest]] = {}
    for s in sources:
        src_by_release.setdefault(s.release, []).append(s)

    out = []
    for release in sorted(by_release):
        ks = by_release[release]
        deltas = sorted({k.length_delta for k in ks})
        n_bad = sorted({len(k.out_of_range_indices) for k in ks})
        values = sorted({v for k in ks for v in k.out_of_range_values})
        out.append({
            "schema": "divergence/1",
            "release": release,
            "n_invalid_keys": len(ks),
            "length_deltas": deltas,
            "wrong_length": [d for d in deltas if d != 0],
            "out_of_range_counts": n_bad,
            "out_of_range_values": values,
            "n_keys_with_no_violation": sum(
                1 for k in ks if k.length_delta == 0 and not k.out_of_range_indices),
            "sources": {s.path: s.digest for s in sorted(
                src_by_release.get(release, []), key=lambda s: s.path)},
        })
    return out


def unchanged_sources(sources: list[SourceDigest]) -> dict[str, list[str]]:
    """Source paths whose digest is identical across every release measured."""
    by_path: dict[str, set[str]] = {}
    for s in sources:
        by_path.setdefault(s.path, set()).add(s.digest)
    return {path: sorted(digests) for path, digests in sorted(by_path.items())
            if len(digests) == 1}
