"""Canonical serialisation. The only bytes that are ever hashed.

Every record id computed from structured data is a sha256 over
`canonical_bytes(...)`, so a run computed on two machines gets the same id.

Raw blobs are different and are hashed by `sha256_bytes` over their actual
bytes, because a fetched file has to hash to what upstream serves. Canonicalising
it first would compare cupel's re-encoding rather than the artifact.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

_SEPARATORS = (",", ":")


def canonical_bytes(obj: Any) -> bytes:
    """Deterministic JSON encoding: sorted keys, no whitespace, UTF-8, LF."""
    return json.dumps(
        obj,
        sort_keys=True,
        separators=_SEPARATORS,
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def canonical_str(obj: Any) -> str:
    return canonical_bytes(obj).decode("utf-8")


def sha256_of(obj: Any) -> str:
    """Content hash of a JSON-serialisable object, prefixed with its algorithm."""
    return "sha256:" + hashlib.sha256(canonical_bytes(obj)).hexdigest()


def sha256_bytes(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def sha256_file(path, chunk: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        while block := fh.read(chunk):
            h.update(block)
    return "sha256:" + h.hexdigest()


def bare(digest: str) -> str:
    """Strip the `sha256:` prefix, for contexts that want the hex alone."""
    return digest.split(":", 1)[1] if ":" in digest else digest
