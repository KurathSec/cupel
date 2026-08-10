"""Acquire pinned upstream files into a content-addressed cache.

Per-file HTTPS GET rather than a clone. The ACVP-Server clone is about 1.19 GiB
against roughly 191 MiB of PQC vector payload, and a sparse checkout still pulls
history that nothing here reads.

Blobs are never committed. `data/vectors/lock.toml` plus the pinned commit
reproduce them, and the recorded hash proves what was actually run even if
upstream force-pushes or a file is edited in place.

Set CUPEL_OFFLINE=1 to turn any cache miss into a hard failure rather than a
network call, so a run can be shown to have used only committed inputs.
"""

from __future__ import annotations

import os
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path

from ..util.canonical import sha256_bytes

RAW = "https://raw.githubusercontent.com/{repo}/{commit}/{path}"

# Courtesy pacing. raw.githubusercontent is generous but this project fetches
# a few hundred files across several pinned states and there is no reason to
# burst.
_MIN_INTERVAL_S = 0.15
_RETRIES = 4
_BACKOFF_S = 2.0

_last_request = 0.0


class OfflineMiss(RuntimeError):
    """CUPEL_OFFLINE=1 was set and the blob was not already cached."""


class HashMismatch(RuntimeError):
    """A fetched blob did not match the hash recorded in the lock."""


def offline() -> bool:
    return os.environ.get("CUPEL_OFFLINE", "") not in ("", "0")


def cache_root() -> Path:
    base = os.environ.get("CUPEL_CACHE") or os.environ.get("XDG_CACHE_HOME")
    root = Path(base) if base else Path.home() / ".cache"
    if not base or "cupel" not in str(root):
        root = root / "cupel"
    return root


def blob_path(digest: str) -> Path:
    """Content-addressed location. Two-level fanout keeps directories small."""
    hexd = digest.split(":", 1)[-1]
    return cache_root() / "blobs" / "sha256" / hexd[:2] / hexd[2:]


def cached(digest: str) -> bytes | None:
    p = blob_path(digest)
    if p.exists():
        data = p.read_bytes()
        # Re-verify on read. A corrupted cache is worse than a cold one because
        # it is silent, and the whole point of this project is not being silent.
        if sha256_bytes(data) == digest:
            return data
        p.unlink()
    return None


def store(data: bytes) -> str:
    digest = sha256_bytes(data)
    p = blob_path(digest)
    p.parent.mkdir(parents=True, exist_ok=True)
    if not p.exists():
        tmp = p.with_suffix(".partial")
        tmp.write_bytes(data)
        tmp.replace(p)
    return digest


def raw_url(repo: str, commit: str, path: str) -> str:
    return RAW.format(repo=repo, commit=commit, path=path.lstrip("/"))


def _get(url: str) -> bytes:
    global _last_request
    last_error: Exception | None = None
    for attempt in range(_RETRIES):
        gap = time.monotonic() - _last_request
        if gap < _MIN_INTERVAL_S:
            time.sleep(_MIN_INTERVAL_S - gap)
        _last_request = time.monotonic()
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "cupel"})
            with urllib.request.urlopen(req, timeout=120) as resp:
                return resp.read()
        except urllib.error.HTTPError as exc:
            if exc.code in (403, 429, 500, 502, 503, 504) and attempt < _RETRIES - 1:
                last_error = exc
                time.sleep(_BACKOFF_S * (2 ** attempt))
                continue
            raise
        except (urllib.error.URLError, TimeoutError) as exc:
            last_error = exc
            if attempt < _RETRIES - 1:
                time.sleep(_BACKOFF_S * (2 ** attempt))
                continue
            raise
    raise RuntimeError(f"exhausted retries for {url}: {last_error}")


@dataclass(frozen=True)
class Blob:
    repo: str
    commit: str
    path: str
    digest: str
    n_bytes: int
    from_cache: bool

    @property
    def url(self) -> str:
        return raw_url(self.repo, self.commit, self.path)


def fetch(repo: str, commit: str, path: str, expect: str | None = None) -> tuple[Blob, bytes]:
    """Fetch one pinned file. Returns its blob record and its bytes.

    `expect` is the digest recorded in the lock. When given, a mismatch is a
    hard failure: it means upstream content changed under a commit that is
    supposed to be immutable, which is a finding rather than a retry.
    """
    if expect:
        hit = cached(expect)
        if hit is not None:
            return Blob(repo, commit, path, expect, len(hit), True), hit

    if offline():
        raise OfflineMiss(
            f"CUPEL_OFFLINE=1 and {repo}@{commit[:12]}:{path} is not cached"
            + (f" (expected {expect})" if expect else "")
        )

    url = raw_url(repo, commit, path)
    data = _get(url)
    digest = store(data)

    if expect and digest != expect:
        raise HashMismatch(
            f"{url}\n  lock records {expect}\n  fetched       {digest}\n"
            "  A pinned commit returned different bytes. Do not update the lock "
            "without establishing why."
        )
    return Blob(repo, commit, path, digest, len(data), False), data
