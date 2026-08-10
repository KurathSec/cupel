"""The vector lock: what was fetched, from where, and what it hashed to.

`data/vectors/lock.toml` is committed; the blobs it names are not. Together with
data/pins.toml it makes a run reproducible from committed inputs alone, and it
makes upstream tampering visible: a pinned commit that returns different bytes
fails loudly instead of quietly changing a measurement.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from . import fetch as fetchmod
from . import pins as pinsmod

LOCK = pinsmod.REPO / "data" / "vectors" / "lock.toml"


@dataclass(frozen=True)
class Entry:
    release: str
    commit: str
    path: str
    digest: str
    n_bytes: int
    fetched_utc: str

    @property
    def key(self) -> tuple[str, str]:
        return (self.release, self.path)


def load(path: str | Path = LOCK) -> dict[tuple[str, str], Entry]:
    import tomllib

    p = Path(path)
    if not p.exists():
        return {}
    data = tomllib.loads(p.read_text(encoding="utf-8"))
    out = {}
    for row in data.get("entry", []):
        e = Entry(
            release=row["release"],
            commit=row["commit"],
            path=row["path"],
            digest=row["sha256"],
            n_bytes=row["bytes"],
            fetched_utc=row.get("fetched_utc", ""),
        )
        out[e.key] = e
    return out


def _toml_escape(s: str) -> str:
    return s.replace("\\", "\\\\").replace('"', '\\"')


def save(entries: dict[tuple[str, str], Entry], path: str | Path = LOCK) -> int:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "# Fetched upstream files, by pinned release. Generated, do not hand-edit.",
        "#",
        "# Blobs themselves are never committed. This file plus data/pins.toml",
        "# reproduces them, and the recorded hash proves what was run even if",
        "# upstream force-pushes or edits a file in place.",
        "#",
        "# Regenerate with:  python -m cupel vectors fetch",
        "",
    ]
    for key in sorted(entries):
        e = entries[key]
        lines += [
            "[[entry]]",
            f'release     = "{_toml_escape(e.release)}"',
            f'commit      = "{e.commit}"',
            f'path        = "{_toml_escape(e.path)}"',
            f'sha256      = "{e.digest}"',
            f"bytes       = {e.n_bytes}",
            f'fetched_utc = "{e.fetched_utc}"',
            "",
        ]
    p.write_text("\n".join(lines), encoding="utf-8", newline="\n")
    return len(entries)


def now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def ensure(release_id: str, path: str, entries: dict, repo: str | None = None) -> bytes:
    """Fetch one pinned file, verifying against the lock and recording it if new."""
    rel = pinsmod.release(release_id)
    repo = repo or pinsmod.acvp_repo()
    key = (release_id, path)
    known = entries.get(key)
    blob, data = fetchmod.fetch(repo, rel.commit, path, expect=known.digest if known else None)
    if known is None:
        entries[key] = Entry(
            release=release_id,
            commit=rel.commit,
            path=path,
            digest=blob.digest,
            n_bytes=blob.n_bytes,
            fetched_utc=now_utc(),
        )
    return data
