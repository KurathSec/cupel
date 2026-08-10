"""Read data/pins.toml, the single source of truth for upstream state."""

from __future__ import annotations

import tomllib
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
PINS = REPO / "data" / "pins.toml"

# The only vector file that carries the `reason` label naming what a negative
# case is supposed to test. Everything else can be derived, so this one is
# read exactly once per pin, into the case index.
REASON_FILE = "internalProjection.json"
VECTOR_FILES = ("prompt.json", "expectedResults.json", "internalProjection.json", "registration.json")


@dataclass(frozen=True)
class Release:
    id: str
    commit: str
    committed: str
    subject: str
    note: str


@dataclass(frozen=True)
class VectorDir:
    dir: str
    algorithm: str
    mode: str
    note: str = ""


@lru_cache(maxsize=1)
def load(path: str | Path = PINS) -> dict:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"missing pins file: {p}")
    return tomllib.loads(p.read_text(encoding="utf-8"))


def acvp_repo(pins: dict | None = None) -> str:
    return (pins or load())["acvp_server"]["repo"]


def releases(pins: dict | None = None) -> list[Release]:
    data = (pins or load())["acvp_server"].get("releases", [])
    return [
        Release(
            id=r["id"],
            commit=r["commit"],
            committed=r.get("committed", ""),
            subject=r.get("subject", ""),
            note=r.get("note", ""),
        )
        for r in data
    ]


def release(release_id: str, pins: dict | None = None) -> Release:
    for r in releases(pins):
        if r.id == release_id:
            return r
    known = ", ".join(r.id for r in releases(pins))
    raise KeyError(f"unknown release {release_id!r}; pinned releases are: {known}")


def latest_release(pins: dict | None = None) -> Release:
    """The most recently committed pinned release, by date rather than by order."""
    rels = releases(pins)
    if not rels:
        raise KeyError("no ACVP releases are pinned")
    return max(rels, key=lambda r: r.committed)


def vector_dirs(pins: dict | None = None) -> list[VectorDir]:
    data = (pins or load())["acvp_server"].get("vector_dirs", [])
    return [
        VectorDir(dir=d["dir"], algorithm=d["algorithm"], mode=d["mode"], note=d.get("note", ""))
        for d in data
    ]


def disposition_files(pins: dict | None = None) -> list[str]:
    dt = (pins or load())["acvp_server"]["disposition_types"]
    return [f"{dt['base']}/{name}" for name in dt["files"]]


def manipulator_files(pins: dict | None = None) -> list[str]:
    """The producer sources, fetched per release rather than once.

    A disposition enum member names a failure mode. The manipulator is what
    builds it, so comparing the manipulator's bytes across a release boundary
    against the vectors that changed at that boundary is what decides whether
    the published source produced the published data.
    """
    mp = (pins or load())["acvp_server"].get("manipulators")
    if not mp:
        return []
    return [f"{mp['base']}/{name}" for name in mp["files"]]


def vector_path(vdir: str, filename: str) -> str:
    return f"gen-val/json-files/{vdir}/{filename}"
