"""JSONL read and write, canonical on the way out."""

from __future__ import annotations

import gzip
import json
from pathlib import Path
from typing import Any, Iterable, Iterator

from .canonical import canonical_str


def _open_read(path: Path):
    if str(path).endswith(".gz"):
        return gzip.open(path, "rt", encoding="utf-8")
    return open(path, "r", encoding="utf-8")


def _open_write(path: Path, append: bool = False):
    mode = "at" if append else "wt"
    if str(path).endswith(".gz"):
        return gzip.open(path, mode, encoding="utf-8")
    return open(path, mode, encoding="utf-8", newline="\n")


def read(path: str | Path) -> Iterator[dict]:
    path = Path(path)
    if not path.exists():
        return
    with _open_read(path) as fh:
        for lineno, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}:{lineno}: malformed JSONL: {exc}") from exc


def write(path: str | Path, rows: Iterable[Any], append: bool = False) -> int:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    n = 0
    with _open_write(path, append=append) as fh:
        for row in rows:
            fh.write(canonical_str(row))
            fh.write("\n")
            n += 1
    return n


def count(path: str | Path) -> int:
    return sum(1 for _ in read(path))
