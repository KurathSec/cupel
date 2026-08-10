#!/usr/bin/env python3
"""Fail if the repository contains forbidden vocabulary.

Two guarantees, both mechanical rather than remembered:

  1. No citation path into the author's separate double-anonymous submission.
     See `data/namecheck.toml` for the terms and the reason each one is listed.
  2. No em-dashes, anywhere, including commit messages.

Usage:
    bin/namecheck.py                     scan tracked files
    bin/namecheck.py --commits main..HEAD  also scan those commit messages
    bin/namecheck.py --paths dist/       scan a directory instead of git

Exit codes: 0 clean, 1 violations found, 2 could not run.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
CONFIG = REPO / "data" / "namecheck.toml"

# Extensions we treat as text. Anything else is skipped as binary.
TEXT_SUFFIXES = {
    ".py", ".md", ".toml", ".json", ".jsonl", ".yaml", ".yml", ".txt", ".cfg",
    ".ini", ".sh", ".c", ".h", ".cc", ".cpp", ".rs", ".go", ".csv", ".tex",
    ".cff", ".patch", ".diff", ".in", "",
}


@dataclass(frozen=True)
class Term:
    pattern: re.Pattern
    display: str
    reason: str


@dataclass(frozen=True)
class Hit:
    where: str
    line: int
    term: str
    reason: str
    excerpt: str


def load_terms(config: Path) -> tuple[list[Term], set[str]]:
    if not config.exists():
        print(f"namecheck: missing config {config}", file=sys.stderr)
        raise SystemExit(2)
    data = tomllib.loads(config.read_text(encoding="utf-8"))
    terms = []
    for entry in data.get("banned", []):
        raw = entry["term"]
        pattern = re.compile(raw if entry.get("regex") else re.escape(raw), re.IGNORECASE)
        terms.append(Term(pattern=pattern, display=raw, reason=entry.get("reason", "")))
    skip = set(data.get("skip", {}).get("paths", []))
    return terms, skip


def tracked_files() -> list[Path]:
    try:
        out = subprocess.run(
            ["git", "ls-files", "-z"],
            cwd=REPO, capture_output=True, check=True, text=True,
        ).stdout
    except (subprocess.CalledProcessError, FileNotFoundError) as exc:
        print(f"namecheck: cannot list tracked files: {exc}", file=sys.stderr)
        raise SystemExit(2)
    return [REPO / p for p in out.split("\0") if p]


def walk_files(root: Path) -> list[Path]:
    return [p for p in root.rglob("*") if p.is_file()]


def scan_text(text: str, where: str, terms: list[Term]) -> list[Hit]:
    hits = []
    for lineno, line in enumerate(text.splitlines(), 1):
        for term in terms:
            match = term.pattern.search(line)
            if match:
                excerpt = line.strip()
                if len(excerpt) > 120:
                    start = max(0, match.start() - 40)
                    excerpt = "..." + excerpt[start:start + 110] + "..."
                hits.append(Hit(where, lineno, term.display, term.reason, excerpt))
    return hits


def scan_files(paths: list[Path], terms: list[Term], skip: set[str]) -> list[Hit]:
    hits = []
    for path in paths:
        try:
            rel = str(path.relative_to(REPO))
        except ValueError:
            rel = str(path)
        if rel in skip:
            continue
        if path.suffix.lower() not in TEXT_SUFFIXES:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        hits.extend(scan_text(text, rel, terms))
    return hits


def scan_commits(rev_range: str, terms: list[Term]) -> list[Hit]:
    try:
        out = subprocess.run(
            ["git", "log", "--format=%H%x00%B%x01", rev_range],
            cwd=REPO, capture_output=True, check=True, text=True,
        ).stdout
    except subprocess.CalledProcessError as exc:
        print(f"namecheck: cannot read commits in {rev_range}: {exc}", file=sys.stderr)
        raise SystemExit(2)
    hits = []
    for record in out.split("\x01"):
        record = record.strip("\n")
        if not record or "\0" not in record:
            continue
        sha, message = record.split("\0", 1)
        hits.extend(scan_text(message, f"commit {sha[:12]}", terms))
    return hits


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--commits", metavar="RANGE", help="also scan commit messages in this range")
    ap.add_argument("--paths", metavar="DIR", help="scan a directory tree instead of tracked files")
    ap.add_argument("--config", default=str(CONFIG))
    args = ap.parse_args()

    terms, skip = load_terms(Path(args.config))

    if args.paths:
        root = Path(args.paths).resolve()
        if not root.exists():
            print(f"namecheck: no such path {root}", file=sys.stderr)
            return 2
        files, scope = walk_files(root), str(root)
    else:
        files, scope = tracked_files(), "tracked files"

    hits = scan_files(files, terms, skip)
    if args.commits:
        hits.extend(scan_commits(args.commits, terms))

    n_files = len([p for p in files if p.suffix.lower() in TEXT_SUFFIXES])
    if not hits:
        print(f"namecheck: clean. {len(terms)} terms checked over {n_files} text files in {scope}.")
        if args.commits:
            print(f"namecheck: commit messages in {args.commits} clean.")
        return 0

    print(f"namecheck: {len(hits)} violation(s).\n", file=sys.stderr)
    for hit in hits:
        print(f"  {hit.where}:{hit.line}: {hit.term!r}", file=sys.stderr)
        print(f"    reason: {hit.reason}", file=sys.stderr)
        print(f"    line:   {hit.excerpt}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
