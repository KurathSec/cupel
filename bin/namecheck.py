#!/usr/bin/env python3
"""Fail if the repository contains forbidden vocabulary.

Two guarantees, both mechanical rather than remembered:

  1. No citation path into a separate body of work.
  2. No em-dashes, anywhere, including commit messages.

The forbidden terms are held in `data/namecheck.toml` as sha256 digests rather
than as plaintext. The first version of this file listed them openly, each with
a reason explaining why it mattered, in a public repository. That made the
firewall into the leak it existed to prevent: a reader learned the terms, the
connection between them, and why they were sensitive.

What digests buy, stated honestly. They check exactly as well, and they remove
the reasons and the stated connection between the terms, which was the worst of
what leaked. They do NOT make the terms unrecoverable. The digests are unsalted
sha256 over short natural-language strings, so anyone who guesses a candidate
can confirm it, and an audit of this repository recovered half of them in about
a second from an ordinary word list. A salt would not help, since it would have
to ship here to be checkable. Treat this as raising the cost of reading the list,
and not as hiding it: the guarantee worth relying on is that the terms cannot
enter the repository, and that one is real.

Matching is over n-grams. Each line is split on non-word characters and
lowercased, then every 1-gram through n-gram is hashed and looked up, so a
multi-word or hyphenated term matches however it happens to be spelled or
spaced.

Usage:
    bin/namecheck.py                             scan tracked files
    bin/namecheck.py --commits main..HEAD        also scan those commit messages
    bin/namecheck.py --repo DIR --commits RANGE  scan another repository's log
    bin/namecheck.py --paths dist/               scan a directory instead of git

Exit codes: 0 clean, 1 violations found, 2 could not run.
"""

from __future__ import annotations

import argparse
import hashlib
import re
import subprocess
import sys
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
CONFIG = REPO / "data" / "namecheck.toml"

TOKEN = re.compile(r"[^\W_]+", re.UNICODE)

TEXT_SUFFIXES = {
    ".py", ".md", ".toml", ".json", ".jsonl", ".yaml", ".yml", ".txt", ".cfg",
    ".ini", ".sh", ".c", ".h", ".cc", ".cpp", ".rs", ".go", ".csv", ".tex",
    ".cff", ".patch", ".diff", ".in", "",
    # A bibliography is the canonical place a citation path would appear, so the
    # firewall must read one.
    ".bib", ".bbl", ".rst", ".org", ".adoc", ".xml", ".html", ".lock",
}


@dataclass(frozen=True)
class Rule:
    id: str
    pattern: re.Pattern
    note: str


@dataclass
class Config:
    digests: frozenset = frozenset()
    ngram_max: int = 3
    rules: list = field(default_factory=list)
    skip: frozenset = frozenset()

    @property
    def n_checks(self) -> int:
        return len(self.digests) + len(self.rules)


@dataclass(frozen=True)
class Hit:
    where: str
    line: int
    what: str
    note: str
    excerpt: str


def load_config(path: Path) -> Config:
    if not path.exists():
        print(f"namecheck: missing config {path}", file=sys.stderr)
        raise SystemExit(2)
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    rules = []
    for r in data.get("rule", []):
        pattern = (re.compile(r["regex"], re.IGNORECASE) if "regex" in r
                   else re.compile(re.escape(r["literal"])))
        rules.append(Rule(id=r.get("id", "?"), pattern=pattern, note=r.get("note", "")))
    return Config(
        digests=frozenset(data.get("digests", [])),
        ngram_max=int(data.get("ngram_max", 3)),
        rules=rules,
        skip=frozenset(data.get("skip", {}).get("paths", [])),
    )


def scan_text(text: str, where: str, cfg: Config) -> list[Hit]:
    hits = []
    for lineno, line in enumerate(text.splitlines(), 1):
        excerpt = line.strip()
        if len(excerpt) > 120:
            excerpt = excerpt[:117] + "..."

        tokens = [t.lower() for t in TOKEN.findall(line)]
        for size in range(1, cfg.ngram_max + 1):
            for i in range(len(tokens) - size + 1):
                gram = " ".join(tokens[i:i + size])
                if hashlib.sha256(gram.encode("utf-8")).hexdigest() in cfg.digests:
                    # The matched term is deliberately NOT printed. Printing it
                    # would put the plaintext back into logs and CI output,
                    # which is the leak this design removes. The location is
                    # enough to find and fix it.
                    hits.append(Hit(where, lineno, "forbidden term",
                                    "a registered term appears on this line; consult the "
                                    "local plaintext source to identify it", excerpt))

        for rule in cfg.rules:
            if rule.pattern.search(line):
                hits.append(Hit(where, lineno, rule.id, rule.note, excerpt))
    return hits


# Directories that are never part of the repository's own content, used when
# walking a tree that git cannot enumerate.
UNTRACKED_DIRS = {".git", "vendor", "paper", "dist", "build", "__pycache__",
                  ".pytest_cache", ".ruff_cache", ".venv", "venv", ".cache",
                  "cache", "scratch", ".eggs"}


def tracked_files(repo: Path) -> list[Path]:
    """Every file the repository considers its own.

    Falls back to walking the tree when git cannot enumerate it. A release
    tarball has no `.git`, so `git ls-files` exits 128 there and the scan used
    to abort with exit 2. That made three tests fail and this command unusable
    in exactly the artifact people download, while CI never noticed because
    actions/checkout leaves a work tree behind. A vocabulary firewall that only
    runs where the repository is a git checkout is not much of a firewall.
    """
    try:
        out = subprocess.run(["git", "ls-files", "-z"], cwd=repo,
                             capture_output=True, check=True, text=True).stdout
        return [repo / p for p in out.split("\0") if p]
    except FileNotFoundError:
        pass
    except subprocess.CalledProcessError:
        pass
    if not (repo / ".git").exists():
        out_files = []
        for path in sorted(repo.rglob("*")):
            if not path.is_file():
                continue
            if UNTRACKED_DIRS & set(path.relative_to(repo).parts):
                continue
            out_files.append(path)
        return out_files
    print("namecheck: cannot list tracked files in a git work tree", file=sys.stderr)
    raise SystemExit(2)


def scan_files(paths: list[Path], cfg: Config, scanned: list[str]) -> list[Hit]:
    hits = []
    for path in paths:
        try:
            rel = str(path.relative_to(REPO))
        except ValueError:
            rel = str(path)
        if rel in cfg.skip or path.suffix.lower() not in TEXT_SUFFIXES:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError) as exc:
            # A file the scanner cannot read is not a file it cleared.
            hits.append(Hit(rel, 0, "unreadable",
                            f"could not be scanned ({type(exc).__name__})", ""))
            continue
        scanned.append(rel)
        hits.extend(scan_text(text, rel, cfg))
    return hits


def scan_commits(rev_range: str, cfg: Config, repo: Path | None = None) -> list[Hit]:
    """Scan commit messages in a range.

    `repo` exists so the guarantee is testable: hardcoding the repository root
    meant a test could plant a commit elsewhere and silently scan this
    repository's history instead, which is a test that cannot fail.
    """
    try:
        out = subprocess.run(["git", "log", "--format=%H%x00%B%x01", rev_range],
                             cwd=repo or REPO, capture_output=True,
                             check=True, text=True).stdout
    except subprocess.CalledProcessError as exc:
        print(f"namecheck: cannot read commits in {rev_range}: {exc}", file=sys.stderr)
        raise SystemExit(2)
    hits = []
    for record in out.split("\x01"):
        record = record.strip("\n")
        if not record or "\0" not in record:
            continue
        sha, message = record.split("\0", 1)
        hits.extend(scan_text(message, f"commit {sha[:12]}", cfg))
    return hits


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--commits", metavar="RANGE")
    ap.add_argument("--paths", metavar="DIR")
    ap.add_argument("--repo", help="repository whose commit messages to scan")
    ap.add_argument("--config", default=str(CONFIG))
    args = ap.parse_args()

    cfg = load_config(Path(args.config))

    if args.paths:
        root = Path(args.paths).resolve()
        if not root.exists():
            print(f"namecheck: no such path {root}", file=sys.stderr)
            return 2
        files, scope = [p for p in root.rglob("*") if p.is_file()], str(root)
    else:
        files, scope = tracked_files(REPO), "tracked files"

    scanned: list[str] = []
    hits = scan_files(files, cfg, scanned)
    if args.commits:
        hits.extend(scan_commits(args.commits, cfg,
                                 Path(args.repo).resolve() if args.repo else None))

    if not hits:
        n_skipped = len(files) - len(scanned)
        print(f"namecheck: clean. {cfg.n_checks} checks over {len(scanned)} files "
              f"actually read in {scope}; {n_skipped} not scanned.")
        if args.commits:
            print(f"namecheck: commit messages in {args.commits} clean.")
        return 0

    print(f"namecheck: {len(hits)} violation(s).\n", file=sys.stderr)
    for hit in hits:
        print(f"  {hit.where}:{hit.line}: {hit.what}", file=sys.stderr)
        print(f"    {hit.note}", file=sys.stderr)
        if hit.excerpt:
            print(f"    line: {hit.excerpt}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
