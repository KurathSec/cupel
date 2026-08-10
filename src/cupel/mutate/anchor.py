"""Anchored source rewrites.

A mutation is specified as exact text to find and exact text to put in its place,
with the number of times the anchor must occur. If the count does not match, the
mutation is NOT_APPLICABLE and is recorded as such. It is never applied to a
best guess.

Line numbers were the obvious alternative and are the wrong one. They drift
silently when upstream edits anything above them, and a mutation applied three
lines off still compiles and still produces a verdict. For an instrument whose
headline is "this mutant survived", a silently misplaced mutation is the worst
available failure, because it looks exactly like a real result.
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from ..vectors.pins import REPO

MUTATIONS = REPO / "data" / "mutations"


@dataclass(frozen=True)
class Edit:
    path: str
    anchor: str
    replacement: str
    occurrences: int


@dataclass(frozen=True)
class Mutation:
    mutation_id: str
    clause_id: str
    target: str
    target_commit: str
    state: str
    cls: str
    intent: str
    kill_mode: str
    edits: tuple[Edit, ...]
    is_sentinel: bool
    prediction: str
    positive_must_pass: bool
    witness_labels: tuple[str, ...] = field(default=())


def load_for(target: str) -> list[Mutation]:
    out = []
    d = MUTATIONS / target
    if not d.exists():
        return out
    for p in sorted(d.glob("*.toml")):
        m = tomllib.loads(p.read_text(encoding="utf-8"))
        post = m.get("postcondition", {})
        out.append(Mutation(
            mutation_id=m["mutation_id"], clause_id=m["clause_id"], target=m["target"],
            target_commit=m["target_commit"], state=m.get("state", "located"),
            cls=m.get("class", ""), intent=m.get("intent", ""),
            kill_mode=m.get("kill_mode", ""),
            edits=tuple(Edit(e["path"], e["anchor"], e["replacement"], e.get("occurrences", 1))
                        for e in m.get("edit", [])),
            is_sentinel=bool(post.get("is_sentinel", False)),
            prediction=post.get("prediction", ""),
            positive_must_pass=bool(post.get("positive_vectors_must_pass", True)),
            witness_labels=tuple(post.get("witness_reason_labels", [])),
        ))
    return out


class AnchorMismatch(RuntimeError):
    pass


def check(mutation: Mutation, tree: Path) -> list[str]:
    """Verify every anchor occurs exactly as many times as declared. No build."""
    problems = []
    for e in mutation.edits:
        f = tree / e.path
        if not f.exists():
            problems.append(f"{e.path}: missing from the target tree")
            continue
        n = f.read_text(encoding="utf-8").count(e.anchor)
        if n != e.occurrences:
            problems.append(f"{e.path}: anchor occurs {n} times, expected {e.occurrences}")
    return problems


def apply(mutation: Mutation, tree: Path) -> dict[str, str]:
    """Apply, returning the original contents so the tree can be restored."""
    problems = check(mutation, tree)
    if problems:
        raise AnchorMismatch("; ".join(problems))
    originals = {}
    for e in mutation.edits:
        f = tree / e.path
        text = f.read_text(encoding="utf-8")
        originals[e.path] = text
        f.write_text(text.replace(e.anchor, e.replacement), encoding="utf-8")
    return originals


def restore(originals: dict[str, str], tree: Path) -> None:
    for path, text in originals.items():
        (tree / path).write_text(text, encoding="utf-8")


def render(mutation: Mutation, tree: Path) -> str:
    """The unified diff a reviewer would read, without applying anything."""
    import difflib

    chunks = []
    for e in mutation.edits:
        f = tree / e.path
        before = f.read_text(encoding="utf-8")
        after = before.replace(e.anchor, e.replacement)
        chunks.append("".join(difflib.unified_diff(
            before.splitlines(keepends=True), after.splitlines(keepends=True),
            fromfile=f"a/{e.path}", tofile=f"b/{e.path}", n=3,
        )))
    return "".join(chunks)
