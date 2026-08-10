"""Derivation D2: where an implementation actually rejects.

D1b enumerates what the specification defines and D3 what the generator can
produce. Neither says what a real implementation checks, and that is the third
corner: a clause nobody implements and a clause nobody tests are different
findings, and only an implementation census tells them apart.

The signal is deliberately mechanical rather than clever. Both native targets
signal rejection by returning a named error code, so every site that produces
one is a point at which the implementation refuses an input. Collecting them
with their enclosing function gives a census that was authored by someone else
for their own reasons, which is what makes it usable as an independent
derivation rather than as a restatement of D1b.

CBMC proof harnesses were considered as a signal and rejected. Both repositories
prove memory safety for arithmetic helpers and constant-time primitives as well
as for checks, so the harness list is dominated by things that are not clauses.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

# Match the error constant wherever it appears in a statement. Anchoring on
# `return` or `=` immediately before it missed every ternary rejection, which is
# exactly how ML-KEM spells its two input checks:
#     ret = mlk_ct_memcmp(...) ? MLK_ERR_INVALID_PK : 0;
# and so produced a census of zero sites for that target.
ERROR_RETURN = re.compile(r"\b(ML[KD]_ERR_[A-Z_]+)")

# Contract annotations restate the error codes a function may return. They are
# documentation of the site, not the site.
CONTRACT = re.compile(r"^\s*(?:ensures|requires|assigns|invariant|__CPROVER)")

# A doc comment naming an error code documents a site; it is not one. Eight of
# thirty-one rows were prose from /* ... */ blocks describing what a function
# returns, which made the implementation census count documentation as evidence
# that a check exists.
COMMENT_LINE = re.compile(r"^\s*(?:\*|/\*|//)")
FUNC_HEAD = re.compile(r"^[A-Za-z_][\w \t\*]*\b([a-z_][\w]*)\s*\([^;]*$")

# Sites that are not input rejection. A failed self-test or allocation is a
# runtime condition rather than a normative check on an input.
# Runtime conditions, not normative checks on an input. Allocation failure, a
# dead RNG, a failed pairwise consistency test and an exhausted signing loop all
# refuse to proceed, but none of them is a clause an input can violate.
NOT_A_CHECK = {
    "MLK_ERR_OUT_OF_MEMORY", "MLD_ERR_OUT_OF_MEMORY",
    "MLK_ERR_RNG_FAIL", "MLD_ERR_RNG_FAIL",
    "MLK_ERR_PCT_FAIL", "MLD_ERR_PCT_FAIL",
    "MLD_ERR_SIGNING_PAUSED", "MLD_ERR_SIGN_ATTEMPTS_EXHAUSTED",
}


@dataclass
class Site:
    target: str
    path: str
    line: int
    function: str
    error: str
    snippet: str
    context: str = ""

    def as_record(self) -> dict:
        return {
            "schema": "site/1",
            "derivation": "D2",
            "target": self.target,
            "source": {"path": self.path, "line": self.line},
            "function": self.function,
            "error_code": self.error,
            "snippet": self.snippet,
            "context": self.context,
        }


def scan_file(text: str, path: str, target: str) -> list[Site]:
    lines = text.splitlines()
    out, current = [], "?"
    for n, raw in enumerate(lines, 1):
        if not raw[:1].isspace() and (m := FUNC_HEAD.match(raw)):
            current = m.group(1)
        if CONTRACT.match(raw) or COMMENT_LINE.match(raw):
            continue
        for m in ERROR_RETURN.finditer(raw):
            code = m.group(1)
            if code in NOT_A_CHECK:
                continue
            if "#define" in raw or "typedef" in raw:
                continue
            # The error code sits on the `return` line; the condition that
            # decides it is above. Matching a clause on the return line alone
            # silently attributed three separable sub-clauses to none of them,
            # so the preceding lines travel with the site.
            before = " ".join(x.strip() for x in lines[max(0, n - 4):n - 1])
            out.append(Site(target=target, path=path, line=n, function=current,
                            error=code, snippet=raw.strip()[:100],
                            context=before[-300:]))
    return out


def scan_target(root: Path, target: str, subdir: str) -> list[Site]:
    out = []
    src = root / subdir
    if not src.exists():
        return out
    for f in sorted(src.rglob("*.c")):
        out += scan_file(f.read_text(encoding="utf-8", errors="replace"),
                         str(f.relative_to(root)), target)
    return out


def by_function(sites: list[Site]) -> dict[str, list[Site]]:
    out: dict[str, list[Site]] = {}
    for s in sites:
        out.setdefault(s.function, []).append(s)
    return out
