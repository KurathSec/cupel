"""Derivation D1: the clause list, from cryptol-specs docstrings.

The denominator is the half of this measurement most easily attacked. A fraction
whose denominator is one person's judgement is not a measurement, so N is
derived from an executable specification maintained by someone else, with each
clause carrying the document section it came from.

Three properties make it auditable:

  * Every clause cites a `[FIPS-20x] Section ..., Algorithm ...` tag that exists
    in a pinned file, so a reviewer can look it up.
  * Tags that do not match the strict form are only accepted if a numbered
    source repair in `data/clauses/overlay/source_repairs.toml` covers them.
    Upstream has real typos, and absorbing them silently would let N drift.
    Better still, when upstream FIXES one the repair stops matching and
    extraction fails rather than quietly shifting the count.
  * Scope is decided by numbered rules, and a clause with no rule is an error
    rather than a default. The boundary is a judgement; the point is to make it
    explicit, numbered and countable instead of implicit.

Cryptol is not required and must not be installed. The provenance lives in
comment text.
"""

from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from ..util.canonical import sha256_bytes
from ..vectors.pins import REPO

OVERLAY = REPO / "data" / "clauses" / "overlay"
REPAIRS = OVERLAY / "source_repairs.toml"

# A clause citation is a tag followed by a LOCATOR. Surveying both pinned files
# turns up five locator keywords in use plus two non-citation forms, so the set
# is enumerated rather than guessed:
#
#   Section 4.2.1 / Appendix A / Introduction / Algorithm 9 / Equation 4.7
#
# Two forms are deliberately NOT clause citations. A tag followed by a colon is
# the module header's bibliography entry naming the document itself, and a bare
# tag with no locator points at the standard as a whole. Both are real and both
# would inflate N if counted.
LOCATOR = r"(?:Section|Sec\.?|Appendix|Introduction|Algorithm|Equation|Table|Figure)"

TAG_STRICT = re.compile(
    r"\[FIPS-(203|204|205)\]\s*,?\s*"
    r"(" + LOCATOR + r")"
    r"\s*,?\s*([0-9]+(?:\.[0-9]+)*|[A-Z]\b)?"
    r"(?:\s*,?\s*(Algorithm|Equation|Table|Figure)\s*([0-9]+(?:\.[0-9]+)?))?",
    re.IGNORECASE,
)

# The bibliography form, excluded before the loose check so it is not mistaken
# for a malformed citation.
TAG_BIBLIOGRAPHY = re.compile(r"\[FIPS-(?:203|204|205)\]\s*:")

# Loose form, for finding tags that are malformed rather than absent. Every hit
# here that is neither strict nor bibliography must be covered by a repair.
TAG_LOOSE = re.compile(r"\[\s*FIPS[\s-]?([0-9]{1,3})\s*\]", re.IGNORECASE)

DOCSTRING = re.compile(r"/\*\*(.*?)\*/", re.DOTALL)

# What the docstring attaches to. Order matters: a type signature and a binding
# both start with an identifier, so signatures are recognised first.
DEF_PATTERNS = [
    ("property", re.compile(r"^\s*property\s+([A-Za-z_][\w']*)")),
    ("type", re.compile(r"^\s*type\s+([A-Za-z_][\w']*)")),
    ("module", re.compile(r"^\s*(?:module|submodule|import|parameter)\b")),
    ("signature", re.compile(r"^\s*([A-Za-z_][\w']*)\s*:(?!=)")),
    ("binding", re.compile(r"^\s*([A-Za-z_][\w']*)[\w\s',\[\]]*=")),
]


@dataclass(frozen=True)
class Repair:
    id: str
    path: str
    lines: tuple[int, ...]
    observed: str
    corrected: str
    evidence: str


def load_repairs(path: Path = REPAIRS) -> list[Repair]:
    if not path.exists():
        return []
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    return [
        Repair(
            id=r["id"], path=r["path"], lines=tuple(r.get("lines", [])),
            observed=r["observed"], corrected=r["corrected"], evidence=r.get("evidence", ""),
        )
        for r in data.get("repair", [])
    ]


@dataclass
class Clause:
    clause_id: str
    doc: str
    section: str
    kind: str            # Algorithm | Equation | Table | Figure | ""
    number: str
    definition: str
    definition_kind: str
    scope: str           # top-level | local
    path: str
    line_start: int
    line_end: int
    tag_raw: str
    tag_tier: str        # strict | repaired
    repair_id: str | None
    statement: str
    surface: str | None = None
    surface_rule: str | None = None
    notes: list[str] = field(default_factory=list)

    def as_record(self) -> dict:
        return {
            "schema": "clause/1",
            "derivation": "D1",
            "clause_id": self.clause_id,
            "doc": self.doc,
            "section": self.section,
            "citation_kind": self.kind,
            "citation_number": self.number,
            "definition": self.definition,
            "definition_kind": self.definition_kind,
            "scope": self.scope,
            "source": {"path": self.path, "line_start": self.line_start,
                       "line_end": self.line_end},
            "tag": {"raw": self.tag_raw, "tier": self.tag_tier, "repair_id": self.repair_id},
            "statement_sha256": sha256_bytes(self.statement.encode("utf-8")),
            "surface": self.surface,
            "surface_rule": self.surface_rule,
            "notes": self.notes,
        }


class StaleRepair(RuntimeError):
    """A declared repair no longer matches the pinned source."""


def _attach(text: str, pos: int) -> tuple[str, str]:
    """Find the definition a docstring precedes."""
    for raw in text[pos:].splitlines():
        line = raw.strip()
        if not line or line.startswith("//"):
            continue
        if line.startswith("/**"):
            return ("", "orphan")
        for kind, pat in DEF_PATTERNS:
            m = pat.match(raw)
            if m:
                return (m.group(1) if m.groups() else "", kind)
        return ("", "unrecognised")
    return ("", "eof")


def extract(source: str, path: str, doc_hint: str,
            repairs: list[Repair]) -> tuple[list[Clause], dict]:
    """Pull every provenance-tagged docstring out of one .cry file."""
    lines = source.splitlines()

    def line_of(offset: int) -> int:
        return source.count("\n", 0, offset) + 1

    applicable = [r for r in repairs if r.path == path]
    for r in applicable:
        if r.observed not in source:
            raise StaleRepair(
                f"{r.id}: {r.observed!r} no longer appears in {path}. Upstream may have "
                "fixed it. Remove the repair and re-derive rather than leaving N to drift."
            )

    clauses, stats = [], {
        "n_docstrings": 0, "n_attached": 0, "n_tagged": 0,
        "n_strict": 0, "n_repaired": 0, "n_untagged": 0, "n_orphan": 0,
        "n_bibliography": 0,
    }
    for m in DOCSTRING.finditer(source):
        stats["n_docstrings"] += 1
        body = m.group(1)
        definition, def_kind = _attach(source, m.end())
        if def_kind in ("orphan", "eof"):
            stats["n_orphan"] += 1
            continue
        if def_kind == "module":
            continue
        stats["n_attached"] += 1

        repaired_body, used_repair = body, None
        for r in applicable:
            if r.observed in body:
                repaired_body = repaired_body.replace(r.observed, r.corrected)
                used_repair = r.id

        if TAG_BIBLIOGRAPHY.search(repaired_body):
            stats["n_bibliography"] = stats.get("n_bibliography", 0) + 1
            continue

        hit = TAG_STRICT.search(repaired_body)
        if not hit:
            if TAG_LOOSE.search(body):
                raise StaleRepair(
                    f"{path}:{line_of(m.start())}: a FIPS-like tag is present but does not "
                    f"parse and no source repair covers it: {body.strip()[:120]!r}"
                )
            stats["n_untagged"] += 1
            continue

        tier = "repaired" if used_repair else "strict"
        stats["n_tagged"] += 1
        stats["n_repaired" if used_repair else "n_strict"] += 1

        doc = f"FIPS-{hit.group(1)}"
        locator, locnum = hit.group(2), (hit.group(3) or "")
        kind = (hit.group(4) or "")
        number = (hit.group(5) or "")
        if not kind and locator.lower().startswith(("algorithm", "equation", "table", "figure")):
            kind, number = locator, locnum
            section = ""
        else:
            section = locnum
        indent = len(lines[line_of(m.start()) - 1]) - len(lines[line_of(m.start()) - 1].lstrip())
        anchor = number or section
        clauses.append(Clause(
            clause_id=f"{doc.lower().replace('-', '')}.{(kind or 'sec').lower()}{anchor}.{definition}",
            doc=doc, section=section, kind=kind, number=number,
            definition=definition, definition_kind=def_kind,
            scope="local" if indent > 0 else "top-level",
            path=path, line_start=line_of(m.start()), line_end=line_of(m.end()),
            tag_raw=hit.group(0), tag_tier=tier, repair_id=used_repair,
            statement=" ".join(x.strip(" *") for x in body.splitlines() if x.strip(" *")),
        ))
    return clauses, stats


# ---------------------------------------------------------------------------
# scope classification
# ---------------------------------------------------------------------------

SCOPE_RULES = OVERLAY / "scope_rules.toml"


def load_scope_rules(path: Path = SCOPE_RULES) -> list[dict]:
    if not path.exists():
        return []
    return tomllib.loads(path.read_text(encoding="utf-8")).get("rule", [])


def classify(clauses: list[Clause], rules: list[dict]) -> dict:
    """Apply the automatic rules. Anything they do not settle stays unclassified.

    The automatic rules are deliberately conservative: they only fire on
    structural facts that need no reading of the clause text. Everything else is
    left for a recorded decision, and `bin/regen.py` refuses to print a fraction
    while any clause is unclassified. That is the honest position, since the
    boundary is a judgement and the point is to make it countable rather than
    invisible.
    """
    auto = {r["id"]: r for r in rules if r.get("mode") == "auto"}
    counts: dict[str, int] = {}
    for c in clauses:
        rule = None
        if "SCOPE-05" in auto and c.scope == "local":
            rule = "SCOPE-05"
        elif "SCOPE-09" in auto and c.definition_kind == "property":
            rule = "SCOPE-09"
        elif "SCOPE-10" in auto and c.kind in ("Table", "Equation"):
            rule = "SCOPE-10"
        if rule:
            c.surface_rule = rule
            c.surface = "out_of_scope" if auto[rule]["verdict"] == "out" else "api_boundary_checkable"
            counts[rule] = counts.get(rule, 0) + 1
        else:
            counts["UNCLASSIFIED"] = counts.get("UNCLASSIFIED", 0) + 1
    return counts
