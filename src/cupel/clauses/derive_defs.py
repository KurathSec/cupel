"""Derivation D1b: candidate clauses from definitions, not from tags.

D1 took the clause set from provenance tags and that was wrong. KT3 caught it:
`encapsulationKeyCheck` carries no tag at all and is the cleanest
boundary-checkable clause in the ML-KEM specification. Tag presence and
checkability are uncorrelated, so selecting on tags omits exactly what matters.

This module inverts the selection. It enumerates every top-level definition in
the pinned specification, then attaches whatever provenance happens to exist,
from any comment style. A definition with no tag is still a candidate; it simply
carries no citation. That way a missing comment cannot remove a clause from the
denominator, which is the failure mode that invalidated the first attempt.

Selection is then made on the SHAPE of the definition, which is a property of
the specification rather than of its comments:

  returns Bool                 a predicate over inputs, so a candidate check
  returns Option               encodes rejection in the type
  named *Check / *Valid        the specification's own naming for validation
  is a public API entry point   KeyGen, Encaps, Decaps, Sign, Verify

None of that is a final answer. It is a candidate set with the reason each
member was proposed recorded, which is what a recorded decision needs as input.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# A top-level definition starts at column 0. Anything indented is inside a
# where block or a submodule and has no independent API surface.
SIGNATURE = re.compile(r"^([A-Za-z_][\w']*)\s*:(?!=)\s*(.*)$")
BINDING = re.compile(r"^([A-Za-z_][\w']*)[^=\n]*=")
PROPERTY = re.compile(r"^property\s+([A-Za-z_][\w']*)")
# `type constraint ...` is a keyword phrase declaring a numeric constraint, not
# a named type. Matching it yields eight candidates all called "constraint".
TYPEDEF = re.compile(r"^type\s+(?!constraint\b)([A-Za-z_][\w']*)")

# Only these type aliases fix an encoding length observable at the boundary.
# Proposing every alias in scope swept in parameters like `ell` and `tau`.
ENCODING_TYPE = re.compile(
    r"(Key|Ciphertext|Signature|SharedSecret|Seed|Digest)$")

TAG = re.compile(
    r"\[FIPS-?(\d{2,3})\]\s*,?\s*"
    r"(?:(Section|Sec\.?|Appendix|Introduction|Algorithm|Equation|Table|Figure)"
    r"\s*,?\s*([0-9]+(?:\.[0-9]+)*|[A-Z]\b)?)?",
    re.IGNORECASE,
)

CHECK_NAME = re.compile(r"(check|valid|verify|inverts|correct)", re.IGNORECASE)

API_ENTRY = {
    "KeyGen", "Encaps", "Decaps", "Sign", "Verify",
    "KeyGen_internal", "Encaps_internal", "Decaps_internal",
    "Sign_internal", "Verify_internal",
    "encapsulationKeyCheck", "decapsulationKeyCheck", "decapsulationInputCheck",
    "keyPairCheck",
}


@dataclass
class Definition:
    name: str
    kind: str              # signature | binding | property | type
    signature: str
    path: str
    line: int
    comment: str
    comment_style: str     # docstring | block | line | none
    tags: list[str] = field(default_factory=list)
    doc: str = ""
    section: str = ""
    citation: str = ""
    proposed_surface: str | None = None
    proposed_rule: str | None = None
    proposed_why: str = ""

    @property
    def tagged(self) -> bool:
        return bool(self.tags)

    @property
    def returns_bool(self) -> bool:
        return bool(re.search(r"->\s*Bool\s*$", self.signature.strip()))

    @property
    def returns_option(self) -> bool:
        return bool(re.search(r"->\s*Option\b", self.signature))

    def as_record(self) -> dict:
        return {
            "schema": "candidate/1",
            "derivation": "D1b",
            "name": self.name,
            "kind": self.kind,
            "signature": self.signature.strip(),
            "source": {"path": self.path, "line": self.line},
            "comment_style": self.comment_style,
            "tagged": self.tagged,
            "doc": self.doc,
            "section": self.section,
            "citation": self.citation,
            "returns_bool": self.returns_bool,
            "returns_option": self.returns_option,
            "proposed_surface": self.proposed_surface,
            "proposed_rule": self.proposed_rule,
            "proposed_why": self.proposed_why,
        }


def _preceding_comment(lines: list[str], idx: int) -> tuple[str, str]:
    """Walk back over any comment block immediately above a definition.

    All three styles count. Scanning only /** */ loses 22 of ML-KEM's 89
    citations, including the output-length clauses for every public API type.
    """
    i = idx - 1
    while i >= 0 and not lines[i].strip():
        i -= 1
    if i < 0:
        return "", "none"

    if lines[i].strip().endswith("*/"):
        j = i
        while j >= 0 and "/*" not in lines[j]:
            j -= 1
        if j < 0:
            return "", "none"
        style = "docstring" if lines[j].strip().startswith("/**") else "block"
        return "\n".join(lines[j:i + 1]), style

    if lines[i].strip().startswith("//"):
        j = i
        while j > 0 and lines[j - 1].strip().startswith("//"):
            j -= 1
        return "\n".join(lines[j:i + 1]), "line"

    return "", "none"


# `module X where`, `submodule Y where`, `private submodule Z where`. The
# top-level module contributes no name prefix; submodules do.
MODULE_OPEN = re.compile(
    r"^(\s*)(private\s+)?(?:(?:interface\s+)?module\s+\S+"
    r"|(?:interface\s+)?submodule\s+([A-Za-z_][\w']*))"
    r"\s+where\s*$")

# A bare `private` on its own line opens a private block whose body is indented.
# ML-KEM uses one at line 1466 to hide decapsulationKeyCheck behind the public
# decapsulationInputCheck. Excluding its contents happened to fall out of the
# indent rule, but accident is not a reason, so it is handled explicitly.
PRIVATE_BLOCK = re.compile(r"^(\s*)private\s*$")


def extract(source: str, path: str) -> list[Definition]:
    """Enumerate definitions at the module's own surface.

    Column zero alone is not the surface. ML-KEM keeps most of its content
    inside `submodule NTT` and `private submodule K_PKE`, so a column-zero rule
    finds twelve definitions in a 1495-line specification and silently drops
    `decapsulationKeyCheck`. A definition inside a NON-private submodule is
    reachable from outside and belongs in the candidate set; one inside a
    private submodule is not.

    Names are qualified by their enclosing submodule, because `KeyGen` and
    `Ciphertext` are each defined twice in ML-KEM (once in K_PKE, once at the
    top) and keying on the bare name silently overwrites one with the other.
    """
    lines = source.splitlines()
    out: list[Definition] = []
    seen_sig: dict[str, Definition] = {}
    # [header_indent, name, private, body_indent] per open scope, outermost first.
    # body_indent is DETECTED, not assumed: the two pinned files disagree about
    # it. ML-KEM opens its module at column 0 and indents the body by four,
    # while ML-DSA indents its body by zero. Assuming either one finds twelve
    # definitions in a 1495-line file and silently drops decapsulationKeyCheck.
    stack: list[list] = []

    for n, raw in enumerate(lines):
        if not raw.strip():
            continue
        stripped = raw.lstrip()
        if stripped.startswith(("*", "//", "/*")):
            continue
        indent = len(raw) - len(stripped)

        while stack and stack[-1][3] is not None and indent < stack[-1][3]:
            stack.pop()

        if m := MODULE_OPEN.match(raw):
            stack.append([len(m.group(1)), m.group(3) or "", bool(m.group(2)), None])
            continue
        if m := PRIVATE_BLOCK.match(raw):
            stack.append([len(m.group(1)), "", True, None])
            continue

        if stack and stack[-1][3] is None:
            stack[-1][3] = indent          # first body line fixes the surface

        expected = stack[-1][3] if stack else 0
        if indent != expected:
            continue                       # deeper than this module's surface
        if any(sc[2] for sc in stack):
            continue                       # inside a private submodule
        prefix = "::".join(sc[1] for sc in stack if sc[1])
        raw = stripped
        if raw.lstrip().startswith(("//", "/*", "*", "module", "submodule",
                                    "import", "private", "parameter", "}")):
            continue

        name = kind = None
        sig = ""
        if m := PROPERTY.match(raw):
            name, kind = m.group(1), "property"
        elif m := TYPEDEF.match(raw):
            name, kind = m.group(1), "type"
        elif m := SIGNATURE.match(raw):
            name, kind, sig = m.group(1), "signature", m.group(2)
            # a signature may wrap onto following indented lines
            k = n + 1
            while k < len(lines) and lines[k].startswith((" ", "\t")) and "=" not in lines[k]:
                sig += " " + lines[k].strip()
                k += 1
        elif m := BINDING.match(raw):
            name, kind = m.group(1), "binding"
        if not name:
            continue

        # A binding whose signature was already recorded is the same clause.
        qual_key = f"{prefix}::{name}" if prefix else name
        if kind == "binding" and qual_key in seen_sig:
            continue

        comment, style = _preceding_comment(lines, n)
        qualified = f"{prefix}::{name}" if prefix else name
        d = Definition(name=qualified, kind=kind, signature=sig, path=path, line=n + 1,
                       comment=comment, comment_style=style)
        for t in TAG.finditer(comment):
            if comment[t.end():t.end() + 1] == ":":
                continue                   # bibliography entry, not a citation
            d.tags.append(t.group(0).strip())
            if not d.doc:
                d.doc = f"FIPS-{t.group(1)}"
                d.section = t.group(3) or ""
                d.citation = (t.group(2) or "").title()
        if kind == "signature":
            seen_sig[qualified] = d
        out.append(d)
    return out


def propose(defs: list[Definition]) -> None:
    """Propose a scope for each candidate, recording why.

    A proposal is not a decision. It is the input to one, and every candidate
    carries the reason it was put forward so the decision can disagree with a
    stated argument rather than with a black box.
    """
    for d in defs:
        bare = d.name.split("::")[-1]
        if bare in API_ENTRY:
            d.proposed_surface, d.proposed_rule = "api_boundary_checkable", "SCOPE-03"
            d.proposed_why = "public API entry point or a validation function the standard names"
        elif d.kind == "property":
            d.proposed_surface, d.proposed_rule = "out_of_scope", "SCOPE-09"
            d.proposed_why = "algebraic identity, checkable by proof rather than by an input"
        elif d.returns_bool:
            d.proposed_surface, d.proposed_rule = "api_boundary_checkable", "SCOPE-03"
            d.proposed_why = "returns Bool, so it is a predicate over its inputs"
        elif d.returns_option:
            d.proposed_surface, d.proposed_rule = "api_boundary_checkable", "SCOPE-03"
            d.proposed_why = "returns Option, so rejection is encoded in the type"
        elif d.kind == "type":
            if ENCODING_TYPE.search(bare):
                d.proposed_surface, d.proposed_rule = "api_boundary_checkable", "SCOPE-04"
                d.proposed_why = "type alias fixing the encoding length of a boundary value"
            else:
                d.proposed_surface, d.proposed_rule = "out_of_scope", "SCOPE-01"
                d.proposed_why = "parameter or internal type alias, not a boundary encoding"
        elif CHECK_NAME.search(d.name):
            d.proposed_surface, d.proposed_rule = None, None
            d.proposed_why = "check-shaped name but no decisive signature; needs a decision"
        else:
            d.proposed_surface, d.proposed_rule = "out_of_scope", "SCOPE-01"
            d.proposed_why = "internal transformation, not a decision at the boundary"
