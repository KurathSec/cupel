"""Derivation D4: the negative-case taxonomy the ACVP algorithm specification mandates.

D3 reads the generator's disposition enums, which is a property of one
implementation. This reads the documents that require those dispositions, which
is a property of the programme. The distinction carries the paper's lead claim,
and review pointed out that it was the one step asserted in prose and measured
nowhere while everything else here is pinned and regenerated.

The specifications are living Internet-Drafts served as HTML with no commit a
third party can address, so what is recorded is the retrieval date and the
sha256 of the bytes parsed. A later reader who gets a different digest knows the
document moved under them, which is the same guarantee the vector lock gives.

What is extracted: the quoted modification names each specification defines for
each function, taken from the sentences that introduce them. Those quoted names
are the same strings the vector data carries in its `reason` field and the same
strings the C# enums attach to their members, so the three can be joined and
disagreement between them becomes a control rather than a reading.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass

# The specifications introduce each taxonomy with a sentence of this shape, then
# list the members as quoted strings with a description after a dash.
INTRO = re.compile(
    r"The\s+(?P<function>[a-z][a-z \-]*?)\s+modifications\s+are\s*:",
    re.I)
MEMBER = re.compile(r"[“\"]([^”\"]{3,80})[”\"]\s*-\s*", re.U)


def strip_html(raw: str) -> str:
    text = re.sub(r"<script.*?</script>", " ", raw, flags=re.S | re.I)
    text = re.sub(r"<style.*?</style>", " ", text, flags=re.S | re.I)
    text = re.sub(r"<[^>]+>", " ", text)
    for entity, char in (("&amp;", "&"), ("&lt;", "<"), ("&gt;", ">"),
                         ("&quot;", '"'), ("&#8220;", "“"),
                         ("&#8221;", "”"), ("&nbsp;", " ")):
        text = text.replace(entity, char)
    return re.sub(r"\s+", " ", text)


@dataclass
class Mandated:
    document: str
    digest: str
    function: str
    label: str
    is_valid: bool

    def as_record(self) -> dict:
        return {
            "schema": "mandate/1",
            "derivation": "D4",
            "document": self.document,
            "document_digest": self.digest,
            "function": self.function,
            "label": self.label,
            "is_valid": self.is_valid,
        }


def parse(raw: str, document: str) -> list[Mandated]:
    """Every modification the document defines, per function it defines them for."""
    text = strip_html(raw)
    digest = "sha256:" + hashlib.sha256(raw.encode("utf-8", "replace")).hexdigest()
    out: list[Mandated] = []
    intros = list(INTRO.finditer(text))
    for i, m in enumerate(intros):
        end = intros[i + 1].start() if i + 1 < len(intros) else min(
            m.end() + 4000, len(text))
        block = text[m.end():end]
        function = re.sub(r"\s+", " ", m.group("function")).strip().lower()
        seen = set()
        for member in MEMBER.finditer(block):
            label = member.group(1).strip()
            if label in seen:
                continue
            seen.add(label)
            # The specification's own convention: a modification whose name
            # begins "valid" is the unmodified case.
            out.append(Mandated(document=document, digest=digest,
                                function=function, label=label,
                                is_valid=label.lower().startswith("valid")))
    return out


def negative_by_function(rows: list[Mandated]) -> dict[str, list[str]]:
    by: dict[str, list[str]] = {}
    for r in rows:
        if not r.is_valid:
            by.setdefault(r.function, []).append(r.label)
    return {k: sorted(v) for k, v in sorted(by.items())}
