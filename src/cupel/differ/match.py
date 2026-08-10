"""Match test cases across two pinned vector releases.

Matching is the whole difficulty. `tcId` is regenerated between releases, so
matching on it alone would report an entire suite as replaced the first time
NIST renumbers. Matching on content alone cannot see a case whose content is
exactly what changed.

So two passes, in this order:

  1. structural, when both releases have the same group and case shape. Groups
     are keyed on their declared parameters, cases on their ordinal within the
     group. This is the common case for a corrective commit, which regenerates
     a file in place without changing what each slot is for.
  2. content, for anything left over: cases are keyed on the hash of their
     input fields, so a case that moved slot is still recognised.

Whatever remains unmatched after both passes is genuinely added or removed, and
is reported as such rather than being forced into a pair.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..util.canonical import sha256_of

# Fields that are outputs, bookkeeping or secrets rather than IUT inputs. They
# are excluded from case identity so that regenerating an expectation does not
# read as replacing the case.
NON_INPUT_FIELDS = frozenset({
    "tcId", "reason", "testPassed", "deferred",
    "sk", "dk",           # secrets present only in internalProjection
    "k", "c",             # KEM outputs; `c` is re-added as an input for decap below
})

# Per (mode, function), the fields that constitute the input a verifier or
# decapsulator actually receives. Declared rather than inferred, so a reviewer
# can check the identity definition without running anything.
IDENTITY_FIELDS: dict[tuple[str, str], tuple[str, ...]] = {
    ("sigVer", ""): ("pk", "message", "signature", "context", "hashAlg", "mu"),
    ("encapDecap", "encapsulation"): ("ek", "m"),
    ("encapDecap", "decapsulation"): ("dk", "c"),
    ("encapDecap", "encapsulationKeyCheck"): ("ek",),
    ("encapDecap", "decapsulationKeyCheck"): ("dk",),
    ("keyGen", ""): ("seed", "d", "z", "skSeed", "skPrf", "pkSeed"),
    ("sigGen", ""): ("sk", "message", "context", "hashAlg", "rnd", "mu"),
}

GROUP_KEY_FIELDS = (
    "parameterSet", "function", "testType", "preHash",
    "signatureInterface", "externalMu", "hashAlg",
)


@dataclass(frozen=True)
class Case:
    vdir: str
    tg_id: int
    tc_id: int
    ordinal: int
    group_key: str
    # Groups are NOT uniquely identified by their declared parameters. In
    # ML-KEM-encapDecap-FIPS203-tr1, six of fifteen groups collide in three
    # pairs: decapsulation VAL groups exist twice per parameter set. Keying
    # slots on the parameters alone silently discards thirty cases, so the
    # occurrence index of the group among its identical siblings is part of
    # the slot identity.
    group_occurrence: int
    mode: str
    function: str
    reason: str | None
    expected: bool | None
    fields: dict[str, Any]

    @property
    def slot(self) -> tuple[str, int, int]:
        return (self.group_key, self.group_occurrence, self.ordinal)

    @property
    def identity(self) -> str:
        """Hash over declared input fields only. Excludes tcId by construction."""
        names = IDENTITY_FIELDS.get((self.mode, self.function))
        if names is None:
            names = tuple(sorted(set(self.fields) - NON_INPUT_FIELDS))
        payload = {k: self.fields[k] for k in names if k in self.fields}
        return sha256_of({"group": self.group_key, "input": payload})

    @property
    def payload_digest(self) -> str:
        """Hash over everything except bookkeeping. Detects any content change."""
        payload = {k: v for k, v in self.fields.items() if k not in {"tcId"}}
        return sha256_of(payload)


def group_key(group: dict) -> str:
    return sha256_of({k: group.get(k) for k in GROUP_KEY_FIELDS if k in group})


def load_cases(doc: dict, vdir: str, mode: str) -> list[Case]:
    cases = []
    seen_keys: dict[str, int] = {}
    for group in doc.get("testGroups", []):
        gkey = group_key(group)
        occurrence = seen_keys.get(gkey, 0)
        seen_keys[gkey] = occurrence + 1
        fn = group.get("function", "") or ""
        for ordinal, test in enumerate(group.get("tests", [])):
            cases.append(
                Case(
                    vdir=vdir,
                    tg_id=group.get("tgId", -1),
                    tc_id=test.get("tcId", -1),
                    ordinal=ordinal,
                    group_key=gkey,
                    group_occurrence=occurrence,
                    mode=mode,
                    function=fn,
                    reason=test.get("reason"),
                    expected=test.get("testPassed"),
                    fields=test,
                )
            )
    return cases


def slot_index(cases: list[Case], label: str) -> dict[tuple[str, int, int], Case]:
    """Index cases by slot, refusing to lose any to a key collision.

    A dict comprehension here would silently drop colliding cases, which is how
    thirty ML-KEM cases went missing the first time this was written. Losing
    test cases inside a tool that counts test cases is not an acceptable
    failure mode, so it raises.
    """
    out: dict[tuple[str, int, int], Case] = {}
    for c in cases:
        if c.slot in out:
            raise ValueError(
                f"{label}: slot collision at {c.slot} between tcId "
                f"{out[c.slot].tc_id} and {c.tc_id}. Slot identity is not unique."
            )
        out[c.slot] = c
    if len(out) != len(cases):
        raise ValueError(f"{label}: indexed {len(out)} slots for {len(cases)} cases")
    return out


@dataclass
class Pairing:
    pairs: list[tuple[Case, Case]] = field(default_factory=list)
    added: list[Case] = field(default_factory=list)
    removed: list[Case] = field(default_factory=list)
    n_structural: int = 0
    n_content: int = 0


def match(old: list[Case], new: list[Case]) -> Pairing:
    out = Pairing()

    # Pass 1: structural, on (group key, group occurrence, ordinal within group).
    old_slots = slot_index(old, "from")
    new_slots = slot_index(new, "to")
    shared = old_slots.keys() & new_slots.keys()
    for slot in sorted(shared):
        out.pairs.append((old_slots[slot], new_slots[slot]))
        out.n_structural += 1

    leftover_old = [c for k, c in old_slots.items() if k not in shared]
    leftover_new = [c for k, c in new_slots.items() if k not in shared]

    # Pass 2: content, on input identity.
    by_identity: dict[str, list[Case]] = {}
    for c in leftover_new:
        by_identity.setdefault(c.identity, []).append(c)
    still_old = []
    for c in leftover_old:
        bucket = by_identity.get(c.identity)
        if bucket:
            out.pairs.append((c, bucket.pop(0)))
            out.n_content += 1
        else:
            still_old.append(c)

    out.removed = still_old
    out.added = [c for bucket in by_identity.values() for c in bucket]
    return out
