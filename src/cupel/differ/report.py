"""Diff two pinned vector releases at the level of individual test cases.

The census cannot see a corrective regeneration: group counts, case counts and
label distributions all stay fixed while the bytes underneath change. That is
not a hypothetical. Both of the corrective commits pinned in this project are
invisible to every summary statistic the suite exposes.

So the differ reports four things per directory, each with its n:

  input_changed       the bytes the implementation receives are different
  expectation_flipped testPassed changed for a matched case
  reason_changed      the case now claims to test something else
  added / removed     cases with no counterpart under either matching pass

`expectation_flipped` is the one that matters most and is usually zero. A fix
that changes inputs without changing a single expectation has, by construction,
not changed what any implementation must do to pass.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from . import match as matchmod


@dataclass
class DirDiff:
    vdir: str
    from_release: str
    to_release: str
    n_cases_from: int = 0
    n_cases_to: int = 0
    n_matched_structural: int = 0
    n_matched_content: int = 0
    n_added: int = 0
    n_removed: int = 0
    n_input_changed: int = 0
    n_payload_changed: int = 0
    n_expectation_flipped: int = 0
    n_reason_changed: int = 0
    n_groups_recomposed: int = 0
    n_groups: int = 0
    input_changed_by_reason: dict[str, int] = field(default_factory=dict)
    composition_delta: dict[str, int] = field(default_factory=dict)
    flips: list[dict] = field(default_factory=list)
    reason_changes: list[dict] = field(default_factory=list)

    @property
    def changed(self) -> bool:
        return bool(
            self.n_added or self.n_removed or self.n_input_changed
            or self.n_expectation_flipped or self.n_reason_changed
        )

    def as_record(self) -> dict:
        return {
            "schema": "diff/1",
            "dir": self.vdir,
            "from_release": self.from_release,
            "to_release": self.to_release,
            "n_cases_from": self.n_cases_from,
            "n_cases_to": self.n_cases_to,
            "n_matched_structural": self.n_matched_structural,
            "n_matched_content": self.n_matched_content,
            "n_added": self.n_added,
            "n_removed": self.n_removed,
            "n_input_changed": self.n_input_changed,
            "n_payload_changed": self.n_payload_changed,
            "n_expectation_flipped": self.n_expectation_flipped,
            "n_reason_changed": self.n_reason_changed,
            "n_groups": self.n_groups,
            "n_groups_recomposed": self.n_groups_recomposed,
            "composition_delta": self.composition_delta,
            "input_changed_by_reason": self.input_changed_by_reason,
            "flips": self.flips,
            "reason_changes": self.reason_changes,
            "changed": self.changed,
        }


def diff_dir(vdir: str, mode: str, from_release: str, to_release: str,
             old_doc: dict, new_doc: dict) -> DirDiff:
    old = matchmod.load_cases(old_doc, vdir, mode)
    new = matchmod.load_cases(new_doc, vdir, mode)
    pairing = matchmod.match(old, new)

    d = DirDiff(vdir=vdir, from_release=from_release, to_release=to_release)
    d.n_cases_from = len(old)
    d.n_cases_to = len(new)
    d.n_matched_structural = pairing.n_structural
    d.n_matched_content = pairing.n_content
    d.n_added = len(pairing.added)
    d.n_removed = len(pairing.removed)

    for a, b in pairing.pairs:
        if a.identity != b.identity:
            d.n_input_changed += 1
            label = a.reason or "(unlabelled)"
            d.input_changed_by_reason[label] = d.input_changed_by_reason.get(label, 0) + 1
        if a.payload_digest != b.payload_digest:
            d.n_payload_changed += 1
        if a.expected != b.expected:
            d.n_expectation_flipped += 1
            d.flips.append({
                "tc_id_from": a.tc_id, "tc_id_to": b.tc_id,
                "expected_from": a.expected, "expected_to": b.expected,
                "reason": b.reason,
            })
        if a.reason != b.reason:
            d.n_reason_changed += 1
            d.reason_changes.append({
                "tc_id_from": a.tc_id, "tc_id_to": b.tc_id,
                "reason_from": a.reason, "reason_to": b.reason,
            })

    # Slot-level label change conflates two very different events: a group that
    # now tests a different mix of things, and a group that tests the same mix
    # in a different order. A regenerated file routinely does the second. Only
    # the first changes what the suite covers, so compare each group's
    # disposition multiset, which is order-insensitive.
    def composition(cases):
        per_group: dict[tuple[str, int], dict[str, int]] = {}
        for c in cases:
            key = (c.group_key, c.group_occurrence)
            bucket = per_group.setdefault(key, {})
            label = c.reason or "(unlabelled)"
            bucket[label] = bucket.get(label, 0) + 1
        return per_group

    comp_old, comp_new = composition(old), composition(new)
    d.n_groups = len(comp_new)
    for key in comp_old.keys() | comp_new.keys():
        if comp_old.get(key) != comp_new.get(key):
            d.n_groups_recomposed += 1

    totals_old: dict[str, int] = {}
    totals_new: dict[str, int] = {}
    for c in old:
        label = c.reason or "(unlabelled)"
        totals_old[label] = totals_old.get(label, 0) + 1
    for c in new:
        label = c.reason or "(unlabelled)"
        totals_new[label] = totals_new.get(label, 0) + 1
    for label in totals_old.keys() | totals_new.keys():
        delta = totals_new.get(label, 0) - totals_old.get(label, 0)
        if delta:
            d.composition_delta[label] = delta
    return d
