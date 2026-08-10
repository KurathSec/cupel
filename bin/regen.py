#!/usr/bin/env python3
"""Print every number this project will ever quote, each with its n.

The rule this enforces: a number does not exist until a committed script
regenerates it from committed data. Prose is not a number. A memory of a run is
not a number. If a figure is going into a paper, a table or a README, it is
printed here, from `data/` and `results/`, or it does not get quoted.

Two behaviours are deliberate and load bearing:

  * An empty aggregation prints NA, never 0. `mean([])` is not 0.00 and an
    unrun experiment is not a coverage of zero.
  * `--headline` refuses to print the paper's headline sentence unless every
    precondition holds: controls green, derivations reconciled, denominator
    derived. It exits 3 and says which precondition failed.

Usage:
    bin/regen.py                 print every section
    bin/regen.py --section corpus
    bin/regen.py --json          machine-readable state (no CI job consumes it yet)
    bin/regen.py --headline      print the headline sentence, or refuse

Exit codes: 0 ok, 3 precondition failed, 4 a control failed.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "src"))

from cupel.util import jsonl  # noqa: E402
from cupel.util.na import NA, Rate, count  # noqa: E402

DATA = REPO / "data"
RESULTS = REPO / "results"


def _rows(path: Path) -> list[dict]:
    return list(jsonl.read(path)) if path.exists() else []


def _rule(title: str) -> None:
    print(f"\n{title}")
    print("-" * len(title))


# ----------------------------------------------------------------------------
# sections
# ----------------------------------------------------------------------------

def section_pins() -> dict:
    """What everything downstream is pinned to. No number is interpretable without this."""
    _rule("Pins")
    path = DATA / "pins.toml"
    if not path.exists():
        print(f"  pins.toml: {NA} (not yet written)")
        return {"defined": False, "pins": {}}
    import tomllib
    pins = tomllib.loads(path.read_text(encoding="utf-8"))
    out = {}
    for name, entry in sorted(pins.items()):
        if isinstance(entry, dict) and "commit" in entry:
            print(f"  {name:20s} {entry.get('repo', '?')} @ {entry['commit'][:12]}")
            out[name] = entry["commit"]
    releases = pins.get("acvp_server", {}).get("releases", [])
    for rel in releases:
        print(f"  {'acvp release':20s} {rel.get('id', '?')} @ {rel.get('commit', '?')[:12]}"
              f"  {rel.get('note', '')}")
    print(count("  pinned sources", len(out)))
    return {"defined": True, "pins": out, "n_releases": len(releases)}


def section_corpus() -> dict:
    """Table 1: what is actually in the mandated vector set."""
    _rule("Corpus census")
    rows = _rows(RESULTS / "census.jsonl")
    if not rows:
        print(f"  vector directories: {NA} (census not yet run)")
        print(f"  test cases:         {NA}")
        print(f"  negative cases:     {NA}")
        return {"defined": False}

    # Per release. Stacking three pinned states into one table would list every
    # directory three times and invite a reader to sum across them.
    by_release: dict[str, list[dict]] = {}
    for r in rows:
        by_release.setdefault(r.get("release", "?"), []).append(r)

    per_release = {}
    for release in sorted(by_release):
        rs = by_release[release]
        total_cases = sum(r["n_cases"] for r in rs)
        total_neg = sum(r["n_negative"] for r in rs)
        print(f"\n  {release}")
        print(f"    {'directory':38s} {'groups':>7s} {'cases':>7s} {'negative':>9s}")
        for r in sorted(rs, key=lambda r: r["dir"]):
            print(f"    {r['dir']:38s} {r['n_groups']:>7d} {r['n_cases']:>7d} "
                  f"{r['n_negative']:>9d}")
        print("    " + count("vector directories", len(rs)))
        print("    " + Rate(total_neg, total_cases, "negative case share").render())
        no_neg = sorted(r["dir"] for r in rs if r["n_negative"] == 0)
        print("    " + count("directories with zero negative cases", len(no_neg)))
        for d in no_neg:
            print(f"        {d}")
        per_release[release] = {
            "n_dirs": len(rs), "n_cases": total_cases, "n_negative": total_neg,
            "n_dirs_without_negatives": len(no_neg),
        }
    return {"defined": True, "n_releases": len(by_release), "per_release": per_release}


def section_reasons() -> dict:
    """The disposition labels the suite actually ships, per algorithm."""
    _rule("Reason labels in the shipped corpus")
    rows = _rows(RESULTS / "reason_histogram.jsonl")
    if not rows:
        print(f"  distinct reason labels: {NA} (census not yet run)")
        return {"defined": False}
    # Keyed on directory, not algorithm: ML-KEM ships two encapDecap vector sets
    # and the tr1 one carries key-check groups the other does not. Folding them
    # together would double-count and would hide exactly the difference that
    # matters.
    # Keyed on (release, dir). The file holds one row per (release, dir, reason),
    # so keying on dir alone stacked all three pinned releases into each bucket
    # and tripled every count printed here.
    newest = max(r.get("release", "") for r in rows)
    rows = [r for r in rows if r.get("release") == newest]
    print(f"  release {newest}")
    by_dir: dict[str, list[dict]] = {}
    for r in rows:
        by_dir.setdefault(r["dir"], []).append(r)
    for vdir in sorted(by_dir):
        rs = by_dir[vdir]
        n_neg = sum(r["n"] for r in rs if not r["is_valid_label"])
        print(f"  {vdir}  ({len(rs)} labels, {n_neg} negative cases)")
        for r in sorted(rs, key=lambda r: (r["is_valid_label"], -r["n"], r["reason"])):
            mark = " " if r["is_valid_label"] else "-"
            print(f"    {mark} {r['n']:>5d}  {r['reason']}")

    n_pairs = len({(r["dir"], r["reason"]) for r in rows})
    n_distinct_by_algo = {}
    for r in rows:
        n_distinct_by_algo.setdefault(r["algorithm"], set()).add(r["reason"])
    print()
    print(count("  distinct (directory, reason) pairs", n_pairs))
    for algo in sorted(n_distinct_by_algo):
        print(count(f"    distinct labels for {algo}", len(n_distinct_by_algo[algo])))
    return {
        "defined": True,
        "n_pairs": n_pairs,
        "n_distinct_by_algo": {k: len(v) for k, v in n_distinct_by_algo.items()},
    }


def section_disposition() -> dict:
    """D3: the structural upper bound read from the generator's own enums."""
    _rule("Disposition enums (structural bound on negative coverage)")
    rows = _rows(DATA / "clauses" / "generated" / "derivation_d3.jsonl")
    if not rows:
        print(f"  enum members: {NA} (enums not yet parsed)")
        return {"defined": False}
    planned = [r for r in rows if r.get("planned_but_absent")]
    print(count("  enum members across all disposition types", len(rows)))
    print(count("  members flagged planned_but_absent by upstream comment", len(planned)))
    for r in sorted(planned, key=lambda r: r.get("name", "")):
        print(f"      {r.get('enum')}::{r.get('name')}  {r.get('note', '')}")
    return {"defined": True, "n_members": len(rows), "n_planned_absent": len(planned)}


def section_reconciliation() -> dict:
    """The three derivations set against each other. KT3, mechanised."""
    _rule("Derivation reconciliation (D1b spec / D2 implementation / D3 disposition)")
    rows = _rows(RESULTS / "reconciliation.jsonl")
    if not rows:
        print(f"  cells: {NA} (reconciliation not yet run)")
        return {"defined": False}
    MEAN = {
        "123": "all three agree",
        "12": "specified and implemented, but no disposition can produce a violating input",
        "13": "specified and producible, but this implementation does not check it",
        "1": "specified only",
        "23": "implemented and producible, extraction missed it",
        "2": "implementation only", "3": "disposition only",
    }
    for r_ in sorted(rows, key=lambda r_: r_["clause"]):
        print(f"  {r_['clause']:40s} {r_['cell']:5s} {MEAN.get(r_['cell'], '?')}")
    agree = [r_ for r_ in rows if not r_["needs_decision"]]
    print()
    print("  " + Rate(len(agree), len(rows), "cells where all three derivations agree").render())
    struct = [r_ for r_ in rows if r_["cell"] == "12"]
    if struct:
        print(count("  structurally unexercisable (implemented, no disposition reaches them)",
                    len(struct)))
    return {"defined": True, "n_cells": len(rows), "n_agree": len(agree),
            "n_structurally_unexercisable": len(struct)}


def section_candidates() -> dict:
    """D1b: the candidate clause set, derived from definitions rather than tags."""
    _rule("Clause candidates (D1b, from definitions)")
    rows = _rows(DATA / "clauses" / "generated" / "candidates.jsonl")
    if not rows:
        print(f"  candidates: {NA} (derivation not yet run)")
        return {"defined": False}
    inb = [r for r in rows if r.get("proposed_surface") == "api_boundary_checkable"]
    untagged = [r for r in inb if not r.get("tagged")]
    undecided = [r for r in rows if r.get("proposed_surface") is None]
    print(count("  definitions at the module surface", len(rows)))
    print(Rate(len(inb), len(rows), "  proposed boundary-checkable").render())
    print(Rate(len(untagged), len(inb), "  of those, carrying no citation").render())
    print(count("  needing a recorded decision", len(undecided)))
    print("  A tag-based derivation cannot see the untagged ones, which is why D1")
    print("  supplies provenance and this supplies the candidate set.")
    return {"defined": True, "n_candidates": len(rows), "n_in_scope": len(inb),
            "n_untagged_in_scope": len(untagged), "n_undecided": len(undecided),
            "reconciled": not undecided}


def section_clauses() -> dict:
    """D1 provenance coverage. NOT the denominator, and titled so it cannot be
    mistaken for one.

    This section reads the superseded tag-based extraction. That derivation was
    retracted as a clause set, because tag presence does not correlate with
    boundary-checkability, so what it reports is how much of the specification
    carries a citation and nothing more. The denominator lives in the candidate
    section above.
    """
    _rule("Provenance coverage (D1, superseded as a clause set)")
    rows = _rows(DATA / "clauses" / "generated" / "clauses.jsonl")
    if not rows:
        print(f"  tagged docstrings:   {NA} (extractor not yet run)")
        return {"defined": False, "reconciled": False}

    in_scope = [r for r in rows if r.get("surface") == "api_boundary_checkable"]
    unclassified = [r for r in rows if not r.get("surface_rule")]
    # D1 records carry no api_boundary_checkable surface at all: every row is
    # out_of_scope or unclassified, so in_scope is empty by construction and the
    # per-document breakdown it fed was always blank. Report the citation spread
    # instead, which is what this section is actually about.
    by_doc: dict[str, int] = {}
    for r in rows:
        by_doc[r.get("doc", "?")] = by_doc.get(r.get("doc", "?"), 0) + 1

    print("  This is D1, the tag-based extraction, retained as PROVENANCE only.")
    print("  It was retracted as a clause set: tag presence does not correlate")
    print("  with boundary-checkability. The denominator is the candidate section.")
    print(count("  docstrings carrying a FIPS citation", len(rows)))
    for doc in sorted(by_doc):
        print(count(f"    {doc}", by_doc[doc]))
    print(f"    FIPS-205: {NA} (no specification-derived clause source; see plan)")

    by_rule: dict[str, int] = {}
    for r in rows:
        rule = r.get("surface_rule") or "UNCLASSIFIED"
        by_rule[rule] = by_rule.get(rule, 0) + 1
    print("  decided by scope rule:")
    for rule in sorted(by_rule):
        print(count(f"    {rule}", by_rule[rule]))

    adjudications = _rows(DATA / "clauses" / "overlay" / "adjudications.jsonl")
    open_adj = [a for a in adjudications if not a.get("decision")]
    print(count("  adjudications recorded", len(adjudications)))
    print(count("  adjudications still open", len(open_adj)))
    if unclassified:
        print(f"  WARNING: {len(unclassified)} clause(s) have no scope rule; the denominator is not final.")

    reconciled = not open_adj and not unclassified
    return {
        "defined": True,
        "reconciled": reconciled,
        "n_extracted": len(rows),
        "n_in_scope": len(in_scope),
        "n_unclassified": len(unclassified),
        "n_open_adjudications": len(open_adj),
        "by_doc": by_doc,
    }


def section_verdicts() -> dict:
    """The numerator: which clauses the vector set actually exercises.

    Per release. A clause killed at one pinned release and surviving at another
    is not 75 percent exercised; it is exercised at one and not at the other,
    and pooling them describes neither. Substrate is the axis the any-kill rule
    aggregates over, and release is not.
    """
    _rule("Exercised verdicts")
    rows = [r for r in _rows(RESULTS / "verdicts.jsonl") if r.get("release")]
    if not rows:
        print(f"  clauses with a verdict: {NA} (no runs yet)")
        print(f"  exercised:              {NA}")
        return {"defined": False}

    # Scan the whole directory rather than named files, so a new witness is
    # picked up by existing rather than by being remembered here.
    witnessed = set()
    for wf in sorted((REPO / "witness").glob("*.jsonl")):
        for w in _rows(wf):
            if w.get("clause_id") and w.get("isolates_clause", True):
                witnessed.add(w["clause_id"])

    by_release: dict[str, dict[str, set]] = {}
    for r in rows:
        v = r.get("exercised", {}).get("verdict", "UNKNOWN")
        by_release.setdefault(r["release"], {}).setdefault(r["clause_id"], set()).add(v)

    per_release = {}
    for release in sorted(by_release):
        per = by_release[release]
        killed = [c for c, vs in per.items() if "KILLED" in vs]
        survived = [c for c, vs in per.items() if vs <= {"SURVIVED"}]
        other = [c for c in per if c not in killed and c not in survived]
        print(f"\n  {release}")
        print("    " + Rate(len(killed), len(per), "exercised (killed in some substrate)").render())
        for c in sorted(survived):
            mark = "witnessed" if c in witnessed else "no witness yet"
            print(f"      not exercised: {c}  ({mark})")
        if other:
            print("    " + count("inconclusive", len(other)))
        per_release[release] = {"n_clauses": len(per), "n_killed": len(killed),
                                "n_survived": len(survived), "n_other": len(other)}

    # Witness coverage is reported at the newest pinned release, not unioned
    # across releases. Unioning is the aggregation this section's docstring
    # forbids: a clause that survives at one release and dies at another is not
    # a survivor of the corpus, it is a survivor of that release.
    newest = max(by_release)
    surv_newest = {c for c, vs in by_release[newest].items() if vs <= {"SURVIVED"}}
    print()
    print("  " + Rate(len(surv_newest & witnessed), len(surv_newest),
                      f"survivors at {newest} carrying a constructed witness").render())
    return {"defined": True, "per_release": per_release, "newest": newest,
            "n_survivors": len(surv_newest),
            "n_witnessed": len(surv_newest & witnessed)}


def section_misattribution() -> dict:
    """Negative vectors that cannot fail for the reason their label claims."""
    _rule("Label misattribution")
    rows = _rows(RESULTS / "misattribution.jsonl")
    if not rows:
        print(f"  negative cases checked: {NA} (violation matrix not yet built)")
        print(f"  misattributed:          {NA}")
        return {"defined": False}
    # Per release, never pooled. These releases are consecutive states across a
    # corrective commit, so a pooled rate averages a pre-fix corpus with a
    # post-fix one and describes neither.
    scored = [r for r in rows if r.get("status") in ("attributed", "misattributed")]
    if not scored:
        print(f"  scored negative cases: {NA} (no label had an evaluable predicate)")
        skipped = len(rows)
        print(count("  not scored (no predicate or unmapped label)", skipped))
        return {"defined": False, "n_scored": 0}

    by_release: dict[str, list[dict]] = {}
    for r in scored:
        by_release.setdefault(r.get("release", "?"), []).append(r)

    per_release = {}
    for release in sorted(by_release):
        rs = by_release[release]
        bad = [r for r in rs if r.get("misattributed")]
        print(Rate(len(bad), len(rs), f"  {release}").render())
        by_reason: dict[str, int] = {}
        for r in bad:
            by_reason[r["reason"]] = by_reason.get(r["reason"], 0) + 1
        for reason in sorted(by_reason):
            n_total = sum(1 for r in rs if r["reason"] == reason)
            print(Rate(by_reason[reason], n_total, f"      {reason}").render())
        per_release[release] = {"n_scored": len(rs), "n_misattributed": len(bad)}

    n_skipped = len(rows) - len(scored)
    print(count("  not scored (no predicate or unmapped label)", n_skipped))
    return {
        "defined": True,
        "n_scored": len(scored),
        "n_skipped": n_skipped,
        "per_release": per_release,
    }


def section_controls() -> dict:
    """The tool's own oracle checks. A red control blocks the headline."""
    _rule("Controls")
    rows = _rows(RESULTS / "controls.jsonl")
    if not rows:
        print(f"  controls run: {NA} (selftest not yet run)")
        return {"defined": False, "all_green": False, "n_failed": 0}
    # A skipped control is not a failed one. selfcheck already draws that line
    # and writes skipped=true; reading only `passed` collapsed the two, so a
    # checkout without vendored trees, where MUT-1 correctly skips, made regen
    # exit 4 as though a control had gone red.
    skipped = [r for r in rows if r.get("skipped")]
    failed = [r for r in rows if not r.get("passed") and not r.get("skipped")]
    for r in sorted(rows, key=lambda r: r.get("control_id", "")):
        status = "skip" if r.get("skipped") else ("pass" if r.get("passed") else "FAIL")
        print(f"  {r.get('control_id', '?'):10s} {status:5s} {r.get('note', '')}")
    print()
    print(Rate(len(rows) - len(failed) - len(skipped), len(rows) - len(skipped),
               "  controls passing").render())
    if skipped:
        print(count("  skipped, their input is not present", len(skipped)))
    return {"defined": True, "all_green": not failed, "n_failed": len(failed),
            "n_skipped": len(skipped), "n_total": len(rows)}


# ----------------------------------------------------------------------------
# headline
# ----------------------------------------------------------------------------

def headline(state: dict) -> int:
    """Print the paper's headline sentence, or refuse and say why."""
    _rule("Headline")
    blockers = []
    if not state["controls"].get("all_green"):
        blockers.append("controls are not all green (bin/selfcheck.py)")
    # The gate reads the CANDIDATE derivation, not the tag-based one. D1 was
    # shown to select the wrong set, so gating on it would let a headline
    # through on the strength of a derivation known to be invalid.
    cand = state.get("candidates", {})
    if not cand.get("defined"):
        blockers.append("no clause candidate set has been derived")
    elif not cand.get("reconciled"):
        blockers.append(
            f"{cand.get('n_undecided')} clause candidate(s) await a recorded decision")
    if not state.get("clauses", {}).get("defined"):
        blockers.append("no provenance derivation has been run")
    if not state["verdicts"].get("defined"):
        blockers.append("no exercised verdicts exist")

    if blockers:
        print("  REFUSED. The headline is not yet a number.")
        for b in blockers:
            print(f"    - {b}")
        return 3

    cand, v = state["candidates"], state["verdicts"]
    pins = state["pins"]["pins"]

    # Both operands must be CLAUSE IDS. The candidate set counts Cryptol
    # DEFINITIONS (encapsulationKeyCheck, Verify, HintBitUnpack), while verdicts
    # count clause ids (fips203.s7.2.ek-modulus). Subtracting one from the other
    # produced a difference that counted nothing, and it was printed in the
    # headline. The bridge is the same declared mapping the reconciliation uses.
    from cupel.clauses import reconcile as _rec

    # `.get(name, [])` drops a definition with no declared mapping without a
    # word, which is the same population defect as before in the other
    # direction: the union would be credited to all 26 while 7 produce it.
    in_scope_clauses, unmapped = set(), []
    for c in _rows(DATA / "clauses" / "generated" / "candidates.jsonl"):
        if c.get("proposed_surface") != "api_boundary_checkable":
            continue
        mapped = _rec.SPEC_TO_CLAUSE.get(c["name"].split("::")[-1])
        if mapped is None:
            unmapped.append(c["name"])
            continue
        in_scope_clauses.update(mapped)
    measured_ids = {r["clause_id"] for r in _rows(RESULTS / "verdicts.jsonl")
                    if r.get("release")}
    unmeasured = sorted(in_scope_clauses - measured_ids)
    orphans = sorted(measured_ids - in_scope_clauses)

    print(
        f"  The {cand['n_in_scope']} boundary-checkable definitions derived from\n"
        f"  cryptol-specs @{pins.get('cryptol_specs', '?')[:12]} "
        f"({cand['n_in_scope']} of {cand['n_candidates']} at the module surface;\n"
        f"  {cand['n_untagged_in_scope']} carry no citation, so a tag-based derivation cannot\n"
        f"  see them), {cand['n_in_scope'] - len(unmapped)} carry a recorded clause\n"
        f"  mapping and together state {len(in_scope_clauses)} distinct normative clauses.\n"
        f"  {len(measured_ids & in_scope_clauses)} of those have been put to a mutation and\n"
        f"  have a verdict. The remaining {len(unmeasured)} are UNMEASURED: neither\n"
        f"  exercised nor unexercised, and not foldable into either count."
    )
    for c in unmeasured:
        print(f"      unmeasured: {c}")
    if unmapped:
        print(f"  WARNING: {len(unmapped)} of {cand['n_in_scope']} in-scope definitions have no\n"
              f"  recorded clause mapping, so {len(in_scope_clauses)} and the unmeasured count\n"
              f"  below are LOWER BOUNDS: {sorted(unmapped)}")
    if orphans:
        print(f"  WARNING: {len(orphans)} measured clause(s) are not reachable from the "
              f"candidate set: {orphans}")
    print(f"  Against ACVP-Server @{pins.get('acvp_server', '?')[:12]}, over those measured:")
    for release, per in sorted(v["per_release"].items()):
        print(f"    {release}: " + Rate(per["n_killed"], per["n_clauses"],
                                        "exercised of those measured").render())
    print(f"  {v['n_witnessed']} of {v['n_survivors']} survivors carry a constructed witness.")
    print(f"  FIPS 205 denominator: {NA} (no specification-derived clause source).")
    return 0


SECTIONS = {
    "pins": section_pins,
    "corpus": section_corpus,
    "reasons": section_reasons,
    "disposition": section_disposition,
    "candidates": section_candidates,
    "reconciliation": section_reconciliation,
    "clauses": section_clauses,
    "verdicts": section_verdicts,
    "misattribution": section_misattribution,
    "controls": section_controls,
}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--section", choices=sorted(SECTIONS), help="print one section only")
    ap.add_argument("--json", action="store_true", help="emit machine-readable state")
    ap.add_argument("--headline", action="store_true", help="print the headline sentence, or refuse")
    args = ap.parse_args()

    names = [args.section] if args.section else list(SECTIONS)
    state = {}
    if args.json:
        import io, contextlib
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            for name in names:
                state[name] = SECTIONS[name]()
        print(json.dumps(state, indent=2, sort_keys=True))
        return 0

    print(f"cupel regen: every number below is computed from data/ and results/ in {REPO}")
    for name in names:
        state[name] = SECTIONS[name]()

    if args.headline:
        for name in SECTIONS:
            if name not in state:
                import io, contextlib
                with contextlib.redirect_stdout(io.StringIO()):
                    state[name] = SECTIONS[name]()
        return headline(state)

    if state.get("controls", {}).get("n_failed"):
        print(f"\ncupel regen: {state['controls']['n_failed']} control(s) failed.", file=sys.stderr)
        return 4
    return 0


if __name__ == "__main__":
    sys.exit(main())
