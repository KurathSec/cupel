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
    bin/regen.py --json          machine-readable, for the CI drift check
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
    """The denominator, and whether it is yet allowed to be one."""
    _rule("Clause denominator")
    rows = _rows(DATA / "clauses" / "generated" / "clauses.jsonl")
    if not rows:
        print(f"  extracted clauses:   {NA} (extractor not yet run)")
        print(f"  in scope:            {NA}")
        return {"defined": False, "reconciled": False}

    in_scope = [r for r in rows if r.get("surface") == "api_boundary_checkable"]
    unclassified = [r for r in rows if not r.get("surface_rule")]
    by_doc: dict[str, int] = {}
    for r in in_scope:
        by_doc[r.get("doc", "?")] = by_doc.get(r.get("doc", "?"), 0) + 1

    print(count("  extracted clause records", len(rows)))
    print(Rate(len(in_scope), len(rows), "  in scope (API-boundary-checkable)").render())
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

    n_surv = {c for per in by_release.values() for c, vs in per.items() if vs <= {"SURVIVED"}}
    print()
    print("  " + Rate(len(n_surv & witnessed), len(n_surv),
                      "survivors carrying a constructed witness").render())
    return {"defined": True, "per_release": per_release,
            "n_survivors": len(n_surv), "n_witnessed": len(n_surv & witnessed)}


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
    failed = [r for r in rows if not r.get("passed")]
    for r in sorted(rows, key=lambda r: r.get("control_id", "")):
        status = "pass" if r.get("passed") else "FAIL"
        print(f"  {r.get('control_id', '?'):10s} {status:5s} {r.get('note', '')}")
    print()
    print(Rate(len(rows) - len(failed), len(rows), "  controls passing").render())
    return {"defined": True, "all_green": not failed, "n_failed": len(failed), "n_total": len(rows)}


# ----------------------------------------------------------------------------
# headline
# ----------------------------------------------------------------------------

def headline(state: dict) -> int:
    """Print the paper's headline sentence, or refuse and say why."""
    _rule("Headline")
    blockers = []
    if not state["controls"].get("all_green"):
        blockers.append("controls are not all green (bin/selfcheck.py)")
    if not state["clauses"].get("defined"):
        blockers.append("no clause denominator has been derived")
    elif not state["clauses"].get("reconciled"):
        blockers.append("derivations are not reconciled: unadjudicated disagreements remain")
    if not state["verdicts"].get("defined"):
        blockers.append("no exercised verdicts exist")

    if blockers:
        print("  REFUSED. The headline is not yet a number.")
        for b in blockers:
            print(f"    - {b}")
        return 3

    c, v = state["clauses"], state["verdicts"]
    pins = state["pins"]["pins"]
    docs = ", ".join(f"{d} n={n}" for d, n in sorted(c["by_doc"].items()))
    print(
        f"  Of the {c['n_in_scope']} API-boundary-checkable normative clauses derived from\n"
        f"  cryptol-specs @{pins.get('cryptol_specs', '?')[:12]} for FIPS 203 and FIPS 204\n"
        f"  ({docs}; {c['n_in_scope']} in scope of {c['n_extracted']} extracted),\n"
        f"  {v['n_killed']} are exercised by the ACVP vector set at\n"
        f"  ACVP-Server @{pins.get('acvp_server', '?')[:12]}\n"
        f"  ({v['n_killed']} killed, {v['n_survived']} not exercised, {v['n_inconclusive']} inconclusive;\n"
        f"  {v['n_witnessed']} survivors carry a constructed witness).\n"
        f"  FIPS 205: {NA} (no specification-derived clause source)."
    )
    return 0


SECTIONS = {
    "pins": section_pins,
    "corpus": section_corpus,
    "reasons": section_reasons,
    "disposition": section_disposition,
    "candidates": section_candidates,
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
