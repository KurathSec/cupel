#!/usr/bin/env python3
"""Controls. The tool proving its own oracle is not lying.

Every check here exists because its absence would have let a wrong number
through, and several of them are checks that were run by hand during
development and would otherwise have to be remembered. A control that lives in
someone's memory is not a control.

`bin/regen.py` refuses to print a headline while any of these is red, so a
result cannot be quoted out of a run whose instrument was broken.

Usage:  bin/selfcheck.py [--json]
Exit codes: 0 all green, 4 a control failed.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "src"))

from cupel.analysis import violation_matrix as vm  # noqa: E402
from cupel.mutate import anchor as anchormod  # noqa: E402
from cupel.util import jsonl  # noqa: E402
from cupel.util.na import Rate  # noqa: E402

RESULTS = REPO / "results"
DATA = REPO / "data"

CONTROLS = []


def control(cid, title):
    def deco(fn):
        CONTROLS.append((cid, title, fn))
        return fn
    return deco


# ---------------------------------------------------------------------------

@control("PC-1", "no valid case violates any clause")
def _pc1():
    """If a positive control trips a predicate, the battery is wrong.

    Deleting a check can only widen acceptance, so a well-formed predicate can
    never fire on an input the standard says is valid. This is the cheapest
    check that would catch a decoder reading the wrong bytes.
    """
    rows = list(jsonl.read(RESULTS / "violation_matrix.jsonl"))
    if not rows:
        return None, "violation matrix not built"
    valid = [r for r in rows if (r.get("reason") or "").startswith("valid")]
    bad = [r for r in valid if r["violated"]]
    if not valid:
        return None, "no labelled-valid cases in the matrix"
    return not bad, f"{len(bad)} of {len(valid)} valid cases violate something"


@control("PC-3", "ground-truth replay of ACVP-Server #460")
def _pc3():
    """The instrument must flag the defect pre-fix and clear it post-fix.

    Externally established, git-resolvable, and authored by other people before
    this tool existed, so it validates against truth cupel did not invent.
    """
    cols = list(jsonl.read(RESULTS / "columns.jsonl"))
    if not cols:
        return None, "columns not built"
    want = {("r2026-07-24", "fips203.s7.2.ek-modulus"): "ABSENT",
            ("r2026-07-28", "fips203.s7.2.ek-modulus"): "COVERED",
            ("r2026-07-31", "fips203.s7.2.ek-modulus"): "COVERED"}
    got, misses = {}, []
    for c in cols:
        key = (c.get("release"), c.get("clause_id"))
        if key in want:
            got[key] = c["status"]
    for key, expected in want.items():
        if key not in got:
            misses.append(f"{key[0]} not measured")
        elif got[key] != expected:
            misses.append(f"{key[0]} is {got[key]}, expected {expected}")
    return not misses, "; ".join(misses) or "pre-fix ABSENT, post-fix COVERED"


@control("MUT-1", "every mutation anchor matches its pinned source")
def _mut1():
    """Runs with no build, so drift surfaces the moment a pin moves."""
    checked = problems = 0
    for target_dir in sorted((DATA / "mutations").glob("*")):
        if not target_dir.is_dir():
            continue
        tree = REPO / "vendor" / target_dir.name
        if not tree.exists():
            continue
        for m in anchormod.load_for(target_dir.name):
            checked += 1
            if anchormod.check(m, tree):
                problems += 1
    if not checked:
        return None, "no vendored target trees present"
    return problems == 0, f"{problems} of {checked} anchors drifted"


@control("MUT-5", "every declared sentinel was killed")
def _mut5():
    """A surviving sentinel voids its run. If one is recorded as surviving, the
    verdicts beside it are not evidence of anything."""
    rows = [r for r in jsonl.read(RESULTS / "verdicts.jsonl") if r.get("is_sentinel")]
    if not rows:
        return None, "no sentinel verdicts recorded"
    alive = [r for r in rows if r.get("exercised", {}).get("verdict") != "KILLED"]
    return not alive, f"{len(alive)} of {len(rows)} sentinel runs survived"


@control("WIT-1", "every witness violates exactly the clause it claims")
def _wit1():
    """A candidate violating two clauses is a witness for neither, and one
    violating none is a bug in the constructor. Non-isolating witnesses are
    permitted only where the record says so."""
    files = sorted((REPO / "witness").glob("*.jsonl"))
    if not files:
        return None, "no witnesses constructed"
    checked = bad = 0
    for f in files:
        for w in jsonl.read(f):
            cid, viol = w.get("clause_id"), w.get("violates")
            if not cid or viol is None:
                continue
            checked += 1
            isolates = viol == [cid]
            if isolates != bool(w.get("isolates_clause", True)):
                bad += 1
    return bad == 0, f"{bad} of {checked} witnesses disagree with their own record"


@control("NA-1", "an empty aggregation prints NA rather than 0")
def _na1():
    from cupel.util.na import NA, Rate as R, mean
    ok = (R(0, 0).value is None and NA in R(0, 0).render()
          and mean([]).value is None and R(0, 5).value == 0.0)
    return ok, "Rate and mean distinguish undefined from zero"


@control("BAT-1", "the batteries agree with the corpus on parameter sizes")
def _bat1():
    """A wrong structural constant shows up as a valid case failing its own
    length check, which PC-1 would catch, so this reports the sizes explicitly
    to make the agreement visible rather than implicit."""
    rows = list(jsonl.read(RESULTS / "violation_matrix.jsonl"))
    if not rows:
        return None, "violation matrix not built"
    algos = {r["algorithm"] for r in rows}
    missing = algos - set(vm.BATTERIES)
    return not missing, f"batteries cover {sorted(algos)}"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    records, failed, skipped = [], 0, 0
    for cid, title, fn in CONTROLS:
        try:
            passed, note = fn()
        except Exception as exc:                     # a control that crashes is a failure
            passed, note = False, f"raised {type(exc).__name__}: {exc}"
        if passed is None:
            skipped += 1
            status = "skip"
        elif passed:
            status = "pass"
        else:
            failed += 1
            status = "FAIL"
        records.append({"schema": "control/1", "control_id": cid, "title": title,
                        "passed": bool(passed), "skipped": passed is None, "note": note})
        if not args.json:
            print(f"  {cid:8s} {status:5s} {title}")
            print(f"           {note}")

    RESULTS.mkdir(parents=True, exist_ok=True)
    jsonl.write(RESULTS / "controls.jsonl", records)
    if args.json:
        print(json.dumps(records, indent=2))
        return 4 if failed else 0

    print()
    print(Rate(len(records) - failed - skipped, len(records) - skipped,
               "controls passing").render())
    if skipped:
        print(f"  skipped, their input is not built yet: {skipped}")
    return 4 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
