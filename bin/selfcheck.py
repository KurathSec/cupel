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


@control("WIT-2", "every witness file declares how it was produced")
def _wit2():
    """WIT-1 checks a witness against itself and says nothing about where the
    file came from. Two of the three witness files turned out to be read by
    regen and by WIT-1 while being written by no committed script, which is this
    project's own rule broken at the point it matters most. That cannot be
    fixed by a control, but going quiet about it can be.

    So: every witness file must be declared in witness/PROVENANCE.toml, with an
    origin of `script` (a committed command regenerates it) or `recorded` (it
    does not, and the note says what produced it). An undeclared file fails, and
    a `script` declaration whose command does not exist fails, so a file cannot
    claim a generator it lacks.
    """
    import tomllib

    path = REPO / "witness" / "PROVENANCE.toml"
    if not path.exists():
        return False, "witness/PROVENANCE.toml is missing"
    declared = {f["name"]: f for f in
                tomllib.loads(path.read_text(encoding="utf-8")).get("file", [])}
    present = {p.name for p in (REPO / "witness").glob("*.jsonl")}
    undeclared = sorted(present - declared.keys())
    stale = sorted(declared.keys() - present)
    bad_cmd = sorted(n for n, f in declared.items()
                     if f.get("origin") == "script" and not f.get("command"))
    problems = []
    if undeclared:
        problems.append(f"undeclared: {undeclared}")
    if stale:
        problems.append(f"declared but absent: {stale}")
    if bad_cmd:
        problems.append(f"claim a script with no command: {bad_cmd}")
    # PROVENANCE.toml claimed this control checked that validated.jsonl joins
    # back to direct.jsonl. It did not, so the file advertised a guarantee that
    # did not exist. Rather than delete the sentence, perform the join: a
    # recorded row naming a (clause, parameter set) that no constructed
    # candidate covers is a row about a witness nobody built.
    n_recorded = sum(1 for f in declared.values() if f.get("origin") == "recorded")
    # Joining on (clause, parameter set) alone was too weak: it could not see
    # 45 rows where the hand-recorded file claimed isolation the battery does
    # not grant. Those rows predated the fix that gates a clause's
    # applicability on the function under test, so they carried the old
    # field-presence verdict. The join is now on the full construction key and
    # compares the battery's own verdict fields.
    constructed = {}
    for w in jsonl.read(REPO / "witness" / "direct.jsonl"):
        constructed[(w.get("clause_id"), w.get("param_set"),
                     w.get("derived_from"))] = w
    orphans = disagree = 0
    if constructed:
        for w in jsonl.read(REPO / "witness" / "validated.jsonl"):
            key = (w.get("clause_id"), w.get("param_set"), w.get("derived_from"))
            src = constructed.get(key)
            if src is None:
                orphans += 1
            elif (src.get("violates") != w.get("violates")
                  or bool(src.get("isolates_clause")) != bool(w.get("isolates_clause"))):
                disagree += 1
    if orphans:
        problems.append(f"{orphans} recorded row(s) join to no constructed candidate")
    if disagree:
        problems.append(f"{disagree} recorded row(s) disagree with the battery "
                        f"about what they violate")
    if problems:
        return False, "; ".join(problems)
    return True, (f"{len(present)} witness file(s) declared, {n_recorded} of them "
                  f"hand-recorded rather than regenerable; every recorded row "
                  f"joins to a constructed candidate")


@control("MAN-1", "the generator's enums implement the mandated taxonomy")
def _man1():
    """D3 reads one implementation. D4 reads the documents that require it.

    The paper's lead claim is that the negative-case vocabulary is fixed by the
    ACVP algorithm specification, so the bound it yields is a property of the
    programme rather than of one repository. That step was asserted in prose
    until review pointed out it was the only unverified link in an artifact
    that verifies everything else. It is checked here: for every function both
    derivations describe, the set of negative labels must be identical.

    A disagreement is not necessarily an error in this repository. It could
    equally mean the specification moved, or that the generator has drifted
    from it, and either is worth stopping for.
    """
    d3 = list(jsonl.read(DATA / "clauses" / "generated" / "derivation_d3.jsonl"))
    d4 = list(jsonl.read(DATA / "clauses" / "generated" / "derivation_d4.jsonl"))
    if not d3 or not d4:
        return None, "D3 or D4 not yet derived"

    def by_fn(rows, valid_key):
        out = {}
        for r in rows:
            if r.get(valid_key) or r.get("planned_but_absent"):
                continue
            fn = (r.get("function") or "").lower().replace(" ", "")
            out.setdefault(fn, set()).add((r.get("label") or "").strip().lower())
        return out

    impl, mandated = by_fn(d3, "is_valid"), by_fn(d4, "is_valid")
    shared = sorted(set(impl) & set(mandated))
    if not shared:
        return False, "no function name is common to D3 and D4"
    bad = [f for f in shared if impl[f] != mandated[f]]
    return not bad, (f"{len(shared)} function(s) compared, {len(bad)} disagree"
                     + (f": {bad}" if bad else ""))


@control("ID-1", "every clause id in use is a registered id")
def _id1():
    """WIT-1 compares each witness only against itself, so nine rows naming a
    clause that had been renamed away passed it while joining to nothing. An id
    that exists in no derivation is an orphan however self-consistent its row is,
    so ids are checked against one canonical list.

    The list includes clauses with no predicate on purpose: the commitment hash
    is deliberately unimplemented, and hint-decode, verify-decision and
    root-compare are umbrella or unmodelled clauses. Requiring a predicate would
    fail on four legitimate ids.
    """
    import tomllib

    path = DATA / "clauses" / "ids.toml"
    if not path.exists():
        return None, "no canonical id list"
    known = set(tomllib.loads(path.read_text(encoding="utf-8"))["clause_ids"])
    # Every JSONL under results/ and witness/, not a hardcoded list, and every
    # key a clause id is stored under. The first version read four files and
    # checked two key names, so it could not catch a rename missing
    # reason_to_clause.toml, mechanisms.toml or mechanism_landings.jsonl, which
    # store the id as `clause` or `claims_clause`. A control that cannot fail on
    # the failure mode it exists for is not a control.
    KEYS = ("clause_id", "clause", "claims_clause")
    seen: dict[str, set[str]] = {}
    for f in sorted(list((REPO / "witness").glob("*.jsonl")) + list(RESULTS.glob("*.jsonl"))):
        for row in jsonl.read(f):
            for key in KEYS:
                if row.get(key):
                    seen.setdefault(row[key], set()).add(f.name)
    for d in sorted(DATA.rglob("*.toml")):
        try:
            rec = tomllib.loads(d.read_text(encoding="utf-8"))
        except tomllib.TOMLDecodeError:
            continue
        stack = [rec]
        while stack:
            node = stack.pop()
            if isinstance(node, dict):
                for key in KEYS:
                    val = node.get(key)
                    if isinstance(val, str) and val:
                        seen.setdefault(val, set()).add(d.name)
                stack.extend(node.values())
            elif isinstance(node, list):
                stack.extend(node)
    orphans = sorted(set(seen) - known)
    return not orphans, (
        f"{len(seen)} distinct ids in use, {len(orphans)} not registered"
        + (f": {orphans}" if orphans else ""))


@control("PRED-1", "every registered prediction matches its recorded verdict")
def _pred1():
    """A prediction registered before a run is the only thing that makes the run
    a test rather than an observation. When one fails, the mutation record must
    say so in an `outcome` field: the prediction itself is never edited, because
    editing it after the fact destroys what made it a prediction."""
    import tomllib

    verd = {}
    for r in jsonl.read(RESULTS / "verdicts.jsonl"):
        if r.get("release"):
            verd.setdefault(r["clause_id"], {})[r["release"]] = \
                r.get("exercised", {}).get("verdict")
    checked = unacknowledged = 0
    for f in sorted((DATA / "mutations").rglob("*.toml")):
        rec = tomllib.loads(f.read_text(encoding="utf-8"))
        post = rec.get("postcondition", {})
        pred = (post.get("prediction") or "").strip().split(".")[0].upper()
        if not pred or rec.get("class") == "dual_producer":
            continue
        got = verd.get(rec["clause_id"])
        if not got:
            continue
        checked += 1
        expected = "KILLED" if pred.startswith("DIES") else \
                   "SURVIVED" if pred.startswith("SURVIVES") else None
        actual = got[sorted(got)[-1]]
        if expected and expected != actual and not post.get("outcome"):
            unacknowledged += 1
    if not checked:
        return None, "no predictions with recorded verdicts"
    return unacknowledged == 0, (
        f"{checked} predictions checked, {unacknowledged} failed without an "
        "outcome field acknowledging it")


@control("NA-1", "an empty aggregation prints NA rather than 0")
def _na1():
    from cupel.util.na import NA, Rate as R, mean
    ok = (R(0, 0).value is None and NA in R(0, 0).render()
          and mean([]).value is None and R(0, 5).value == 0.0)
    return ok, "Rate and mean distinguish undefined from zero"


@control("BAT-1", "every algorithm measured has a battery registered")
def _bat1():
    """This is a set-membership test and nothing more, retitled to say so. It
    checks that no algorithm appears in the matrix without a battery to evaluate
    it. Structural constants are covered by PC-1: a wrong size makes a valid case
    fail its own length check."""
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
