"""cupel command line.

Exit codes are contractual:
    0  success
    1  internal error
    2  a pin or lock hash did not verify
    3  an unadjudicated derivation disagreement, or an unmet precondition
    4  a control failed
    5  offline cache miss
"""

from __future__ import annotations

import argparse
import sys

from ..util import jsonl
from ..util.na import Rate
from ..vectors import census as censusmod
from ..vectors import fetch as fetchmod
from ..vectors import lock as lockmod
from ..vectors import pins as pinsmod

RESULTS = pinsmod.REPO / "results"


def _release_ids(args) -> list[str]:
    if args.release == "all":
        return [r.id for r in pinsmod.releases()]
    if args.release:
        return [pinsmod.release(args.release).id]
    return [pinsmod.latest_release().id]


def cmd_vectors_fetch(args) -> int:
    entries = lockmod.load()
    before = len(entries)
    n_files = 0
    for release_id in _release_ids(args):
        rel = pinsmod.release(release_id)
        print(f"release {rel.id} @ {rel.commit[:12]}  {rel.subject}")
        paths = [
            pinsmod.vector_path(vd.dir, fn)
            for vd in pinsmod.vector_dirs()
            for fn in (args.files or [pinsmod.REASON_FILE])
        ]
        if args.disposition:
            paths += pinsmod.disposition_files()
        for path in paths:
            data = lockmod.ensure(release_id, path, entries)
            n_files += 1
            print(f"  {len(data):>10d}  {path}")
    lockmod.save(entries)
    print(f"\nfetched {n_files} file(s); lock holds {len(entries)} entr(ies) "
          f"({len(entries) - before} new)")
    return 0


def cmd_vectors_verify(args) -> int:
    """Re-verify every locked blob against its recorded hash."""
    entries = lockmod.load()
    if not entries:
        print("lock is empty; nothing to verify")
        return 0
    ok, missing, bad = 0, [], []
    for (release_id, path), e in sorted(entries.items()):
        blob = fetchmod.cached(e.digest)
        if blob is None:
            missing.append((release_id, path))
        elif len(blob) != e.n_bytes:
            bad.append((release_id, path))
        else:
            ok += 1
    print(Rate(ok, len(entries), "locked blobs verified from cache").render())
    for release_id, path in missing:
        print(f"  not cached: {release_id} {path}")
    for release_id, path in bad:
        print(f"  SIZE MISMATCH: {release_id} {path}")
    return 2 if bad else 0


def cmd_vectors_census(args) -> int:
    entries = lockmod.load()
    all_census, all_hist = [], []
    for release_id in _release_ids(args):
        censuses, histogram = censusmod.run(release_id, entries)
        all_census += [c.as_record() for c in censuses]
        all_hist += histogram

        print(f"\nrelease {release_id}")
        print(f"  {'directory':38s} {'groups':>7s} {'cases':>7s} {'negative':>9s} {'reasons':>8s}")
        for c in censuses:
            print(f"  {c.dir:38s} {c.n_groups:>7d} {c.n_cases:>7d} "
                  f"{c.n_negative:>9d} {len(c.reasons):>8d}")
        total_cases = sum(c.n_cases for c in censuses)
        total_neg = sum(c.n_negative for c in censuses)
        print("  " + Rate(total_neg, total_cases, "negative case share").render())

        unknown = sorted({u for c in censuses for u in c.unknown_labels})
        if unknown:
            print(f"  unrecognised labels ({len(unknown)}): {unknown}")

    lockmod.save(entries)
    RESULTS.mkdir(parents=True, exist_ok=True)
    n1 = jsonl.write(RESULTS / "census.jsonl", all_census)
    n2 = jsonl.write(RESULTS / "reason_histogram.jsonl", all_hist)
    print(f"\nwrote results/census.jsonl ({n1} rows), results/reason_histogram.jsonl ({n2} rows)")
    return 0


def cmd_mechanics(args) -> int:
    """What a disposition can detect, as opposed to what its label claims."""
    import json

    from ..analysis import mechanics as mech

    entries = lockmod.load()
    release_id = _release_ids(args)[0]
    mechs = {m.id: m for m in mech.load()}
    target = mechs.get("mldsa.ModifyZ")
    if target is None:
        print("cupel: no mldsa.ModifyZ mechanism record", file=sys.stderr)
        return 1

    # Every signature the generator could perturb, not only the labelled ones.
    cases = []
    for vd in pinsmod.vector_dirs():
        if vd.algorithm != "ML-DSA" or vd.mode not in ("sigVer", "sigGen"):
            continue
        doc = json.loads(lockmod.ensure(release_id, pinsmod.vector_path(vd.dir, pinsmod.REASON_FILE),
                                        entries))
        for group in doc.get("testGroups", []):
            ps = group.get("parameterSet")
            for test in group.get("tests", []):
                sig = test.get("signature")
                if sig:
                    cases.append((ps, bytes.fromhex(sig)))
    lockmod.save(entries)

    reaches = mech.analyse_modify_z(cases, target)

    print(f"release {release_id}\n")
    print(f"  {target.id}   label {target.label!r}")
    print(f"  claims clause  {target.claims_clause}")
    print(f"  source         {target.source}")
    print(f"  expression     {target.expression}")
    print(f"  deterministic  {target.deterministic}\n")

    problems = []
    print(f"  {'parameter set':14s} {'signatures':>11s} {'coeffs':>7s} {'delta':>7s} "
          f"{'could breach':>13s} {'window/range':>13s} {'min headroom':>13s}")
    for ps in sorted(reaches):
        r = reaches[ps]
        problems += mech.verify_transcription(r, target)
        frac = r.window_fraction
        print(f"  {ps:14s} {r.n_cases:>11d} {sorted(r.n_coeffs_changed)!s:>7s} "
              f"{sorted({abs(d) for d in r.deltas})!s:>7s} {r.n_could_breach:>13d} "
              f"{frac if frac is None else f'{frac:.2e}':>13} {r.min_headroom:>13d}")

    total = sum(r.n_cases for r in reaches.values())
    breach = sum(r.n_could_breach for r in reaches.values())
    print("\n  " + Rate(breach, total, "signatures the perturbation could carry past the bound").render())

    if problems:
        print("\n  TRANSCRIPTION MISMATCH, the mechanism record does not describe the corpus:")
        for p in problems:
            print(f"    {p}")
        return 2
    print("  transcription verified against the corpus")

    if total and breach == 0:
        print(f"\n  {target.disposition} alters one coefficient by a bounded amount and so can")
        print(f"  violate {target.claims_clause} only when that coefficient already lies")
        print("  within the perturbation of the bound. It does so for no signature in this")
        print("  corpus. This is a property of the generator, not of the sample size.")

    RESULTS.mkdir(parents=True, exist_ok=True)
    rows = [r.as_record() | {"release": release_id} for r in reaches.values()]
    jsonl.write(RESULTS / "mechanism_reach.jsonl", rows)
    print(f"\nwrote results/mechanism_reach.jsonl ({len(rows)} rows)")
    return 0


def cmd_clauses_disposition(args) -> int:
    """Derivation D3: parse the generator's disposition enums."""
    from ..clauses import derive_disposition as d3

    entries = lockmod.load()
    release_id = _release_ids(args)[0]
    members = []
    for path in pinsmod.disposition_files():
        src = lockmod.ensure(release_id, path, entries).decode("utf-8-sig")
        members += d3.parse(src, path.split("/")[-1])
    lockmod.save(entries)

    bounds = d3.bounds(members)
    print(f"release {release_id}\n")
    print(f"  {'enum':38s} {'algorithm':10s} {'function':24s} {'members':>8s} {'negative':>9s}")
    for b in bounds:
        print(f"  {b.enum:38s} {b.algorithm:10s} {b.function:24s} "
              f"{b.n_members:>8d} {b.n_negative:>9d}")
    print()
    print("  Upper bound on distinct negative case kinds, per vector-set function.")
    print("  A function whose standard mandates more separable checks than its enum")
    print("  has negative members has clauses no generated set can exercise alone.\n")
    for b in bounds:
        for label in b.labels:
            print(f"    {b.function:24s} {label}")

    planned = [m for m in members if m.planned_but_absent]
    print()
    print(Rate(len(planned), len(members), "enum members named but not implemented").render())
    for m in planned:
        print(f"    {m.enum}::{m.name}  {m.note}")

    out = pinsmod.REPO / "data" / "clauses" / "generated" / "derivation_d3.jsonl"
    jsonl.write(out, [m.as_record() for m in members])
    jsonl.write(RESULTS / "disposition_bounds.jsonl", [b.as_record() for b in bounds])
    print(f"\nwrote {out.relative_to(pinsmod.REPO)} ({len(members)} rows)")
    return 0


def cmd_matrix(args) -> int:
    """Build the violation matrix and run the zero-column, masking and
    misattribution joins."""
    import json

    from ..analysis import misattribution as misattr
    from ..analysis import violation_matrix as vm

    entries = lockmod.load()
    all_rows, all_cols, all_findings = [], [], []
    # Clause columns are per algorithm. Evaluating an ML-KEM clause against an
    # ML-DSA case would report six spurious ABSENT columns and a coverage rate
    # of zero, which is a statement about the battery rather than the corpus.
    known = {p.clause_id for battery in vm.BATTERIES.values() for p in battery}
    labels = misattr.load_labels()

    for release_id in _release_ids(args):
        rel = pinsmod.release(release_id)
        by_algo: dict[str, list] = {}
        for vd in pinsmod.vector_dirs():
            if vd.algorithm not in vm.BATTERIES:
                continue
            if args.dir and args.dir not in vd.dir:
                continue
            path = pinsmod.vector_path(vd.dir, pinsmod.REASON_FILE)
            doc = json.loads(lockmod.ensure(release_id, path, entries))
            by_algo.setdefault(vd.algorithm, []).extend(
                vm.build(doc, vd.dir, vd.algorithm, vd.mode))

        n_total = sum(len(v) for v in by_algo.values())
        print(f"\nrelease {release_id} @ {rel.commit[:12]}   {n_total} cases")

        for algorithm in sorted(by_algo):
            rows = by_algo[algorithm]
            clause_ids = [p.clause_id for p in vm.BATTERIES[algorithm]]
            cols = vm.columns(rows, clause_ids)
            findings = misattr.check(rows, labels, known)

            print(f"\n  {algorithm}  ({len(rows)} cases)")
            print(f"    {'status':9s} {'clause':44s} {'violating':>10s} "
                  f"{'isolated':>9s} {'applicable':>11s}")
            for c in cols:
                print(f"    {c.status:9s} {c.clause_id:44s} {c.n_violating:>10d} "
                      f"{c.n_isolated:>9d} {c.n_applicable:>11d}")
            print("    " + vm.coverage(cols).render())

            for c in cols:
                if c.status == "ABSENT":
                    print(f"      ABSENT: no case violates {c.clause_id}. "
                          f"Deleting this check cannot be caught by this corpus.")
                elif c.status == "MASKED":
                    masks = sorted(c.co_violated_with.items(), key=lambda kv: -kv[1])
                    print(f"      MASKED: {c.clause_id} is never violated alone; "
                          f"always with {masks[0][0]} ({masks[0][1]} cases)")

            scored = [f for f in findings if f.status in ("attributed", "misattributed")]
            bad = [f for f in scored if f.misattributed]
            print("    " + Rate(len(bad), len(scored), "negative vectors misattributed").render())
            by_reason: dict[str, list] = {}
            for f in bad:
                by_reason.setdefault(f.reason, []).append(f)
            for reason in sorted(by_reason):
                fs = by_reason[reason]
                n_tot = sum(1 for f in scored if f.reason == reason)
                print("      " + Rate(len(fs), n_tot, reason).render())
                ex = fs[0]
                print(f"        example tcId {ex.tc_id}: label names {ex.claimed}, "
                      f"case violates {sorted(ex.violated) or 'nothing in this battery'}")
            skipped = [f for f in findings if f.status in ("no-predicate", "unmapped-label")]
            if skipped:
                reasons = sorted({f.reason for f in skipped})
                print(f"    not scored, no predicate for the clause they name: "
                      f"{len(skipped)} ({', '.join(reasons)})")

            all_rows += [r.as_record() | {"release": release_id} for r in rows]
            all_cols += [c.as_record() | {"release": release_id} for c in cols]
            all_findings += [f.as_record() | {"release": release_id} for f in findings]

    lockmod.save(entries)
    RESULTS.mkdir(parents=True, exist_ok=True)
    jsonl.write(RESULTS / "violation_matrix.jsonl", all_rows)
    jsonl.write(RESULTS / "columns.jsonl", all_cols)
    jsonl.write(RESULTS / "misattribution.jsonl", all_findings)
    print(f"\nwrote results/violation_matrix.jsonl ({len(all_rows)} rows), "
          f"columns.jsonl ({len(all_cols)}), misattribution.jsonl ({len(all_findings)})")
    return 0


def cmd_diff(args) -> int:
    """Diff two pinned releases at the level of individual test cases."""
    import json

    from ..differ import report as diffmod

    entries = lockmod.load()
    a, b = pinsmod.release(args.from_release), pinsmod.release(args.to_release)
    print(f"from {a.id} @ {a.commit[:12]}  {a.subject}")
    print(f"to   {b.id} @ {b.commit[:12]}  {b.subject}\n")

    rows = []
    for vd in pinsmod.vector_dirs():
        if args.dir and args.dir not in vd.dir:
            continue
        path = pinsmod.vector_path(vd.dir, pinsmod.REASON_FILE)
        old = json.loads(lockmod.ensure(a.id, path, entries))
        new = json.loads(lockmod.ensure(b.id, path, entries))
        d = diffmod.diff_dir(vd.dir, vd.mode, a.id, b.id, old, new)
        rows.append(d.as_record())
        if not d.changed:
            continue
        print(f"  {d.vdir}")
        print(f"    cases {d.n_cases_from} -> {d.n_cases_to}   "
              f"matched {d.n_matched_structural} structural, {d.n_matched_content} by content")
        if d.n_added or d.n_removed:
            print(f"    added {d.n_added}, removed {d.n_removed}")
        print("    " + Rate(d.n_input_changed, d.n_cases_to, "input bytes changed").render())
        print("    " + Rate(d.n_expectation_flipped, d.n_cases_to, "expectations flipped").render())
        print("    " + Rate(d.n_reason_changed, d.n_cases_to, "labels changed at slot").render())
        print("    " + Rate(d.n_groups_recomposed, d.n_groups, "groups recomposed").render())
        if d.composition_delta:
            print("    corpus composition delta:")
            for label, delta in sorted(d.composition_delta.items()):
                print(f"      {delta:+5d}  {label}")
        else:
            print("    corpus composition delta: none, the mix of labels is unchanged")

    changed = [r for r in rows if r["changed"]]
    total_flips = sum(r["n_expectation_flipped"] for r in rows)
    print()
    print(Rate(len(changed), len(rows), "directories changed").render())
    print(f"  expectations flipped across the whole corpus: {total_flips}")
    if changed and total_flips == 0:
        print("\n  Note: vector content changed while no expectation changed anywhere.")
        print("  Nothing an implementation must do to pass has changed.")

    RESULTS.mkdir(parents=True, exist_ok=True)
    out = RESULTS / f"diff_{a.id}_{b.id}.jsonl"
    jsonl.write(out, rows)
    lockmod.save(entries)
    print(f"\nwrote {out.relative_to(pinsmod.REPO)} ({len(rows)} rows)")
    return 0


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="cupel", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="group", required=True)

    vectors = sub.add_parser("vectors", help="acquire and characterise ACVP vector sets")
    vsub = vectors.add_subparsers(dest="cmd", required=True)

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--release", help="pinned release id, or 'all' (default: newest pinned)")

    p = vsub.add_parser("fetch", parents=[common], help="fetch pinned files into the cache")
    p.add_argument("--files", nargs="*", help=f"filenames (default: {pinsmod.REASON_FILE})")
    p.add_argument("--disposition", action="store_true", help="also fetch the C# disposition enums")
    p.set_defaults(func=cmd_vectors_fetch)

    p = vsub.add_parser("verify", parents=[common], help="re-verify locked blobs")
    p.set_defaults(func=cmd_vectors_verify)

    p = vsub.add_parser("census", parents=[common], help="count groups, cases, negatives, reasons")
    p.set_defaults(func=cmd_vectors_census)

    clauses = sub.add_parser("clauses", help="derive and reconcile the clause list")
    csub = clauses.add_subparsers(dest="cmd", required=True)
    p = csub.add_parser("disposition", parents=[common],
                        help="derivation D3: parse the generator disposition enums")
    p.set_defaults(func=cmd_clauses_disposition)

    p = sub.add_parser("mechanics", parents=[common],
                       help="what a disposition can detect, not what its label claims")
    p.set_defaults(func=cmd_mechanics)

    p = sub.add_parser("matrix", parents=[common],
                       help="build the violation matrix and run its joins")
    p.add_argument("--dir", help="restrict to vector directories matching this substring")
    p.set_defaults(func=cmd_matrix)

    p = sub.add_parser("diff", help="diff two pinned releases case by case")
    p.add_argument("--from", dest="from_release", required=True, help="pinned release id")
    p.add_argument("--to", dest="to_release", required=True, help="pinned release id")
    p.add_argument("--dir", help="restrict to vector directories matching this substring")
    p.set_defaults(func=cmd_diff)

    return ap


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except fetchmod.OfflineMiss as exc:
        print(f"cupel: {exc}", file=sys.stderr)
        return 5
    except fetchmod.HashMismatch as exc:
        print(f"cupel: hash mismatch\n{exc}", file=sys.stderr)
        return 2
    except KeyError as exc:
        print(f"cupel: {exc}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
