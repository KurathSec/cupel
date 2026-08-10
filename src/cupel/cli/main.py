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
from ..util.na import Rate, count
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
    """Where each disposition's perturbation actually lands, resolved from source."""
    from ..analysis import mechanics as mech

    mechs = [m for m in mech.load() if m.algorithm == "ML-DSA"]
    rows = []
    print("Resolving each BitString index against the FIPS 204 signature layout.\n")
    print("  BitString.Bits is documented \"In LSb\" and is built by reversing the byte")
    print("  order, so Bits[i] addresses byte (n - 1 - i div 8) from the END.\n")
    print(f"  {'disposition':16s} {'param set':12s} {'bit':>7s} {'byte':>6s} "
          f"{'region':8s} {'slot':>5s}  {'reaches its claimed clause?'}")
    for m in mechs:
        for land in mech.land_mldsa(m):
            verdict = "yes" if land.reaches_claim else "NO"
            slot = "" if land.lsb_slot is None else str(land.lsb_slot)
            print(f"  {m.disposition:16s} {land.param_set:12s} {land.bit_index:>7d} "
                  f"{land.lsb_offset:>6d} {land.lsb_region:8s} {slot:>5s}  {verdict}")
            rows.append(land.as_record())
        print()

    missed = [r for r in rows if not r["reaches_claimed_region"]]
    print("  " + Rate(len(missed), len(rows), "landings that miss the region their label names").render())
    for r in missed:
        print(f"    {r['mechanism_id']} {r['param_set']}: claims {r['claims_clause']}, "
              f"lands in {r['region']} slot {r['slot_within_region']}")
        print(f"      under the MSB reading this module first assumed it would have been "
              f"{r['msb_would_be_region']}, which is how the error arose")

    RESULTS.mkdir(parents=True, exist_ok=True)
    jsonl.write(RESULTS / "mechanism_landings.jsonl", rows)
    print(f"\nwrote results/mechanism_landings.jsonl ({len(rows)} rows)")
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


def cmd_clauses_defs(args) -> int:
    """Derivation D1b: candidates from definitions rather than from tags."""
    from ..clauses import derive_defs as d1b

    entries = lockmod.load()
    pins = pinsmod.load()
    cs = pins["cryptol_specs"]
    alld = []
    print(f"cryptol-specs @ {cs['commit'][:12]}\n")
    for f in cs["files"]:
        src = lockmod.ensure_source("cryptol-specs", cs["repo"], cs["commit"],
                                    f["path"], entries).decode()
        ds = d1b.extract(src, f["path"])
        d1b.propose(ds)
        alld += ds
        print(f"  {f['path'].split('/')[-1]:22s} {f['doc']}  {len(ds):>3d} definitions")
    lockmod.save(entries)

    adj = list(jsonl.read(pinsmod.REPO / d1b.ADJUDICATIONS))
    n_adj = d1b.apply_adjudications(alld, adj)
    if n_adj:
        print(f"\n  applied {n_adj} recorded adjudication(s)")

    inb = [d for d in alld if d.proposed_surface == "api_boundary_checkable"]
    untagged = [d for d in inb if not d.tagged]
    undecided = [d for d in alld if d.proposed_surface is None]
    print()
    print("  " + Rate(len(inb), len(alld), "proposed boundary-checkable").render())
    print("  " + Rate(len(untagged), len(inb), "of those, carrying NO citation").render())
    print(f"  needing a recorded decision: {len(undecided)}")
    print()
    print("  Clauses a tag-based derivation cannot see:")
    for d in sorted(untagged, key=lambda d: d.name):
        print(f"    {d.name:34s} {d.proposed_why}")
    if undecided:
        print()
        print("  Undecided, proposed by name shape alone:")
        for d in undecided:
            print(f"    {d.name:34s} {d.proposed_why}")

    out = pinsmod.REPO / "data" / "clauses" / "generated" / "candidates.jsonl"
    jsonl.write(out, [d.as_record() for d in alld])
    print(f"\nwrote {out.relative_to(pinsmod.REPO)} ({len(alld)} rows)")
    return 0


def cmd_witness(args) -> int:
    """Construct a witness for every clause that can have one, per parameter set.

    Generalised across parameter sets deliberately. A witness that exists only
    for ML-DSA-44 is evidence about ML-DSA-44, and a partial vector set is a
    worse contribution upstream than none at all.
    """
    import json

    from ..analysis import witness as wit

    entries = lockmod.load()
    release_id = _release_ids(args)[0]

    # One valid source case per (directory, function, parameter set), so a
    # keyGen case cannot shadow the sigVer case that carries a signature.
    sources = {}
    for vd in pinsmod.vector_dirs():
        if vd.algorithm not in wit.BATTERIES:
            continue
        doc = json.loads(lockmod.ensure(
            release_id, pinsmod.vector_path(vd.dir, pinsmod.REASON_FILE), entries))
        for group in doc.get("testGroups", []):
            for test in group.get("tests", []):
                reason = test.get("reason") or ""
                if reason and not reason.startswith("valid"):
                    continue
                key = (vd.algorithm, vd.dir, group.get("function", ""),
                       group.get("parameterSet", ""))
                sources.setdefault(key, (test, group, vd.dir, test.get("tcId")))
    lockmod.save(entries)

    ALGO = {"fips203": "ML-KEM", "fips204": "ML-DSA", "fips205": "SLH-DSA"}
    built = []
    for clause, (field_name, _, _) in wit.DIRECT.items():
        algo = ALGO[clause.split(".")[0]]
        for (a, d, fn, ps), (t, g, dd, tc) in sorted(sources.items()):
            if a != algo or not t.get(field_name):
                continue
            w = wit.construct_direct(clause, t, g, a, f"{dd} tcId {tc}")
            if w:
                built.append(w)
    for (a, d, fn, ps), (t, g, dd, tc) in sorted(sources.items()):
        if a == "ML-DSA" and t.get("signature"):
            w = wit.construct_hint_weight(t, g, f"{dd} tcId {tc}")
            if w:
                built.append(w)
        if a == "ML-KEM" and t.get("dk"):
            w = wit.construct_dk_embedded_modulus(t, g, f"{dd} tcId {tc}")
            if w:
                built.append(w)

    by_clause = {}
    for w in built:
        by_clause.setdefault(w.clause_id, []).append(w)
    print(f"  {'clause':38s} {'param sets':>10s} {'isolating':>10s}")
    for clause, ws in sorted(by_clause.items()):
        iso = sum(1 for w in ws if w.isolates)
        print(f"  {clause:38s} {len({w.param_set for w in ws}):>10d} {iso:>4d}/{len(ws):<5d}")
    print()
    print("  " + Rate(sum(1 for w in built if w.isolates), len(built),
                      "witnesses isolating exactly their clause").render())
    out = wit.witness_path("direct.jsonl")
    jsonl.write(out, [w.as_record() for w in built])
    print(f"wrote {out.relative_to(pinsmod.REPO)} ({len(built)} rows)")
    return 0


def cmd_clauses_sites(args) -> int:
    """Derivation D2: where each target actually rejects an input."""
    from pathlib import Path

    from ..clauses import derive_sites as d2

    sites = []
    for target, subdir in (("mlkem-native", "mlkem/src"), ("mldsa-native", "mldsa/src")):
        root = pinsmod.REPO / "vendor" / target
        found = d2.scan_target(root, target, subdir)
        sites += found
        print(f"  {target:16s} {len(found):>3d} rejection sites in "
              f"{len({s.path for s in found})} file(s)")
    if not sites:
        print("cupel: no vendored target trees present", file=sys.stderr)
        return 1
    print()
    print(f"  {'function':34s} {'target':14s} {'n':>3s}")
    for fn, ss in sorted(d2.by_function(sites).items(), key=lambda kv: (kv[1][0].target, -len(kv[1]))):
        print(f"  {fn:34s} {ss[0].target:14s} {len(ss):>3d}")
    out = pinsmod.REPO / "data" / "clauses" / "generated" / "derivation_d2.jsonl"
    jsonl.write(out, [s.as_record() for s in sites])
    print(f"\nwrote {out.relative_to(pinsmod.REPO)} ({len(sites)} rows)")
    return 0


def cmd_clauses_reconcile(args) -> int:
    """Set the three derivations against each other. KT3, mechanised."""
    from ..clauses import reconcile as rec

    gen = pinsmod.REPO / "data" / "clauses" / "generated"
    cells = rec.build(list(jsonl.read(gen / "candidates.jsonl")),
                      list(jsonl.read(gen / "derivation_d2.jsonl")),
                      list(jsonl.read(gen / "derivation_d3.jsonl")))
    if not cells:
        print("cupel: run `clauses defs`, `clauses sites` and `clauses disposition` first",
              file=sys.stderr)
        return 3
    for c in cells:
        print(f"  {c.clause:40s} {c.code}")
    agree = [c for c in cells if not c.needs_decision]
    print()
    print("  " + Rate(len(agree), len(cells), "cells where all three agree").render())
    RESULTS.mkdir(parents=True, exist_ok=True)
    jsonl.write(RESULTS / "reconciliation.jsonl", [c.as_record() for c in cells])
    print(f"wrote results/reconciliation.jsonl ({len(cells)} rows)")
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


def cmd_measure(args) -> int:
    """Run every mutation for a target and persist the verdicts.

    The mutation spine had been run by hand, which by this project's own rule
    means its results were not yet numbers. This makes them regenerable: one
    record per (clause, target, release) written to results/verdicts.jsonl, with
    the sentinel outcome recorded alongside so a run whose sentinel survived can
    be voided rather than believed.
    """
    from ..mutate import anchor as anchormod
    from ..targets import native

    target = args.target
    tree = native.tree(target)
    if not tree.exists():
        print(f"cupel: {tree} not present; clone the pinned target first", file=sys.stderr)
        return 1

    entries = lockmod.load()
    releases = _release_ids(args)
    for rel in releases:
        native.export_corpus(target, rel, entries)
    lockmod.save(entries)

    muts = [m for m in anchormod.load_for(target) if m.cls != "dual_producer"]
    if not muts:
        print(f"cupel: no mutation records for {target}")
        return 0

    # Anchors first. This needs no build and catches upstream drift immediately.
    drift = {m.mutation_id: anchormod.check(m, tree) for m in muts}
    bad = {k: v for k, v in drift.items() if v}
    for k, v in bad.items():
        print(f"  ANCHOR DRIFT {k}: {v}", file=sys.stderr)
    muts = [m for m in muts if not drift[m.mutation_id]]

    print(f"target {target}   {len(muts)} mutation(s)   releases {', '.join(releases)}\n")
    baseline = {}
    for rel in releases:
        native.build(target)
        baseline[rel] = native.run_acvp(target, rel).passed
        print(f"  baseline {rel}: {'PASS' if baseline[rel] else 'FAIL'}")
    if not all(baseline.values()):
        print("cupel: a baseline failed; no mutant verdict from this run is meaningful",
              file=sys.stderr)
        return 4

    rows, sentinels = [], []
    print()
    print(f"  {'clause':34s} " + " ".join(f"{r:>13s}" for r in releases))
    for m in sorted(muts, key=lambda m: not m.is_sentinel):
        originals = anchormod.apply(m, tree)
        try:
            build = native.build(target)
            if build.returncode != 0:
                print(f"  {m.clause_id:34s} BUILD_FAILED")
                rows.append({"schema": "verdict/1", "clause_id": m.clause_id,
                             "target": target, "verdict": "BUILD_FAILED",
                             "mutation_id": m.mutation_id})
                continue
            verdicts = {}
            for rel in releases:
                verdicts[rel] = "SURVIVED" if native.run_acvp(target, rel).passed else "KILLED"
            print(f"  {m.clause_id:34s} " + " ".join(f"{verdicts[r]:>13s}" for r in releases))
            for rel, v in verdicts.items():
                rows.append({
                    "schema": "verdict/1", "clause_id": m.clause_id, "target": target,
                    "release": rel, "mutation_id": m.mutation_id,
                    "is_sentinel": m.is_sentinel, "prediction": m.prediction.strip(),
                    "exercised": {"verdict": v, "kill_mode": m.kill_mode},
                })
            if m.is_sentinel:
                sentinels.append(all(v == "KILLED" for v in verdicts.values()))
        finally:
            anchormod.restore(originals, tree)
    native.build(target)

    RESULTS.mkdir(parents=True, exist_ok=True)
    existing = [r for r in jsonl.read(RESULTS / "verdicts.jsonl")
                if r.get("target") != target]
    jsonl.write(RESULTS / "verdicts.jsonl", existing + rows)
    print()
    if sentinels and not all(sentinels):
        print("  SENTINEL SURVIVED. This run is void; no verdict above may be believed.",
              file=sys.stderr)
        return 4
    print("  " + Rate(sum(sentinels), len(sentinels), "sentinels killed as required").render())
    print(f"wrote results/verdicts.jsonl ({len(existing) + len(rows)} rows)")
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


def cmd_divergence(args) -> int:
    """Compare the published producer source against the vectors it should produce."""
    import json

    from ..analysis import divergence as dv

    entries = lockmod.load()
    releases = pinsmod.releases()
    # BOTH encapsulation directories. The first version read only the tr1 set
    # and reported 15 invalid keys per release, which is half the population:
    # the non-tr1 set carries 15 more, all distinct. The violation matrix had
    # been reporting 30 isolated violations for the same clause all along, so
    # the two artifacts disagreed and the smaller number reached the paper.
    dirs = [d.dir for d in pinsmod.vector_dirs()
            if d.algorithm == "ML-KEM" and d.mode == "encapDecap"]

    keys, sources = [], []
    for rel in releases:
        for vdir in dirs:
            projection = json.loads(
                lockmod.ensure(rel.id, pinsmod.vector_path(vdir, pinsmod.REASON_FILE),
                               entries).decode("utf-8-sig"))
            keys += dv.measure_release(rel.id, projection, vdir)
        for src in pinsmod.manipulator_files():
            data = lockmod.ensure(rel.id, src, entries)
            sources.append(dv.digest_source(rel.id, rel.commit, src, data))
    lockmod.save(entries)

    if not keys:
        print("divergence: no invalid encapsulation keys found in any pinned release",
              file=sys.stderr)
        return 2

    print(f"  {'release':12s} {'keys':>5s} {'length delta':>14s} "
          f"{'out-of-range':>13s} {'values':>10s}")
    summary = dv.summarise(keys, sources)
    for row in summary:
        print(f"  {row['release']:12s} {row['n_invalid_keys']:5d} "
              f"{str(row['length_deltas']):>14s} "
              f"{str(row['out_of_range_counts']):>13s} "
              f"{str(row['out_of_range_values']):>10s}")

    print()
    for row in summary:
        clean = row["n_keys_with_no_violation"]
        if clean:
            print(f"  {row['release']}: {clean} of {row['n_invalid_keys']} invalid key(s) "
                  f"are the standard length and carry no out-of-range coefficient.")

    unchanged = dv.unchanged_sources(sources)
    n_releases = len({s.release for s in sources})
    print()
    print(count(f"  producer sources byte-identical across all {n_releases} pinned releases",
                len(unchanged)))
    for path_, digests in unchanged.items():
        print(f"      {path_}")
        print(f"        {digests[0]}")

    # The comparison the whole command exists for. Only report it when the data
    # actually moved: identical source over identical data is not a divergence,
    # it is a repository that did not change.
    shapes = {(tuple(r["length_deltas"]), tuple(r["out_of_range_counts"]))
              for r in summary}
    if unchanged and len(shapes) > 1:
        print()
        print(f"  DIVERGENCE: the invalid keys take {len(shapes)} distinct shapes across "
              f"these\n  releases while {len(unchanged)} producer source(s) did not change "
              f"at all.\n  Regenerating from the published source cannot yield more than one "
              f"of them.")
    elif unchanged:
        print("\n  No divergence: the source did not change and neither did the data.")

    # How near the corpus gets to the bound it never crosses. An empty column
    # says nothing about whether the vectors were aimed at the bound and missed
    # or never aimed at all, and the answer differs by release.
    margins, msum = [], []
    zpath = pinsmod.vector_path("ML-DSA-sigVer-FIPS204", pinsmod.REASON_FILE)
    for rel in releases:
        doc = json.loads(lockmod.ensure(rel.id, zpath, entries).decode("utf-8-sig"))
        margins += dv.z_margins(doc, rel.id, "modified signature - z")
    lockmod.save(entries)
    if margins:
        msum = dv.summarise_margins(margins)
        print()
        print(f"  Largest |z| in the cases labelled for a large z, against the bound")
        print(f"  {'release':12s} {'param set':12s} {'cases':>5s} {'peak |z|':>10s} "
              f"{'bound':>8s} {'closest':>8s} {'violating':>10s}")
        for r in msum:
            print(f"  {r['release']:12s} {r['param_set']:12s} {r['n_cases']:5d} "
                  f"{r['max_abs_z_max']:10d} {r['bound']:8d} {r['closest_margin']:8d} "
                  f"{r['n_violating']:10d}")

    RESULTS.mkdir(parents=True, exist_ok=True)
    if margins:
        jsonl.write(RESULTS / "z_margins.jsonl", msum)
    jsonl.write(RESULTS / "divergence.jsonl", summary)
    jsonl.write(RESULTS / "divergence_keys.jsonl", [k.as_record() for k in keys])
    jsonl.write(RESULTS / "divergence_sources.jsonl", [s.as_record() for s in sources])
    print(f"\nwrote results/divergence.jsonl ({len(summary)} rows), "
          f"divergence_keys.jsonl ({len(keys)}), "
          f"divergence_sources.jsonl ({len(sources)})")
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
    p = csub.add_parser("sites", help="derivation D2: implementation rejection sites")
    p.set_defaults(func=cmd_clauses_sites)
    p = csub.add_parser("reconcile", help="set the three derivations against each other")
    p.set_defaults(func=cmd_clauses_reconcile)
    p = csub.add_parser("defs", help="derivation D1b: candidates from definitions")
    p.set_defaults(func=cmd_clauses_defs)
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

    p = sub.add_parser("witness", parents=[common],
                       help="construct a witness per clause per parameter set")
    p.set_defaults(func=cmd_witness)

    p = sub.add_parser("measure", parents=[common],
                       help="run every mutation for a target and persist the verdicts")
    p.add_argument("--target", required=True, help="e.g. mldsa-native")
    p.set_defaults(func=cmd_measure)

    p = sub.add_parser("divergence",
                       help="compare the producer source against the vectors it should produce")
    p.set_defaults(func=cmd_divergence)

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
