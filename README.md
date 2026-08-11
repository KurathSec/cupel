# cupel

A coverage meter over the ACVP validation path for FIPS 203 and FIPS 204, with partial
coverage of FIPS 205.

A module that holds a FIPS 140-3 certificate for ML-KEM or ML-DSA passed ACVP. What nobody can
say today is **what passing means**: which normative clauses of the standard the mandated vector
set actually exercises, and which ones an implementation could get wrong while still passing
everything.

cupel answers that as a measurement. Point it at an implementation and a vector set and it prints
one row per API-boundary-checkable normative clause, with two columns in each row, each carrying
its `n`:

| column | meaning |
|---|---|
| `status` | the violation matrix column: `ABSENT` if no applicable case violates the clause, `MASKED` if every violating case also violates another modelled clause, `COVERED` if some case violates it alone |
| `exercised` | deleting exactly that check from a real implementation causes at least one mandated ACVP vector to change verdict |

The second is the one that does not exist elsewhere. The first is cheap and is what makes the
second affordable: mutation means building a patched cryptographic library and replaying thousands
of vectors, so the matrix decides where that is worth spending.

A third column, `reachable`, was specified and is **not built**. It was to record whether a check
is reachable from the public API, read from the exported symbol table and public headers.
`src/cupel/reach/` is an empty package. Read every result as two columns.

## Status

The corpus census, the violation matrix, the mutation spine, the witness constructions and the
three clause derivations all run and write committed results. What is not built: the `reachable`
column, the second implementation lineage described below, and a FIPS 205 clause source.
`bin/regen.py` prints `NA` for everything not yet measured and refuses to print a headline until
its preconditions hold. That is the intended behaviour and not a gap.

## How it works

**The violation matrix is the primary mechanism.** A non-short-circuiting predicate battery
evaluates every normative predicate independently against every test case, producing
`V[testCase][clause]`. Real implementations short-circuit, so a check that is present can be
permanently masked by an earlier one, and a first-order mutant survives identically whether the
input class is absent or merely masked. Everything falls out of `V`:

- a clause whose column is all-zero is never exercised, and a surviving mutant is guaranteed
- a clause whose every violation co-occurs with another is masked, not absent
- joining `V` against each vector's own `reason` label yields a **misattribution rate**: negative
  vectors that cannot fail for the reason they claim
- any input violating one clause and nothing else is the witness that would close the gap

**Mutation on real implementations remains the oracle.** `V` predicts kill or survive; deleting
the check from mlkem-native or mldsa-native decides. Every prediction is registered in the mutation
record before the run, and control PRED-1 fails if a verdict contradicts one without an `outcome`
field acknowledging it.

**The two directions are not equally sound, and that asymmetry was learned the hard way.** An
`ABSENT` column predicts survival soundly: if no applicable case violates the clause, the branch is
never taken and removing it cannot change a verdict. A `COVERED` column predicts death only
conditionally, because "isolated" means isolated among the clauses the battery *models*. If an
unmodelled check rejects the same case, removing the modelled one moves the rejection site without
changing the verdict. This is not hypothetical: the registered prediction for
`fips204.alg21.hint-trailing-zeros` was `DIES`, the mutant survived, and the reason is the FIPS 204
commitment hash, a near-universal backstop the battery deliberately does not model. The failed
prediction is left in `data/mutations/mldsa-native/` verbatim, with its `outcome` recorded beside
it. Editing it would have destroyed the only property that made it a prediction.

A clause counts as exercised if it is killed in **any** substrate, which maximises the numerator
and so minimises the claimed gap.

The intended converse rule is that a clause counts as unexercised only if it survives across
substrates spanning at least two distinct code lineages, since OpenSSL's ML-KEM is a port of
BoringSSL's and counting those as independent would be wrong. **That rule is not implemented.**
Only one substrate family is wired up today, pq-code-package's mlkem-native and mldsa-native, so
every survival currently rests on a single lineage and `bin/regen.py` applies no lineage test. Read
the survivals accordingly, and treat this paragraph as a specification of what a second lineage
must be made to satisfy rather than as a description of what runs.

## Discipline

Two rules the project holds itself to. The first is enforced by CI on every commit. The second
is enforced by a control that CI runs, with one gap stated below.

**A number does not exist until a committed script regenerates it from committed data.**
`bin/regen.py` is the only place a quotable number is printed. Every figure carries its `n`. An
empty aggregation prints `NA`, never `0`, because zero killed out of forty is a finding and an
unrun experiment is not. `cupel.util.na.Rate` is the only division primitive in the codebase and
it raises rather than return a ratio above 1.0.

**Mutations are anchored content rewrites, not line ranges.** Each mutation record names the file,
the pinned target commit, the exact anchor text and the required occurrence count. If the anchor
does not match exactly, `check()` reports the mismatch and `apply()` refuses; it is never applied
to a best guess. Control MUT-1 runs that check with no build at all, so drift surfaces the moment
a pin moves. The gap: MUT-1 needs the vendored targets, and CI does not clone them, so there it
skips rather than passes and `selfcheck` still exits 0. Run `python -m cupel targets clone`
locally to make it bite. For a tool whose headline is "this mutant survived", a silently misapplied mutation
is the worst available failure, and line ranges fail silently under upstream drift.

## Scope, and what this does not show

- A clause the suite does not exercise is a gap in the validation, **not** a defect in any
  particular implementation. Conflating those would be dishonest.
- The measurement covers API-boundary-checkable clauses only. Clauses about internal state, side
  channel behaviour or key lifecycle are out of scope by construction, so the fraction is over a
  stated subset and never over "the standard".
- A surviving mutant says the vectors would not have caught that deletion. Whether a real
  implementation would ever make that mistake is a separate question this tool does not answer.
- Laboratories may run vectors beyond the mandated set.
- The empirical arm measures the vector files committed to `usnistgov/ACVP-Server` at a pinned
  commit. Those are samples; the production suite is generated from a database that is not public.
  Only the disposition-enum bound speaks to what a laboratory actually receives, and it is
  reported separately for that reason.

## Install

```
pip install -e ".[dev]"
```

The mutation arm needs the two pinned substrates, which are gitignored and
reproduced rather than committed:

```
python -m cupel targets clone      # clones into vendor/ at the pins in data/pins.toml
python -m cupel vectors fetch      # pinned vector data, hash-verified on read
```

Without the substrates, control MUT-1 skips rather than passes and `cupel
measure` refuses; `bin/selfcheck.py` says which.

## Regenerating everything from the pins

Artifact evaluation found this undocumented: the order had to be reconstructed
by reading `src/cupel/cli/main.py`. It is the artifact's central claim, so it
belongs here.

```
python -m cupel vectors fetch --release all --disposition   # ~108 MB, hash-verified
python -m cupel vectors census --release all                # results/census.jsonl, reason_histogram.jsonl
python -m cupel clauses spec                                # data/clauses/generated/clauses.jsonl      (D1)
python -m cupel clauses defs                                # ...candidates.jsonl                       (D1b)
python -m cupel clauses disposition                         # ...derivation_d3.jsonl, disposition_bounds (D3)
python -m cupel clauses mandate                             # ...derivation_d4.jsonl                     (D4)
python -m cupel clauses sites                               # ...derivation_d2.jsonl                     (D2)
python -m cupel clauses reconcile                           # results/reconciliation.jsonl
python -m cupel mechanics                                   # results/mechanism_landings.jsonl
python -m cupel matrix --release all                        # results/violation_matrix.jsonl, columns, misattribution
python -m cupel witness                                     # witness/direct.jsonl
python -m cupel divergence                                  # results/divergence*.jsonl, z_margins.jsonl
python -m cupel diff --from r2026-07-24 --to r2026-07-28    # results/diff_*.jsonl
python -m cupel diff --from r2026-07-28 --to r2026-07-31
python -m cupel measure --target mldsa-native --release r2026-07-31   # results/verdicts.jsonl
python -m cupel measure --target mlkem-native --release all
```

`clauses sites` and both `measure` commands need the vendored substrates, and
`measure` additionally needs `make` and a C compiler; it builds each target once
per mutation and replays the corpus, so budget ten to twenty minutes per arm.
Everything else runs from the cache alone.

Two things worth knowing. `bin/*.py` run under a bare interpreter with no
install, since they put `src/` on the path themselves; the `pip install` above is
needed only for the `cupel` console script and for `pytest`. And under an
editable install `python -m cupel` resolves to the installed tree regardless of
the current directory, so run it from the repository you mean to modify. Set `CUPEL_OFFLINE=1` to work
from a warm cache and fail loudly on a miss instead of reaching the network.

Python 3.11 or newer. **No runtime third-party dependencies**, by design: stdlib only, no compiled
extension, no lockfile resolution, so the artifact installs anywhere.

## License

MIT. See [LICENSE](LICENSE).
