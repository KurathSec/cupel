# cupel

A coverage meter over the ACVP validation path for FIPS 203, FIPS 204 and FIPS 205.

A module that holds a FIPS 140-3 certificate for ML-KEM or ML-DSA passed ACVP. What nobody can
say today is **what passing means**: which normative clauses of the standard the mandated vector
set actually exercises, and which ones an implementation could get wrong while still passing
everything.

cupel answers that as a measurement. Point it at an implementation and a vector set and it prints
one row per API-boundary-checkable normative clause, with three booleans in each row, each
carrying its `n`:

| column | meaning |
|---|---|
| `implemented` | the check exists in the implementation |
| `reachable` | it is reachable from the public API, read from the exported symbol table and public headers |
| `exercised` | deleting exactly that check causes at least one mandated ACVP vector to fail |

The third is the one that does not exist elsewhere. The first two are cheap and are what make the
third interpretable: a clause that is unimplemented and a clause that is implemented but untested
are different findings with different remedies.

## Status

Early. The discipline layer and the vocabulary firewall are in place; the corpus census, the
violation matrix and the mutation spine are being built. `bin/regen.py` prints `NA` for everything
not yet measured and refuses to print a headline until its preconditions hold. That is the
intended behaviour, not a gap.

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
the check from mlkem-native, mldsa-native or OpenSSL decides. Disagreement means the battery
misencodes the specification, and that surfaces mechanically rather than in review.

A clause counts as exercised if it is killed in **any** substrate. It counts as unexercised only
if it survives across substrates spanning at least two distinct code lineages. Anything else is
inconclusive and is reported in its own bucket with its own `n`.

## Discipline

Two rules are enforced by CI rather than by intention.

**A number does not exist until a committed script regenerates it from committed data.**
`bin/regen.py` is the only place a quotable number is printed. Every figure carries its `n`. An
empty aggregation prints `NA`, never `0`, because zero killed out of forty is a finding and an
unrun experiment is not. `cupel.util.na.Rate` is the only division primitive in the codebase and
it raises rather than return a ratio above 1.0.

**Mutations are anchored content rewrites, not line ranges.** Each mutation record names the file,
its hash at the pinned commit, the exact anchor text and the required occurrence count. If the
anchor does not match exactly, the result is `NOT_APPLICABLE`, recorded, never guessed. For a tool
whose headline is "this mutant survived", a silently misapplied mutation is the worst available
failure, and line ranges fail silently under upstream drift.

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

Python 3.11 or newer. **No runtime third-party dependencies**, by design: stdlib only, no compiled
extension, no lockfile resolution, so the artifact installs anywhere.

## License

MIT. See [LICENSE](LICENSE).
