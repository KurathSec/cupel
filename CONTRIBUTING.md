# Contributing

## Commit messages

English, imperative, describing what changed and why. **No tool attribution and no
`Co-Authored-By` trailer**, in any commit. `bin/namecheck.py --commits <range>` enforces the
vocabulary rules over commit messages as well as files, and CI runs it on every pull request.

No em-dashes, anywhere: not in prose, not in code comments, not in commit messages.

## Before you push

```
python bin/namecheck.py     # vocabulary firewall, no dependencies needed
pytest                      # unit, golden and control tests
python bin/regen.py         # every quotable number, with its n
```

## The three rules that are not style preferences

**1. A number does not exist until a committed script regenerates it from committed data.**

If a figure is going into a table, a paper or the README, it is printed by `bin/regen.py` from
`data/` and `results/`, or it does not get quoted. Prose is not a number and a remembered run is
not a number. Divide only through `cupel.util.na.Rate`; average only through
`cupel.util.na.mean`. Both report `NA` over an empty input rather than `0`, because zero killed
out of forty is a finding and an unrun experiment is not.

**2. `data/` is input and `results/` is output.**

Nothing in `src/` writes to `data/` except the clause generators, which write only to
`data/clauses/generated/`. Hand-authored overlays and machine-derived records never share a file.

**3. Adjudicated decisions are numbered, committed and counted.**

A scope decision is a `SCOPE-nn` scope rule in `data/clauses/overlay/scope_rules.toml`. A
correction to a defect in an upstream source is a `REPAIR-nn` source repair in
`data/clauses/overlay/source_repairs.toml`. Both carry evidence and both are counted by
`bin/regen.py`. The denominator cannot change without a diff in a committed file, and when
upstream fixes a defect the repair entry stops matching and extraction fails rather than silently
shifting the count.

## Adding a mutation

A mutation is a TOML record in `data/mutations/<target>/`, naming the file, its hash at the pinned
commit, the exact anchor text, the replacement and the required occurrence count. Do not use line
numbers. Do not use `patch` files, which fuzz-apply by default.

Prefer `0 && cond` over deleting a block, so surrounding variables stay used under the strict
warning flags the target repositories compile with.

Then:

```
python -m cupel mutate verify-anchors    # must be green, no build required
python -m cupel mutate render <id>       # prints the diff a reviewer will read
```

## Adding a target

Implement the `Target` protocol in `src/cupel/targets/base.py`. Note that it has no `grade()`
method, deliberately: grading is central, in `src/cupel/runner/grade.py`, against
`expectedResults.json`. If each adapter graded, the `exercised` boolean would inherit a different
notion of failure per adapter and the headline would stop being one measurement. Adapters produce
ACVP response JSON and nothing else.

Declare `lineage` per algorithm honestly. OpenSSL's ML-KEM is a port of BoringSSL's, so those two
are one lineage and the tool must refuse to count them as two independent witnesses.

## Vocabulary

`data/namecheck.toml` lists terms this repository must not contain, each with its reason. The
list exists because the author has a separate double-anonymous submission under review whose rules
forbid any citation path into it. Reusing that project's vocabulary would manufacture the path its
rules forbid, so the guarantee is made mechanical here rather than remembered.

If you need a concept the list blocks, rename it. Numbered adjudicated decisions in this
repository are scope rules and source repairs.
