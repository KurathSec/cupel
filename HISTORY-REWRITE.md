# This repository's history was rewritten on 2026-08-11

Every commit before that date has a different hash than it originally did, and
the repository was deleted and recreated on GitHub. If you have an older clone,
discard it and clone again; do not merge the two.

## What was removed

A configuration file listing a vocabulary this project must not contain. It was
committed in plaintext, with a written reason beside each term and a header
explaining why the list existed. That file was the thing it was meant to
prevent: anyone reading it learned the terms, the connection between them, and
why they were sensitive.

The working tree was fixed on 2026-08-10 by moving the list to sha256 digests
held in `data/namecheck.toml`. The commit that did so said the history "is dealt
with separately". This is that. The delay was about eight days and the file was
publicly readable throughout, so treat the contents as disclosed.

Occurrences in file contents and in one commit message were replaced with
`REDACTED-TERM-<n>`, consistently, so a reader can still see the shape of what
changed and when. 383 occurrences across 29 of 41 commits.

## What was not changed

Nothing else. The tree at the tip is byte-identical to the tree at the tip
before the rewrite, verified by diffing the two. No result file, no measurement,
no pinned hash and no vendored input moved. Every pin in `data/pins.toml` and
every digest in `data/vectors/lock.toml` refers to upstream repositories and is
unaffected by anything done here.

## Why delete and recreate rather than force-push

Force-pushing leaves the old commits unreachable but still retrievable from
GitHub by their hash, on no published schedule for collection. At the time of
the rewrite the repository had no forks, no stars and no watchers and was one
day old, so deleting it cost nothing and gave a hard guarantee instead of a
soft one.

## On the digests that replaced the list

They are unsalted sha256 over short natural-language strings, so a guessed
candidate can be confirmed, and an audit of this repository recovered several
of them from an ordinary word list in about a second. A salt would have to ship
here to be checkable, so it would not help. The digests remove the reasons and
the stated connection between the terms, which was the worst of what leaked.
They do not make the terms unrecoverable, and `bin/namecheck.py` no longer
claims they do. The guarantee worth relying on is the check itself, which keeps
those terms out of the tree.
