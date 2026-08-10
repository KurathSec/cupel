"""Single naming point for the project.

This is the canonical value of the tool name, and it must never appear in a
record schema, a clause id, a mutation id, a results file, or a guard token
injected into vendored source. Those constraints hold and are worth keeping.

It is NOT true that the name appears only here. Counted 2026-08-10: 32 tracked
files contain it, because the package directory is `src/cupel/` and every import
names it. No anonymiser exists. Producing a double-blind supplementary archive
therefore means renaming the package and rewriting imports, so treat that
readiness as a requirement rather than a property the repository already has.
"""

TOOL_NAME = "cupel"
VERSION = "0.1.0"

# Prefix for preprocessor tokens injected into target source trees by guarded
# mutations. Deliberately neutral so a mutated tree carries no project identity.
GUARD_PREFIX = "CLAUSE_OFF_"
