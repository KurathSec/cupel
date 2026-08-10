"""Single naming point for the project.

The tool name appears here and nowhere else. It must never appear in a record
schema, a clause id, a mutation id, a results file, or a guard token injected
into vendored source. `bin/anonymize.py` rewrites this module and asserts the
name does not survive anywhere in the supplementary archive.
"""

TOOL_NAME = "cupel"
VERSION = "0.1.0"

# Prefix for preprocessor tokens injected into target source trees by guarded
# mutations. Deliberately neutral so a mutated tree carries no project identity.
GUARD_PREFIX = "CLAUSE_OFF_"
