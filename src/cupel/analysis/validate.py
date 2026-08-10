"""Does the implementation actually reject a witness, and by what?

The `implemented` boolean has a third state, and missing it produced a wrong
result here. Some clauses cannot be violated at the API at all, because the
type makes the malformed input unrepresentable: mlkem-native declares
`mlk_kem_check_pk(const unsigned char ek[MLKEM_PK_BYTES])`, so a short key
cannot be passed to it. The repository says so itself, in a comment at the call
site in its ACVP driver:

    ACVP 1.1.0.40+ {en, de}capsulationKeyCheck test cases test keys of
    incorrect length. The mlkem-native API does not allow passing keys
    of incorrect length. We, hence, fail during decoding instead.
        printf("testPassed=0\\n");

So the harness prints a rejection the library never made. Reading that as
"the length check is implemented" credits the library with a check it does not
contain, and would put a clause in the exercised numerator on the strength of
an argument parser.

Three states, therefore:

  REJECTED_BY_LIBRARY    the input reached the code under test and was refused
  NOT_REPRESENTABLE      the harness refused it at the boundary; the API cannot
                         express the violation, so `implemented` is not a
                         meaningful boolean for this clause
  ACCEPTED               the input reached the code under test and passed, so
                         this implementation does not perform the check

A fourth state exists for a reason that also caught this module out. Only an
ISOLATING witness can establish anything about its own clause. The
dk-embedded-ek-modulus witness necessarily violates the decapsulation key hash
as well, because the hash covers the bytes it perturbs, so the library rejecting
it says the HASH check is implemented and says nothing at all about the embedded
modulus check. Reading that rejection as evidence for the clause under test
would have credited mlkem-native with a check it does not perform.

  INCONCLUSIVE_NON_ISOLATING   the witness violates more than its own clause,
                               so the implementation's verdict cannot be
                               attributed to this clause
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path

REJECTED = "REJECTED_BY_LIBRARY"
UNREPRESENTABLE = "NOT_REPRESENTABLE"
ACCEPTED = "ACCEPTED"
INCONCLUSIVE = "INCONCLUSIVE_NON_ISOLATING"

# The driver reports a parse failure on stderr before it reaches the library.
PARSE_MARKERS = ("Argument ", "invalid", "Expected argument")


@dataclass(frozen=True)
class Outcome:
    state: str
    returncode: int
    stdout: str
    stderr: str

    @property
    def implemented(self) -> bool | None:
        """None when the question does not apply, not False."""
        if self.state in (UNREPRESENTABLE, INCONCLUSIVE):
            return None
        return self.state == REJECTED


def classify(proc: subprocess.CompletedProcess, isolating: bool = True) -> Outcome:
    out, err = proc.stdout.strip(), proc.stderr.strip()
    if not isolating:
        return Outcome(INCONCLUSIVE, proc.returncode, out, err)
    reached = "testPassed=" in out
    parse_failed = any(m in err for m in PARSE_MARKERS)

    # A driver that prints testPassed=0 AFTER failing to parse is reporting its
    # own refusal, not the library's. The stderr marker is what separates them.
    if parse_failed:
        return Outcome(UNREPRESENTABLE, proc.returncode, out, err)
    if reached:
        passed = out.endswith("=1")
        return Outcome(ACCEPTED if passed else REJECTED, proc.returncode, out, err)
    return Outcome(REJECTED if proc.returncode != 0 else ACCEPTED,
                   proc.returncode, out, err)


def run(binary: Path, argv: list[str], isolating: bool = True) -> Outcome:
    return classify(subprocess.run([str(binary), *argv], capture_output=True, text=True),
                    isolating=isolating)
