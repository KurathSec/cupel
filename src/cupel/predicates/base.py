"""The predicate battery: normative checks evaluated independently.

The point of this module is what it refuses to do. A real implementation
short-circuits: the first failing check returns and the rest never run. That
makes a present check indistinguishable from an absent one whenever an earlier
check always fires first, which is exactly the shape of ACVP-Server issue #460,
where invalid encapsulation keys were the wrong length and so were rejected on
length before the modulus check was ever reached.

Every predicate here is therefore total and independent. Each one answers "does
this input violate this clause", on its own, for every input, whether or not any
other clause is also violated. The resulting matrix distinguishes:

    absent   no case violates the clause at all
    masked   cases violate it, but never in isolation
    covered  some case violates it and nothing else

A predicate returns True when the input VIOLATES the clause, so a positive
result means "a conformant implementation must reject this input for this
reason". Predicates never raise on malformed input: a truncated field is itself
a violation of the length clause, and crashing would lose the row.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable


@dataclass(frozen=True)
class Predicate:
    """One normative check, evaluated in isolation."""

    clause_id: str
    algorithm: str
    doc: str
    anchor: str
    title: str
    fn: Callable[[dict, dict], bool | None]

    def __call__(self, case: dict, group: dict) -> bool | None:
        """True if the case violates this clause, False if not, None if the
        clause does not apply to this case at all.

        None is distinct from False on purpose: a clause the input cannot
        violate is not a clause the input satisfies, and counting it as
        satisfied inflates the denominator of every coverage statement.

        The example this used to give was wrong and is worth keeping as a
        warning. It said a decapsulation case "has no encapsulation key", but
        ACVP emits `ek` on every ML-KEM test object, so a presence check never
        fired. Applicability is a property of which function receives the input,
        not of which fields the JSON happens to carry. See mlkem.py.
        """
        try:
            return self.fn(case, group)
        except (KeyError, ValueError, TypeError):
            # A field that is missing or unparseable cannot be judged against
            # this clause. Record not-applicable rather than guessing, and let
            # the structural clauses speak to malformedness.
            return None


def hexbytes(value: str | None) -> bytes | None:
    if not value:
        return None
    try:
        return bytes.fromhex(value)
    except ValueError:
        return None


def bits12(data: bytes) -> list[int]:
    """Unpack packed 12-bit little-endian fields, as FIPS 203 ByteDecode_12 reads them.

    Three bytes carry two coefficients: b0 | (b1 & 0x0f) << 8, and (b1 >> 4) | b2 << 4.
    """
    out = []
    for i in range(0, len(data) - 2, 3):
        b0, b1, b2 = data[i], data[i + 1], data[i + 2]
        out.append(b0 | ((b1 & 0x0F) << 8))
        out.append((b1 >> 4) | (b2 << 4))
    return out
