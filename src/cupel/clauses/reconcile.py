"""Reconcile the three derivations.

D1b says what the specification defines, D2 where an implementation rejects, D3
what the generator can produce. Each was built by different people for different
reasons, which is the whole point: a denominator that only one method produces is
one person's list, and a fraction over one person's list is not a measurement.

The cells and what each means:

  D1b and D2 and D3   a spec clause, implemented, and producible as a negative
                      case. The strongest position, and the only one where an
                      unexercised verdict is unambiguous.
  D1b and D2, not D3  implemented and specified, but the generator has no
                      disposition that produces a violating input. Structurally
                      unexercisable, whatever the sample size.
  D1b, not D2         specified but this implementation does not check it.
                      Different finding, different remedy.
  D2, not D1b         the implementation rejects something the extraction did
                      not surface. Either an extraction miss or a defensive
                      extra, and it must be decided rather than ignored.

Nothing here decides anything on its own. It produces the disagreements that
need deciding, and refuses to be quiet about them.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# Which Cryptol definition states which clause. D1b names definitions and the
# clause ids name FIPS anchors, so without this the join compares two different
# namespaces and reports every clause as absent from the specification, which is
# a bug that looks exactly like a finding.
SPEC_TO_CLAUSE = {
    "encapsulationKeyCheck": ["fips203.s7.2.ek-modulus", "fips203.s7.2.ek-length"],
    "decapsulationInputCheck": ["fips203.s7.3.dk-hash", "fips203.s7.3.dk-length",
                                "fips203.s7.3.ct-length"],
    "keyPairCheck": ["fips203.s7.3.dk-embedded-ek-modulus"],
    "Verify": ["fips204.alg08.commitment-hash", "fips204.alg08.z-inf-norm",
               "fips204.alg08.sig-length"],
    "Verify_internal": ["fips204.alg08.verify-decision"],
    "HintBitUnpack": ["fips204.alg15.hint-decode", "fips204.alg15.hint-weight",
                      "fips204.alg15.hint-ordering",
                      "fips204.alg15.hint-trailing-zeros"],
    "sigDecode": ["fips204.alg08.sig-length"],
}

# Which implementation function realises which clause. Hand-written, because the
# mapping between a specification name and a C function name is a judgement and
# pretending otherwise would bury it. Each entry is checkable by reading both.
SITE_TO_CLAUSE = {
    "mlk_kem_check_pk": "fips203.s7.2.ek-modulus",
    "mlk_kem_check_sk": "fips203.s7.3.dk-hash",
    "mld_sig_unpack_hints": "fips204.alg15.hint-decode",   # refined below
    # mld_sign_verify_internal raises INVALID_SIGNATURE from several distinct
    # checks; the snippet rules below separate them and this is the fallback.
    "mld_sign_verify_internal": "fips204.alg08.verify-decision",
}

# One function can realise several separable clauses. mld_sig_unpack_hints holds
# all three HintBitUnpack sub-clauses at distinct lines, and mapping the function
# as a whole reported the three as unimplemented when they are each mutated
# individually elsewhere in this project. Matched on the check text so a reviewer
# can confirm the attribution by reading the source.
SNIPPET_TO_CLAUSE = [
    ("new_hint_count > MLDSA_OMEGA", "fips204.alg15.hint-weight"),
    ("packed_hints[j] <= packed_hints[j - 1]", "fips204.alg15.hint-ordering"),
    ("packed_hints[j] != 0", "fips204.alg15.hint-trailing-zeros"),
    ("mld_polyvecl_chknorm(z", "fips204.alg08.z-inf-norm"),
    ("mld_ct_memcmp(c, c2", "fips204.alg08.commitment-hash"),
    ("cmp == 0", "fips204.alg08.commitment-hash"),
]


def clause_for_site(site: dict) -> str | None:
    haystack = site.get("snippet", "") + " " + site.get("context", "")
    for needle, clause in SNIPPET_TO_CLAUSE:
        if needle in haystack:
            return clause
    return SITE_TO_CLAUSE.get(site.get("function"))


# Which clause a disposition can produce a violating input for. From D3.
DISPOSITION_TO_CLAUSE = {
    "ValuesTooLarge": "fips203.s7.2.ek-modulus",
    "ModifyH": "fips203.s7.3.dk-hash",
    "ModifyZ": "fips204.alg08.z-inf-norm",
    "ModifyHint": "fips204.alg15.hint-decode",
    "ModifySignature": "fips204.alg08.commitment-hash",
    "ModifyMessage": "fips204.alg08.commitment-hash",
    "ModifySignatureTooLarge": "fips205.alg20.sig-length",
    "ModifySignatureTooSmall": "fips205.alg20.sig-length",
}


@dataclass
class Cell:
    clause: str
    in_spec: bool
    in_impl: bool
    in_disposition: bool
    evidence: dict = field(default_factory=dict)

    @property
    def code(self) -> str:
        return "".join(c for c, on in
                       (("1", self.in_spec), ("2", self.in_impl), ("3", self.in_disposition))
                       if on) or "none"

    @property
    def needs_decision(self) -> bool:
        # Agreement across all three needs no adjudication. Anything else is a
        # disagreement between independently built lists and must be decided.
        return self.code != "123"

    def as_record(self) -> dict:
        return {
            "schema": "reconcile/1",
            "clause": self.clause,
            "in_spec_d1b": self.in_spec,
            "in_implementation_d2": self.in_impl,
            "in_disposition_d3": self.in_disposition,
            "cell": self.code,
            "needs_decision": self.needs_decision,
            "evidence": self.evidence,
        }


def build(candidates: list[dict], sites: list[dict], dispositions: list[dict]) -> list[Cell]:
    spec = set()
    for c in candidates:
        if c.get("proposed_surface") != "api_boundary_checkable":
            continue
        bare = c["name"].split("::")[-1]
        spec.update(SPEC_TO_CLAUSE.get(bare, []))
    impl = {}
    for s in sites:
        clause = clause_for_site(s)
        if clause:
            impl.setdefault(clause, []).append(f"{s['source']['path']}:{s['source']['line']}")
    disp = {}
    for d in dispositions:
        if d.get("planned_but_absent"):
            continue
        clause = DISPOSITION_TO_CLAUSE.get(d.get("name"))
        if clause:
            disp.setdefault(clause, []).append(d.get("label"))

    clauses = set(impl) | set(disp) | spec
    out = []
    for clause in sorted(clauses):
        out.append(Cell(
            clause=clause,
            in_spec=clause in spec,
            in_impl=clause in impl,
            in_disposition=clause in disp,
            evidence={"sites": impl.get(clause, []), "dispositions": disp.get(clause, [])},
        ))
    return out
