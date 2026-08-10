"""The NA discipline. These tests exist because both failure modes happened.

A prior audit twice caught a default printed as a measurement: a reported 0.946
that was the identity (s - c) / (s - c), and a reported 0.00 that was mean([]).
If these tests pass, neither can reach a table from this codebase.
"""

import pytest

from cupel.util.na import NA, Mean, Rate, mean


class TestEmptyIsNotZero:
    def test_rate_over_empty_is_undefined_not_zero(self):
        r = Rate(0, 0, "nothing measured")
        assert r.value is None
        assert r.value != 0.0
        assert not r.defined
        assert NA in r.render()

    def test_rate_of_genuine_zero_is_defined(self):
        """Zero killed out of forty is a finding. It must not read as NA."""
        r = Rate(0, 40, "killed")
        assert r.value == 0.0
        assert r.defined
        assert NA not in r.render()
        assert "n=40" in r.render()

    def test_mean_of_empty_is_undefined_not_zero(self):
        m = mean([], "empty")
        assert m.value is None
        assert m.n == 0
        assert NA in m.render()

    def test_mean_of_zeros_is_defined_zero(self):
        m = mean([0.0, 0.0], "real zeros")
        assert m.value == 0.0
        assert NA not in m.render()


class TestNAlwaysTravels:
    @pytest.mark.parametrize("num,den", [(0, 0), (0, 5), (3, 5), (5, 5)])
    def test_render_always_carries_n(self, num, den):
        assert f"n={den}" in Rate(num, den).render()

    def test_record_reports_null_not_zero(self):
        rec = Rate(0, 0).as_record()
        assert rec["value"] is None
        assert rec["n"] == 0
        assert rec["defined"] is False


class TestDegenerateIdentityIsRejected:
    def test_numerator_above_denominator_raises(self):
        """The (s - c) / (s - c) shape produced a 0.946 that meant nothing.

        A Rate cannot silently exceed 1.0. If a caller computes one, that is a
        bug in the caller and it fails here rather than in a table.
        """
        with pytest.raises(ValueError, match="exceeds denominator"):
            Rate(7, 3, "impossible")

    def test_negative_counts_raise(self):
        with pytest.raises(ValueError, match="non-negative"):
            Rate(-1, 10)


class TestPercent:
    def test_percent_of_undefined_is_na(self):
        assert Rate(0, 0).percent() == NA

    def test_percent_rounds_and_labels(self):
        assert Rate(1, 3).percent(places=1) == "33.3%"
