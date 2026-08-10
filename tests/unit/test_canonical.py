"""Canonical serialisation must be stable, or every cached run id is a lie."""

import json

from cupel.util.canonical import canonical_bytes, canonical_str, sha256_bytes, sha256_of


class TestDeterminism:
    def test_key_order_does_not_change_bytes(self):
        a = {"b": 1, "a": 2, "c": {"z": 0, "y": 1}}
        b = {"c": {"y": 1, "z": 0}, "a": 2, "b": 1}
        assert canonical_bytes(a) == canonical_bytes(b)
        assert sha256_of(a) == sha256_of(b)

    def test_no_incidental_whitespace(self):
        assert canonical_str({"a": 1, "b": 2}) == '{"a":1,"b":2}'

    def test_unicode_is_not_escaped(self):
        # ensure_ascii=False keeps the bytes stable across Python versions that
        # differ in which codepoints they choose to escape.
        assert canonical_str({"k": "é"}) == '{"k":"é"}'

    def test_hash_is_prefixed_with_algorithm(self):
        assert sha256_of({"a": 1}).startswith("sha256:")
        assert sha256_bytes(b"x").startswith("sha256:")


class TestRefusesUnstableInput:
    def test_nan_is_rejected(self):
        """NaN round-trips through json but breaks equality, so it cannot be hashed."""
        import pytest

        with pytest.raises(ValueError):
            canonical_bytes({"x": float("nan")})


class TestRoundTrip:
    def test_canonical_output_parses_back_equal(self):
        obj = {"z": [1, 2, {"n": None}], "a": "text", "b": True}
        assert json.loads(canonical_str(obj)) == obj
