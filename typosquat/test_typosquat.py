"""typosquat/test_typosquat.py — shape + behaviour tests for check_domain().

Milestone 2.1 tests: shape contract (all still pass).
Milestone 2.2 tests: edit-distance matching behaviour.
"""

import pytest
from typosquat.main import check_domain

REQUIRED_KEYS = {"domain", "is_suspicious", "closest_match", "distance", "match_type"}


# ---------------------------------------------------------------------------
# Milestone 2.1 — shape contract (must stay green in all future milestones)
# ---------------------------------------------------------------------------


def test_check_domain_returns_dict():
    result = check_domain("paypa1.com")
    assert isinstance(result, dict), "check_domain() must return a dict"


def test_check_domain_has_required_keys():
    result = check_domain("paypa1.com")
    missing = REQUIRED_KEYS - result.keys()
    assert not missing, f"check_domain() is missing keys: {missing}"


def test_check_domain_is_suspicious_is_bool():
    result = check_domain("paypa1.com")
    assert isinstance(result["is_suspicious"], bool), "is_suspicious must be a bool"


def test_check_domain_domain_field_matches_input():
    domain = "micros0ft-support.com"
    result = check_domain(domain)
    assert result["domain"] == domain, "domain field must echo back the input domain"


def test_check_domain_never_raises_on_bad_input():
    """Rule: never raise an exception — even on garbage input."""
    for bad in [None, 123, "", "   ", "\x00\x01"]:
        result = check_domain(bad)  # type: ignore[arg-type]
        assert isinstance(result, dict), f"raised or didn't return dict for input {bad!r}"
        assert REQUIRED_KEYS <= result.keys()


# ---------------------------------------------------------------------------
# Milestone 2.2 — edit-distance matching
# ---------------------------------------------------------------------------


class TestEditDistance:
    """Behavioural tests for the Levenshtein watchlist check."""

    # --- suspicious: should be flagged ---

    def test_paypa1_is_suspicious(self):
        """paypa1.com → paypal.com, distance 1 — classic char-swap typosquat."""
        r = check_domain("paypa1.com")
        assert r["is_suspicious"] is True
        assert r["closest_match"] == "paypal.com"
        assert r["distance"] == 1
        assert r["match_type"] == "edit_distance"

    def test_miicrosoft_is_suspicious(self):
        """miicrosoft.com → microsoft.com, distance 1 — doubled letter."""
        r = check_domain("miicrosoft.com")
        assert r["is_suspicious"] is True
        assert r["closest_match"] == "microsoft.com"
        assert r["distance"] == 1
        assert r["match_type"] == "edit_distance"

    def test_amaz0n_is_suspicious(self):
        """amaz0n.com → amazon.com, distance 1 — digit substitution."""
        r = check_domain("amaz0n.com")
        assert r["is_suspicious"] is True
        assert r["closest_match"] == "amazon.com"
        assert r["distance"] == 1
        assert r["match_type"] == "edit_distance"

    def test_distance_2_still_suspicious(self):
        """applе-id.com → apple.com, distance 2 — two edits, still within threshold."""
        r = check_domain("applee.com")
        assert r["is_suspicious"] is True
        assert r["closest_match"] == "apple.com"
        assert r["distance"] <= 3

    # --- not suspicious: exact watchlist hits ---

    def test_exact_match_paypal_not_suspicious(self):
        """paypal.com itself should never be flagged — it IS the reference."""
        r = check_domain("paypal.com")
        assert r["is_suspicious"] is False
        assert r["match_type"] is None

    def test_exact_match_microsoft_not_suspicious(self):
        r = check_domain("microsoft.com")
        assert r["is_suspicious"] is False

    def test_exact_match_bank_of_america_not_suspicious(self):
        """Fixture legit_1 sender domain — must stay clean."""
        r = check_domain("bank-of-america.com")
        assert r["is_suspicious"] is False
        assert r["match_type"] is None

    # --- not suspicious: clearly unrelated domains ---

    def test_totally_unrelated_domain_not_suspicious(self):
        """A random domain with large edit-distance from all watchlist entries."""
        r = check_domain("xn--completely-unrelated-xyz123.io")
        assert r["is_suspicious"] is False

    def test_empty_string_not_suspicious(self):
        """Empty domain should survive without raising."""
        r = check_domain("")
        assert isinstance(r, dict)
        assert r["is_suspicious"] is False

    # --- field types when suspicious ---

    def test_distance_is_int_when_suspicious(self):
        r = check_domain("paypa1.com")
        assert r["is_suspicious"] is True
        assert isinstance(r["distance"], int)

    def test_closest_match_is_str_when_suspicious(self):
        r = check_domain("paypa1.com")
        assert r["is_suspicious"] is True
        assert isinstance(r["closest_match"], str)

    def test_match_type_is_edit_distance_string_when_suspicious(self):
        r = check_domain("paypa1.com")
        assert r["match_type"] == "edit_distance"

    # --- field types when not suspicious ---

    def test_match_type_is_none_when_not_suspicious(self):
        r = check_domain("paypal.com")
        assert r["match_type"] is None
