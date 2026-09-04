"""typosquat/test_typosquat.py — shape-check tests for check_domain()."""

import pytest
from typosquat.main import check_domain, levenshtein

REQUIRED_KEYS = {"domain", "is_suspicious", "closest_match", "distance", "match_type"}


def test_check_domain_returns_dict():
    result = check_domain("paypa1.com")
    assert isinstance(result, dict), "check_domain() must return a dict"


def test_check_domain_has_required_keys():
    result = check_domain("paypa1.com")
    missing = REQUIRED_KEYS - result.keys()
    assert not missing, f"check_domain() is missing keys: {missing}"


def test_check_domain_is_suspicious_is_bool():
    result = check_domain("paypa1.com")
    assert isinstance(result["is_suspicious"], bool), \
        "is_suspicious must be a bool"


def test_check_domain_domain_field_matches_input():
    domain = "micros0ft-support.com"
    result = check_domain(domain)
    assert result["domain"] == domain, \
        "domain field must echo back the input domain"


@pytest.mark.parametrize("domain", [None, "", "   ", "://", "http:///path", 123, b"paypal.com"])
def test_invalid_or_empty_domain_returns_safe_contract_result(domain):
    assert check_domain(domain) == {
        "domain": domain,
        "is_suspicious": False,
        "closest_match": None,
        "distance": None,
        "match_type": None,
    }


@pytest.mark.parametrize(
    ("source", "target"),
    [
        ("paypa1.com", "paypal.com"),
        ("paypall.com", "paypal.com"),
        ("paypl.com", "paypal.com"),
    ],
)
def test_single_edit_distance_is_one(source, target):
    assert levenshtein(source, target) == 1


def test_adjacent_transposition_distance_is_one():
    assert levenshtein("mircosoft.com", "microsoft.com") == 1


def test_adjacent_transposition_is_detected_by_check_domain():
    result = check_domain("mircosoft.com")
    assert result["is_suspicious"] is True
    assert result["closest_match"] == "microsoft.com"
    assert result["distance"] == 1
    assert result["match_type"] == "edit_distance"


def test_cyrillic_homoglyph_is_detected():
    result = check_domain("pаypal.com")
    assert result["is_suspicious"] is True
    assert result["closest_match"] == "paypal.com"
    assert result["distance"] == 1
    assert result["match_type"] == "homoglyph"


def test_ascii_trusted_domain_keeps_existing_safe_behavior():
    assert check_domain("paypal.com") == {
        "domain": "paypal.com",
        "is_suspicious": False,
        "closest_match": None,
        "distance": None,
        "match_type": None,
    }


@pytest.mark.parametrize("domain", ["pаypal.", "\u0370aypal.com", "\x00"])
def test_unsupported_or_malformed_homoglyph_input_does_not_raise(domain):
    result = check_domain(domain)
    assert set(result) == REQUIRED_KEYS
    assert isinstance(result["is_suspicious"], bool)


def test_exact_trusted_domain_is_safe():
    result = check_domain("paypal.com")
    assert result["is_suspicious"] is False


def test_digit_substitution_is_detected():
    result = check_domain("paypa1.com")
    assert result["is_suspicious"] is True


def test_micros0ft_is_detected():
    result = check_domain("micros0ft.com")
    assert result["is_suspicious"] is True


def test_google_typo_is_detected():
    result = check_domain("go0gle.com")
    assert result["is_suspicious"] is True


def test_unrelated_domain_is_safe():
    result = check_domain("example.com")
    assert result["is_suspicious"] is False