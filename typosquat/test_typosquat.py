"""typosquat/test_typosquat.py — shape + behaviour tests for check_domain().

Milestone 2.1 tests: shape contract (all still pass).
Milestone 2.2 tests: edit-distance matching behaviour.
Milestone 2.3 tests: homoglyph detection behaviour.
Milestone 2.4 tests: subdomain-abuse detection behaviour.
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
# Note: paypa1.com and amaz0n.com are now caught by homoglyph (2.3) first,
# so their match_type moved to "homoglyph". Tests updated accordingly.
# Pure edit-distance cases (no homoglyph chars) remain here.
# ---------------------------------------------------------------------------


class TestEditDistance:
    """Behavioural tests for the Levenshtein watchlist check."""

    # --- suspicious via pure edit-distance (no homoglyph chars) ---

    def test_miicrosoft_is_suspicious(self):
        """miicrosoft.com → microsoft.com, distance 1 — doubled letter.
        No homoglyph chars present, so edit-distance fires.
        """
        r = check_domain("miicrosoft.com")
        assert r["is_suspicious"] is True
        assert r["closest_match"] == "microsoft.com"
        assert r["distance"] == 1
        assert r["match_type"] == "edit_distance"

    def test_distance_2_still_suspicious(self):
        """applee.com → apple.com, distance 1 (extra 'e') — within threshold."""
        r = check_domain("applee.com")
        assert r["is_suspicious"] is True
        assert r["closest_match"] == "apple.com"
        assert r["distance"] <= 3
        assert r["match_type"] == "edit_distance"

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

    # --- field types when suspicious via edit-distance ---

    def test_distance_is_int_when_edit_distance_fires(self):
        r = check_domain("miicrosoft.com")
        assert r["is_suspicious"] is True
        assert isinstance(r["distance"], int)

    def test_closest_match_is_str_when_edit_distance_fires(self):
        r = check_domain("miicrosoft.com")
        assert isinstance(r["closest_match"], str)

    def test_match_type_is_edit_distance_string(self):
        r = check_domain("miicrosoft.com")
        assert r["match_type"] == "edit_distance"

    # --- field types when not suspicious ---

    def test_match_type_is_none_when_not_suspicious(self):
        r = check_domain("paypal.com")
        assert r["match_type"] is None


# ---------------------------------------------------------------------------
# Milestone 2.3 — homoglyph detection
# ---------------------------------------------------------------------------


class TestHomoglyph:
    """Behavioural tests for homoglyph normalisation and watchlist matching."""

    # --- digit-for-letter swaps (ASCII homoglyphs) ---

    def test_paypa1_flagged_as_homoglyph(self):
        """paypa1.com: '1'→'l' normalises to paypal.com — exact watchlist hit.
        Must be 'homoglyph', NOT 'edit_distance', because homoglyph fires first.
        """
        r = check_domain("paypa1.com")
        assert r["is_suspicious"] is True
        assert r["closest_match"] == "paypal.com"
        assert r["distance"] == 0
        assert r["match_type"] == "homoglyph"

    def test_amaz0n_flagged_as_homoglyph(self):
        """amaz0n.com: '0'→'o' normalises to amazon.com."""
        r = check_domain("amaz0n.com")
        assert r["is_suspicious"] is True
        assert r["closest_match"] == "amazon.com"
        assert r["distance"] == 0
        assert r["match_type"] == "homoglyph"

    def test_g00gle_flagged_as_homoglyph(self):
        """g00gle.com: two '0'→'o' swaps normalises to google.com."""
        r = check_domain("g00gle.com")
        assert r["is_suspicious"] is True
        assert r["closest_match"] == "google.com"
        assert r["distance"] == 0
        assert r["match_type"] == "homoglyph"

    def test_appl3_flagged_as_homoglyph(self):
        """appl3.com: '3'→'e' normalises to apple.com."""
        r = check_domain("appl3.com")
        assert r["is_suspicious"] is True
        assert r["closest_match"] == "apple.com"
        assert r["distance"] == 0
        assert r["match_type"] == "homoglyph"

    def test_5lack_flagged_as_homoglyph(self):
        """5lack.com: '5'→'s' normalises to slack.com."""
        r = check_domain("5lack.com")
        assert r["is_suspicious"] is True
        assert r["closest_match"] == "slack.com"
        assert r["distance"] == 0
        assert r["match_type"] == "homoglyph"

    # --- Unicode lookalikes (Cyrillic) ---

    def test_cyrillic_a_in_paypal_flagged(self):
        """p\u0430ypal.com: Cyrillic 'а' (U+0430) → Latin 'a' → paypal.com."""
        domain = "p\u0430ypal.com"          # Cyrillic а in position 1
        r = check_domain(domain)
        assert r["is_suspicious"] is True
        assert r["closest_match"] == "paypal.com"
        assert r["distance"] == 0
        assert r["match_type"] == "homoglyph"

    def test_cyrillic_o_in_google_flagged(self):
        """g\u043egie.com: Cyrillic 'о' (U+043E) → Latin 'o' → google.com."""
        domain = "g\u043e\u043egle.com"     # two Cyrillic о's
        r = check_domain(domain)
        assert r["is_suspicious"] is True
        assert r["closest_match"] == "google.com"
        assert r["distance"] == 0
        assert r["match_type"] == "homoglyph"

    # --- Homoglyph chars that DON'T produce a watchlist hit ---

    def test_homoglyph_normalises_but_not_on_watchlist(self):
        """Domain has homoglyph chars but the normalised form isn't on the watchlist.
        Should fall through to edit-distance, not be incorrectly flagged as homoglyph.
        """
        # '5pinach.com' → 'spinach.com' — not on watchlist
        r = check_domain("5pinach.com")
        assert r["match_type"] != "homoglyph"

    # --- exact watchlist domains with no homoglyph chars stay clean ---

    def test_exact_watchlist_domain_not_homoglyph(self):
        """A real watchlist domain must never be flagged."""
        r = check_domain("google.com")
        assert r["is_suspicious"] is False
        assert r["match_type"] is None

    # --- field types for homoglyph result ---

    def test_homoglyph_distance_is_zero_int(self):
        r = check_domain("paypa1.com")
        assert r["match_type"] == "homoglyph"
        assert r["distance"] == 0
        assert isinstance(r["distance"], int)

    def test_homoglyph_closest_match_is_str(self):
        r = check_domain("paypa1.com")
        assert isinstance(r["closest_match"], str)

    def test_homoglyph_domain_field_echoes_original(self):
        """domain field must echo the RAW input, not the normalised form."""
        raw = "paypa1.com"
        r = check_domain(raw)
        assert r["domain"] == raw   # NOT "paypal.com"


# ---------------------------------------------------------------------------
# Milestone 2.4 — subdomain-abuse detection
# ---------------------------------------------------------------------------


class TestSubdomainAbuse:
    """Behavioural tests for brand-token embedding detection."""

    # ─── main fixture case ─────────────────────────────────────────────────────

    def test_phish_fixture_micros0ft_support_is_suspicious(self):
        """micros0ft-support.com: the actual phish_2/phish_3 sender domain.

        '0'→'o' normalises to microsoft-support.com, which is NOT on the
        watchlist (homoglyph misses it) and edit-distance to microsoft.com is
        9 (above threshold).  Subdomain-abuse catches it because the brand
        token 'microsoft' is embedded in the normalised domain.
        """
        r = check_domain("micros0ft-support.com")
        assert r["is_suspicious"] is True
        assert r["closest_match"] == "microsoft.com"
        assert r["distance"] == 0
        assert r["match_type"] == "subdomain_abuse"

    # ─── other brand-in-prefix attacks ─────────────────────────────────────────

    def test_paypal_secure_is_suspicious(self):
        """paypal-secure.com: brand 'paypal' (5 chars) embedded in domain."""
        r = check_domain("paypal-secure.com")
        assert r["is_suspicious"] is True
        assert r["closest_match"] == "paypal.com"
        assert r["match_type"] == "subdomain_abuse"

    def test_amazon_delivery_is_suspicious(self):
        """amazon-delivery.com: brand 'amazon' embedded."""
        r = check_domain("amazon-delivery.com")
        assert r["is_suspicious"] is True
        assert r["closest_match"] == "amazon.com"
        assert r["match_type"] == "subdomain_abuse"

    def test_microsoft_login_is_suspicious(self):
        """microsoft-login.com: pure ASCII, no homoglyphs needed."""
        r = check_domain("microsoft-login.com")
        assert r["is_suspicious"] is True
        assert r["closest_match"] == "microsoft.com"
        assert r["match_type"] == "subdomain_abuse"

    def test_apple_verify_is_suspicious(self):
        """apple-verify.com: brand 'apple' (5 chars) embedded."""
        r = check_domain("apple-verify.com")
        assert r["is_suspicious"] is True
        assert r["closest_match"] == "apple.com"
        assert r["match_type"] == "subdomain_abuse"

    def test_homoglyph_normalisation_feeds_brand_check(self):
        """micros0ft-login.com: '0'→'o' normalises to microsoft-login.com.
        Homoglyph check misses it (not an exact watchlist entry).
        Brand check catches 'microsoft' in the normalised string.
        """
        r = check_domain("micros0ft-login.com")
        assert r["is_suspicious"] is True
        assert r["match_type"] == "subdomain_abuse"

    # ─── priority: homoglyph still beats subdomain_abuse ─────────────────

    def test_paypa1_still_homoglyph_not_subdomain_abuse(self):
        """paypa1.com normalises to paypal.com (exact watchlist hit).
        Homoglyph fires first — match_type must be 'homoglyph', not 'subdomain_abuse'.
        """
        r = check_domain("paypa1.com")
        assert r["match_type"] == "homoglyph"   # NOT subdomain_abuse

    # ─── priority: edit_distance still beats subdomain_abuse ─────────────

    def test_miicrosoft_still_edit_distance_not_subdomain_abuse(self):
        """miicrosoft.com: edit-distance=1, well within threshold.
        Edit-distance fires first — match_type must be 'edit_distance'.
        """
        r = check_domain("miicrosoft.com")
        assert r["match_type"] == "edit_distance"   # NOT subdomain_abuse

    # ─── exact watchlist domains stay clean ───────────────────────────

    def test_microsoft_exact_not_subdomain_abuse(self):
        """microsoft.com itself must not trigger subdomain-abuse self-match."""
        r = check_domain("microsoft.com")
        assert r["is_suspicious"] is False
        assert r["match_type"] is None

    def test_paypal_exact_not_subdomain_abuse(self):
        r = check_domain("paypal.com")
        assert r["is_suspicious"] is False

    def test_bank_of_america_exact_not_subdomain_abuse(self):
        """Legit fixture domain — must stay clean across all milestones."""
        r = check_domain("bank-of-america.com")
        assert r["is_suspicious"] is False
        assert r["match_type"] is None

    # ─── field types for subdomain_abuse result ────────────────────────

    def test_subdomain_abuse_distance_is_zero_int(self):
        r = check_domain("microsoft-support.com")
        assert r["match_type"] == "subdomain_abuse"
        assert r["distance"] == 0
        assert isinstance(r["distance"], int)

    def test_subdomain_abuse_closest_match_is_str(self):
        r = check_domain("microsoft-support.com")
        assert isinstance(r["closest_match"], str)

    def test_subdomain_abuse_domain_echoes_raw_input(self):
        raw = "micros0ft-support.com"
        r = check_domain(raw)
        assert r["domain"] == raw   # raw input, not normalised

