"""
typosquat/main.py — Person 5: lookalike-domain / typosquat detection.

Public contract:
    check_domain(domain: str) -> dict

Return shape:
{
    "domain":         str,
    "is_suspicious":  bool,
    "closest_match":  str | None,   # e.g. "paypal.com", null if nothing close
    "distance":       int | None,   # edit distance to closest_match, null if none
    "match_type":     "edit_distance" | "homoglyph" | "subdomain_abuse" | None,
}

Rules:
- Never raise an exception.
- Called once on parsed["sender_domain"] from forensics output.

Milestone notes:
    2.1 — Watchlist load + shape stub only.
    2.2 — Edit-distance matching (Levenshtein).
    2.3 — Homoglyph detection.
    2.4 — Subdomain-abuse checking. ← CURRENT
"""

import json
import pathlib

import Levenshtein

# ---------------------------------------------------------------------------
# Watchlist loading — module-level so it is parsed once at import time.
# ---------------------------------------------------------------------------

_WATCHLIST_PATH = pathlib.Path(__file__).parent / "watchlist.json"

# Domains whose edit-distance from the input is within this threshold are
# considered suspicious.  Chosen to catch realistic 1-3 character swaps /
# insertions (e.g. paypa1.com → paypal.com = 1) without over-firing on
# compound attacks like "micros0ft-support.com" (those are milestone 2.4).
_EDIT_DISTANCE_THRESHOLD = 3


def _load_watchlist() -> list[str]:
    """Load and validate the flat watchlist JSON.

    Returns an empty list on any error so check_domain() can still run.
    """
    try:
        with _WATCHLIST_PATH.open(encoding="utf-8") as fh:
            data = json.load(fh)
        if not isinstance(data, list):
            return []
        return [entry for entry in data if isinstance(entry, str)]
    except Exception:  # noqa: BLE001
        return []


_WATCHLIST: list[str] = _load_watchlist()

# Frozenset for O(1) exact-match lookup used by the homoglyph and subdomain checks.
_WATCHLIST_SET: frozenset[str] = frozenset(_WATCHLIST)

# ---------------------------------------------------------------------------
# Brand-token index — milestone 2.4
# ---------------------------------------------------------------------------

# Minimum brand length to consider for substring matching.  Avoids false
# positives from very short tokens (e.g. "irs", "sbi") appearing in
# unrelated domain strings.
_MIN_BRAND_LEN: int = 4

# List of (brand_token, full_watchlist_entry) pairs used by subdomain-abuse
# detection.  Sorted longest-brand-first so the most specific watchlist entry
# wins when multiple brands are substrings of the same domain.
_WATCHLIST_BRANDS: list[tuple[str, str]] = sorted(
    [
        (entry.split(".")[0], entry)
        for entry in _WATCHLIST
        if len(entry.split(".")[0]) >= _MIN_BRAND_LEN
    ],
    key=lambda pair: len(pair[0]),
    reverse=True,  # longest brand first → most specific match wins
)

# ---------------------------------------------------------------------------
# Homoglyph map — milestone 2.3
# ---------------------------------------------------------------------------

# Maps a visually confusable character to its canonical ASCII equivalent.
# Scope: single-character substitutions only.
# Multi-character confusables (rn→m, vv→w) are partially covered by
# edit-distance (2.2) and are out of scope for this milestone.
_HOMOGLYPH_MAP: dict[str, str] = {
    # ── Digit-for-letter swaps (most common in phishing domains) ──────────
    "0": "o",
    "1": "l",
    "3": "e",
    "4": "a",
    "5": "s",
    "6": "g",
    "7": "t",
    "8": "b",
    "9": "q",
    # ── Unicode Latin lookalikes (Cyrillic) ───────────────────────────────
    "\u0430": "a",   # Cyrillic а → Latin a
    "\u0435": "e",   # Cyrillic е → Latin e
    "\u043e": "o",   # Cyrillic о → Latin o
    "\u0440": "r",   # Cyrillic р → Latin r
    "\u0441": "c",   # Cyrillic с → Latin c
    "\u0445": "x",   # Cyrillic х → Latin x
    "\u0456": "i",   # Cyrillic і → Latin i
    # ── Unicode Latin lookalikes (Greek) ──────────────────────────────────
    "\u03bf": "o",   # Greek ο (omicron) → Latin o
    "\u03b1": "a",   # Greek α → Latin a
    "\u03b5": "e",   # Greek ε → Latin e
    # ── Punctuation lookalikes ────────────────────────────────────────────
    "\u2010": "-",   # Unicode hyphen → ASCII hyphen-minus
    "\u2011": "-",   # Non-breaking hyphen → ASCII hyphen-minus
}


def _normalize_homoglyphs(domain: str) -> str:
    """Replace each homoglyph character with its canonical ASCII equivalent."""
    return "".join(_HOMOGLYPH_MAP.get(ch, ch) for ch in domain)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _check_subdomain_abuse(domain: str) -> str | None:
    """Return the watchlist entry being impersonated via brand-in-domain embedding.

    Normalises *domain* via the homoglyph map first, then checks whether any
    watchlist brand token (the label before the first '.') appears as a
    substring.  Exact watchlist matches are excluded — they are handled
    upstream and are not suspicious.

    Returns the matching watchlist entry string, or None.
    """
    if not _WATCHLIST_BRANDS:
        return None

    normalized = _normalize_homoglyphs(domain)

    # Exact matches are legitimate — guard against self-match.
    if domain in _WATCHLIST_SET or normalized in _WATCHLIST_SET:
        return None

    for brand, entry in _WATCHLIST_BRANDS:
        if brand in normalized:
            return entry

    return None


def _closest_watchlist_entry(domain: str) -> tuple[str, int] | tuple[None, None]:
    """Return (closest_watchlist_domain, edit_distance) or (None, None).

    Skips exact matches — if the domain IS on the watchlist it is legitimate
    and should not be flagged.  Returns the entry with the smallest distance;
    on a tie the first (alphabetically sorted) entry wins.
    """
    if not _WATCHLIST:
        return None, None

    best_entry: str | None = None
    best_dist: int = 10_000  # sentinel: larger than any realistic domain distance

    for entry in _WATCHLIST:
        if domain == entry:
            # Exact hit → not suspicious, short-circuit immediately.
            return None, None
        dist = Levenshtein.distance(domain, entry)
        if dist < best_dist:
            best_dist = dist
            best_entry = entry

    return best_entry, best_dist


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def check_domain(domain: str) -> dict:
    """Check whether *domain* looks like an impersonation of a known brand.

    Detection order (highest-confidence first):
      1. Homoglyph check    — exact watchlist match after char-substitution.
         distance=0 because the normalised form IS the watchlist entry.
      2. Edit-distance      — within _EDIT_DISTANCE_THRESHOLD Levenshtein edits.
      3. Subdomain abuse    — a watchlist brand token appears as a substring
         of the (normalised) domain (e.g. "microsoft-support.com").
         distance=0; match_type="subdomain_abuse".

    MILESTONE 2.4 — adds subdomain-abuse detection on top of 2.2/2.3.

    Args:
        domain: The sender domain extracted from the email headers
                (lowercased, via forensics.parse_email).

    Returns:
        A dict with keys: domain, is_suspicious, closest_match, distance,
        match_type.
    """
    try:
        domain = str(domain).lower().strip()

        # ── 1. Homoglyph check ────────────────────────────────────────────
        # Normalise the domain and look for an exact hit in the watchlist.
        # Only fires when at least one char was actually substituted
        # (normalized != domain) so legitimate watchlist domains are safe.
        normalized = _normalize_homoglyphs(domain)
        if normalized != domain and normalized in _WATCHLIST_SET:
            return {
                "domain": domain,
                "is_suspicious": True,
                "closest_match": normalized,   # the watchlist entry it impersonates
                "distance": 0,                 # 0 edits to the canonical form
                "match_type": "homoglyph",
            }

        # ── 2. Edit-distance check (milestone 2.2) ────────────────────────
        closest, dist = _closest_watchlist_entry(domain)

        if closest is not None and dist <= _EDIT_DISTANCE_THRESHOLD:
            return {
                "domain": domain,
                "is_suspicious": True,
                "closest_match": closest,
                "distance": dist,
                "match_type": "edit_distance",
            }

        # ── 3. Subdomain-abuse check (milestone 2.4) ─────────────────────
        # Normalises the domain internally, then checks whether any watchlist
        # brand token (e.g. "microsoft" from "microsoft.com") is embedded in
        # the domain string.  Catches compound attacks like "micros0ft-support.com"
        # that are too far from the watchlist entry to trigger edit-distance.
        abused_entry = _check_subdomain_abuse(domain)
        if abused_entry is not None:
            return {
                "domain": domain,
                "is_suspicious": True,
                "closest_match": abused_entry,
                "distance": 0,              # brand token appears literally (0 transforms)
                "match_type": "subdomain_abuse",
            }

        return {
            "domain": domain,
            "is_suspicious": False,
            "closest_match": closest,   # nearest entry even when not suspicious
            "distance": dist,
            "match_type": None,
        }

    except Exception:  # noqa: BLE001
        return {
            "domain": domain if isinstance(domain, str) else "unknown",
            "is_suspicious": False,
            "closest_match": None,
            "distance": None,
            "match_type": None,
        }
