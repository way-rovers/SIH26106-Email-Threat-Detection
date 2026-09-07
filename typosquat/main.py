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
    "match_type":     "edit_distance" | "homoglyph" | None,
}

Rules:
- Never raise an exception.
- Called once on parsed["sender_domain"] from forensics output.

Milestone notes:
    2.1 — Watchlist load + shape stub only.
    2.2 — Edit-distance matching (Levenshtein). ← CURRENT
    2.3 — Homoglyph detection.
    2.4 — Subdomain-abuse checking.
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


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


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

    MILESTONE 2.2 — Edit-distance matching via python-Levenshtein.
    Flags domains within _EDIT_DISTANCE_THRESHOLD edits of any watchlist
    entry as suspicious, unless they ARE the watchlist entry (exact match).

    Args:
        domain: The sender domain extracted from the email headers
                (lowercased, via forensics.parse_email).

    Returns:
        A dict with keys: domain, is_suspicious, closest_match, distance,
        match_type.
    """
    try:
        domain = str(domain).lower().strip()

        closest, dist = _closest_watchlist_entry(domain)

        if closest is not None and dist <= _EDIT_DISTANCE_THRESHOLD:
            return {
                "domain": domain,
                "is_suspicious": True,
                "closest_match": closest,
                "distance": dist,
                "match_type": "edit_distance",
            }

        return {
            "domain": domain,
            "is_suspicious": False,
            "closest_match": closest,   # still report the nearest, even if not suspicious
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
