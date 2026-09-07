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
    2.1 — Watchlist load + shape stub only. No matching logic yet.
    2.2 — Edit-distance matching (Levenshtein).
    2.3 — Homoglyph detection.
    2.4 — Subdomain-abuse checking.
"""

import json
import pathlib

# ---------------------------------------------------------------------------
# Watchlist loading — module-level so it is parsed once at import time.
# ---------------------------------------------------------------------------

_WATCHLIST_PATH = pathlib.Path(__file__).parent / "watchlist.json"


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
# Public API
# ---------------------------------------------------------------------------


def check_domain(domain: str) -> dict:
    """Check whether *domain* looks like an impersonation of a known brand.

    MILESTONE 2.1 — Watchlist loaded and validated; matching logic is a stub.
    Returns a shape-correct dict with is_suspicious=False and match_type=None
    until milestones 2.2–2.4 implement real detection.

    Args:
        domain: The sender domain extracted from the email headers
                (lowercased, via forensics.parse_email).

    Returns:
        A dict with keys: domain, is_suspicious, closest_match, distance,
        match_type.
    """
    try:
        # Normalise input the same way forensics does.
        domain = str(domain).lower().strip()

        # MILESTONE 2.1: watchlist is loaded — matching logic not yet wired.
        # is_suspicious will remain False until 2.2 (edit-distance) lands.
        _ = _WATCHLIST  # accessed here so linters know it is intentionally used

        return {
            "domain": domain,
            "is_suspicious": False,
            "closest_match": None,
            "distance": None,
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
