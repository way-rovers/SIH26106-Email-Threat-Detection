"""
typosquat/main.py
Lookalike-domain / typosquat detection.
"""

import json
from pathlib import Path


WATCHLIST_FILE = Path(__file__).parent / "watchlist.json"


def load_watchlist():
    """Load legitimate domains from watchlist.json."""
    try:
        with open(WATCHLIST_FILE, "r", encoding="utf-8") as file:
            data = json.load(file)
            return data.get("watchlist", [])
    except (FileNotFoundError, json.JSONDecodeError):
        return []


def levenshtein(a, b):
    """Calculate Levenshtein edit distance between two strings."""
    previous = list(range(len(b) + 1))

    for i, char_a in enumerate(a, 1):
        current = [i]

        for j, char_b in enumerate(b, 1):
            insert = current[j - 1] + 1
            delete = previous[j] + 1
            replace = previous[j - 1] + (char_a != char_b)

            current.append(min(insert, delete, replace))

        previous = current

    return previous[-1]


def normalize_domain(domain):
    """Normalize a domain for comparison."""
    if not isinstance(domain, str):
        return ""

    domain = domain.strip().lower()

    if "://" in domain:
        domain = domain.split("://", 1)[1]

    domain = domain.split("/", 1)[0]
    domain = domain.split(":", 1)[0]

    if domain.startswith("www."):
        domain = domain[4:]

    return domain


def check_domain(domain: str) -> dict:
    """Check whether a domain looks like an impersonation of a known brand."""

    original_domain = domain
    domain = normalize_domain(domain)

    if not domain:
        return {
            "domain": original_domain,
            "is_suspicious": False,
            "closest_match": None,
            "distance": None,
            "match_type": None,
        }

    watchlist = load_watchlist()

    if not watchlist:
        return {
            "domain": original_domain,
            "is_suspicious": False,
            "closest_match": None,
            "distance": None,
            "match_type": None,
        }

    closest_match = min(
        watchlist,
        key=lambda item: levenshtein(domain, item)
    )

    distance = levenshtein(domain, closest_match)

    is_suspicious = (
        domain != closest_match
        and distance <= 2
    )

    return {
        "domain": original_domain,
        "is_suspicious": is_suspicious,
        "closest_match": closest_match if is_suspicious else None,
        "distance": distance if is_suspicious else None,
        "match_type": "edit_distance" if is_suspicious else None,
    }