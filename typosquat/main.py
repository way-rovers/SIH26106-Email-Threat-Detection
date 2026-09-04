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
    """Calculate Damerau-Levenshtein distance between two strings."""
    a_length = len(a)
    b_length = len(b)
    max_distance = a_length + b_length
    distances = [[0] * (b_length + 2) for _ in range(a_length + 2)]
    last_row = {}

    distances[0][0] = max_distance
    for index in range(a_length + 1):
        distances[index + 1][0] = max_distance
        distances[index + 1][1] = index

    for index in range(b_length + 1):
        distances[0][index + 1] = max_distance
        distances[1][index + 1] = index

    for a_index, char_a in enumerate(a, 1):
        last_matching_b_index = 0

        for b_index, char_b in enumerate(b, 1):
            previous_matching_a_index = last_row.get(char_b, 0)
            previous_matching_b_index = last_matching_b_index
            substitution_cost = 1

            if char_a == char_b:
                substitution_cost = 0
                last_matching_b_index = b_index

            distances[a_index + 1][b_index + 1] = min(
                distances[a_index][b_index] + substitution_cost,
                distances[a_index + 1][b_index] + 1,
                distances[a_index][b_index + 1] + 1,
                distances[previous_matching_a_index][previous_matching_b_index]
                + (a_index - previous_matching_a_index - 1)
                + 1
                + (b_index - previous_matching_b_index - 1),
            )

        last_row[char_a] = a_index

    return distances[a_length + 1][b_length + 1]


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