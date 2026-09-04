"""
typosquat/main.py
Lookalike-domain / typosquat detection.
"""

import json
from pathlib import Path


WATCHLIST_FILE = Path(__file__).parent / "watchlist.json"

HOMOGLYPH_MAP = {
    "а": "a",  # Cyrillic small a
    "е": "e",  # Cyrillic small ie
    "о": "o",  # Cyrillic small o
    "р": "p",  # Cyrillic small er
    "с": "c",  # Cyrillic small es
    "х": "x",  # Cyrillic small ha
    "у": "y",  # Cyrillic small u
}


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


def normalize_homoglyphs(domain):
    """Replace supported lookalike characters with their Latin equivalents."""
    return "".join(HOMOGLYPH_MAP.get(character, character) for character in domain)


def find_brand_suffix_match(domain, watchlist):
    """Find a close brand typo used as the first part of a hyphenated label."""
    first_label = domain.split(".", 1)[0]
    if "-" not in first_label:
        return None

    brand_label = first_label.split("-", 1)[0]
    for watchlist_domain in watchlist:
        watchlist_label = watchlist_domain.split(".", 1)[0]
        if brand_label != watchlist_label and levenshtein(brand_label, watchlist_label) <= 2:
            return watchlist_domain

    return None


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

    homoglyph_domain = normalize_homoglyphs(domain)
    if homoglyph_domain != domain:
        for watchlist_domain in watchlist:
            if homoglyph_domain == watchlist_domain:
                return {
                    "domain": original_domain,
                    "is_suspicious": True,
                    "closest_match": watchlist_domain,
                    "distance": levenshtein(domain, watchlist_domain),
                    "match_type": "homoglyph",
                }

    brand_suffix_match = find_brand_suffix_match(domain, watchlist)
    if brand_suffix_match is not None:
        return {
            "domain": original_domain,
            "is_suspicious": True,
            "closest_match": brand_suffix_match,
            "distance": levenshtein(domain, brand_suffix_match),
            "match_type": "edit_distance",
        }

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