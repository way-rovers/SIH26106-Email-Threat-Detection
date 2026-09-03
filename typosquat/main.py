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
"""


def check_domain(domain: str) -> dict:
    """Check whether *domain* looks like an impersonation of a known brand.

    STUB — currently returns hardcoded example data. Replace with real
    Levenshtein / homoglyph logic in Phase 1.

    Args:
        domain: The sender domain extracted from the email headers.

    Returns:
        A dict with keys: domain, is_suspicious, closest_match, distance,
        match_type.
    """
    # HARDCODED STUB — replace with real logic in Phase 1.
    return {
        "domain": domain,
        "is_suspicious": True,
        "closest_match": "paypal.com",
        "distance": 1,
        "match_type": "edit_distance",
    }
