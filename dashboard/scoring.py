"""
dashboard/scoring.py — Person 4: fraud score computation.

Stub formula (Person 4 owns and tunes this):
    DKIM or DMARC fail      → +30
    SPF fail                → +15
    Each sender anomaly     → +10 (capped at +20)
    Typosquat is_suspicious → +20
    NLP label == "phishing" → up to +15 scaled by confidence
    Campaign correlation    → +15 (if campaign_id is present)
    Clamp to 0–100.

Verdict thresholds:
    ≥ 60  → "malicious"
    30–59 → "suspicious"
    < 30  → "safe"

NOTE: This is a heuristic, not a scientific formula. Header/typosquat signals
deliberately outweigh the NLP signal — an attacker can craft legitimate-looking
body text but cannot fake a DKIM verification.
"""


def compute_fraud_score(combined: dict | None = None) -> dict:
    """Compute a 0-100 fraud score and a three-way verdict from *combined*.

    STUB — ignores *combined* and returns a fixed suspicious score. Replace
    with the real formula above in Phase 1.

    Args:
        combined: The combined pipeline record (may be None in stub mode).

    Returns:
        A dict with keys: score (float 0-100), verdict (str).
    """
    # HARDCODED STUB — replace with real formula in Phase 1.
    return {"score": 50.0, "verdict": "suspicious"}
