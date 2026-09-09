"""Fraud-score calculation for the assembled dashboard record."""

from math import isfinite


def _mapping(value: object) -> dict:
    """Return a dictionary-shaped value without trusting partial records."""
    return value if isinstance(value, dict) else {}


def _message_auth_result(message_level: dict, check: str) -> str | None:
    """Return only a real message-level pass/fail result for one check."""
    result = message_level.get(f"{check}_result")
    # SPF "softfail" is deliberately excluded: like "none", it is ambiguous
    # and may fall back to eligible DNS posture rather than scoring as a fail.
    return result if result in {"pass", "fail"} else None


def _dns_auth_result(dns_posture: dict, check: str) -> str | None:
    """Resolve an eligible DNS-posture result to pass/fail, or no signal.

    DNS posture has SPF and DMARC results only.  Its unavailable, timeout,
    lookup-error, and not-needed states intentionally remain no-signal.
    """
    if dns_posture.get("used") is not True:
        return None
    result = dns_posture.get(f"{check}_result")
    if result == "valid":
        return "pass"
    if result == "invalid":
        return "fail"
    return None


def _auth_result(message_level: dict, dns_posture: dict, check: str) -> str | None:
    """Prefer real message evidence, then a real resolved DNS posture."""
    message_result = _message_auth_result(message_level, check)
    if message_result is not None:
        return message_result
    return _dns_auth_result(dns_posture, check)


def compute_fraud_score(record: dict) -> dict:
    """Compute a defensive 0–100 score and verdict from a pipeline record."""
    safe_record = _mapping(record)
    parsed = _mapping(safe_record.get("parsed"))
    auth_evidence = _mapping(parsed.get("auth_evidence"))
    message_level = _mapping(auth_evidence.get("message_level"))
    dns_posture = _mapping(auth_evidence.get("domain_dns_posture"))

    score = 0.0

    # Auth: never inspect legacy parsed.{spf,dkim,dmarc}_result fields.
    if _auth_result(message_level, dns_posture, "dkim") == "fail":
        score += 30.0
    if _auth_result(message_level, dns_posture, "dmarc") == "fail":
        score += 30.0
    if _auth_result(message_level, dns_posture, "spf") == "fail":
        score += 15.0

    anomalies = parsed.get("sender_anomalies")
    if isinstance(anomalies, list):
        score += float(min(len(anomalies), 2) * 10)

    typosquat = _mapping(safe_record.get("typosquat"))
    if typosquat.get("is_suspicious") is True:
        score += 20.0

    nlp = _mapping(safe_record.get("nlp"))
    if nlp.get("label") == "phishing":
        confidence = nlp.get("confidence")
        try:
            confidence = float(confidence)
        except (TypeError, ValueError):
            confidence = 0.0
        if not isfinite(confidence):
            confidence = 0.0
        score += 15.0 * min(max(confidence, 0.0), 1.0)

    correlation = _mapping(safe_record.get("correlation"))
    if correlation.get("campaign_id") is not None:
        score += 15.0

    score = min(max(score, 0.0), 100.0)
    if score >= 60.0:
        verdict = "malicious"
    elif score >= 30.0:
        verdict = "suspicious"
    else:
        verdict = "safe"
    return {"score": float(score), "verdict": verdict}
