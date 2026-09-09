"""Drift-report contract tests for dashboard scoring."""

from dashboard.scoring import compute_fraud_score


def _record(message_level=None, dns_posture=None, **modules):
    return {
        "parsed": {
            "auth_evidence": {
                "message_level": message_level or {},
                "domain_dns_posture": dns_posture or {},
            },
            "sender_anomalies": [],
        },
        "typosquat": {"is_suspicious": False},
        "nlp": {"label": "legitimate", "confidence": 1.0},
        "correlation": {"campaign_id": None},
        **modules,
    }


def test_clean_message_level_auth_passes_score_low():
    result = compute_fraud_score(_record({
        "spf_result": "pass", "dkim_result": "pass", "dmarc_result": "pass",
    }))

    assert result == {"score": 0.0, "verdict": "safe"}


def test_dkim_fail_and_typosquat_add_their_documented_weights():
    result = compute_fraud_score(_record(
        {"dkim_result": "fail"},
        typosquat={"is_suspicious": True, "match_type": "subdomain_abuse"},
    ))

    assert result == {"score": 50.0, "verdict": "suspicious"}


def test_legitimate_nlp_label_never_contributes_its_confidence():
    result = compute_fraud_score(_record(
        nlp={"label": "legitimate", "confidence": 0.99},
    ))

    assert result == {"score": 0.0, "verdict": "safe"}


def test_dns_timeout_is_no_auth_signal():
    result = compute_fraud_score(_record(
        {"spf_result": "none", "dkim_result": "none", "dmarc_result": "none"},
        {
            "used": True,
            "spf_result": "unavailable",
            "dmarc_result": "unavailable",
            "reason": "dns_timeout",
        },
    ))

    assert result == {"score": 0.0, "verdict": "safe"}


def test_spf_softfail_is_no_signal_not_a_fail():
    result = compute_fraud_score(_record(
        {"spf_result": "softfail", "dkim_result": "none", "dmarc_result": "none"},
    ))

    assert result == {"score": 0.0, "verdict": "safe"}
