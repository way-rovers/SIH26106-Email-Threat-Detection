"""Current-contract shape tests for ``dashboard.pipeline.run_pipeline``."""

from dashboard.pipeline import run_pipeline


EML_PATH = "contracts/fixtures/sample_phish_1.eml"

REQUIRED_KEYS = {"email_id", "parsed", "typosquat", "nlp", "correlation"}


def test_run_pipeline_returns_current_module_record_shape():
    result = run_pipeline(EML_PATH)

    assert isinstance(result, dict)
    assert REQUIRED_KEYS <= result.keys()
    assert "geo_hops" not in result
    assert "classification" not in result
    assert "fraud_score" not in result
    assert "verdict" not in result


def test_forensics_auth_evidence_is_preserved():
    result = run_pipeline(EML_PATH)
    parsed = result["parsed"]

    assert isinstance(parsed, dict)
    assert isinstance(parsed.get("auth_evidence"), dict)
    assert isinstance(parsed.get("auth_evidence", {}).get("message_level"), dict)
    assert isinstance(parsed.get("auth_evidence", {}).get("domain_dns_posture"), dict)


def test_every_received_hop_carries_its_geo_result():
    result = run_pipeline(EML_PATH)
    received_chain = result["parsed"].get("received_chain", [])

    assert isinstance(received_chain, list)
    for hop in received_chain:
        assert isinstance(hop, dict)
        assert isinstance(hop.get("geo"), dict)
