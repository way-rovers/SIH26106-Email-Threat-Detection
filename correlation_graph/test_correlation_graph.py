"""Tests for persisted networkx campaign correlation."""

from correlation_graph.main import correlate


REQUIRED_KEYS = {"campaign_id", "linked_emails", "cluster_size", "match_reason"}

SAMPLE_RECORD = {
    "email_id": "test-001",
    "parsed": {
        "origin_ip": "185.220.101.45",
        "sender_domain": "micros0ft-support.com",
    },
    "typosquat": {"closest_match": "microsoft.com"},
}


def test_correlate_returns_dict(tmp_path):
    result = correlate(SAMPLE_RECORD, str(tmp_path / "campaigns.db"))
    assert isinstance(result, dict), "correlate() must return a dict"


def test_correlate_has_required_keys(tmp_path):
    result = correlate(SAMPLE_RECORD, str(tmp_path / "campaigns.db"))
    missing = REQUIRED_KEYS - result.keys()
    assert not missing, f"correlate() is missing keys: {missing}"


def test_correlate_linked_emails_is_list(tmp_path):
    result = correlate(SAMPLE_RECORD, str(tmp_path / "campaigns.db"))
    assert isinstance(result["linked_emails"], list)


def test_correlate_match_reason_is_list(tmp_path):
    result = correlate(SAMPLE_RECORD, str(tmp_path / "campaigns.db"))
    assert isinstance(result["match_reason"], list)


def test_correlate_cluster_size_is_int(tmp_path):
    result = correlate(SAMPLE_RECORD, str(tmp_path / "campaigns.db"))
    assert isinstance(result["cluster_size"], int)


def _record(email_id, origin_ip, closest_match=None):
    return {
        "email_id": email_id,
        "parsed": {"origin_ip": origin_ip, "sender_domain": "example.test"},
        "typosquat": {"closest_match": closest_match},
    }


def test_same_origin_ip_has_a_deterministic_campaign_id(tmp_path):
    db_path = str(tmp_path / "campaigns.db")
    first = _record("email-b", "185.220.101.45")
    second = _record("email-a", "185.220.101.45")

    correlate(first, db_path)
    second_result = correlate(second, db_path)
    first_result = correlate(first, db_path)

    assert second_result["campaign_id"] == "email-a"
    assert first_result["campaign_id"] == second_result["campaign_id"]
    assert second_result["linked_emails"] == ["email-b"]
    assert first_result["linked_emails"] == ["email-a"]
    assert second_result["cluster_size"] == 2
    assert second_result["match_reason"] == ["same_ip_block", "same_origin_ip"]


def test_connected_components_include_transitive_matches(tmp_path):
    db_path = str(tmp_path / "campaigns.db")
    first = _record("email-a", "10.0.0.1")
    second = _record("email-b", "10.0.0.2", "brand.test")
    third = _record("email-c", "198.51.100.3", "brand.test")

    correlate(first, db_path)
    correlate(second, db_path)
    result = correlate(third, db_path)

    assert result == {
        "campaign_id": "email-a",
        "linked_emails": ["email-a", "email-b"],
        "cluster_size": 3,
        "match_reason": ["same_impersonated_domain"],
    }
