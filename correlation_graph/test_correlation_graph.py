"""correlation_graph/test_correlation_graph.py — shape-check tests for correlate()."""

import pytest
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


def test_correlate_returns_dict():
    result = correlate(SAMPLE_RECORD)
    assert isinstance(result, dict), "correlate() must return a dict"


def test_correlate_has_required_keys():
    result = correlate(SAMPLE_RECORD)
    missing = REQUIRED_KEYS - result.keys()
    assert not missing, f"correlate() is missing keys: {missing}"


def test_correlate_linked_emails_is_list():
    result = correlate(SAMPLE_RECORD)
    assert isinstance(result["linked_emails"], list), \
        "linked_emails must be a list"


def test_correlate_match_reason_is_list():
    result = correlate(SAMPLE_RECORD)
    assert isinstance(result["match_reason"], list), \
        "match_reason must be a list"


def test_correlate_cluster_size_is_int():
    result = correlate(SAMPLE_RECORD)
    assert isinstance(result["cluster_size"], int), \
        "cluster_size must be an int"
