"""forensics/test_forensics.py — shape-check tests for parse_email()."""

import pytest
from forensics.main import parse_email

EML_PATH = "contracts/fixtures/sample_phish_1.eml"

REQUIRED_KEYS = {
    "message_id",
    "subject",
    "from_addr",
    "sender_domain",
    "body_text",
    "spf_result",
    "dkim_result",
    "dmarc_result",
    "sender_anomalies",
    "received_chain",
    "origin_ip",
}


def test_parse_email_returns_dict():
    result = parse_email(EML_PATH)
    assert isinstance(result, dict), "parse_email() must return a dict"


def test_parse_email_has_required_keys():
    result = parse_email(EML_PATH)
    missing = REQUIRED_KEYS - result.keys()
    assert not missing, f"parse_email() is missing keys: {missing}"


def test_received_chain_is_list():
    result = parse_email(EML_PATH)
    assert isinstance(result["received_chain"], list), \
        "received_chain must be a list"


def test_sender_anomalies_is_list():
    result = parse_email(EML_PATH)
    assert isinstance(result["sender_anomalies"], list), \
        "sender_anomalies must be a list"
