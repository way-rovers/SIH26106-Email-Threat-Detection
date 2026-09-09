"""Tests for persisted networkx campaign correlation."""

import hashlib
import sqlite3
from pathlib import Path
from unittest.mock import patch

from correlation_graph.main import correlate
from forensics.main import parse_email
from geolocation.main import geolocate_ip
from nlp_classifier.main import classify_text
from typosquat.main import check_domain


REQUIRED_KEYS = {"campaign_id", "linked_emails", "cluster_size", "match_reason"}

SAMPLE_RECORD = {
        "email_id": "test-001",
        "parsed": {
        "origin_ip": "1.1.1.1",
        "sender_domain": "micros0ft-support.com",
    },
    "typosquat": {"closest_match": "microsoft.com"},
}

_FIXTURES_DIR = Path(__file__).resolve().parent.parent / "contracts" / "fixtures"


def _build_pipeline_record(eml_path: Path) -> dict:
    """Run the pre-dashboard pipeline stages for one fixture."""
    parsed = parse_email(str(eml_path))
    typosquat = check_domain(parsed.get("sender_domain") or "")
    geo_hops = [
        geolocate_ip(hop["ip"])
        for hop in parsed.get("received_chain") or []
        if hop.get("ip")
    ]
    classification = classify_text(parsed.get("body_text") or "")

    email_id = parsed.get("message_id") or hashlib.sha256(
        (
            f"{parsed.get('from_addr') or ''}{parsed.get('subject') or ''}"
            f"{parsed.get('body_text') or ''}"
        ).encode()
    ).hexdigest()
    return {
        "email_id": email_id,
        "parsed": parsed,
        "typosquat": typosquat,
        "geo_hops": geo_hops,
        "classification": classification,
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
    first = _record("email-b", "1.1.1.1")
    second = _record("email-a", "1.1.1.1")

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


def test_campaign_a_fixtures_cluster_and_other_fixtures_remain_unlinked(tmp_path):
    """Exercise forensics, typosquat, geo, NLP, and correlation in sequence."""
    db_path = str(tmp_path / "campaigns.db")
    fixture_names = [
        "sample_legit_1.eml",
        "sample_phish_1.eml",
        "sample_phish_2_campaign_a.eml",
        "sample_phish_3_campaign_a.eml",
    ]
    # DNS is outside this test's scope and can be unavailable in CI.  Keep the
    # real parser while making its optional DNS fallback deterministic.
    with patch(
        "forensics.main._checkdmarc_lookup",
        return_value={
            "spf": "none",
            "dmarc": "none",
            "posture": {
                "used": True,
                "spf_result": "unavailable",
                "dmarc_result": "unavailable",
                "reason": "lookup_error",
            },
        },
    ):
        records = {
            fixture_name: _build_pipeline_record(_FIXTURES_DIR / fixture_name)
            for fixture_name in fixture_names
        }

    initial_results = {
        fixture_name: correlate(record, db_path)
        for fixture_name, record in records.items()
    }
    campaign_two_result = correlate(records["sample_phish_2_campaign_a.eml"], db_path)
    campaign_three_result = initial_results["sample_phish_3_campaign_a.eml"]

    assert initial_results["sample_legit_1.eml"] == {
        "campaign_id": None,
        "linked_emails": [],
        "cluster_size": 1,
        "match_reason": [],
    }
    assert initial_results["sample_phish_1.eml"] == {
        "campaign_id": None,
        "linked_emails": [],
        "cluster_size": 1,
        "match_reason": [],
    }
    assert campaign_two_result["campaign_id"] == campaign_three_result["campaign_id"]
    assert campaign_two_result["cluster_size"] >= 2
    assert campaign_three_result["cluster_size"] >= 2
    assert "same_origin_ip" in campaign_three_result["match_reason"]


def test_first_ever_email_has_no_campaign_or_edges(tmp_path):
    result = correlate(_record("first-email", "8.8.8.8"), str(tmp_path / "campaigns.db"))

    assert result == {
        "campaign_id": None,
        "linked_emails": [],
        "cluster_size": 1,
        "match_reason": [],
    }


def test_reprocessing_an_unlinked_email_is_idempotent(tmp_path):
    db_path = str(tmp_path / "campaigns.db")
    record = _record("idempotent-email", "9.9.9.9")

    correlate(record, db_path)
    result = correlate(record, db_path)
    with sqlite3.connect(db_path) as connection:
        email_count = connection.execute(
            "SELECT COUNT(*) FROM emails WHERE email_id = ?", (record["email_id"],)
        ).fetchone()[0]
        edge_count = connection.execute("SELECT COUNT(*) FROM edges").fetchone()[0]

    assert email_count == 1
    assert edge_count == 0
    assert result["campaign_id"] is None


def test_reprocessing_linked_emails_does_not_duplicate_edges(tmp_path):
    db_path = str(tmp_path / "campaigns.db")
    first = _record("email-b", "1.1.1.1")
    second = _record("email-a", "1.1.1.1")

    correlate(first, db_path)
    initial_result = correlate(second, db_path)
    correlate(first, db_path)
    repeated_result = correlate(second, db_path)
    with sqlite3.connect(db_path) as connection:
        edge_count = connection.execute("SELECT COUNT(*) FROM edges").fetchone()[0]

    assert edge_count == 2
    assert initial_result["campaign_id"] == "email-a"
    assert repeated_result["campaign_id"] == initial_result["campaign_id"]
    assert initial_result["cluster_size"] == 2
    assert repeated_result["cluster_size"] == initial_result["cluster_size"]


def test_legacy_duplicate_edges_are_deduplicated_before_unique_index(tmp_path):
    db_path = str(tmp_path / "campaigns.db")
    with sqlite3.connect(db_path) as connection:
        connection.executescript(
            """
            CREATE TABLE emails (
                email_id TEXT PRIMARY KEY, sender_domain TEXT, origin_ip TEXT,
                impersonated_domain TEXT, campaign_id TEXT, raw_record TEXT
            );
            CREATE TABLE edges (
                email_id_a TEXT, email_id_b TEXT, reason TEXT
            );
            """
        )
        connection.executemany(
            "INSERT INTO emails (email_id, origin_ip) VALUES (?, ?)",
            [("email-a", "1.1.1.1"), ("email-b", "1.1.1.1")],
        )
        connection.executemany(
            "INSERT INTO edges VALUES (?, ?, ?)",
            [
                ("email-a", "email-b", "same_origin_ip"),
                ("email-a", "email-b", "same_origin_ip"),
            ],
        )

    result = correlate(_record("email-a", "1.1.1.1"), db_path)
    with sqlite3.connect(db_path) as connection:
        edge_count = connection.execute("SELECT COUNT(*) FROM edges").fetchone()[0]

    assert result["campaign_id"] == "email-a"
    assert result["linked_emails"] == ["email-b"]
    assert result["cluster_size"] == 2
    assert edge_count == 2
