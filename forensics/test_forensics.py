"""forensics/test_forensics.py — Milestone 1.5: real assertions.

Run from the repo root (venv active):
    pytest forensics/test_forensics.py -v

All tests run against the 4 shared fixtures in contracts/fixtures/.
Edge-case tests use in-memory .eml bytes written to tmp files via
pytest's tmp_path fixture — no external network calls needed.
"""

import textwrap
import pytest
from forensics.main import parse_email

# ---------------------------------------------------------------------------
# Fixture paths (relative to repo root — run pytest from there)
# ---------------------------------------------------------------------------

LEGIT   = "contracts/fixtures/sample_legit_1.eml"
PHISH1  = "contracts/fixtures/sample_phish_1.eml"
PHISH2  = "contracts/fixtures/sample_phish_2_campaign_a.eml"
PHISH3  = "contracts/fixtures/sample_phish_3_campaign_a.eml"

REQUIRED_KEYS = {
    "message_id", "subject", "from_addr", "sender_domain",
    "body_text", "spf_result", "dkim_result", "dmarc_result",
    "sender_anomalies", "received_chain", "origin_ip",
}

VALID_SPF   = {"pass", "fail", "softfail", "none"}
VALID_AUTH  = {"pass", "fail", "none"}


# ===========================================================================
# Shape invariants — every fixture must satisfy these regardless of content
# ===========================================================================

@pytest.mark.parametrize("path", [LEGIT, PHISH1, PHISH2, PHISH3])
def test_returns_dict(path):
    assert isinstance(parse_email(path), dict)


@pytest.mark.parametrize("path", [LEGIT, PHISH1, PHISH2, PHISH3])
def test_required_keys_present(path):
    result = parse_email(path)
    missing = REQUIRED_KEYS - result.keys()
    assert not missing, f"Missing keys for {path}: {missing}"


@pytest.mark.parametrize("path", [LEGIT, PHISH1, PHISH2, PHISH3])
def test_auth_result_values_in_contract_vocabulary(path):
    r = parse_email(path)
    assert r["spf_result"]   in VALID_SPF,  f"spf_result out of vocabulary: {r['spf_result']}"
    assert r["dkim_result"]  in VALID_AUTH, f"dkim_result out of vocabulary: {r['dkim_result']}"
    assert r["dmarc_result"] in VALID_AUTH, f"dmarc_result out of vocabulary: {r['dmarc_result']}"


@pytest.mark.parametrize("path", [LEGIT, PHISH1, PHISH2, PHISH3])
def test_received_chain_is_list_of_dicts(path):
    chain = parse_email(path)["received_chain"]
    assert isinstance(chain, list)
    for hop in chain:
        assert isinstance(hop, dict)
        for key in ("hop_index", "from_host", "by_host", "ip", "timestamp"):
            assert key in hop, f"hop missing key '{key}'"


@pytest.mark.parametrize("path", [LEGIT, PHISH1, PHISH2, PHISH3])
def test_hop_indices_are_sequential_from_zero(path):
    chain = parse_email(path)["received_chain"]
    for i, hop in enumerate(chain):
        assert hop["hop_index"] == i, (
            f"hop_index out of order at position {i}: got {hop['hop_index']}"
        )


@pytest.mark.parametrize("path", [LEGIT, PHISH1, PHISH2, PHISH3])
def test_sender_anomalies_is_list_of_strings(path):
    anomalies = parse_email(path)["sender_anomalies"]
    assert isinstance(anomalies, list)
    for a in anomalies:
        assert isinstance(a, str)


# ===========================================================================
# Legit fixture — sample_legit_1.eml
# ===========================================================================

class TestLegit:
    def setup_method(self):
        self.r = parse_email(LEGIT)

    def test_basic_fields(self):
        assert self.r["message_id"]    == "<legit-001@bank-of-america.com>"
        assert self.r["sender_domain"] == "bank-of-america.com"
        assert "bank" in self.r["from_addr"].lower()
        assert self.r["subject"]       == "Your account statement is ready"

    def test_body_text_extracted(self):
        body = self.r["body_text"]
        assert "John" in body
        assert len(body) > 10

    def test_no_sender_anomalies(self):
        # The legit fixture has no Reply-To / Return-Path divergence.
        assert self.r["sender_anomalies"] == [], (
            "Legit fixture should have zero anomalies; "
            f"got: {self.r['sender_anomalies']}"
        )

    def test_no_received_chain(self):
        # sample_legit_1.eml has no Received header — empty chain is correct.
        assert self.r["received_chain"] == []
        assert self.r["origin_ip"] == ""


# ===========================================================================
# Phish 1 — sample_phish_1.eml  (paypa1.com typosquat)
# ===========================================================================

class TestPhish1:
    def setup_method(self):
        self.r = parse_email(PHISH1)

    def test_basic_fields(self):
        assert self.r["message_id"]    == "<phish-001@paypa1.com>"
        assert self.r["sender_domain"] == "paypa1.com"
        assert self.r["subject"]       == "Urgent: Verify your account immediately!"

    def test_body_text_extracted(self):
        body = self.r["body_text"]
        assert "PayPal" in body or "paypal" in body.lower()

    def test_reply_to_mismatch_flagged(self):
        assert "reply_to_mismatch" in self.r["sender_anomalies"], (
            "phish_1 has Reply-To on a different domain — must be flagged"
        )

    def test_received_chain_has_one_hop(self):
        chain = self.r["received_chain"]
        assert len(chain) == 1

    def test_origin_ip_extracted(self):
        assert self.r["origin_ip"] == "1.1.1.1"

    def test_origin_hop_hosts(self):
        hop = self.r["received_chain"][0]
        assert hop["from_host"] == "mail.evil-relay.ru"
        assert hop["by_host"]   == "mx.example.com"

    def test_origin_hop_timestamp_non_empty(self):
        assert self.r["received_chain"][0]["timestamp"] != ""


# ===========================================================================
# Campaign fixtures — phish_2 and phish_3 share infrastructure
# These are the emails the correlation graph will cluster together.
# ===========================================================================

class TestCampaignPair:
    def setup_method(self):
        self.r2 = parse_email(PHISH2)
        self.r3 = parse_email(PHISH3)

    def test_both_use_same_sender_domain(self):
        assert self.r2["sender_domain"] == "micros0ft-support.com"
        assert self.r3["sender_domain"] == "micros0ft-support.com"

    def test_both_have_reply_to_mismatch(self):
        assert "reply_to_mismatch" in self.r2["sender_anomalies"]
        assert "reply_to_mismatch" in self.r3["sender_anomalies"]

    def test_shared_origin_ip(self):
        """Critical for Milestone 7: correlation graph matches on origin_ip."""
        assert self.r2["origin_ip"] == "185.220.101.45"
        assert self.r3["origin_ip"] == "185.220.101.45"
        assert self.r2["origin_ip"] == self.r3["origin_ip"]

    def test_shared_relay_host(self):
        assert self.r2["received_chain"][0]["from_host"] == "smtp.shared-evil.net"
        assert self.r3["received_chain"][0]["from_host"] == "smtp.shared-evil.net"

    def test_different_targets(self):
        # Different subjects confirm these are distinct emails, not duplicates.
        assert self.r2["subject"] != self.r3["subject"]

    def test_message_ids_distinct(self):
        assert self.r2["message_id"] != self.r3["message_id"]


# ===========================================================================
# Edge cases — in-memory .eml bytes via tmp_path
# ===========================================================================

def _write_eml(tmp_path, content: str) -> str:
    """Write *content* to a temp .eml file, return its path as str."""
    p = tmp_path / "test.eml"
    p.write_bytes(textwrap.dedent(content).encode())
    return str(p)


class TestEdgeCases:

    def test_missing_file_does_not_raise(self):
        """A non-existent path must return the error shape, never raise."""
        result = parse_email("does_not_exist_xyz.eml")
        assert isinstance(result, dict)
        assert REQUIRED_KEYS.issubset(result.keys())

    def test_missing_received_header_gives_empty_chain(self, tmp_path):
        eml = _write_eml(tmp_path, """\
            From: sender@example.com
            To: recv@example.com
            Subject: No hops
            Message-ID: <x@example.com>
            MIME-Version: 1.0
            Content-Type: text/plain

            Body text here.
        """)
        r = parse_email(eml)
        assert r["received_chain"] == []
        assert r["origin_ip"] == ""

    def test_html_only_body_falls_back_gracefully(self, tmp_path):
        eml = _write_eml(tmp_path, """\
            From: sender@example.com
            To: recv@example.com
            Subject: HTML only
            Message-ID: <x@example.com>
            MIME-Version: 1.0
            Content-Type: text/html

            <html><body><p>Hello <b>world</b></p></body></html>
        """)
        r = parse_email(eml)
        assert "Hello" in r["body_text"]
        assert "<" not in r["body_text"], "HTML tags should be stripped"

    def test_malformed_from_header_does_not_raise(self, tmp_path):
        eml = _write_eml(tmp_path, """\
            From: not-a-valid-address
            To: recv@example.com
            Subject: Bad From
            Message-ID: <x@example.com>
            MIME-Version: 1.0
            Content-Type: text/plain

            Body.
        """)
        r = parse_email(eml)
        assert isinstance(r, dict)
        # sender_domain may be empty — that's fine; it must not crash.
        assert isinstance(r["sender_domain"], str)

    def test_missing_message_id_flagged_as_anomaly(self, tmp_path):
        eml = _write_eml(tmp_path, """\
            From: phisher@evil.com
            To: victim@example.com
            Subject: No Message-ID here
            MIME-Version: 1.0
            Content-Type: text/plain

            Click here now.
        """)
        r = parse_email(eml)
        assert "missing_message_id" in r["sender_anomalies"]

    def test_message_id_domain_mismatch_flagged(self, tmp_path):
        """Message-ID stamped by a relay domain different from sender_domain."""
        eml = _write_eml(tmp_path, """\
            From: phisher@evil.com
            To: victim@example.com
            Subject: Mismatched MsgID
            Message-ID: <abc@smtp.relay-server.net>
            MIME-Version: 1.0
            Content-Type: text/plain

            Body.
        """)
        r = parse_email(eml)
        assert "suspicious_message_id" in r["sender_anomalies"]

    def test_multipart_prefers_plain_over_html(self, tmp_path):
        # Raw multipart — must pick text/plain, not text/html.
        raw = (
            "From: s@example.com\r\n"
            "To: r@example.com\r\n"
            "Subject: Multipart\r\n"
            "Message-ID: <mp@example.com>\r\n"
            "MIME-Version: 1.0\r\n"
            "Content-Type: multipart/alternative; boundary=\"BOUND\"\r\n"
            "\r\n"
            "--BOUND\r\n"
            "Content-Type: text/plain\r\n"
            "\r\n"
            "Plain text part\r\n"
            "--BOUND\r\n"
            "Content-Type: text/html\r\n"
            "\r\n"
            "<html><body>HTML part</body></html>\r\n"
            "--BOUND--\r\n"
        )
        p = tmp_path / "mp.eml"
        p.write_bytes(raw.encode())
        r = parse_email(str(p))
        assert "Plain text part" in r["body_text"]
        assert "HTML part" not in r["body_text"]
