"""
forensics/main.py — Person 1: SPF/DKIM/DMARC header forensics.

Public contract:
    parse_email(eml_path: str) -> dict

Return shape (hardcoded stub — real parsing comes in Phase 1):
{
    "message_id":       str,          # e.g. "<abc123@mail.example.com>"
    "subject":          str,
    "from_addr":        str,          # full RFC 5322 address
    "sender_domain":    str,          # just the domain part of from_addr
    "body_text":        str,
    "spf_result":       "pass" | "fail" | "softfail" | "none",
    "dkim_result":      "pass" | "fail" | "none",
    "dmarc_result":     "pass" | "fail" | "none",
    "sender_anomalies": [str],        # e.g. ["from_returnpath_mismatch", "reply_to_mismatch"]
    "received_chain":   [
        {
            "hop_index": int,
            "from_host": str,
            "by_host":   str,
            "ip":        str,
            "timestamp": str,         # ISO-8601 or raw header value
        },
        ...
    ],
    "origin_ip":        str,          # earliest reliable IP in the received chain
}

Rules (from master context):
- Never raise an exception. On any failure, return the shape with null/"unknown" values.
- Do NOT change field names without notifying the team — other modules import
  specific keys from this dict.
"""

import email


def parse_email(eml_path: str) -> dict:
    """Open *eml_path* with Python's stdlib email module and return a
    ParsedEmail dict.

    STUB — currently returns hardcoded example data that matches the exact
    contract shape. Replace with real parsing logic in Phase 1.

    Args:
        eml_path: Filesystem path to a .eml file.

    Returns:
        A dict with keys: message_id, subject, from_addr, sender_domain,
        body_text, spf_result, dkim_result, dmarc_result, sender_anomalies,
        received_chain, origin_ip.
    """
    # Open the file (so we at least exercise the file-open path and catch
    # missing-file errors cleanly — real parsing replaces the body below).
    try:
        with open(eml_path, "rb") as fh:
            _msg = email.message_from_binary_file(fh)  # noqa: F841 — real parsing uses this
    except Exception as exc:  # noqa: BLE001
        # Never raise — return the error shape.
        return {
            "message_id": None,
            "subject": None,
            "from_addr": None,
            "sender_domain": None,
            "body_text": None,
            "spf_result": "none",
            "dkim_result": "none",
            "dmarc_result": "none",
            "sender_anomalies": [],
            "received_chain": [],
            "origin_ip": None,
            "error": str(exc),
        }

    # ------------------------------------------------------------------ #
    # HARDCODED STUB DATA — replace every field below with real values     #
    # when implementing Phase 1.                                           #
    # ------------------------------------------------------------------ #
    return {
        "message_id": "<phish-001@paypa1.com>",
        "subject": "Urgent: Verify your account immediately!",
        "from_addr": "security@paypa1.com",
        "sender_domain": "paypa1.com",
        "body_text": (
            "Dear Customer, your PayPal account has been limited. "
            "Click the link below to verify your identity."
        ),
        "spf_result": "fail",
        "dkim_result": "fail",
        "dmarc_result": "fail",
        "sender_anomalies": ["from_returnpath_mismatch", "reply_to_mismatch"],
        "received_chain": [
            {
                "hop_index": 0,
                "from_host": "mail.evil-relay.ru",
                "by_host": "mx.example.com",
                "ip": "185.220.101.45",
                "timestamp": "2026-09-03T11:00:00+00:00",
            }
        ],
        "origin_ip": "185.220.101.45",
    }
