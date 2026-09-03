"""
dashboard/pipeline.py — Person 4: end-to-end pipeline orchestrator.

Public contract:
    run_pipeline(eml_path: str) -> dict

Assembles the combined record:
{
    "email_id":      str,            # SHA-256 of from_addr + subject
    "parsed":        <parse_email output>,
    "typosquat":     <check_domain output>,
    "geo_hops":      [<geolocate_ip output>, ...],
    "classification":<classify_text output>,
    "correlation":   <correlate output>,
    "fraud_score":   float,
    "verdict":       "malicious" | "suspicious" | "safe",
}

Rules:
- Never raise an exception — if any sub-function fails, its slot in the
  combined record will contain whatever error shape that function returns.
- Calls compute_fraud_score() from dashboard/scoring.py.
"""

import hashlib

from forensics.main import parse_email
from typosquat.main import check_domain
from geolocation.main import geolocate_ip
from nlp_classifier.main import classify_text
from correlation_graph.main import correlate
from dashboard.scoring import compute_fraud_score


def run_pipeline(eml_path: str) -> dict:
    """Run the full threat-detection pipeline on a single .eml file.

    Args:
        eml_path: Path to the .eml file to analyse.

    Returns:
        A combined dict with keys: email_id, parsed, typosquat, geo_hops,
        classification, correlation, fraud_score, verdict.
    """
    # 1. Parse email headers + auth results.
    parsed = parse_email(eml_path)

    # 2. Typosquat check on the sender domain.
    sender_domain = parsed.get("sender_domain") or ""
    typosquat = check_domain(sender_domain)

    # 3. Geolocate every hop that has a non-null IP.
    received_chain = parsed.get("received_chain") or []
    geo_hops = [
        geolocate_ip(hop["ip"])
        for hop in received_chain
        if hop.get("ip")
    ]

    # 4. NLP classification on the body text.
    body_text = parsed.get("body_text") or ""
    classification = classify_text(body_text)

    # 5. Build email_id: prefer message_id; fall back to hash.
    message_id = parsed.get("message_id") or ""
    if message_id:
        email_id = message_id
    else:
        from_addr = parsed.get("from_addr") or ""
        subject = parsed.get("subject") or ""
        raw = f"{from_addr}{subject}{body_text[:200]}"
        email_id = hashlib.sha256(raw.encode()).hexdigest()

    # Partial combined record (before correlation, which needs the record itself).
    partial = {
        "email_id": email_id,
        "parsed": parsed,
        "typosquat": typosquat,
        "geo_hops": geo_hops,
        "classification": classification,
    }

    # 6. Correlation — pass the partial record so the graph module can read
    #    origin_ip, typosquat.closest_match, etc.
    correlation = correlate(partial)

    # 7. Fraud score + verdict.
    score_result = compute_fraud_score(partial)

    # 8. Assemble full combined record.
    combined = {
        **partial,
        "correlation": correlation,
        "fraud_score": score_result.get("score", 0.0),
        "verdict": score_result.get("verdict", "unknown"),
    }

    return combined
