"""End-to-end dashboard pipeline orchestration."""

import hashlib

from correlation_graph.main import correlate
from forensics.main import parse_email
from geolocation.main import geolocate_batch
from nlp_classifier.main import classify_text
from typosquat.main import check_domain


def _text(value: object) -> str:
    """Return a safe string for values obtained from defensive ``.get`` calls."""
    return value if isinstance(value, str) else ""


def _parsed_failure(error: Exception) -> dict:
    """Return the documented parse failure shape for an orchestration failure."""
    unavailable_sources = {"spf": "unavailable", "dkim": "unavailable", "dmarc": "unavailable"}
    return {
        "message_id": "", "subject": "", "from_addr": "", "sender_domain": "", "body_text": "",
        "spf_result": "none", "dkim_result": "none", "dmarc_result": "none",
        "auth_evidence": {
            "message_level": {"spf_result": "none", "dkim_result": "none", "dmarc_result": "none", "sources": unavailable_sources},
            "domain_dns_posture": {"used": False, "spf_result": "not_checked", "dmarc_result": "not_checked", "reason": "message_unreadable"},
            "legacy_result_sources": {"spf_result": "unavailable", "dkim_result": "unavailable", "dmarc_result": "unavailable"},
        },
        "sender_anomalies": [], "received_chain": [], "origin_ip": "", "error": str(error),
    }


def _geo_failure(ip: str, error: Exception) -> dict:
    return {"ip": ip, "country": "unknown", "city": "unknown", "isp": "unknown", "lat": None, "lon": None, "error": str(error)}


def run_pipeline(eml_path: str) -> dict:
    """Run every detector, retaining safe partial results if a detector fails."""
    # 1. Forensics is the bedrock. Keep its auth_evidence object intact.
    try:
        parsed_result = parse_email(eml_path)
        parsed = parsed_result if isinstance(parsed_result, dict) else _parsed_failure(TypeError("parse_email returned a non-dict result"))
    except Exception as error:
        parsed = _parsed_failure(error)

    body_text = _text(parsed.get("body_text"))
    message_id = _text(parsed.get("message_id"))
    if message_id:
        email_id = message_id
    else:
        raw = _text(parsed.get("from_addr")) + _text(parsed.get("subject")) + body_text[:200]
        email_id = hashlib.sha256(raw.encode()).hexdigest()

    # 2. Typosquat analysis.
    sender_domain = _text(parsed.get("sender_domain"))
    typo_fallback = {"domain": sender_domain.lower(), "is_suspicious": False, "closest_match": None, "distance": None, "match_type": None}
    try:
        typosquat_result = check_domain(sender_domain)
        typosquat = typosquat_result if isinstance(typosquat_result, dict) else typo_fallback
    except Exception:
        typosquat = typo_fallback

    # 3. One batch lookup for every non-empty received-chain IP.
    received_chain_value = parsed.get("received_chain")
    received_chain = received_chain_value if isinstance(received_chain_value, list) else []
    ips: list[str] = []
    hop_ip_positions: list[tuple[int, str]] = []
    for index, hop in enumerate(received_chain):
        if isinstance(hop, dict):
            ip = _text(hop.get("ip"))
            if ip:
                hop_ip_positions.append((index, ip))
                ips.append(ip)
    try:
        batch_result = geolocate_batch(ips)  # Exactly one call; the batch may be empty.
        geolocations = batch_result if isinstance(batch_result, list) else []
    except Exception as error:
        geolocations = [_geo_failure(ip, error) for ip in ips]

    # Keep the forensics result as the record's source of truth and enrich its
    # received-chain hops in place.  auth_evidence is never copied, flattened,
    # or altered.
    geo_received_chain = [dict(hop) if isinstance(hop, dict) else {"raw_hop": hop} for hop in received_chain]
    for batch_index, (hop_index, ip) in enumerate(hop_ip_positions):
        location = geolocations[batch_index] if batch_index < len(geolocations) else None
        location = location if isinstance(location, dict) else _geo_failure(ip, TypeError("invalid batch result"))
        geo_received_chain[hop_index]["geo"] = location
    for hop in geo_received_chain:
        if not isinstance(hop.get("geo"), dict):
            hop["geo"] = _geo_failure(_text(hop.get("ip")), ValueError("received hop has no IP"))
    parsed["received_chain"] = geo_received_chain

    # 4. Content classifier.
    nlp_fallback = {"label": "legitimate", "confidence": 0.0, "top_words": []}
    try:
        classification_result = classify_text(body_text)
        classification = classification_result if isinstance(classification_result, dict) else nlp_fallback
    except Exception:
        classification = nlp_fallback

    # 5. Correlation is last and receives all field paths it needs.
    combined = {
        "email_id": email_id, "parsed": parsed, "typosquat": typosquat,
        "nlp": classification,
        "correlation": {"campaign_id": None, "linked_emails": [], "cluster_size": 1, "match_reason": []},
    }
    try:
        correlation_result = correlate(combined)
        if isinstance(correlation_result, dict):
            combined["correlation"] = correlation_result
    except Exception:
        pass
    return combined
