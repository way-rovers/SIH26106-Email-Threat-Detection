"""Streamlit UI for the Email Threat Detection dashboard."""

import hashlib
import html
import math
import os
import tempfile

import folium
import streamlit as st
from streamlit_folium import st_folium

from dashboard.pipeline import run_pipeline
from dashboard.scoring import compute_fraud_score


def _mapping(value: object) -> dict:
    """Safely consume partial pipeline records in the UI."""
    return value if isinstance(value, dict) else {}


def _score_value(value: object) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def _status_badge(label: str, value: object, pass_values: set[str], fail_values: set[str]) -> None:
    """Render a pass, fail, or deliberately distinct no-signal status badge."""
    displayed_value = str(value) if value not in (None, "") else "unavailable"
    if value in pass_values:
        color, state = "#15803d", "PASS"
    elif value in fail_values:
        color, state = "#b91c1c", "FAIL"
    else:
        color, state = "#475569", "NO SIGNAL"
    st.markdown(
        f"<span style='background:{color}; color:white; padding:0.35rem 0.65rem; "
        f"border-radius:0.35rem; font-weight:700;'>{html.escape(label)}: {state}</span> "
        f"<small>{html.escape(displayed_value)}</small>",
        unsafe_allow_html=True,
    )


st.set_page_config(page_title="Email Threat Detection", page_icon="🛡️", layout="wide")
st.title("🛡️ Email Threat Detection Platform")
st.caption("Upload a raw .eml file to inspect email threat signals.")

uploaded_file = st.file_uploader(
    "Upload a .eml file",
    type=["eml"],
    help="Drag and drop or browse for an RFC 822 .eml message.",
)

if uploaded_file is not None:
    file_bytes = uploaded_file.getvalue()
    upload_id = hashlib.sha256(file_bytes).hexdigest()
    if st.session_state.get("upload_id") != upload_id:
        st.session_state["upload_id"] = upload_id
        st.session_state.pop("pipeline_result", None)
        st.session_state.pop("score_result", None)
        st.session_state.pop("analysis_error", None)

        temp_path = ""
        try:
            with tempfile.NamedTemporaryFile(delete=False, suffix=".eml", mode="wb") as temporary_file:
                temporary_file.write(file_bytes)
                temp_path = temporary_file.name
            try:
                st.session_state["pipeline_result"] = run_pipeline(temp_path)
            except Exception as error:
                st.session_state["analysis_error"] = f"Pipeline analysis failed: {error}"
            else:
                try:
                    st.session_state["score_result"] = compute_fraud_score(
                        st.session_state.get("pipeline_result")
                    )
                except Exception as error:
                    st.session_state["analysis_error"] = f"Fraud-score calculation failed: {error}"
        except Exception as error:
            st.session_state["analysis_error"] = f"Could not prepare the uploaded email: {error}"
        finally:
            if temp_path and os.path.exists(temp_path):
                os.unlink(temp_path)
else:
    st.session_state.pop("upload_id", None)
    st.session_state.pop("pipeline_result", None)
    st.session_state.pop("score_result", None)
    st.session_state.pop("analysis_error", None)

analysis_error = st.session_state.get("analysis_error")
if analysis_error:
    st.error(analysis_error)

overview_tab, headers_tab, domain_geo_tab, content_tab, campaign_tab = st.tabs(
    ["Overview", "Header Forensics", "Domain & Geo", "Content Analysis", "Campaign Graph"]
)

with overview_tab:
    result = _mapping(st.session_state.get("pipeline_result"))
    score_result = _mapping(st.session_state.get("score_result"))
    if not result or analysis_error:
        st.info("Upload a .eml file above to begin analysis.")
    else:
        parsed = _mapping(result.get("parsed"))
        verdict = str(score_result.get("verdict") or "unknown").lower()
        score = _score_value(score_result.get("score"))
        verdict_style = {
            "malicious": ("#b91c1c", "MALICIOUS"),
            "suspicious": ("#a16207", "SUSPICIOUS"),
            "safe": ("#15803d", "SAFE"),
        }.get(verdict, ("#475569", "UNKNOWN"))

        summary_column, score_column = st.columns(2)
        with summary_column:
            st.markdown(
                f"<span style='background:{verdict_style[0]}; color:white; padding:0.45rem 0.8rem; "
                f"border-radius:0.4rem; font-weight:700;'>{verdict_style[1]}</span>",
                unsafe_allow_html=True,
            )
            st.caption("Threat verdict")
        with score_column:
            st.metric("Fraud score", f"{score:.1f} / 100")

        st.subheader("Email overview")
        st.write(f"**From:** {parsed.get('from_addr') or 'Unavailable'}")
        st.write(f"**Subject:** {parsed.get('subject') or 'Unavailable'}")
        st.write(f"**Sender domain:** {parsed.get('sender_domain') or 'Unavailable'}")

with headers_tab:
    header_record = _mapping(st.session_state.get("pipeline_result"))
    header_parsed = _mapping(header_record.get("parsed"))
    if not header_record or analysis_error:
        st.info("Upload a .eml file above to inspect its header forensics.")
    else:
        st.subheader("Message authentication")
        auth_evidence = _mapping(header_parsed.get("auth_evidence"))
        message_level = _mapping(auth_evidence.get("message_level"))
        spf_column, dkim_column, dmarc_column = st.columns(3)
        with spf_column:
            _status_badge("SPF", message_level.get("spf_result"), {"pass"}, {"fail"})
        with dkim_column:
            _status_badge("DKIM", message_level.get("dkim_result"), {"pass"}, {"fail"})
        with dmarc_column:
            _status_badge("DMARC", message_level.get("dmarc_result"), {"pass"}, {"fail"})

        st.subheader("DNS posture (secondary evidence)")
        dns_posture = _mapping(auth_evidence.get("domain_dns_posture"))
        st.write(f"**DNS posture used:** {dns_posture.get('used') is True}")
        dns_spf_column, dns_dmarc_column = st.columns(2)
        with dns_spf_column:
            _status_badge("SPF posture", dns_posture.get("spf_result"), {"valid"}, {"invalid"})
        with dns_dmarc_column:
            _status_badge("DMARC posture", dns_posture.get("dmarc_result"), {"valid"}, {"invalid"})
        posture_reason = dns_posture.get("reason")
        if posture_reason:
            st.caption(f"DNS posture reason: {posture_reason}")

        st.subheader("Received chain")
        received_chain = header_parsed.get("received_chain")
        if isinstance(received_chain, list) and received_chain:
            chain_rows = []
            for hop in received_chain:
                hop_data = _mapping(hop)
                geo_data = _mapping(hop_data.get("geo"))
                chain_rows.append({
                    "hop_index": hop_data.get("hop_index", ""),
                    "from_host": hop_data.get("from_host", ""),
                    "by_host": hop_data.get("by_host", ""),
                    "ip": hop_data.get("ip", ""),
                    "timestamp": hop_data.get("timestamp", ""),
                    "country": geo_data.get("country") or "",
                    "city": geo_data.get("city") or "",
                })
            st.dataframe(chain_rows, hide_index=True, use_container_width=True)
        else:
            st.info("No received-chain hops were available.")

        st.subheader("Sender anomalies")
        anomalies = header_parsed.get("sender_anomalies")
        if isinstance(anomalies, list) and anomalies:
            for anomaly in anomalies:
                st.warning(str(anomaly))
        else:
            st.success("No anomalies detected.")

with domain_geo_tab:
    domain_record = _mapping(st.session_state.get("pipeline_result"))
    domain_parsed = _mapping(domain_record.get("parsed"))
    if not domain_record or analysis_error:
        st.info("Upload a .eml file above to inspect domain and relay-location signals.")
    else:
        st.subheader("Typosquat analysis")
        typosquat = _mapping(domain_record.get("typosquat"))
        is_suspicious = typosquat.get("is_suspicious") is True
        badge_color, badge_text = (
            ("#b91c1c", "SUSPICIOUS DOMAIN") if is_suspicious else ("#15803d", "CLEAN DOMAIN")
        )
        st.markdown(
            f"<span style='background:{badge_color}; color:white; padding:0.4rem 0.7rem; "
            f"border-radius:0.35rem; font-weight:700;'>{badge_text}</span>",
            unsafe_allow_html=True,
        )

        closest_match = typosquat.get("closest_match")
        distance = typosquat.get("distance")
        match_type = typosquat.get("match_type")
        match_type_labels = {
            "homoglyph": "Homoglyph lookalike (visually similar characters)",
            "subdomain_abuse": "Subdomain abuse (a trusted name embedded in another domain)",
            "edit_distance": "Edit-distance lookalike (small spelling variation)",
        }
        match_columns = st.columns(3)
        match_columns[0].metric("Closest watchlist match", closest_match or "None")
        match_columns[1].metric("Edit distance", distance if distance is not None else "N/A")
        match_columns[2].metric("Match type", match_type_labels.get(match_type, "No suspicious match type"))
        if not is_suspicious and closest_match:
            st.info("A nearest watchlist domain is shown for context only; this sender was not flagged as suspicious.")

        st.subheader("Relay path map")
        received_chain = domain_parsed.get("received_chain")
        plottable_hops = []
        if isinstance(received_chain, list):
            for chain_position, hop in enumerate(received_chain):
                hop_data = _mapping(hop)
                geo_data = _mapping(hop_data.get("geo"))
                lat = geo_data.get("lat")
                lon = geo_data.get("lon")
                has_coordinates = (
                    geo_data.get("error") == ""
                    and isinstance(lat, (int, float)) and not isinstance(lat, bool)
                    and isinstance(lon, (int, float)) and not isinstance(lon, bool)
                    and math.isfinite(lat) and math.isfinite(lon)
                )
                if has_coordinates:
                    plottable_hops.append({
                        "order": chain_position,
                        "hop_index": hop_data.get("hop_index", chain_position),
                        "ip": hop_data.get("ip") or "Unknown IP",
                        "country": geo_data.get("country") or "unknown",
                        "city": geo_data.get("city") or "unknown",
                        "lat": lat,
                        "lon": lon,
                    })

        if not plottable_hops:
            st.info("No relay hops have valid geolocation coordinates to plot.")
        else:
            center_lat = sum(hop.get("lat", 0.0) for hop in plottable_hops) / len(plottable_hops)
            center_lon = sum(hop.get("lon", 0.0) for hop in plottable_hops) / len(plottable_hops)
            relay_map = folium.Map(location=[center_lat, center_lon], zoom_start=2, control_scale=True)
            for hop in plottable_hops:
                popup = (
                    f"Hop {html.escape(str(hop.get('hop_index')))}<br>"
                    f"IP: {html.escape(str(hop.get('ip')))}<br>"
                    f"Location: {html.escape(str(hop.get('city')))}, {html.escape(str(hop.get('country')))}"
                )
                folium.Marker(
                    location=[hop.get("lat"), hop.get("lon")],
                    popup=folium.Popup(popup, max_width=280),
                    tooltip=f"Hop {hop.get('hop_index')}: {hop.get('ip')}",
                ).add_to(relay_map)
            if len(plottable_hops) >= 2:
                folium.PolyLine(
                    [(hop.get("lat"), hop.get("lon")) for hop in plottable_hops],
                    color="#2563eb",
                    weight=3,
                    opacity=0.75,
                ).add_to(relay_map)
            st_folium(relay_map, use_container_width=True, height=440, key="relay_path_map")

with content_tab:
    st.info("Coming soon")

with campaign_tab:
    st.info("Coming soon")
