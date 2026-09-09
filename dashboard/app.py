"""Streamlit UI for the Email Threat Detection dashboard."""

import hashlib
import html
import json
import math
import os
from pathlib import Path
import re
import tempfile

import folium
import streamlit as st
from dotenv import load_dotenv
from folium.plugins import AntPath
from streamlit_folium import st_folium

from dashboard.pipeline import run_pipeline
from dashboard.scoring import compute_fraud_score


_PROJECT_ROOT = Path(__file__).resolve().parent.parent
# Streamlit does not load .env files itself; do this before CARTO_API_KEY is read.
load_dotenv(_PROJECT_ROOT / ".env")


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
                        "isp": geo_data.get("isp") or "unknown",
                        "lat": lat,
                        "lon": lon,
                    })

        if not plottable_hops:
            st.info("No relay hops have valid geolocation coordinates to plot.")
        else:
            coords = [(hop.get("lat"), hop.get("lon")) for hop in plottable_hops]
            if len(plottable_hops) == 1:
                relay_map = folium.Map(location=coords[0], tiles=None, zoom_start=6, control_scale=True)
            else:
                relay_map = folium.Map(location=[0, 0], tiles=None, control_scale=True)

            carto_key = os.getenv("CARTO_API_KEY", "").strip()
            if carto_key:
                carto_tiles = (
                    "https://basemaps.cartocdn.com/rastertiles/dark_all/"
                    f"{{z}}/{{x}}/{{y}}.png?key={carto_key}"
                )
                folium.TileLayer(
                    tiles=carto_tiles,
                    attr="&copy; CARTO",
                    name="CartoDB Dark Matter",
                    no_wrap=True,
                ).add_to(relay_map)
            else:
                folium.TileLayer(tiles="OpenStreetMap", no_wrap=True).add_to(relay_map)

            marker_colours = {"origin": "#e74c3c", "intermediate": "#3498db", "destination": "#2ecc71"}
            for marker_index, hop in enumerate(plottable_hops):
                if marker_index == 0:
                    role = "origin"
                elif marker_index == len(plottable_hops) - 1:
                    role = "destination"
                else:
                    role = "intermediate"
                marker_colour = marker_colours.get(role, "#3498db")
                popup = (
                    f"<b>Hop {html.escape(str(hop.get('hop_index')))} — {role.capitalize()}</b><br>"
                    f"IP: {html.escape(str(hop.get('ip')))}<br>"
                    f"Country: {html.escape(str(hop.get('country')))}<br>"
                    f"City: {html.escape(str(hop.get('city')))}<br>"
                    f"ISP: {html.escape(str(hop.get('isp') or 'unknown'))}"
                )
                folium.CircleMarker(
                    location=(hop.get("lat"), hop.get("lon")),
                    radius=10 if role == "origin" else 8,
                    color=marker_colour,
                    fill=True,
                    fill_color=marker_colour,
                    fill_opacity=0.9,
                    popup=folium.Popup(popup, max_width=280),
                    tooltip=f"Hop {hop.get('hop_index')}: {hop.get('city')}, {hop.get('country')}",
                ).add_to(relay_map)
            if len(plottable_hops) >= 2:
                AntPath(
                    locations=coords,
                    color="#f39c12",
                    weight=3,
                    opacity=0.8,
                    delay=800,
                    dash_array=[10, 20],
                    pulse_color="#ffffff",
                ).add_to(relay_map)
                relay_map.fit_bounds(coords)
            st_folium(relay_map, use_container_width=True, height=440, key="relay_path_map")

with content_tab:
    content_record = _mapping(st.session_state.get("pipeline_result"))
    content_parsed = _mapping(content_record.get("parsed"))
    if not content_record or analysis_error:
        st.info("Upload a .eml file above to inspect its content-analysis signals.")
    else:
        st.subheader("Classifier result")
        nlp = _mapping(content_record.get("nlp"))
        label = str(nlp.get("label") or "unavailable")
        confidence = min(max(_score_value(nlp.get("confidence")), 0.0), 1.0)
        st.metric("Classification confidence", f"{confidence:.0%} confidence in {label}")

        threshold_path = Path(__file__).resolve().parent.parent / "nlp_classifier" / "model" / "threshold_meta.json"
        try:
            with threshold_path.open("r", encoding="utf-8") as threshold_file:
                threshold_meta = _mapping(json.load(threshold_file))
            trained_threshold = threshold_meta.get("threshold")
            threshold_display = f"{float(trained_threshold):.4f}"
        except (OSError, ValueError, TypeError, json.JSONDecodeError):
            threshold_display = "threshold unavailable"
        st.caption(f"Active trained classification threshold: {threshold_display}")

        st.subheader("Email body and influential terms")
        body_text = content_parsed.get("body_text")
        body_text = body_text if isinstance(body_text, str) else ""
        top_words_value = nlp.get("top_words")
        top_words = []
        if isinstance(top_words_value, list):
            seen_words = set()
            for word in top_words_value:
                if isinstance(word, str) and word.strip() and word.casefold() not in seen_words:
                    top_words.append(word.strip())
                    seen_words.add(word.casefold())

        if not body_text:
            st.info("No body text was available for content analysis.")
        elif not top_words:
            st.text(body_text)
        else:
            # Longer words win overlapping matches; each original fragment is
            # HTML-escaped before Streamlit renders the inline highlighting.
            word_pattern = re.compile(
                "(" + "|".join(re.escape(word) for word in sorted(top_words, key=len, reverse=True)) + ")",
                flags=re.IGNORECASE,
            )
            body_parts = word_pattern.split(body_text)
            highlighted_body = "".join(
                f"<mark><strong>{html.escape(part)}</strong></mark>" if index % 2 else html.escape(part)
                for index, part in enumerate(body_parts)
            )
            st.markdown(
                f"<div style='white-space: pre-wrap; line-height: 1.6;'>{highlighted_body}</div>",
                unsafe_allow_html=True,
            )

with campaign_tab:
    st.info("Coming soon")
