"""Streamlit UI for the Email Threat Detection dashboard."""

import hashlib
import html
import json
import math
import os
from pathlib import Path
import re
import sqlite3
import tempfile

import folium
import networkx as nx
import streamlit as st
from dotenv import load_dotenv
from folium.plugins import AntPath
from pyvis.network import Network
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


def render_overview_tab(record: dict, score_result: dict) -> None:
    """Render the overview for either an uploaded or batch-selected record."""
    result = _mapping(record)
    score_data = _mapping(score_result)
    if not result:
        st.info("Upload a .eml file above to begin analysis.")
        return

    parsed = _mapping(result.get("parsed"))
    verdict = str(score_data.get("verdict") or "unknown").lower()
    score = _score_value(score_data.get("score"))
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


def render_header_forensics_tab(record: dict, score_result: dict) -> None:
    """Render header and authentication evidence for a pipeline record."""
    del score_result
    header_record = _mapping(record)
    header_parsed = _mapping(header_record.get("parsed"))
    if not header_record:
        st.info("Upload a .eml file above to inspect its header forensics.")
        return

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


def render_domain_geo_tab(record: dict, score_result: dict) -> None:
    """Render typosquat results and the geo-enriched relay map."""
    del score_result
    domain_record = _mapping(record)
    domain_parsed = _mapping(domain_record.get("parsed"))
    if not domain_record:
        st.info("Upload a .eml file above to inspect domain and relay-location signals.")
        return

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
        return

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


def render_content_analysis_tab(record: dict, score_result: dict) -> None:
    """Render NLP label semantics, trained threshold, and highlighted body text."""
    del score_result
    content_record = _mapping(record)
    content_parsed = _mapping(content_record.get("parsed"))
    if not content_record:
        st.info("Upload a .eml file above to inspect its content-analysis signals.")
        return

    st.subheader("Classifier result")
    nlp = _mapping(content_record.get("nlp"))
    label = str(nlp.get("label") or "unavailable")
    confidence = min(max(_score_value(nlp.get("confidence")), 0.0), 1.0)
    st.metric("Classification confidence", f"{confidence:.0%} confidence in {label}")

    threshold_path = _PROJECT_ROOT / "nlp_classifier" / "model" / "threshold_meta.json"
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


def render_campaign_tab(record: dict, score_result: dict) -> None:
    """Render neutral campaign clustering details and the persisted edge graph."""
    del score_result
    campaign_record = _mapping(record)
    if not campaign_record:
        st.info("Upload a .eml file above to inspect campaign clustering information.")
        return

    correlation = _mapping(campaign_record.get("correlation"))
    campaign_id = correlation.get("campaign_id")
    linked_emails_value = correlation.get("linked_emails")
    linked_emails = linked_emails_value if isinstance(linked_emails_value, list) else []
    cluster_size = correlation.get("cluster_size")
    try:
        is_single_email_cluster = int(cluster_size) == 1 and not linked_emails
    except (TypeError, ValueError):
        is_single_email_cluster = False

    if campaign_id is None or is_single_email_cluster:
        st.info("No campaign link found — this email was not clustered with any previously processed email.")
        return

    st.subheader("Campaign cluster")
    campaign_column, size_column = st.columns(2)
    campaign_column.metric("Campaign ID", str(campaign_id))
    size_column.metric("Cluster size", cluster_size or "Unavailable")
    st.caption(
        "Campaign clustering describes shared infrastructure or impersonation signals; "
        "it does not determine this email's verdict."
    )

    reason_labels = {
        "same_origin_ip": "Same origin IP",
        "same_ip_block": "Same IP block",
        "same_impersonated_domain": "Same impersonated domain",
    }
    match_reason_value = correlation.get("match_reason")
    match_reasons = match_reason_value if isinstance(match_reason_value, list) else []
    displayed_reasons = [reason_labels.get(reason, str(reason)) for reason in match_reasons]
    st.write(
        "**Cluster match reason(s):** "
        + (", ".join(displayed_reasons) if displayed_reasons else "No reason recorded")
    )

    current_email_id = campaign_record.get("email_id")
    cluster_email_ids = []
    if isinstance(current_email_id, str) and current_email_id:
        cluster_email_ids.append(current_email_id)
    for linked_email in linked_emails:
        if isinstance(linked_email, str) and linked_email and linked_email not in cluster_email_ids:
            cluster_email_ids.append(linked_email)

    graph = nx.Graph()
    graph_error = None
    if len(cluster_email_ids) >= 2:
        try:
            placeholders = ", ".join("?" for _ in cluster_email_ids)
            edge_query = (
                "SELECT email_id_a, email_id_b, reason FROM edges "
                f"WHERE email_id_a IN ({placeholders}) OR email_id_b IN ({placeholders})"
            )
            campaigns_db = _PROJECT_ROOT / "data" / "campaigns.db"
            database_uri = campaigns_db.resolve().as_uri() + "?mode=ro"
            with sqlite3.connect(database_uri, uri=True) as connection:
                persisted_edges = connection.execute(edge_query, cluster_email_ids + cluster_email_ids).fetchall()

            graph.add_nodes_from(cluster_email_ids)
            for email_id_a, email_id_b, edge_reason in persisted_edges:
                if graph.has_edge(email_id_a, email_id_b):
                    graph[email_id_a][email_id_b].setdefault("reasons", []).append(edge_reason)
                else:
                    graph.add_edge(email_id_a, email_id_b, reasons=[edge_reason])
        except (OSError, sqlite3.Error):
            graph_error = True

    if graph.number_of_edges() > 0:
        st.subheader("Cluster graph")
        try:
            network = Network(
                height="500px", width="100%", directed=False, bgcolor="#ffffff",
                font_color="#1e293b", notebook=False, cdn_resources="in_line",
            )
            for node in graph.nodes:
                is_current_email = node == current_email_id
                network.add_node(
                    node,
                    label="Current email" if is_current_email else str(node),
                    title=f"Email ID: {html.escape(str(node))}",
                    color="#dc2626" if is_current_email else "#2563eb",
                    borderWidth=3 if is_current_email else 1,
                    size=28 if is_current_email else 20,
                )
            for email_id_a, email_id_b, edge_data in graph.edges(data=True):
                edge_reasons = edge_data.get("reasons")
                edge_reasons = edge_reasons if isinstance(edge_reasons, list) else []
                edge_tooltip = " | ".join(
                    reason_labels.get(reason, str(reason)) for reason in edge_reasons
                ) or "Linked"
                network.add_edge(
                    email_id_a,
                    email_id_b,
                    title=html.escape(edge_tooltip),
                    color="#64748b",
                )
            st.components.v1.html(network.generate_html(), height=500, scrolling=True)
        except Exception:
            st.info("The interactive cluster graph could not be rendered; use the table below.")
    elif graph_error:
        st.info("Persisted campaign edges could not be loaded; use the linked-email table below.")
    else:
        st.info("No persisted campaign edges are available to visualize yet.")

    with st.expander("View as table"):
        st.markdown("**Linked emails**")
        linked_rows = [{"email_id": str(email_id)} for email_id in linked_emails]
        if linked_rows:
            st.dataframe(linked_rows, hide_index=True, use_container_width=True)
        else:
            st.info("This campaign has no linked email identifiers to display yet.")
        st.caption(f"{cluster_size} total in cluster ({len(linked_emails)} others + this email)")


st.set_page_config(page_title="Email Threat Detection", page_icon="🛡️", layout="wide")
st.title("🛡️ Email Threat Detection Platform")
st.caption("Upload a raw .eml file to inspect email threat signals.")

upload_widget_nonce = st.session_state.get("upload_widget_nonce", 0)
if not isinstance(upload_widget_nonce, int):
    upload_widget_nonce = 0
    st.session_state["upload_widget_nonce"] = upload_widget_nonce

uploaded_file = st.file_uploader(
    "Upload a .eml file",
    type=["eml"],
    help="Drag and drop or browse for an RFC 822 .eml message.",
    key=f"uploaded_email_{upload_widget_nonce}",
)

clear_uploaded_emails = st.button(
    "Clear uploaded emails",
    help="Clears only this browser session's uploaded-email list. Correlation history is unchanged.",
)
if clear_uploaded_emails:
    st.session_state.pop("uploaded_results", None)
    st.session_state.pop("upload_id", None)
    st.session_state.pop("analysis_source", None)
    st.session_state["upload_widget_nonce"] = upload_widget_nonce + 1
    st.rerun()

if uploaded_file is not None and not clear_uploaded_emails:
    file_bytes = uploaded_file.getvalue()
    upload_id = hashlib.sha256(file_bytes).hexdigest()
    if st.session_state.get("upload_id") != upload_id:
        st.session_state["upload_id"] = upload_id
        upload_record = {}
        upload_score = {}
        upload_error = None

        temp_path = ""
        try:
            with tempfile.NamedTemporaryFile(delete=False, suffix=".eml", mode="wb") as temporary_file:
                temporary_file.write(file_bytes)
                temp_path = temporary_file.name
            try:
                upload_record = _mapping(run_pipeline(temp_path))
            except Exception as error:
                upload_error = f"Pipeline analysis failed: {error}"
            else:
                try:
                    upload_score = _mapping(compute_fraud_score(upload_record))
                except Exception as error:
                    upload_error = f"Fraud-score calculation failed: {error}"
        except Exception as error:
            upload_error = f"Could not prepare the uploaded email: {error}"
        finally:
            if temp_path and os.path.exists(temp_path):
                os.unlink(temp_path)

        uploaded_results_value = st.session_state.get("uploaded_results")
        uploaded_results = uploaded_results_value if isinstance(uploaded_results_value, list) else []
        upload_filename = uploaded_file.name
        existing_filenames = {str(item.get("filename", "")) for item in uploaded_results}
        if upload_filename in existing_filenames:
            suffix = 2
            while f"{upload_filename} ({suffix})" in existing_filenames:
                suffix += 1
            upload_filename = f"{upload_filename} ({suffix})"
        uploaded_results.append({
            "filename": upload_filename,
            "record": upload_record,
            "score": upload_score,
            "error": upload_error,
        })
        st.session_state["uploaded_results"] = uploaded_results
else:
    st.session_state.pop("upload_id", None)

st.divider()
with st.expander("Advanced"):
    st.warning(
        "Resetting the campaign database removes all correlation history, including the planted "
        "campaign-fixture linkage, until Run all fixtures is run again."
    )
    confirm_campaign_reset = st.checkbox(
        "I understand that this removes all persisted correlation history.",
        key="confirm_campaign_reset",
    )
    if st.button("Reset campaign database", disabled=not confirm_campaign_reset):
        campaigns_db = _PROJECT_ROOT / "data" / "campaigns.db"
        try:
            with sqlite3.connect(campaigns_db) as connection:
                connection.execute("DELETE FROM edges")
                connection.execute("DELETE FROM emails")
                connection.commit()
                connection.execute("VACUUM")
        except (OSError, sqlite3.Error) as error:
            st.error(f"Could not reset the campaign database: {error}")
        else:
            st.session_state.pop("uploaded_results", None)
            st.session_state.pop("batch_results", None)
            st.session_state.pop("upload_id", None)
            st.session_state.pop("analysis_source", None)
            st.session_state["upload_widget_nonce"] = upload_widget_nonce + 1
            st.session_state["campaign_reset_success"] = True
            st.rerun()

if st.session_state.pop("campaign_reset_success", False):
    st.success("Campaign database reset. Run all fixtures to restore the campaign-demo linkage.")

st.subheader("Judge batch demo")
batch_summary = st.empty()
if st.button("Run all fixtures", type="secondary"):
    fixture_directory = _PROJECT_ROOT / "contracts" / "fixtures"
    fixture_paths = sorted(
        path for path in fixture_directory.iterdir()
        if path.is_file() and path.suffix.lower() == ".eml"
    ) if fixture_directory.is_dir() else []
    st.session_state["batch_results"] = []
    st.session_state.pop("analysis_source", None)

    if not fixture_paths:
        st.warning("No .eml fixtures were found in contracts/fixtures.")
    else:
        progress = st.progress(0, text="Preparing fixture batch…")
        for index, fixture_path in enumerate(fixture_paths, start=1):
            batch_record = {}
            batch_score = {}
            batch_error = None
            try:
                batch_record = _mapping(run_pipeline(str(fixture_path)))
                batch_score = _mapping(compute_fraud_score(batch_record))
            except Exception as error:
                batch_error = f"Analysis failed: {error}"
            st.session_state["batch_results"].append({
                "filename": fixture_path.name,
                "record": batch_record,
                "score": batch_score,
                "error": batch_error,
            })
            summary_rows = [{
                "filename": item.get("filename", ""),
                "verdict": _mapping(item.get("score")).get("verdict", "error" if item.get("error") else "unknown"),
                "score": _mapping(item.get("score")).get("score", "—"),
            } for item in st.session_state.get("batch_results", [])]
            batch_summary.dataframe(summary_rows, hide_index=True, use_container_width=True)
            progress.progress(index / len(fixture_paths), text=f"Processed {index}/{len(fixture_paths)}: {fixture_path.name}")
        progress.empty()

batch_results_value = st.session_state.get("batch_results")
batch_results = batch_results_value if isinstance(batch_results_value, list) else []
uploaded_results_value = st.session_state.get("uploaded_results")
uploaded_results = uploaded_results_value if isinstance(uploaded_results_value, list) else []
if batch_results:
    summary_rows = [{
        "filename": item.get("filename", ""),
        "verdict": _mapping(item.get("score")).get("verdict", "error" if item.get("error") else "unknown"),
        "score": _mapping(item.get("score")).get("score", "—"),
    } for item in batch_results]
    batch_summary.dataframe(summary_rows, hide_index=True, use_container_width=True)
if uploaded_results or batch_results:
    source_options = (
        ["Current uploaded email"]
        + [str(item.get("filename", "")) for item in uploaded_results]
        + [str(item.get("filename", "")) for item in batch_results]
    )
    selected_source = st.selectbox(
        "View details in all five tabs",
        source_options,
        key="analysis_source",
        help="Choose an uploaded email or batch fixture to open it in the same five-tab dashboard below.",
    )
else:
    selected_source = "Current uploaded email"

current_upload = uploaded_results[-1] if uploaded_results else {}
active_record = _mapping(current_upload.get("record"))
active_score = _mapping(current_upload.get("score"))
active_error = current_upload.get("error")
if selected_source != "Current uploaded email":
    selected_upload = next(
        (item for item in uploaded_results if item.get("filename") == selected_source),
        None,
    )
    if selected_upload is not None:
        active_record = _mapping(selected_upload.get("record"))
        active_score = _mapping(selected_upload.get("score"))
        active_error = selected_upload.get("error")
        st.caption(f"Viewing uploaded email: {selected_source}")
    else:
        selected_batch = next(
            (item for item in batch_results if item.get("filename") == selected_source),
            {},
        )
        active_record = _mapping(selected_batch.get("record"))
        active_score = _mapping(selected_batch.get("score"))
        active_error = selected_batch.get("error")
        st.caption(f"Viewing batch fixture: {selected_source}")

if active_error:
    st.error(str(active_error))
    active_record = {}
    active_score = {}

overview_tab, headers_tab, domain_geo_tab, content_tab, campaign_tab = st.tabs(
    ["Overview", "Header Forensics", "Domain & Geo", "Content Analysis", "Campaign Graph"]
)

with overview_tab:
    render_overview_tab(active_record, active_score)

with headers_tab:
    render_header_forensics_tab(active_record, active_score)

with domain_geo_tab:
    render_domain_geo_tab(active_record, active_score)

with content_tab:
    render_content_analysis_tab(active_record, active_score)

with campaign_tab:
    render_campaign_tab(active_record, active_score)
