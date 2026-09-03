"""
dashboard/app.py — Person 4: Streamlit dashboard.

Run with:
    streamlit run dashboard/app.py

Displays a file uploader for .eml files, runs the full pipeline on upload,
and renders the combined record as JSON. Works immediately with stub data.
"""

import streamlit as st
from dashboard.pipeline import run_pipeline
import tempfile
import os
import json

st.set_page_config(
    page_title="Email Threat Detection",
    page_icon="🛡️",
    layout="wide",
)

st.title("🛡️ Email Threat Detection Platform")
st.caption(
    "Upload a raw .eml file to analyse headers, detect typosquatting, "
    "geolocate relay hops, classify body text, and correlate with known campaigns."
)

uploaded_file = st.file_uploader(
    "Upload a .eml file",
    type=["eml"],
    help="Drag and drop or click to browse. Only .eml files are accepted.",
)

if uploaded_file is not None:
    if st.button("🔍 Analyse Email", type="primary"):
        with st.spinner("Running pipeline…"):
            # Write uploaded file to a temp path so pipeline can open it.
            with tempfile.NamedTemporaryFile(
                delete=False, suffix=".eml", mode="wb"
            ) as tmp:
                tmp.write(uploaded_file.read())
                tmp_path = tmp.name

            try:
                result = run_pipeline(tmp_path)
            finally:
                os.unlink(tmp_path)

        # ── Summary metrics ───────────────────────────────────────────── #
        verdict = result.get("verdict", "unknown")
        score = result.get("fraud_score", 0.0)

        verdict_color = {"malicious": "🔴", "suspicious": "🟡", "safe": "🟢"}.get(
            verdict, "⚪"
        )

        col1, col2, col3 = st.columns(3)
        col1.metric("Verdict", f"{verdict_color} {verdict.upper()}")
        col2.metric("Fraud Score", f"{score:.1f} / 100")
        col3.metric(
            "Campaign",
            result.get("correlation", {}).get("campaign_id") or "None detected",
        )

        st.divider()

        # ── Full combined record ──────────────────────────────────────── #
        st.subheader("Full Pipeline Record")
        st.json(result)
else:
    st.info("⬆️ Upload a .eml file above to get started.")

    with st.expander("Sample fixture files (for testing)"):
        st.code(
            "contracts/fixtures/sample_phish_1.eml\n"
            "contracts/fixtures/sample_phish_2_campaign_a.eml\n"
            "contracts/fixtures/sample_phish_3_campaign_a.eml\n"
            "contracts/fixtures/sample_legit_1.eml",
            language="text",
        )
