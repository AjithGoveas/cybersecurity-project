from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

import streamlit as st

from core.decoder import decode_qr
from core.url_analyzer import analyze_url
from core.ml_classifier import classify_url
from core.homograph_detector import check_homograph
from core.payload_profiler import profile_payload
from core.domain_intel import check_domain_intel
from core.sandbox_preview import safe_preview
from utils.helpers import is_valid_url, redirect_chain_display, clean_domain

st.set_page_config(
    page_title="QRShield — QR Security Analyzer",
    page_icon="🛡️",
    layout="wide",
)

st.markdown("""
<style>
    .stApp { max-width: 900px; margin: 0 auto; }
    div[data-testid="stMetricValue"] { font-size: 1.8rem; }
</style>
""", unsafe_allow_html=True)


def score_color(score: int) -> str:
    if score <= 40:
        return "green"
    if score <= 70:
        return "orange"
    return "red"


def score_label(score: int) -> str:
    if score <= 40:
        return "Low Risk"
    if score <= 70:
        return "Medium Risk"
    return "High Risk"


def run_full_analysis(payload: str):
    if is_valid_url(payload):
        run_url_analysis(payload)
    else:
        run_payload_analysis(payload)


def run_url_analysis(url: str):
    with st.spinner("Tracing redirects..."):
        url_result = analyze_url(url)
    with st.spinner("Classifying with ML model..."):
        ml_result = classify_url(url_result.final_url)
    with st.spinner("Checking for homograph attacks..."):
        homograph_result = check_homograph(url)
    with st.spinner("Gathering domain intelligence..."):
        domain_result = check_domain_intel(url_result.final_url)

    combined = compute_combined_score(
        url_result.risk_score, ml_result.score,
        homograph_result.is_suspicious, domain_result.warnings,
    )

    # ── Score ──
    st.subheader("Threat Score")
    color = score_color(combined)
    st.markdown(
        f"### :{color}[{combined}/100 — {score_label(combined)}]"
    )
    st.progress(combined)

    # ── Key metrics ──
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("ML Score", f"{ml_result.score}", ml_result.label)
    c2.metric("URL Risk", url_result.risk_score, f"{len(url_result.risk_factors)} flags")
    c3.metric("Redirects", max(len(url_result.redirect_chain) - 1, 0), "hops")
    c4.metric("Model", ml_result.model_source.replace("_", " "), f"{ml_result.confidence:.0%} conf")

    # ── Check table ──
    st.subheader("Analysis Breakdown")
    checks = [
        ("URL length", url_result.features.get("url_length", 0) <= 75,
         f"{url_result.features.get('url_length', 0)} chars"),
        ("HTTPS enabled", url_result.features.get("has_https", False), ""),
        ("No IP hostname", not url_result.features.get("has_ip_host", False), ""),
        ("No punycode", not url_result.features.get("has_punycode", False), ""),
        ("Low entropy", url_result.features.get("entropy", 0) <= 4.5,
         f"{url_result.features.get('entropy', 0):.2f}"),
        ("ML classification", ml_result.label == "safe", f"{ml_result.score}/100"),
        ("No homograph attack", not homograph_result.is_suspicious,
         ", ".join(homograph_result.flags[:1]) if homograph_result.flags else ""),
        ("Domain age", domain_result.domain_age_days is None or domain_result.domain_age_days >= 30,
         f"{domain_result.domain_age_days} days" if domain_result.domain_age_days else "unknown"),
        ("SSL valid", domain_result.ssl_valid is not False,
         domain_result.ssl_issuer or "unavailable"),
    ]

    for label, passed, detail in checks:
        if passed is True:
            icon, text = "✅", f"{label}"
        elif passed is False:
            icon, text = "❌", f"**{label}**"
        else:
            icon, text = "⚠️", label

        suffix = f" — {detail}" if detail else ""
        st.markdown(f"{icon} {text}{suffix}")

    # ── Risk factors ──
    if url_result.risk_factors:
        st.subheader(f"Risk Factors ({len(url_result.risk_factors)})")
        for factor in url_result.risk_factors:
            st.warning(factor)

    # ── Redirect chain ──
    if len(url_result.redirect_chain) > 1:
        st.subheader(f"Redirect Chain ({len(url_result.redirect_chain)} hops)")
        st.code(redirect_chain_display(url_result.redirect_chain), language=None)

    # ── Domain intel ──
    if domain_result.ssl_issuer or domain_result.dns_a_records or domain_result.registrar:
        st.subheader("Domain Intelligence")
        col1, col2 = st.columns(2)
        with col1:
            if domain_result.ssl_issuer:
                st.write(f"**SSL Issuer:** {domain_result.ssl_issuer}")
            if domain_result.ssl_expiry:
                st.write(f"**SSL Expiry:** {domain_result.ssl_expiry}")
            if domain_result.registrar:
                st.write(f"**Registrar:** {domain_result.registrar}")
        with col2:
            if domain_result.dns_a_records:
                st.write(f"**A Records:** {', '.join(domain_result.dns_a_records)}")
            if domain_result.dns_mx_records:
                st.write(f"**MX Records:** {', '.join(domain_result.dns_mx_records[:3])}")

        for w in domain_result.warnings:
            st.warning(w)

    # ── Sandbox ──
    render_sandbox(url_result.final_url)

    # ── Raw ──
    with st.expander("Raw payload"):
        st.code(url, language=None)


def run_payload_analysis(payload: str):
    profile = profile_payload(payload)

    st.subheader("Payload Analysis")

    risk_colors = {"HIGH": "red", "MEDIUM": "orange", "LOW": "green"}
    color = risk_colors.get(profile.risk_level, "green")

    st.markdown(f"### :{color}[{profile.payload_type} — {profile.risk_level} RISK]")
    st.info(profile.description)

    if profile.extracted_data:
        st.subheader("Extracted Data")
        cols = st.columns(min(len(profile.extracted_data), 4))
        for i, (k, v) in enumerate(profile.extracted_data.items()):
            if isinstance(v, dict):
                for k2, v2 in v.items():
                    cols[i % len(cols)].metric(k2.title(), str(v2))
            else:
                cols[i % len(cols)].metric(k.title(), str(v))

    with st.expander("Raw payload"):
        st.code(payload, language=None)


def render_sandbox(url: str):
    st.subheader("Safe Preview (Sandbox)")
    with st.spinner("Fetching page..."):
        preview = safe_preview(url)

    if preview.error:
        st.error(preview.error)
        return

    if preview.title:
        st.write(f"**Title:** {preview.title}")
    if preview.meta_description:
        st.caption(preview.meta_description)

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Images", preview.images_found)
    col2.metric("Forms", preview.forms_found)
    col3.metric("External links", preview.external_links)
    col4.metric("Blocked elements", preview.scripts_blocked)

    if preview.scripts_blocked > 0:
        st.warning(f"Blocked {preview.scripts_blocked} dangerous elements (scripts, iframes, forms)")

    if preview.text_preview:
        with st.expander("Page content"):
            st.text(preview.text_preview[:1500])


def compute_combined_score(url_score: int, ml_score: int, is_homograph: bool, warnings: list[str]) -> int:
    scores = [url_score, ml_score]
    if is_homograph:
        scores.append(80)
    if warnings:
        scores.append(min(30 + len(warnings) * 15, 90))
    return min(max(scores), 100)


def main():
    st.title("🛡️ QRShield")
    st.caption("Smart QR code security analyzer — detect phishing, quishing & payload attacks before you scan")

    tab_upload, tab_url = st.tabs(["📷 Upload QR Code", "🔗 Enter URL"])

    with tab_upload:
        uploaded = st.file_uploader(
            "Upload a QR code image",
            type=["png", "jpg", "jpeg", "bmp", "gif", "tiff"],
        )

        if uploaded:
            image_bytes = uploaded.read()
            st.image(image_bytes, width=250, caption="Uploaded QR code")

            try:
                results = decode_qr(image_bytes)
            except Exception as e:
                st.error(f"Could not decode QR code: {e}")
                results = []

            if results:
                st.success(f"Decoded {len(results)} QR code{'s' if len(results) > 1 else ''}")
                for i, result in enumerate(results):
                    if len(results) > 1:
                        st.markdown(f"---\n### QR code #{i + 1}")
                    run_full_analysis(result.payload)
            else:
                st.warning("No QR codes found. Try a sharper image or the original file.")

    with tab_url:
        url_input = st.text_input(
            "Enter a URL to analyze",
            placeholder="https://example.com/some-link",
        )
        if url_input:
            run_full_analysis(url_input)

    st.divider()
    st.caption(
        "QRShield v1.0 | Built with Streamlit, scikit-learn & OpenCV | "
        "ML model: pirocheto/phishing-url-detection (HuggingFace)"
    )


if __name__ == "__main__":
    main()
