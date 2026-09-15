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
from utils.helpers import (
    format_score,
    color_for_score,
    severity_emoji,
    truncate,
    redirect_chain_display,
    is_valid_url,
)

st.set_page_config(
    page_title="QRShield — Smart QR Security Analyzer",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)

st.markdown("""
<style>
    .main-header {
        font-size: 2.2rem;
        font-weight: 700;
        color: #1e293b;
        margin-bottom: 0.2rem;
    }
    .sub-header {
        font-size: 1rem;
        color: #64748b;
        margin-bottom: 1.5rem;
    }
    .risk-box {
        padding: 1rem;
        border-radius: 0.5rem;
        font-size: 1.5rem;
        font-weight: 700;
        text-align: center;
    }
    .risk-low { background: #dcfce7; color: #166534; border: 1px solid #22c55e; }
    .risk-medium { background: #fef3c7; color: #92400e; border: 1px solid #f59e0b; }
    .risk-high { background: #fee2e2; color: #991b1b; border: 1px solid #ef4444; }
    .check-pass { color: #22c55e; font-weight: 600; }
    .check-fail { color: #ef4444; font-weight: 600; }
    .check-warn { color: #f59e0b; font-weight: 600; }
    .stTabs [data-baseweb="tab-list"] { gap: 8px; }
    .stTabs [data-baseweb="tab"] {
        padding: 10px 20px;
        border-radius: 4px 4px 0 0;
    }
</style>
""", unsafe_allow_html=True)


def render_risk_gauge(score: int):
    """Render a risk score gauge."""
    if score <= 40:
        css_class = "risk-low"
        label = "LOW RISK"
    elif score <= 70:
        css_class = "risk-medium"
        label = "MEDIUM RISK"
    else:
        css_class = "risk-high"
        label = "HIGH RISK"

    st.markdown(
        f'<div class="risk-box {css_class}">{score}/100 — {label}</div>',
        unsafe_allow_html=True,
    )


def render_check_row(label: str, passed: bool | None, detail: str = ""):
    """Render a single analysis check row."""
    if passed is True:
        icon = "PASS"
        css = "check-pass"
    elif passed is False:
        icon = "FAIL"
        css = "check-fail"
    else:
        icon = "WARN"
        css = "check-warn"

    detail_str = f" — {detail}" if detail else ""
    st.markdown(
        f'<span class="{css}">[{icon}]</span> {label}{detail_str}',
        unsafe_allow_html=True,
    )


def run_full_analysis(payload: str):
    """Run the complete security analysis pipeline."""
    st.markdown("---")

    is_url = is_valid_url(payload)

    if is_url:
        _run_url_analysis(payload)
    else:
        _run_payload_analysis(payload)


def _run_url_analysis(url: str):
    """Analyze a URL payload."""
    with st.spinner("Tracing redirects..."):
        url_result = analyze_url(url)

    with st.spinner("Running ML classification..."):
        ml_result = classify_url(url_result.final_url)

    with st.spinner("Checking for homograph attacks..."):
        homograph_result = check_homograph(url)

    with st.spinner("Gathering domain intelligence..."):
        domain_result = check_domain_intel(url_result.final_url)

    combined_score = _compute_combined_score(
        url_result.risk_score, ml_result.score, homograph_result.is_suspicious, domain_result.warnings
    )

    col1, col2 = st.columns([1, 2])

    with col1:
        st.subheader("Threat Score")
        render_risk_gauge(combined_score)

        st.metric("ML Score", f"{ml_result.score}/100", ml_result.label.upper())
        st.caption(f"Model: {ml_result.model_source} | Confidence: {ml_result.confidence:.0%}")

    with col2:
        st.subheader("Analysis Breakdown")
        _render_url_checks(url_result, ml_result, homograph_result, domain_result)

    _render_redirect_chain(url_result.redirect_chain)

    _render_domain_intel(domain_result)

    with st.expander("Raw Decoded Payload", expanded=False):
        st.code(url, language=None)

    _render_sandbox_section(url_result.final_url)


def _run_payload_analysis(payload: str):
    """Analyze a non-URL payload."""
    payload_profile = profile_payload(payload)

    col1, col2 = st.columns([1, 2])

    with col1:
        st.subheader("Payload Type")
        risk_class = {
            "HIGH": "risk-high",
            "MEDIUM": "risk-medium",
            "LOW": "risk-low",
        }.get(payload_profile.risk_level, "risk-low")

        st.markdown(
            f'<div class="risk-box {risk_class}">{payload_profile.payload_type} — {payload_profile.risk_level} RISK</div>',
            unsafe_allow_html=True,
        )

    with col2:
        st.subheader("Payload Analysis")
        st.info(payload_profile.description)

        if payload_profile.extracted_data:
            st.markdown("**Extracted Data:**")
            for key, val in payload_profile.extracted_data.items():
                if isinstance(val, dict):
                    st.markdown(f"  **{key}:**")
                    for k2, v2 in val.items():
                        st.text(f"    {k2}: {v2}")
                else:
                    st.text(f"  {key}: {val}")

    with st.expander("Raw Payload", expanded=False):
        st.code(payload, language=None)


def _compute_combined_score(
    url_score: int,
    ml_score: int,
    is_homograph: bool,
    domain_warnings: list[str],
) -> int:
    """Compute a combined threat score from all analyzers."""
    scores = [url_score, ml_score]
    if is_homograph:
        scores.append(80)
    if domain_warnings:
        scores.append(min(30 + len(domain_warnings) * 15, 90))

    return min(max(scores), 100)


def _render_url_checks(url_result, ml_result, homograph_result, domain_result):
    """Render the analysis check breakdown."""
    checks = [
        ("URL Length", url_result.features.get("url_length", 0) <= 75,
         f"{url_result.features.get('url_length', 0)} chars"),
        ("HTTPS Enabled", url_result.features.get("has_https", False), ""),
        ("No IP Hostname", not url_result.features.get("has_ip_host", False), ""),
        ("No Punycode", not url_result.features.get("has_punycode", False), ""),
        ("Low Entropy", url_result.features.get("entropy", 0) <= 4.5,
         f"{url_result.features.get('entropy', 0):.2f}"),
        ("ML Classification", ml_result.label == "safe",
         f"{ml_result.score}/100 phishing confidence"),
        ("No Homograph Attack", not homograph_result.is_suspicious,
         ", ".join(homograph_result.flags[:2]) if homograph_result.flags else ""),
        ("Domain Age", domain_result.domain_age_days is None or domain_result.domain_age_days >= 30,
         f"{domain_result.domain_age_days} days" if domain_result.domain_age_days else "Unknown"),
        ("SSL Valid", domain_result.ssl_valid is not False,
         domain_result.ssl_issuer if domain_result.ssl_valid else (domain_result.ssl_issuer or "Check failed")),
    ]

    for label, passed, detail in checks:
        render_check_row(label, passed, detail)


def _render_redirect_chain(chain: list):
    """Render redirect chain visualization."""
    if not chain or len(chain) <= 1:
        return

    with st.expander(f"Redirect Chain ({len(chain)} hops)", expanded=True):
        st.text(redirect_chain_display(chain))


def _render_domain_intel(result):
    """Render domain intelligence section."""
    if not result.dns_a_records and not result.ssl_issuer and not result.registrar:
        return

    with st.expander("Domain Intelligence", expanded=False):
        if result.ssl_issuer:
            st.markdown(f"**SSL Issuer:** {result.ssl_issuer}")
        if result.ssl_expiry:
            st.markdown(f"**SSL Expiry:** {result.ssl_expiry}")
        if result.registrar:
            st.markdown(f"**Registrar:** {result.registrar}")
        if result.dns_a_records:
            st.markdown(f"**A Records:** {', '.join(result.dns_a_records)}")
        if result.dns_mx_records:
            st.markdown(f"**MX Records:** {', '.join(result.dns_mx_records[:3])}")
        if result.warnings:
            for w in result.warnings:
                st.warning(w)


def _render_sandbox_section(url: str):
    """Render the sandbox preview section."""
    with st.expander("Safe Preview (Sandbox)", expanded=False):
        with st.spinner("Fetching page preview..."):
            preview = safe_preview(url)

        if preview.error:
            st.error(preview.error)
            return

        if preview.title:
            st.markdown(f"**Title:** {preview.title}")
        if preview.meta_description:
            st.markdown(f"**Description:** {preview.meta_description}")

        col1, col2, col3 = st.columns(3)
        col1.metric("Images", preview.images_found)
        col2.metric("Forms", preview.forms_found)
        col3.metric("External Links", preview.external_links)

        if preview.scripts_blocked > 0:
            st.warning(f"Blocked {preview.scripts_blocked} dangerous elements (scripts, iframes, etc.)")

        if preview.text_preview:
            st.markdown("**Page Content Preview:**")
            st.text(preview.text_preview[:1500])


def main():
    st.markdown('<div class="main-header">QRShield</div>', unsafe_allow_html=True)
    st.markdown('<div class="sub-header">Smart QR Code Security Analyzer — Detect Phishing, Quishing & Payload Attacks</div>', unsafe_allow_html=True)

    tab_upload, tab_url = st.tabs(["Upload QR Code", "Enter URL Directly"])

    with tab_upload:
        uploaded = st.file_uploader(
            "Upload a QR code image",
            type=["png", "jpg", "jpeg", "bmp", "gif", "tiff"],
            help="Supports PNG, JPG, BMP, GIF, TIFF formats",
        )

        if uploaded:
            image_bytes = uploaded.read()

            st.image(image_bytes, caption="Uploaded QR Code", width=300)

            try:
                results = decode_qr(image_bytes)
            except Exception as e:
                st.error(f"Failed to decode QR code: {e}")
                results = []

            if results:
                st.success(f"Decoded {len(results)} QR code(s)")

                for i, result in enumerate(results):
                    st.markdown(f"**QR Code #{i + 1}** ({result.payload_type})")

                    if result.payload_type != "URL":
                        st.info(f"Non-URL payload detected: {result.payload_type}")

                    run_full_analysis(result.payload)
            else:
                st.warning("No QR codes found in the image. Try a clearer image or different angle.")

    with tab_url:
        url_input = st.text_input(
            "Enter a URL to analyze",
            placeholder="https://example.com/suspicious-link",
            help="Paste any URL for security analysis",
        )

        if url_input:
            run_full_analysis(url_input)

    st.markdown("---")
    st.caption("QRShield v1.0 | Built with Streamlit + scikit-learn + OpenCV")


if __name__ == "__main__":
    main()
