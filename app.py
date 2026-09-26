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
from utils.helpers import is_valid_url, redirect_chain_display

st.set_page_config(
    page_title="QRShield — QR Security Analyzer",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# ── Design tokens ────────────────────────────────────────────────────────────
C = {
    "bg": "#F8FAFC",
    "surface": "#FFFFFF",
    "border": "#E2E8F0",
    "text": "#0F172A",
    "text2": "#64748B",
    "text3": "#94A3B8",
    "primary": "#4338CA",
    "primary_light": "#EEF2FF",
    "green": "#059669",
    "green_bg": "#ECFDF5",
    "amber": "#D97706",
    "amber_bg": "#FFFBEB",
    "red": "#DC2626",
    "red_bg": "#FEF2F2",
    "mono": "'Cascadia Code', 'Fira Code', 'JetBrains Mono', Consolas, monospace",
}

st.markdown(f"""
<style>
    /* ── Base ─────────────────────────────────────────── */
    .stApp {{
        background: {C['bg']};
    }}
    blockquote {{ display: none; }}

    /* ── Header ───────────────────────────────────────── */
    .qrs-header {{
        display: flex;
        align-items: center;
        gap: 14px;
        padding: 28px 0 6px 0;
    }}
    .qrs-logo {{
        width: 48px; height: 48px;
        background: {C['primary']};
        border-radius: 12px;
        display: flex; align-items: center; justify-content: center;
        font-size: 24px;
        flex-shrink: 0;
    }}
    .qrs-title {{
        font-size: 1.75rem;
        font-weight: 800;
        color: {C['text']};
        line-height: 1.15;
        margin: 0;
        letter-spacing: -0.02em;
    }}
    .qrs-title span {{ color: {C['primary']}; }}
    .qrs-sub {{
        font-size: 0.875rem;
        color: {C['text2']};
        margin: 2px 0 0 0;
        line-height: 1.4;
    }}

    /* ── Tabs ─────────────────────────────────────────── */
    .stTabs [data-baseweb="tab-list"] {{
        gap: 0;
        background: {C['surface']};
        border: 1px solid {C['border']};
        border-radius: 10px;
        padding: 4px;
    }}
    .stTabs [data-baseweb="tab"] {{
        padding: 8px 24px;
        border-radius: 7px;
        font-weight: 500;
        font-size: 0.9rem;
        color: {C['text2']};
        background: transparent;
        border: none;
    }}
    .stTabs [aria-selected="true"] {{
        background: {C['primary']} !important;
        color: #fff !important;
    }}
    .stTabs [data-baseweb="tab-highlight"] {{ display: none; }}
    .stTabs [data-baseweb="tab-border"] {{ display: none; }}

    /* ── Metric cards ─────────────────────────────────── */
    .metric-grid {{
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
        gap: 12px;
        margin: 12px 0;
    }}
    .metric-card {{
        background: {C['surface']};
        border: 1px solid {C['border']};
        border-radius: 10px;
        padding: 16px;
    }}
    .metric-card .m-label {{
        font-size: 0.72rem;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.06em;
        color: {C['text3']};
        margin-bottom: 6px;
    }}
    .metric-card .m-value {{
        font-size: 1.5rem;
        font-weight: 700;
        color: {C['text']};
        line-height: 1.2;
    }}
    .metric-card .m-detail {{
        font-size: 0.78rem;
        color: {C['text2']};
        margin-top: 2px;
    }}

    /* ── Threat gauge ─────────────────────────────────── */
    .gauge-container {{
        background: {C['surface']};
        border: 1px solid {C['border']};
        border-radius: 12px;
        padding: 24px;
        margin: 8px 0 16px 0;
    }}
    .gauge-score {{
        font-size: 3rem;
        font-weight: 800;
        font-family: {C['mono']};
        line-height: 1;
        margin-bottom: 4px;
    }}
    .gauge-label {{
        font-size: 0.82rem;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.08em;
        margin-bottom: 16px;
    }}
    .gauge-bar-track {{
        width: 100%;
        height: 12px;
        background: {C['border']};
        border-radius: 6px;
        overflow: hidden;
        display: flex;
    }}
    .gauge-seg {{
        height: 100%;
        display: inline-block;
    }}
    .gauge-marker {{
        position: relative;
        height: 6px;
        margin-top: -9px;
        margin-bottom: 8px;
    }}
    .gauge-dot {{
        position: absolute;
        width: 14px; height: 14px;
        border-radius: 50%;
        background: {C['surface']};
        border: 3px solid;
        top: -4px;
        transform: translateX(-50%);
        box-shadow: 0 1px 4px rgba(0,0,0,0.18);
        transition: left 0.6s cubic-bezier(0.22, 1, 0.36, 1);
    }}
    .gauge-ticks {{
        display: flex;
        justify-content: space-between;
        font-size: 0.68rem;
        color: {C['text3']};
        font-family: {C['mono']};
    }}

    /* ── Check rows ───────────────────────────────────── */
    .check-table {{
        width: 100%;
        border-collapse: separate;
        border-spacing: 0;
        margin-top: 4px;
    }}
    .check-table tr {{
        transition: background 0.15s;
    }}
    .check-table tr:hover {{
        background: {C['primary_light']};
    }}
    .check-table td {{
        padding: 9px 12px;
        border-bottom: 1px solid {C['border']};
        font-size: 0.86rem;
        vertical-align: middle;
    }}
    .check-table tr:last-child td {{ border-bottom: none; }}
    .check-pill {{
        display: inline-block;
        padding: 2px 10px;
        border-radius: 9999px;
        font-size: 0.7rem;
        font-weight: 700;
        letter-spacing: 0.04em;
        text-transform: uppercase;
    }}
    .pill-pass {{ background: {C['green_bg']}; color: {C['green']}; border: 1px solid #A7F3D0; }}
    .pill-fail {{ background: {C['red_bg']}; color: {C['red']}; border: 1px solid #FECACA; }}
    .pill-warn {{ background: {C['amber_bg']}; color: {C['amber']}; border: 1px solid #FDE68A; }}
    .check-name {{ font-weight: 500; color: {C['text']}; }}
    .check-detail {{
        font-size: 0.78rem;
        color: {C['text2']};
        font-family: {C['mono']};
    }}

    /* ── Section headers ──────────────────────────────── */
    .section-head {{
        font-size: 0.78rem;
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: 0.1em;
        color: {C['text3']};
        margin: 20px 0 8px 0;
        padding-bottom: 6px;
        border-bottom: 2px solid {C['border']};
    }}

    /* ── Info banner ──────────────────────────────────── */
    .info-banner {{
        background: {C['primary_light']};
        border: 1px solid #C7D2FE;
        border-radius: 10px;
        padding: 14px 18px;
        font-size: 0.88rem;
        color: {C['primary']};
        margin: 8px 0;
        line-height: 1.5;
    }}

    /* ── Payload card ─────────────────────────────────── */
    .payload-badge {{
        display: inline-block;
        padding: 4px 14px;
        border-radius: 8px;
        font-size: 0.82rem;
        font-weight: 700;
        letter-spacing: 0.04em;
        text-transform: uppercase;
    }}
    .payload-high {{ background: {C['red_bg']}; color: {C['red']}; border: 1px solid #FECACA; }}
    .payload-medium {{ background: {C['amber_bg']}; color: {C['amber']}; border: 1px solid #FDE68A; }}
    .payload-low {{ background: {C['green_bg']}; color: {C['green']}; border: 1px solid #A7F3D0; }}

    /* ── Redirect chain ───────────────────────────────── */
    .chain-row {{
        display: flex;
        align-items: center;
        gap: 8px;
        flex-wrap: wrap;
        font-family: {C['mono']};
        font-size: 0.82rem;
        padding: 4px 0;
    }}
    .chain-hop {{
        background: {C['surface']};
        border: 1px solid {C['border']};
        border-radius: 6px;
        padding: 4px 10px;
        color: {C['text']};
        white-space: nowrap;
    }}
    .chain-hop-final {{
        border-color: {C['primary']};
        background: {C['primary_light']};
        font-weight: 600;
    }}
    .chain-arrow {{ color: {C['text3']}; font-weight: 700; }}
    .chain-status {{
        font-size: 0.7rem;
        font-weight: 700;
        padding: 1px 6px;
        border-radius: 4px;
        margin-right: 6px;
    }}

    /* ── Footer ───────────────────────────────────────── */
    .qrs-footer {{
        text-align: center;
        padding: 24px 0 8px 0;
        font-size: 0.78rem;
        color: {C['text3']};
        border-top: 1px solid {C['border']};
        margin-top: 32px;
    }}

    /* ── Remove Streamlit chrome we replace ───────────── */
    #MainMenu, footer, header {{ visibility: hidden; }}
</style>
""", unsafe_allow_html=True)


# ── Components ────────────────────────────────────────────────────────────────

def render_gauge(score: int):
    """Render a segmented threat gauge with animated position marker."""
    if score <= 40:
        color = C["green"]
        label = "Low Risk"
        verdict = "Looks safe to scan"
    elif score <= 70:
        color = C["amber"]
        label = "Medium Risk"
        verdict = "Proceed with caution"
    else:
        color = C["red"]
        label = "High Risk"
        verdict = "Likely malicious — do not open"

    marker_pos = max(0, min(score, 100))

    st.markdown(f"""
    <div class="gauge-container">
        <div class="gauge-score" style="color:{color}">{score}<span style="font-size:1.2rem;color:{C['text3']}">/100</span></div>
        <div class="gauge-label" style="color:{color}">{label}</div>
        <div class="gauge-bar-track">
            <span class="gauge-seg" style="width:40%;background:{C['green']}"></span>
            <span class="gauge-seg" style="width:30%;background:{C['amber']}"></span>
            <span class="gauge-seg" style="width:30%;background:{C['red']}"></span>
        </div>
        <div class="gauge-marker">
            <span class="gauge-dot" style="left:{marker_pos}%;border-color:{color}"></span>
        </div>
        <div class="gauge-ticks">
            <span>0</span><span>40</span><span>70</span><span>100</span>
        </div>
        <div style="margin-top:14px;font-size:0.88rem;color:{C['text2']};font-style:italic">{verdict}</div>
    </div>
    """, unsafe_allow_html=True)


def render_metrics(items: list[tuple[str, str, str]]):
    """Render a grid of metric cards. items = [(label, value, detail), ...]"""
    cards = "".join(
        f'<div class="metric-card">'
        f'<div class="m-label">{label}</div>'
        f'<div class="m-value">{value}</div>'
        f'<div class="m-detail">{detail}</div>'
        f'</div>'
        for label, value, detail in items
    )
    st.markdown(f'<div class="metric-grid">{cards}</div>', unsafe_allow_html=True)


def render_checks(checks: list[tuple[str, bool | None, str]]):
    """Render analysis checks as a table with status pills."""
    rows = ""
    for label, passed, detail in checks:
        if passed is True:
            pill, cls = "PASS", "pill-pass"
        elif passed is False:
            pill, cls = "FAIL", "pill-fail"
        else:
            pill, cls = "WARN", "pill-warn"

        detail_html = f'<span class="check-detail">{detail}</span>' if detail else ""
        rows += (
            f"<tr>"
            f'<td style="width:70px"><span class="check-pill {cls}">{pill}</span></td>'
            f'<td class="check-name">{label}</td>'
            f'<td style="text-align:right">{detail_html}</td>'
            f"</tr>"
        )

    st.markdown(
        f'<table class="check-table">{rows}</table>',
        unsafe_allow_html=True,
    )


def render_redirect_chain(chain: list):
    """Render redirect chain as connected hops."""
    if not chain or len(chain) <= 1:
        return

    from utils.helpers import clean_domain

    parts = ""
    for i, hop in enumerate(chain):
        is_final = i == len(chain) - 1
        cls = "chain-hop chain-hop-final" if is_final else "chain-hop"
        status_cls = ""
        if hop.status_code in (301, 302, 303, 307, 308):
            status_bg, status_fg = C["amber_bg"], C["amber"]
        elif hop.status_code == 200:
            status_bg, status_fg = C["green_bg"], C["green"]
        else:
            status_bg, status_fg = C["red_bg"], C["red"]

        domain = clean_domain(hop.url)
        parts += (
            f'<span class="{cls}">'
            f'<span class="chain-status" style="background:{status_bg};color:{status_fg}">{hop.status_code}</span>'
            f'{domain}'
            f'</span>'
        )
        if not is_final:
            parts += '<span class="chain-arrow">→</span>'

    st.markdown(f'<div class="chain-row">{parts}</div>', unsafe_allow_html=True)


def section_head(title: str):
    st.markdown(f'<div class="section-head">{title}</div>', unsafe_allow_html=True)


# ── Analysis pipeline ─────────────────────────────────────────────────────────

def run_full_analysis(payload: str):
    if is_valid_url(payload):
        run_url_analysis(payload)
    else:
        run_payload_analysis(payload)


def run_url_analysis(url: str):
    with st.spinner("Tracing redirects…"):
        url_result = analyze_url(url)
    with st.spinner("Classifying with ML model…"):
        ml_result = classify_url(url_result.final_url)
    with st.spinner("Checking for homograph attacks…"):
        homograph_result = check_homograph(url)
    with st.spinner("Gathering domain intelligence…"):
        domain_result = check_domain_intel(url_result.final_url)

    combined = compute_combined_score(
        url_result.risk_score, ml_result.score,
        homograph_result.is_suspicious, domain_result.warnings,
    )

    # ── Score + metrics ──
    section_head("Threat Assessment")
    col_score, col_metrics = st.columns([1, 2], gap="large")

    with col_score:
        render_gauge(combined)

    with col_metrics:
        render_metrics([
            ("ML Score", f"{ml_result.score}", ml_result.label.title()),
            ("URL Risk", f"{url_result.risk_score}", f"{len(url_result.risk_factors)} flags"),
            ("Redirects", f"{max(len(url_result.redirect_chain) - 1, 0)}", "hops"),
            ("Model", ml_result.model_source.replace("_", " ").title(), f"{ml_result.confidence:.0%} conf."),
        ])

    # ── Check table ──
    section_head("Analysis Breakdown")
    checks = [
        ("URL length", url_result.features.get("url_length", 0) <= 75,
         f"{url_result.features.get('url_length', 0)} chars"),
        ("HTTPS enabled", url_result.features.get("has_https", False), ""),
        ("No IP hostname", not url_result.features.get("has_ip_host", False), ""),
        ("No punycode", not url_result.features.get("has_punycode", False), ""),
        ("Low entropy", url_result.features.get("entropy", 0) <= 4.5,
         f"{url_result.features.get('entropy', 0):.2f}"),
        ("ML classification", ml_result.label == "safe",
         f"{ml_result.score}/100"),
        ("No homograph attack", not homograph_result.is_suspicious,
         ", ".join(homograph_result.flags[:1]) if homograph_result.flags else ""),
        ("Domain age", domain_result.domain_age_days is None or domain_result.domain_age_days >= 30,
         f"{domain_result.domain_age_days} days" if domain_result.domain_age_days else "unknown"),
        ("SSL valid", domain_result.ssl_valid is not False,
         domain_result.ssl_issuer or "unavailable"),
    ]
    render_checks(checks)

    # ── Risk factors ──
    if url_result.risk_factors:
        section_head(f"Risk Factors ({len(url_result.risk_factors)})")
        for factor in url_result.risk_factors:
            st.markdown(f'<div class="info-banner">⚠ &nbsp;{factor}</div>', unsafe_allow_html=True)

    # ── Redirect chain ──
    if len(url_result.redirect_chain) > 1:
        section_head(f"Redirect Chain — {len(url_result.redirect_chain)} hops")
        render_redirect_chain(url_result.redirect_chain)

    # ── Domain intelligence ──
    if domain_result.ssl_issuer or domain_result.dns_a_records or domain_result.registrar:
        section_head("Domain Intelligence")
        intel = []
        if domain_result.ssl_issuer:
            intel.append(("SSL Issuer", domain_result.ssl_issuer[:30], domain_result.ssl_expiry or ""))
        if domain_result.registrar:
            intel.append(("Registrar", domain_result.registrar[:30], f"{domain_result.domain_age_days} days" if domain_result.domain_age_days else ""))
        if domain_result.dns_a_records:
            intel.append(("A Records", str(len(domain_result.dns_a_records)), ", ".join(domain_result.dns_a_records[:2])))
        if domain_result.dns_mx_records:
            intel.append(("MX Records", str(len(domain_result.dns_mx_records)), domain_result.dns_mx_records[0][:30] if domain_result.dns_mx_records else ""))
        render_metrics(intel)

        if domain_result.warnings:
            for w in domain_result.warnings:
                st.warning(w)

    # ── Sandbox preview ──
    render_sandbox(url_result.final_url)

    # ── Raw payload ──
    with st.expander("Raw payload"):
        st.code(url, language=None)


def run_payload_analysis(payload: str):
    profile = profile_payload(payload)

    section_head("Payload Assessment")

    risk_map = {"HIGH": "high", "MEDIUM": "medium", "LOW": "low"}
    risk_cls = risk_map.get(profile.risk_level, "low")

    col1, col2 = st.columns([1, 2], gap="large")

    with col1:
        st.markdown(f"""
        <div class="gauge-container" style="text-align:center">
            <div class="payload-badge payload-{risk_cls}">{profile.risk_level} RISK</div>
            <div style="font-size:2rem;font-weight:800;color:{C['text']};margin-top:16px">{profile.payload_type}</div>
            <div style="font-size:0.82rem;color:{C['text2']};margin-top:4px">Detected payload type</div>
        </div>
        """, unsafe_allow_html=True)

    with col2:
        st.markdown(f'<div class="info-banner">{profile.description}</div>', unsafe_allow_html=True)

        if profile.extracted_data:
            section_head("Extracted Data")
            items = []
            for k, v in profile.extracted_data.items():
                if isinstance(v, dict):
                    for k2, v2 in v.items():
                        items.append((k2.title(), str(v2)[:40], k.title()))
                else:
                    items.append((k.title(), str(v)[:40], ""))
            render_metrics(items)

    with st.expander("Raw payload"):
        st.code(payload, language=None)


def render_sandbox(url: str):
    section_head("Safe Preview (Sandbox)")
    with st.spinner("Fetching page…"):
        preview = safe_preview(url)

    if preview.error:
        st.error(preview.error)
        return

    if preview.title:
        st.markdown(f"**{preview.title}**")
    if preview.meta_description:
        st.caption(preview.meta_description)

    render_metrics([
        ("Images", str(preview.images_found), ""),
        ("Forms", str(preview.forms_found), ""),
        ("External links", str(preview.external_links), ""),
        ("Blocked elements", str(preview.scripts_blocked), "scripts / iframes"),
    ])

    if preview.scripts_blocked > 0:
        st.warning(f"Blocked {preview.scripts_blocked} dangerous elements (scripts, iframes, forms)")

    if preview.text_preview:
        with st.expander("Page content", expanded=False):
            st.text(preview.text_preview[:1500])


def compute_combined_score(url_score: int, ml_score: int, is_homograph: bool, warnings: list[str]) -> int:
    scores = [url_score, ml_score]
    if is_homograph:
        scores.append(80)
    if warnings:
        scores.append(min(30 + len(warnings) * 15, 90))
    return min(max(scores), 100)


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    # Header
    st.markdown(f"""
    <div class="qrs-header">
        <div class="qrs-logo">🛡️</div>
        <div>
            <div class="qrs-title">QR<span>Shield</span></div>
            <div class="qrs-sub">Smart QR code security analyzer — detect phishing, quishing &amp; payload attacks before you scan</div>
        </div>
    </div>
    """, unsafe_allow_html=True)

    st.write("")

    tab_upload, tab_url = st.tabs(["📷  Upload QR Code", "🔗  Enter URL"])

    with tab_upload:
        uploaded = st.file_uploader(
            "Drop a QR code image here",
            type=["png", "jpg", "jpeg", "bmp", "gif", "tiff"],
            label_visibility="collapsed",
        )

        if uploaded:
            image_bytes = uploaded.read()
            col_img, _ = st.columns([1, 2])
            with col_img:
                st.image(image_bytes, use_container_width=True, caption="Uploaded QR code")

            try:
                results = decode_qr(image_bytes)
            except Exception as e:
                st.error(f"Could not decode QR code: {e}")
                results = []

            if results:
                st.success(f"Decoded {len(results)} QR code{'s' if len(results) > 1 else ''}")
                for i, result in enumerate(results):
                    if len(results) > 1:
                        st.markdown(f"### QR code #{i + 1}")
                    run_full_analysis(result.payload)
            else:
                st.warning(
                    "No QR codes found in this image. "
                    "Try a sharper photo or upload the original file."
                )

    with tab_url:
        url_input = st.text_input(
            "URL to analyze",
            placeholder="https://example.com/some-link",
            label_visibility="collapsed",
        )
        if url_input:
            run_full_analysis(url_input)

    st.markdown(f"""
    <div class="qrs-footer">
        QRShield v1.0 &nbsp;·&nbsp; Built with Streamlit, scikit-learn &amp; OpenCV
        &nbsp;·&nbsp; ML model: pirocheto/phishing-url-detection (HuggingFace)
    </div>
    """, unsafe_allow_html=True)


if __name__ == "__main__":
    main()
