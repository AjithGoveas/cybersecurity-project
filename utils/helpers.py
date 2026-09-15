from __future__ import annotations

import re
from urllib.parse import urlparse


def is_valid_url(url: str) -> bool:
    """Check if a string is a valid URL."""
    try:
        parsed = urlparse(url)
        return parsed.scheme in ("http", "https") and bool(parsed.netloc)
    except Exception:
        return False


def format_score(score: int) -> str:
    """Format a risk score with label."""
    if score <= 40:
        return f"{score}/100 — Low Risk"
    if score <= 70:
        return f"{score}/100 — Medium Risk"
    return f"{score}/100 — High Risk"


def color_for_score(score: int) -> str:
    """Return a hex color for a risk score."""
    if score <= 40:
        return "#22c55e"  # green
    if score <= 70:
        return "#f59e0b"  # amber
    return "#ef4444"  # red


def severity_emoji(level: str) -> str:
    """Return an indicator for a risk level."""
    level = level.upper()
    if level == "HIGH":
        return "HIGH"
    if level == "MEDIUM":
        return "MEDIUM"
    if level == "LOW":
        return "LOW"
    return "INFO"


def truncate(text: str, max_len: int = 100) -> str:
    """Truncate text with ellipsis."""
    if len(text) <= max_len:
        return text
    return text[: max_len - 3] + "..."


def clean_domain(url: str) -> str:
    """Extract the clean domain from a URL."""
    try:
        parsed = urlparse(url)
        return parsed.hostname or url
    except Exception:
        return url


def redirect_chain_display(chain: list) -> str:
    """Format a redirect chain for display."""
    if not chain:
        return "No redirects"

    parts = []
    for hop in chain:
        domain = clean_domain(hop.url)
        status = hop.status_code if hop.status_code > 0 else "ERR"
        parts.append(f"[{status}] {domain}")

    return " → ".join(parts)
