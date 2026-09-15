from __future__ import annotations

import unicodedata
from dataclasses import dataclass
from urllib.parse import urlparse

from config import HOMOGLYPHS


@dataclass
class HomographResult:
    is_suspicious: bool
    original_domain: str
    decoded_domain: str
    flags: list[str]


def _decompose_domain(domain: str) -> str:
    """Decompose a domain using NFKD normalization and map homoglyphs to ASCII."""
    normalized = unicodedata.normalize("NFKD", domain)
    decoded = []
    for ch in normalized:
        mapped = HOMOGLYPHS.get(ch)
        if mapped:
            decoded.append(mapped)
        elif ord(ch) < 128:
            decoded.append(ch)
        else:
            decoded.append(ch)
    return "".join(decoded)


def _has_mixed_scripts(domain: str) -> bool:
    """Check if domain mixes Latin with non-Latin scripts."""
    has_latin = False
    has_non_latin = False
    for ch in domain:
        if ch == "." or ch == "-":
            continue
        code = ord(ch)
        if 0x0041 <= code <= 0x007A:
            has_latin = True
        elif code > 0x024F:
            has_non_latin = True
    return has_latin and has_non_latin


def _is_punycode_domain(domain: str) -> bool:
    """Check if domain uses punycode encoding."""
    return domain.startswith("xn--") or any(
        part.startswith("xn--") for part in domain.split(".")
    )


def _find_non_ascii_chars(domain: str) -> list[tuple[str, str, str]]:
    """Find non-ASCII characters and their Unicode names."""
    results = []
    for ch in domain:
        if ord(ch) > 127 and ch != "." and ch != "-":
            try:
                name = unicodedata.name(ch, "UNKNOWN")
            except ValueError:
                name = "UNKNOWN"
            results.append((ch, f"U+{ord(ch):04X}", name))
    return results


def check_homograph(url: str) -> HomographResult:
    """Detect Unicode/IDN homograph attacks in a URL.

    Checks for:
    - Cyrillic/Greek characters mimicking Latin letters
    - Mixed-script domains
    - Punycode-encoded domains
    - Non-ASCII characters with suspicious Unicode names

    Args:
        url: The URL to check.

    Returns:
        HomographResult with analysis details.
    """
    try:
        parsed = urlparse(url)
        domain = parsed.hostname or ""
    except Exception:
        return HomographResult(
            is_suspicious=False,
            original_domain="",
            decoded_domain="",
            flags=["Failed to parse URL"],
        )

    if not domain:
        return HomographResult(
            is_suspicious=False,
            original_domain="",
            decoded_domain="",
            flags=[],
        )

    flags = []
    decoded = _decompose_domain(domain)

    non_ascii = _find_non_ascii_chars(domain)
    if non_ascii:
        chars_info = ", ".join(
            f"'{ch}' ({code}: {name})" for ch, code, name in non_ascii[:5]
        )
        flags.append(f"Non-ASCII characters in domain: {chars_info}")

    if _has_mixed_scripts(domain):
        flags.append("Mixed-script domain detected (potential homograph attack)")

    if _is_punycode_domain(domain):
        flags.append("Punycode/IDN encoded domain")

    if decoded != domain and non_ascii:
        flags.append(f"Decoded domain looks like: {decoded}")

    known_homoglyph_used = any(ch in HOMOGLYPHS for ch in domain)
    if known_homoglyph_used:
        flags.append("Known homoglyph characters detected")

    return HomographResult(
        is_suspicious=len(flags) > 0,
        original_domain=domain,
        decoded_domain=decoded,
        flags=flags,
    )
