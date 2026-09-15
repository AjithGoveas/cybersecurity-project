from __future__ import annotations

import math
import re
from urllib.parse import urlparse

IP_REGEX = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")


def url_length(url: str) -> int:
    return len(url)


def domain_length(domain: str) -> int:
    return len(domain)


def count_dots(url: str) -> int:
    return url.count(".")


def count_hyphens(url: str) -> int:
    return url.count("-")


def count_at_signs(url: str) -> int:
    return url.count("@")


def count_slashes(url: str) -> int:
    return url.count("/")


def count_digits(url: str) -> int:
    return sum(c.isdigit() for c in url)


def count_subdomains(domain: str) -> int:
    parts = domain.split(".")
    return max(0, len(parts) - 2)


def has_ip_host(url: str) -> bool:
    parsed = urlparse(url)
    host = parsed.hostname or ""
    return bool(IP_REGEX.match(host))


def has_https(url: str) -> bool:
    return urlparse(url).scheme == "https"


def has_suspicious_tokens(url: str, tokens: list[str]) -> list[str]:
    lower = url.lower()
    return [t for t in tokens if t in lower]


def has_punycode(domain: str) -> bool:
    return domain.startswith("xn--") or any(
        part.startswith("xn--") for part in domain.split(".")
    )


def has_high_entropy(s: float, threshold: float = 4.5) -> bool:
    return s > threshold


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    length = len(s)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


def count_query_params(url: str) -> int:
    parsed = urlparse(url)
    if not parsed.query:
        return 0
    return len(parsed.query.split("&"))


def has_port(url: str) -> bool:
    parsed = urlparse(url)
    return parsed.port is not None and parsed.port not in (80, 443)


def url_depth(url: str) -> int:
    parsed = urlparse(url)
    path = parsed.path.strip("/")
    if not path:
        return 0
    return len(path.split("/"))


def extract_url_features(url: str, suspicious_tokens: list[str] | None = None) -> dict:
    """Extract all lexical features from a URL."""
    parsed = urlparse(url)
    domain = parsed.hostname or ""
    scheme = parsed.scheme

    features = {
        "url_length": url_length(url),
        "domain_length": domain_length(domain),
        "dot_count": count_dots(url),
        "hyphen_count": count_hyphens(url),
        "at_count": count_at_signs(url),
        "slash_count": count_slashes(url),
        "digit_count": count_digits(url),
        "subdomain_count": count_subdomains(domain),
        "has_ip_host": has_ip_host(url),
        "has_https": has_https(url),
        "has_punycode": has_punycode(domain),
        "entropy": shannon_entropy(url),
        "query_param_count": count_query_params(url),
        "has_port": has_port(url),
        "url_depth": url_depth(url),
        "is_ip_host": has_ip_host(url),
    }

    if suspicious_tokens:
        matches = has_suspicious_tokens(url, suspicious_tokens)
        features["suspicious_token_count"] = len(matches)
        features["suspicious_tokens"] = matches
    else:
        features["suspicious_token_count"] = 0
        features["suspicious_tokens"] = []

    return features
