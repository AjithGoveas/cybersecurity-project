from __future__ import annotations

import logging
from dataclasses import dataclass, field
from urllib.parse import urlparse

import requests

from config import (
    ENTROPY_SUSPICIOUS,
    REDIRECT_CHAIN_MAX,
    REQUEST_TIMEOUT,
    SUSPICIOUS_TOKENS,
    URL_LENGTH_SUSPICIOUS,
)
from utils.url_features import extract_url_features, shannon_entropy, has_ip_host, has_punycode

logger = logging.getLogger(__name__)


@dataclass
class RedirectHop:
    url: str
    status_code: int


@dataclass
class URLAnalysisResult:
    url: str
    final_url: str
    risk_factors: list[str]
    risk_score: int
    redirect_chain: list[RedirectHop]
    features: dict
    is_valid: bool = True
    error: str | None = None


def _trace_redirects(url: str) -> tuple[list[RedirectHop], str, str | None]:
    """Follow redirects and return chain, final URL, and any error."""
    chain: list[RedirectHop] = []
    current = url

    for _ in range(REDIRECT_CHAIN_MAX):
        try:
            resp = requests.head(
                current,
                allow_redirects=False,
                timeout=REQUEST_TIMEOUT,
                headers={"User-Agent": "QRShield/1.0"},
            )
            chain.append(RedirectHop(url=current, status_code=resp.status_code))

            if resp.status_code in (301, 302, 303, 307, 308):
                location = resp.headers.get("Location", "")
                if not location:
                    break
                if location.startswith("/"):
                    parsed = urlparse(current)
                    location = f"{parsed.scheme}://{parsed.netloc}{location}"
                current = location
            else:
                break
        except requests.RequestException as e:
            logger.debug("Redirect trace failed at %s: %s", current, e)
            chain.append(RedirectHop(url=current, status_code=-1))
            return chain, current, str(e)

    return chain, current, None


def _check_risk_factors(url: str, features: dict, redirect_chain: list[RedirectHop]) -> list[str]:
    """Identify risk factors from lexical analysis and redirect behavior."""
    risks = []

    if features["url_length"] > URL_LENGTH_SUSPICIOUS:
        risks.append(f"Abnormally long URL ({features['url_length']} chars)")

    if features["entropy"] > ENTROPY_SUSPICIOUS:
        risks.append(f"High URL entropy ({features['entropy']:.2f})")

    if features["has_ip_host"]:
        risks.append("IP address used as hostname")

    if features["has_punycode"]:
        risks.append("Punycode/IDN domain detected")

    if not features["has_https"]:
        risks.append("No HTTPS encryption")

    if features["subdomain_count"] > 3:
        risks.append(f"Excessive subdomains ({features['subdomain_count']})")

    if features["has_port"]:
        risks.append("Non-standard port in URL")

    if features["hyphen_count"] > 3:
        risks.append(f"Multiple hyphens in URL ({features['hyphen_count']})")

    if features["at_count"] > 0:
        risks.append("@ sign found in URL (potential credential spoofing)")

    if features["digit_count"] > features["url_length"] * 0.3:
        risks.append("High ratio of digits in URL")

    if features["suspicious_token_count"] > 0:
        tokens = ", ".join(features["suspicious_tokens"][:5])
        risks.append(f"Suspicious keywords: {tokens}")

    redirect_count = len(redirect_chain) - 1
    if redirect_count > 3:
        risks.append(f"Long redirect chain ({redirect_count} redirects)")

    if redirect_count > 0:
        final_hop = redirect_chain[-1]
        if final_hop.status_code == -1:
            risks.append("Redirect chain failed to resolve")

    parsed_final = urlparse(redirect_chain[-1].url if redirect_chain else url)
    if parsed_final.scheme == "http" and features["has_https"]:
        risks.append("Redirect downgraded from HTTPS to HTTP")

    return risks


def _calculate_score(risk_factors: list[str], features: dict) -> int:
    """Calculate a 0-100 risk score. Higher = more dangerous."""
    score = 0

    score += min(features["url_length"] // 5, 20)
    score += min(int(features["entropy"] * 3), 15)
    score += 15 if features["has_ip_host"] else 0
    score += 10 if features["has_punycode"] else 0
    score += 5 if not features["has_https"] else 0
    score += min(features["subdomain_count"] * 3, 12)
    score += 5 if features["has_port"] else 0
    score += min(features["hyphen_count"] * 2, 8)
    score += 10 if features["at_count"] > 0 else 0
    score += min(features["suspicious_token_count"] * 5, 15)
    score += min(len(risk_factors) * 3, 10)

    return min(score, 100)


def analyze_url(url: str) -> URLAnalysisResult:
    """Perform multi-stage URL security analysis.

    Args:
        url: The URL to analyze.

    Returns:
        URLAnalysisResult with risk assessment.
    """
    if not url or not url.strip():
        return URLAnalysisResult(
            url=url,
            final_url=url,
            risk_factors=["Empty URL"],
            risk_score=0,
            redirect_chain=[],
            features={},
            is_valid=False,
            error="Empty URL",
        )

    url = url.strip()

    features = extract_url_features(url, suspicious_tokens=SUSPICIOUS_TOKENS)

    redirect_chain, final_url, trace_error = _trace_redirects(url)

    if redirect_chain:
        final_features = extract_url_features(final_url, suspicious_tokens=SUSPICIOUS_TOKENS)
        features.update({f"final_{k}": v for k, v in final_features.items()})

    risk_factors = _check_risk_factors(url, features, redirect_chain)

    score = _calculate_score(risk_factors, features)

    return URLAnalysisResult(
        url=url,
        final_url=final_url,
        risk_factors=risk_factors,
        risk_score=score,
        redirect_chain=redirect_chain,
        features=features,
        is_valid=True,
        error=trace_error,
    )
