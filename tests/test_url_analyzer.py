from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.url_analyzer import analyze_url
from utils.url_features import (
    extract_url_features,
    shannon_entropy,
    has_ip_host,
    has_punycode,
    count_subdomains,
)


def test_extract_features_safe_url():
    features = extract_url_features("https://www.google.com")
    assert features["url_length"] == 22
    assert features["has_https"] is True
    assert features["has_ip_host"] is False
    assert features["subdomain_count"] == 1


def test_extract_features_ip_host():
    features = extract_url_features("http://192.168.1.1/login")
    assert features["has_ip_host"] is True
    assert features["is_ip_host"] is True


def test_extract_features_punycode():
    features = extract_url_features("http://xn--pple-43a.com")
    assert features["has_punycode"] is True


def test_extract_features_long_url():
    long_url = "https://" + "a" * 100 + ".com/path"
    features = extract_url_features(long_url)
    assert features["url_length"] > 75


def test_shannon_entropy():
    assert shannon_entropy("") == 0.0
    assert shannon_entropy("aaaa") < shannon_entropy("abcd")
    assert shannon_entropy("abcdefghij") > 3.0


def test_has_ip_host():
    assert has_ip_host("http://192.168.1.1") is True
    assert has_ip_host("https://google.com") is False
    assert has_ip_host("http://10.0.0.1:8080/path") is True


def test_has_punycode():
    assert has_punycode("xn--pple-43a.com") is True
    assert has_punycode("example.com") is False
    assert has_punycode("sub.xn--e1afmapc.com") is True


def test_count_subdomains():
    assert count_subdomains("example.com") == 0
    assert count_subdomains("www.example.com") == 1
    assert count_subdomains("a.b.c.example.com") == 3


def test_analyze_safe_url():
    result = analyze_url("https://www.google.com")
    assert result.is_valid is True
    assert result.risk_score < 40
    assert len(result.risk_factors) == 0


def test_analyze_suspicious_url():
    result = analyze_url("http://192.168.1.1/secure-login-verify-account-update.html")
    assert result.risk_score > 30
    assert len(result.risk_factors) > 0


def test_analyze_empty_url():
    result = analyze_url("")
    assert result.is_valid is False


def test_analyze_redirect_chain():
    result = analyze_url("https://bit.ly/3x")
    assert result.redirect_chain is not None
