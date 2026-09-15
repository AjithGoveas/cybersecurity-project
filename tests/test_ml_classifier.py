from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.ml_classifier import classify_url, _fallback_classify


def test_classify_url_returns_result():
    result = classify_url("https://google.com")
    assert hasattr(result, "score")
    assert hasattr(result, "label")
    assert hasattr(result, "confidence")
    assert 0 <= result.score <= 100
    assert result.label in ("safe", "phishing")


def test_classify_safe_url():
    result = classify_url("https://www.google.com")
    assert result.score < 60
    assert result.label == "safe"


def test_classify_suspicious_url():
    result = classify_url("http://192.168.1.1/secure-login-verify-account-update")
    assert result.score > 30


def test_fallback_classify():
    result = _fallback_classify("https://google.com")
    assert result.model_source == "heuristic_fallback"
    assert 0 <= result.score <= 100


def test_fallback_suspicious():
    result = _fallback_classify("http://192.168.1.1/login-verify-secure-account")
    assert result.score > 40
