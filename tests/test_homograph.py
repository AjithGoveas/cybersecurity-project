from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.homograph_detector import check_homograph, _decompose_domain, _has_mixed_scripts


def test_decompose_domain_cyrillic():
    decoded = _decompose_domain("pаypal.com")
    assert decoded == "paypal.com"


def test_decompose_domain_clean():
    decoded = _decompose_domain("google.com")
    assert decoded == "google.com"


def test_has_mixed_scripts_true():
    assert _has_mixed_scripts("goоgle.com") is True


def test_has_mixed_scripts_false():
    assert _has_mixed_scripts("google.com") is False


def test_check_homograph_clean_url():
    result = check_homograph("https://google.com")
    assert result.is_suspicious is False
    assert len(result.flags) == 0


def test_check_homograph_cyrillic():
    result = check_homograph("https://pаypal.com")
    assert result.is_suspicious is True
    assert any("Non-ASCII" in f or "homoglyph" in f.lower() for f in result.flags)


def test_check_homograph_punycode():
    result = check_homograph("https://xn--pple-43a.com")
    assert result.is_suspicious is True
    assert any("Punycode" in f for f in result.flags)


def test_check_homograph_empty_domain():
    result = check_homograph("https://")
    assert result.is_suspicious is False
    assert result.original_domain == ""
