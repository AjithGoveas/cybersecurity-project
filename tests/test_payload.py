from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.payload_profiler import profile_payload


def test_empty_payload():
    result = profile_payload("")
    assert result.payload_type == "EMPTY"
    assert result.risk_level == "NONE"


def test_wifi_payload():
    result = profile_payload('WIFI:T:WPA;S:FreeWiFi;P:hack123;;')
    assert result.payload_type == "WIFI"
    assert result.risk_level == "HIGH"
    assert result.extracted_data["ssid"] == "FreeWiFi"
    assert result.extracted_data["password"] == "hack123"


def test_sms_payload():
    result = profile_payload("SMSTO:+1234567890:Click this link to verify")
    assert result.payload_type == "SMS"
    assert result.risk_level == "MEDIUM"
    assert result.extracted_data["number"] == "+1234567890"


def test_tel_payload():
    result = profile_payload("TEL:+1-800-555-1234")
    assert result.payload_type == "TEL"
    assert result.risk_level == "MEDIUM"
    assert result.extracted_data["number"] == "+1-800-555-1234"


def test_email_payload():
    result = profile_payload("mailto:phisher@evil.com?subject=Verify&body=Click")
    assert result.payload_type == "EMAIL"
    assert result.risk_level == "MEDIUM"


def test_vcard_payload():
    payload = "BEGIN:VCARD\nVERSION:3.0\nFN:John Doe\nTEL:+1234567890\nEND:VCARD"
    result = profile_payload(payload)
    assert result.payload_type == "VCARD"
    assert result.risk_level == "LOW"


def test_url_payload():
    result = profile_payload("https://example.com")
    assert result.payload_type == "URL"
    assert result.risk_level == "VARIABLE"
    assert result.extracted_data["domain"] == "example.com"


def test_text_payload():
    result = profile_payload("Hello World")
    assert result.payload_type == "TEXT"
    assert result.risk_level == "LOW"
