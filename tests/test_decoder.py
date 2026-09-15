from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import numpy as np

from core.decoder import decode_qr, _detect_payload_type


def test_detect_payload_type_url():
    assert _detect_payload_type("https://example.com") == "URL"
    assert _detect_payload_type("http://example.com") == "URL"


def test_detect_payload_type_wifi():
    assert _detect_payload_type('WIFI:T:WPA;S:MyNetwork;P:pass123;;') == "WIFI"


def test_detect_payload_type_sms():
    assert _detect_payload_type("SMSTO:+1234567890:Hello") == "SMS"
    assert _detect_payload_type("SMS:+1234567890") == "SMS"


def test_detect_payload_type_tel():
    assert _detect_payload_type("TEL:+1234567890") == "TEL"


def test_detect_payload_type_email():
    assert _detect_payload_type("MATMSG:TO:me@example.com;SUB:Hi;;") == "EMAIL"
    assert _detect_payload_type("mailto:user@example.com") == "EMAIL"


def test_detect_payload_type_vcard():
    assert _detect_payload_type("BEGIN:VCARD\nVERSION:3.0\nFN:John\nEND:VCARD") == "VCARD"


def test_detect_payload_type_text():
    assert _detect_payload_type("Hello World") == "TEXT"
    assert _detect_payload_type("") == "TEXT"


def test_decode_qr_numpy_array():
    """Test decoding from a numpy array (simulated QR code)."""
    img = np.zeros((200, 200, 3), dtype=np.uint8)
    img[:] = 255
    results = decode_qr(img)
    assert isinstance(results, list)


def test_decode_qr_invalid_file():
    """Test that invalid file path raises error."""
    try:
        decode_qr("nonexistent_file.png")
        assert False, "Should have raised FileNotFoundError"
    except FileNotFoundError:
        pass


def test_decode_qr_invalid_bytes():
    """Test that invalid bytes raises error."""
    try:
        decode_qr(b"not an image")
        assert False, "Should have raised ValueError"
    except ValueError:
        pass
