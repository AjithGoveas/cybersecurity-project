from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import unquote, urlparse, parse_qs

from config import SUSPICIOUS_SCHEMES


@dataclass
class PayloadProfile:
    payload_type: str
    risk_level: str
    description: str
    extracted_data: dict
    raw_payload: str


def _parse_wifi_payload(payload: str) -> dict:
    """Parse WIFI: QR payload.

    Supports both standard WIFI:S:name;T:WPA;P:pass; format
    and WIFI:SSID=name;T=WPA;PASSWORD=pass; format.
    """
    data = {}
    s = payload[len("WIFI:"):].rstrip(";")

    if "=" in s and ":" not in s.split(";")[0]:
        for part in s.split(";"):
            if "=" in part:
                key, _, val = part.partition("=")
                key = key.strip().upper()
                val = val.strip().strip('"')
                _assign_wifi_field(data, key, val)
    else:
        for part in s.split(";"):
            if ":" in part:
                key, _, val = part.partition(":")
                key = key.strip().upper()
                val = val.strip().strip('"')
                _assign_wifi_field(data, key, val)
            elif "=" in part:
                key, _, val = part.partition("=")
                key = key.strip().upper()
                val = val.strip().strip('"')
                _assign_wifi_field(data, key, val)

    return data


def _assign_wifi_field(data: dict, key: str, val: str) -> None:
    if key in ("S", "SSID"):
        data["ssid"] = val
    elif key in ("P", "PASSWORD", "PWD"):
        data["password"] = val
    elif key in ("T", "SECURITY"):
        data["security"] = val
    elif key in ("H", "HIDDEN"):
        data["hidden"] = val.lower() == "true"
    elif key in ("I", "IDENTITY", "E", "ANONYMOUS_IDENTITY"):
        data["identity"] = val


def _parse_sms_payload(payload: str) -> dict:
    """Parse SMSTO: or SMS: payload."""
    s = payload
    for prefix in ("SMSTO:", "SMS:"):
        if s.upper().startswith(prefix):
            s = s[len(prefix):]
            break

    parts = s.split(":", 1)
    result = {"number": parts[0].strip()}
    if len(parts) > 1:
        result["message"] = parts[1].strip()
    return result


def _parse_tel_payload(payload: str) -> dict:
    """Parse TEL: payload."""
    number = payload[len("TEL:"):].strip()
    return {"number": number}


def _parse_email_payload(payload: str) -> dict:
    """Parse MATMSG: or mailto: payload."""
    if payload.upper().startswith("MATMSG:"):
        body = payload[len("MATMSG:"):].strip()
        parts = body.split(";")
        result = {}
        for part in parts:
            if ":" in part:
                key, _, val = part.partition(":")
                result[key.strip().lower()] = val.strip()
        return result

    if payload.lower().startswith("mailto:"):
        parsed = urlparse(payload)
        params = parse_qs(parsed.query)
        return {
            "to": parsed.path,
            "subject": params.get("subject", [""])[0],
            "body": params.get("body", [""])[0],
        }

    return {}


def _parse_vcard_payload(payload: str) -> dict:
    """Parse BEGIN:VCARD payload."""
    result = {"fields": {}}
    for line in payload.split("\n"):
        line = line.strip()
        if ":" in line:
            key, _, val = line.partition(":")
            key = key.split(";")[0].upper()
            if key in ("FN", "N", "TEL", "EMAIL", "ORG", "URL", "ADR"):
                result["fields"][key] = val
    return result


def profile_payload(payload: str) -> PayloadProfile:
    """Analyze a QR code payload and classify its type and risk.

    Args:
        payload: Raw decoded string from QR code.

    Returns:
        PayloadProfile with type, risk, description, and extracted data.
    """
    if not payload or not payload.strip():
        return PayloadProfile(
            payload_type="EMPTY",
            risk_level="NONE",
            description="Empty QR code payload",
            extracted_data={},
            raw_payload=payload,
        )

    upper = payload.upper().strip()

    if upper.startswith("WIFI:"):
        data = _parse_wifi_payload(payload)
        return PayloadProfile(
            payload_type="WIFI",
            risk_level="HIGH",
            description="Auto-connect Wi-Fi network — credential exfiltration risk. "
            "Your device may automatically connect to this network and share saved credentials.",
            extracted_data=data,
            raw_payload=payload,
        )

    if upper.startswith("SMSTO:") or upper.startswith("SMS:"):
        data = _parse_sms_payload(payload)
        return PayloadProfile(
            payload_type="SMS",
            risk_level="MEDIUM",
            description="Pre-filled SMS message — social engineering vector. "
            "Opens SMS app with recipient and message pre-filled.",
            extracted_data=data,
            raw_payload=payload,
        )

    if upper.startswith("TEL:"):
        data = _parse_tel_payload(payload)
        return PayloadProfile(
            payload_type="TEL",
            risk_level="MEDIUM",
            description="Auto-dial phone number — vishing risk. "
            "Opens phone dialer with number pre-filled.",
            extracted_data=data,
            raw_payload=payload,
        )

    if upper.startswith("MATMSG:") or upper.startswith("MAILTO:"):
        data = _parse_email_payload(payload)
        return PayloadProfile(
            payload_type="EMAIL",
            risk_level="MEDIUM",
            description="Email payload — may pre-fill recipient, subject, and body. "
            "Can be used for phishing or spam.",
            extracted_data=data,
            raw_payload=payload,
        )

    if upper.startswith("BEGIN:VCARD"):
        data = _parse_vcard_payload(payload)
        return PayloadProfile(
            payload_type="VCARD",
            risk_level="LOW",
            description="Contact card — may inject fake contact details into your address book.",
            extracted_data=data,
            raw_payload=payload,
        )

    if upper.startswith("BEGIN:VCALENDAR"):
        return PayloadProfile(
            payload_type="VCALENDAR",
            risk_level="LOW",
            description="Calendar event — may inject events with malicious links.",
            extracted_data={"raw": payload[:500]},
            raw_payload=payload,
        )

    if upper.startswith("MECARD:"):
        s = payload[len("MECARD:"):].rstrip(";")
        data = {}
        for part in s.split(";"):
            if "=" in part:
                key, _, val = part.partition("=")
                data[key.strip().lower()] = val.strip()
        return PayloadProfile(
            payload_type="MECARD",
            risk_level="LOW",
            description="Contact card (MECARD format) — similar to VCARD.",
            extracted_data=data,
            raw_payload=payload,
        )

    if upper.startswith("HTTP://") or upper.startswith("HTTPS://"):
        parsed = urlparse(payload)
        return PayloadProfile(
            payload_type="URL",
            risk_level="VARIABLE",
            description=f"Web URL pointing to {parsed.netloc}",
            extracted_data={
                "scheme": parsed.scheme,
                "domain": parsed.netloc,
                "path": parsed.path,
            },
            raw_payload=payload,
        )

    return PayloadProfile(
        payload_type="TEXT",
        risk_level="LOW",
        description="Plain text payload — no active content detected.",
        extracted_data={"text": payload[:500]},
        raw_payload=payload,
    )
