from __future__ import annotations

import logging
import socket
import ssl
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timezone
from urllib.parse import urlparse

import dns.resolver

from config import REQUEST_TIMEOUT

logger = logging.getLogger(__name__)


@dataclass
class DomainIntelResult:
    domain: str
    ssl_valid: bool | None = None
    ssl_issuer: str = ""
    ssl_expiry: str = ""
    dns_a_records: list[str] = field(default_factory=list)
    dns_mx_records: list[str] = field(default_factory=list)
    dns_txt_records: list[str] = field(default_factory=list)
    domain_age_days: int | None = None
    registrar: str = ""
    warnings: list[str] = field(default_factory=list)
    error: str | None = None


def _check_ssl(domain: str) -> tuple[bool | None, str, str]:
    """Check SSL certificate for a domain."""
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=REQUEST_TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                issuer_parts = []
                for rdn in cert.get("issuer", ()):
                    for attr, val in rdn:
                        if attr == "organizationName" and isinstance(val, str):
                            issuer_parts.append(val)
                issuer = ", ".join(issuer_parts) if issuer_parts else "Unknown"

                not_after_raw = cert.get("notAfter", "")
                not_after = str(not_after_raw) if not_after_raw else ""
                expiry = ""
                if not_after:
                    try:
                        exp_dt = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                        expiry = exp_dt.strftime("%Y-%m-%d")
                        if exp_dt < datetime.now(timezone.utc):
                            return False, issuer, expiry
                    except ValueError:
                        expiry = not_after

                return True, issuer, expiry
    except ssl.SSLCertVerificationError as e:
        logger.debug("SSL verification failed for %s: %s", domain, e)
        return False, "", ""
    except Exception as e:
        logger.debug("SSL check failed for %s: %s", domain, e)
        return None, "", ""


def _check_dns(domain: str) -> tuple[list[str], list[str], list[str]]:
    """Resolve DNS records for a domain."""
    a_records = []
    mx_records = []
    txt_records = []

    try:
        answers = dns.resolver.resolve(domain, "A", lifetime=REQUEST_TIMEOUT)
        a_records = [str(rdata) for rdata in answers]
    except Exception as e:
        logger.debug("A record lookup failed for %s: %s", domain, e)

    try:
        answers = dns.resolver.resolve(domain, "MX", lifetime=REQUEST_TIMEOUT)
        mx_records = [str(rdata.exchange).rstrip(".") for rdata in answers]
    except dns.resolver.NoAnswer:
        pass
    except Exception as e:
        logger.debug("MX record lookup failed for %s: %s", domain, e)

    try:
        answers = dns.resolver.resolve(domain, "TXT", lifetime=REQUEST_TIMEOUT)
        txt_records = [str(rdata).strip('"') for rdata in answers]
    except dns.resolver.NoAnswer:
        pass
    except Exception as e:
        logger.debug("TXT record lookup failed for %s: %s", domain, e)

    return a_records, mx_records, txt_records


def _check_whois(domain: str) -> tuple[int | None, str]:
    """Attempt WHOIS lookup via system command."""
    try:
        result = subprocess.run(
            ["whois", domain],
            capture_output=True,
            text=True,
            timeout=15,
            creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0,
        )
        output = result.stdout

        age_days = None
        registrar = ""

        for line in output.split("\n"):
            lower = line.lower().strip()
            if "creation date" in lower or "created" in lower:
                parts = line.split(":", 1)
                if len(parts) > 1:
                    date_str = parts[1].strip()
                    try:
                        for fmt in ("%Y-%m-%d", "%d-%m-%Y", "%Y%m%d", "%d %b %Y"):
                            try:
                                dt = datetime.strptime(date_str[:10], fmt)
                                age_days = (datetime.now() - dt).days
                                break
                            except ValueError:
                                continue
                    except Exception:
                        pass

            if "registrar" in lower and not registrar:
                parts = line.split(":", 1)
                if len(parts) > 1:
                    registrar = parts[1].strip()

        return age_days, registrar
    except FileNotFoundError:
        logger.debug("whois command not available on this system")
        return None, ""
    except subprocess.TimeoutExpired:
        logger.debug("whois lookup timed out for %s", domain)
        return None, ""
    except Exception as e:
        logger.debug("whois lookup failed for %s: %s", domain, e)
        return None, ""


def check_domain_intel(url: str) -> DomainIntelResult:
    """Perform domain intelligence gathering for a URL.

    Checks:
    - SSL certificate validity, issuer, and expiry
    - DNS A, MX, TXT records
    - Domain age via WHOIS (if available)

    Args:
        url: The URL to analyze.

    Returns:
        DomainIntelResult with intelligence data.
    """
    try:
        parsed = urlparse(url)
        domain = parsed.hostname or ""
    except Exception:
        return DomainIntelResult(domain="", error="Failed to parse URL")

    if not domain:
        return DomainIntelResult(domain="", error="No domain found in URL")

    ssl_valid, ssl_issuer, ssl_expiry = _check_ssl(domain)

    a_records, mx_records, txt_records = _check_dns(domain)

    age_days, registrar = _check_whois(domain)

    warnings = []
    if ssl_valid is False:
        warnings.append("SSL certificate is invalid or expired")
    if ssl_valid is None:
        warnings.append("Could not verify SSL certificate")
    if age_days is not None and age_days < 30:
        warnings.append(f"Domain is very new ({age_days} days old)")
    if not a_records:
        warnings.append("No DNS A records found")
    if not mx_records and not txt_records:
        warnings.append("No MX or TXT records found (may indicate parked domain)")

    return DomainIntelResult(
        domain=domain,
        ssl_valid=ssl_valid,
        ssl_issuer=ssl_issuer,
        ssl_expiry=ssl_expiry,
        dns_a_records=a_records,
        dns_mx_records=mx_records,
        dns_txt_records=txt_records,
        domain_age_days=age_days,
        registrar=registrar,
        warnings=warnings,
    )
