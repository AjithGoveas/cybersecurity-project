from __future__ import annotations

import logging
import re
from dataclasses import dataclass

import requests
from bs4 import BeautifulSoup, Comment

from config import REQUEST_TIMEOUT, SANDBOX_PREVIEW_MAX_CHARS

logger = logging.getLogger(__name__)

DANGEROUS_TAGS = {"script", "iframe", "object", "embed", "applet", "form", "input"}
EVENT_HANDLER_RE = re.compile(r"^on\w+$", re.IGNORECASE)
HIDDEN_CONTENT_TAGS = {"script", "style", "noscript", "meta", "link"}


@dataclass
class SandboxPreviewResult:
    title: str
    text_preview: str
    meta_description: str
    images_found: int
    forms_found: int
    scripts_blocked: int
    external_links: int
    warnings: list[str]
    error: str | None = None


def _sanitize_html(html: str) -> tuple[str, int, int, list[str]]:
    """Sanitize HTML by removing dangerous elements and event handlers.

    Returns:
        Tuple of (clean_text, forms_found, scripts_blocked, warnings).
    """
    soup = BeautifulSoup(html, "html.parser")

    for comment in soup.find_all(string=lambda s: isinstance(s, Comment)):
        comment.extract()

    scripts_blocked = 0
    for tag_name in DANGEROUS_TAGS:
        for tag in soup.find_all(tag_name):
            if tag_name in ("script", "iframe", "object", "embed", "applet"):
                scripts_blocked += 1
            tag.decompose()

    for tag in soup.find_all(True):
        attrs_to_remove = [
            attr for attr in tag.attrs if EVENT_HANDLER_RE.match(attr)
        ]
        for attr in attrs_to_remove:
            del tag[attr]

        for attr in list(tag.attrs.keys()):
            val = tag.attrs[attr]
            if isinstance(val, str) and val.strip().lower().startswith("javascript:"):
                del tag[attr]

    forms_found = len(soup.find_all("form"))

    warnings = []
    if scripts_blocked > 0:
        warnings.append(f"Blocked {scripts_blocked} dangerous elements")

    text = soup.get_text(separator=" ", strip=True)
    text = re.sub(r"\s+", " ", text)

    return text, forms_found, scripts_blocked, warnings


def _count_images(soup: BeautifulSoup) -> int:
    """Count images in the page."""
    return len(soup.find_all("img"))


def _count_external_links(soup: BeautifulSoup, base_domain: str) -> int:
    """Count links pointing to external domains."""
    count = 0
    for a in soup.find_all("a", href=True):
        href = a["href"]
        if href.startswith(("http://", "https://")):
            from urllib.parse import urlparse

            parsed = urlparse(href)
            if parsed.hostname and parsed.hostname != base_domain:
                count += 1
    return count


def safe_preview(url: str) -> SandboxPreviewResult:
    """Fetch a URL and return a sanitized preview of its content.

    Fetches the page, strips dangerous elements (scripts, iframes, forms),
    and returns a safe text preview.

    Args:
        url: The URL to preview.

    Returns:
        SandboxPreviewResult with sanitized content.
    """
    try:
        parsed_url = __import__("urllib.parse", fromlist=["urlparse"]).urlparse(url)
        base_domain = parsed_url.hostname or ""
    except Exception:
        base_domain = ""

    try:
        resp = requests.get(
            url,
            timeout=REQUEST_TIMEOUT,
            headers={"User-Agent": "QRShield-SafePreview/1.0"},
            allow_redirects=True,
            verify=True,
        )
        resp.raise_for_status()

        content_type = resp.headers.get("Content-Type", "")
        if "text/html" not in content_type and "text/plain" not in content_type:
            return SandboxPreviewResult(
                title="",
                text_preview=f"Non-HTML content: {content_type}",
                meta_description="",
                images_found=0,
                forms_found=0,
                scripts_blocked=0,
                external_links=0,
                warnings=[f"Non-HTML content type: {content_type}"],
            )

        html = resp.text[:500_000]

        soup = BeautifulSoup(html, "html.parser")

        title_tag = soup.find("title")
        title = title_tag.get_text(strip=True) if title_tag else ""

        meta_desc = ""
        meta_tag = soup.find("meta", attrs={"name": "description"})
        if meta_tag and meta_tag.get("content"):
            meta_desc = meta_tag["content"][:300]

        text, forms_found, scripts_blocked, warnings = _sanitize_html(html)

        images = _count_images(soup)
        external_links = _count_external_links(soup, base_domain)

        text_preview = text[:SANDBOX_PREVIEW_MAX_CHARS]
        if len(text) > SANDBOX_PREVIEW_MAX_CHARS:
            text_preview += "..."

        return SandboxPreviewResult(
            title=title,
            text_preview=text_preview,
            meta_description=meta_desc,
            images_found=images,
            forms_found=forms_found,
            scripts_blocked=scripts_blocked,
            external_links=external_links,
            warnings=warnings,
        )

    except requests.exceptions.SSLError:
        return SandboxPreviewResult(
            title="",
            text_preview="",
            meta_description="",
            images_found=0,
            forms_found=0,
            scripts_blocked=0,
            external_links=0,
            warnings=[],
            error="SSL certificate error — site may be using invalid certificate",
        )
    except requests.exceptions.ConnectionError:
        return SandboxPreviewResult(
            title="",
            text_preview="",
            meta_description="",
            images_found=0,
            forms_found=0,
            scripts_blocked=0,
            external_links=0,
            warnings=[],
            error="Could not connect to the server",
        )
    except requests.exceptions.Timeout:
        return SandboxPreviewResult(
            title="",
            text_preview="",
            meta_description="",
            images_found=0,
            forms_found=0,
            scripts_blocked=0,
            external_links=0,
            warnings=[],
            error="Request timed out",
        )
    except Exception as e:
        logger.error("Sandbox preview failed for %s: %s", url, e)
        return SandboxPreviewResult(
            title="",
            text_preview="",
            meta_description="",
            images_found=0,
            forms_found=0,
            scripts_blocked=0,
            external_links=0,
            warnings=[],
            error=f"Preview failed: {e}",
        )
