from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Union

import cv2
import numpy as np

logger = logging.getLogger(__name__)

try:
    from pyzbar import pyzbar

    PYZBAR_AVAILABLE = True
except ImportError:
    PYZBAR_AVAILABLE = False
    logger.warning("pyzbar not available — falling back to OpenCV QR detector only")


@dataclass
class QRResult:
    payload: str
    payload_type: str
    confidence: float
    position: tuple[int, int, int, int] | None = None
    raw_points: list = field(default_factory=list)


def _detect_payload_type(payload: str) -> str:
    upper = payload.upper().strip()
    if upper.startswith("WIFI:"):
        return "WIFI"
    if upper.startswith("SMSTO:") or upper.startswith("SMS:"):
        return "SMS"
    if upper.startswith("TEL:"):
        return "TEL"
    if upper.startswith("MATMSG:"):
        return "EMAIL"
    if upper.startswith("BEGIN:VCARD"):
        return "VCARD"
    if upper.startswith("BEGIN:VCALENDAR"):
        return "VCALENDAR"
    if upper.startswith("MECARD:"):
        return "MECARD"
    if upper.startswith("HTTP://") or upper.startswith("HTTPS://"):
        return "URL"
    if upper.startswith("MAILTO:"):
        return "EMAIL"
    return "TEXT"


def _preprocess_image(image: np.ndarray) -> list[np.ndarray]:
    """Generate multiple preprocessed versions to improve decode rate."""
    variants = []

    gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY) if len(image.shape) == 3 else image
    variants.append(("gray", gray))

    adaptive = cv2.adaptiveThreshold(
        gray, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C, cv2.THRESH_BINARY, 51, 2
    )
    variants.append(("adaptive", adaptive))

    _, otsu = cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
    variants.append(("otsu", otsu))

    kernel = cv2.getStructuringElement(cv2.MORPH_RECT, (3, 3))
    cleaned = cv2.morphologyEx(otsu, cv2.MORPH_CLOSE, kernel)
    variants.append(("morphed", cleaned))

    for scale in [0.5, 1.5, 2.0]:
        resized = cv2.resize(gray, None, fx=scale, fy=scale, interpolation=cv2.INTER_CUBIC)
        variants.append((f"scale_{scale}", resized))

    return variants


def _decode_with_pyzbar(image: np.ndarray) -> list[QRResult]:
    """Decode QR codes using pyzbar."""
    if not PYZBAR_AVAILABLE:
        return []

    results = []
    rgb = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY) if len(image.shape) == 3 else image
    if len(rgb.shape) == 2:
        rgb = cv2.cvtColor(rgb, cv2.COLOR_GRAY2RGB)

    decoded = pyzbar.decode(rgb)
    for obj in decoded:
        payload = obj.data.decode("utf-8", errors="replace")
        results.append(
            QRResult(
                payload=payload,
                payload_type=_detect_payload_type(payload),
                confidence=0.95,
                position=(obj.rect.left, obj.rect.top, obj.rect.width, obj.rect.height),
                raw_points=[(p.x, p.y) for p in obj.polygon] if obj.polygon else [],
            )
        )
    return results


def _decode_with_opencv(image: np.ndarray) -> list[QRResult]:
    """Decode QR codes using OpenCV's built-in detector."""
    results = []
    detector = cv2.QRCodeDetector()

    data, points, _ = detector.detectAndDecodeMulti(image)
    if data is not None and points is not None:
        for i, payload in enumerate(data):
            if payload:
                pts = points[i].astype(int).tolist() if i < len(points) else []
                x, y, w, h = (0, 0, 0, 0)
                if pts:
                    xs = [p[0] for p in pts]
                    ys = [p[1] for p in pts]
                    x, y = min(xs), min(ys)
                    w, h = max(xs) - x, max(ys) - y
                results.append(
                    QRResult(
                        payload=payload,
                        payload_type=_detect_payload_type(payload),
                        confidence=0.90,
                        position=(x, y, w, h),
                        raw_points=pts,
                    )
                )

    if not results:
        data, points = detector.detectAndDecode(image)
        if data and points is not None:
            pts = points.astype(int).tolist()
            x, y, w, h = (0, 0, 0, 0)
            if pts:
                flat = pts if isinstance(pts[0], list) else [pts]
                xs = [p[0] for p in flat]
                ys = [p[1] for p in flat]
                x, y = min(xs), min(ys)
                w, h = max(xs) - x, max(ys) - y
            results.append(
                QRResult(
                    payload=data,
                    payload_type=_detect_payload_type(data),
                    confidence=0.90,
                    position=(x, y, w, h),
                    raw_points=pts,
                )
            )

    return results


def decode_qr(source: Union[str, Path, bytes, np.ndarray]) -> list[QRResult]:
    """Decode QR codes from an image source.

    Args:
        source: File path (str/Path), raw bytes, or numpy array (BGR).

    Returns:
        List of QRResult objects, one per decoded QR code.
    """
    if isinstance(source, (str, Path)):
        image = cv2.imread(str(source))
        if image is None:
            raise FileNotFoundError(f"Cannot read image: {source}")
    elif isinstance(source, bytes):
        arr = np.frombuffer(source, dtype=np.uint8)
        image = cv2.imdecode(arr, cv2.IMREAD_COLOR)
        if image is None:
            raise ValueError("Cannot decode image bytes")
    elif isinstance(source, np.ndarray):
        image = source
    else:
        raise TypeError(f"Unsupported source type: {type(source)}")

    all_results: list[QRResult] = []
    seen_payloads: set[str] = set()

    variants = _preprocess_image(image)

    for variant_name, variant_img in variants:
        for decoder in [_decode_with_pyzbar, _decode_with_opencv]:
            try:
                results = decoder(variant_img)
                for r in results:
                    if r.payload not in seen_payloads:
                        seen_payloads.add(r.payload)
                        all_results.append(r)
            except Exception as e:
                logger.debug("Decoder %s failed on %s: %s", decoder.__name__, variant_name, e)

    if not all_results:
        logger.warning("No QR codes found in image")

    return all_results
