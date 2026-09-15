from __future__ import annotations

import logging
from dataclasses import dataclass

import joblib

from config import HUGGINGFACE_MODEL_ID, HUGGINGFACE_MODEL_FILE, LOCAL_MODEL_PATH

logger = logging.getLogger(__name__)

_model = None
_model_loaded = False


@dataclass
class ClassificationResult:
    score: int
    label: str
    confidence: float
    model_source: str


def _load_model():
    """Load the pre-trained phishing detection model."""
    global _model, _model_loaded

    if _model_loaded:
        return _model

    if LOCAL_MODEL_PATH.exists():
        try:
            _model = joblib.load(LOCAL_MODEL_PATH)
            _model_loaded = True
            logger.info("Loaded cached model from %s", LOCAL_MODEL_PATH)
            return _model
        except Exception as e:
            logger.warning("Failed to load cached model: %s", e)

    try:
        from huggingface_hub import hf_hub_download

        path = hf_hub_download(
            repo_id=HUGGINGFACE_MODEL_ID,
            filename=HUGGINGFACE_MODEL_FILE,
        )
        _model = joblib.load(path)
        _model_loaded = True
        logger.info("Downloaded and loaded model from HuggingFace")

        try:
            import shutil
            LOCAL_MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, LOCAL_MODEL_PATH)
            logger.info("Cached model to %s", LOCAL_MODEL_PATH)
        except Exception as e:
            logger.debug("Could not cache model locally: %s", e)

        return _model
    except Exception as e:
        logger.error("Failed to load HuggingFace model: %s", e)
        _model_loaded = True
        return None


def classify_url(url: str) -> ClassificationResult:
    """Classify a URL using the pre-trained ML model.

    Args:
        url: The URL to classify.

    Returns:
        ClassificationResult with score (0-100), label, and confidence.
    """
    model = _load_model()

    if model is None:
        logger.warning("Model unavailable — using fallback heuristic")
        return _fallback_classify(url)

    try:
        import numpy as np

        prediction = model.predict([url])
        proba = None
        if hasattr(model, "predict_proba"):
            proba = model.predict_proba([url])[0]
        elif hasattr(model, "decision_function"):
            raw = model.decision_function([url])[0]
            proba = _sigmoid(raw)

        if proba is not None and len(proba) >= 2:
            phishing_prob = float(proba[1])
            score = int(phishing_prob * 100)
            confidence = float(max(proba))
        else:
            pred = int(prediction[0])
            score = 90 if pred == 1 else 10
            confidence = 0.7

        label = "phishing" if score >= 50 else "safe"

        return ClassificationResult(
            score=score,
            label=label,
            confidence=confidence,
            model_source="huggingface",
        )
    except Exception as e:
        logger.error("ML prediction failed: %s", e)
        return _fallback_classify(url)


def _sigmoid(x: float) -> list[float]:
    import math
    val = 1 / (1 + math.exp(-x))
    return [1 - val, val]


def _fallback_classify(url: str) -> ClassificationResult:
    """Simple heuristic fallback when ML model is unavailable."""
    from utils.url_features import extract_url_features
    from config import SUSPICIOUS_TOKENS

    features = extract_url_features(url, suspicious_tokens=SUSPICIOUS_TOKENS)

    score = 0
    score += 15 if features["url_length"] > 75 else 0
    score += 15 if features["has_ip_host"] else 0
    score += 10 if not features["has_https"] else 0
    score += 10 if features["has_punycode"] else 0
    score += 5 if features["subdomain_count"] > 3 else 0
    score += 5 if features["hyphen_count"] > 3 else 0
    score += 5 if features["at_count"] > 0 else 0
    score += min(features["suspicious_token_count"] * 8, 20)
    score += 10 if features["entropy"] > 4.5 else 0

    score = min(score, 100)
    label = "phishing" if score >= 50 else "safe"
    confidence = 0.6 if 30 <= score <= 70 else 0.75

    return ClassificationResult(
        score=score,
        label=label,
        confidence=confidence,
        model_source="heuristic_fallback",
    )
