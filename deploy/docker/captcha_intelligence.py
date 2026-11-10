"""Captcha Intelligence: structural challenge detection and authorized image OCR.

This module deliberately does not solve, bypass, or automate third-party CAPTCHA
challenges. It detects common challenge providers and offers OCR for images that
the caller owns or is authorized to process.
"""
from __future__ import annotations

import base64
import binascii
import io
import os
import re
import threading
from typing import Literal

from PIL import Image, UnidentifiedImageError
from pydantic import BaseModel, Field, field_validator

MAX_IMAGE_BYTES = 2 * 1024 * 1024
MAX_IMAGE_PIXELS = 16_000_000
_OCR_LOCK = threading.Lock()
_OCR_ENGINE = None


class CaptchaOCRRequest(BaseModel):
    image_base64: str = Field(min_length=1, max_length=3_000_000)
    mode: Literal["numeric", "alphanumeric"] = "alphanumeric"
    min_confidence: float = Field(default=0.0, ge=0.0, le=1.0)

    @field_validator("image_base64")
    @classmethod
    def strip_data_uri(cls, value: str) -> str:
        value = value.strip()
        if value.startswith("data:"):
            header, separator, payload = value.partition(",")
            if not separator or ";base64" not in header.lower():
                raise ValueError("image_base64 must contain base64 image data")
            value = payload
        return value


def decode_image(encoded: str):
    """Decode a bounded raster image; reject malformed and oversized inputs."""
    try:
        raw = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("Invalid base64 image") from exc

    if not raw or len(raw) > MAX_IMAGE_BYTES:
        raise ValueError("Image must be between 1 byte and 2 MiB")

    try:
        with Image.open(io.BytesIO(raw)) as image:
            if image.format not in {"PNG", "JPEG", "WEBP", "BMP"}:
                raise ValueError("Only PNG, JPEG, WEBP and BMP images are supported")
            width, height = image.size
            if width < 1 or height < 1 or width * height > MAX_IMAGE_PIXELS:
                raise ValueError("Image dimensions exceed the allowed limit")
            image.verify()

        with Image.open(io.BytesIO(raw)) as image:
            return image.convert("RGB")
    except (UnidentifiedImageError, OSError) as exc:
        raise ValueError("Invalid or unsupported image") from exc


def _get_ocr_engine():
    """Initialize PaddleOCR only when explicitly enabled and first requested."""
    global _OCR_ENGINE
    if os.getenv("CAPTCHA_OCR_ENABLED", "false").lower() != "true":
        raise RuntimeError("OCR is disabled. Set CAPTCHA_OCR_ENABLED=true and install the OCR extra.")

    if _OCR_ENGINE is not None:
        return _OCR_ENGINE

    with _OCR_LOCK:
        if _OCR_ENGINE is not None:
            return _OCR_ENGINE
        try:
            from paddleocr import PaddleOCR
        except ImportError as exc:
            raise RuntimeError("PaddleOCR is not installed. Install deploy/docker/requirements-captcha-ocr.txt") from exc

        try:
            _OCR_ENGINE = PaddleOCR(
                lang="en",
                use_doc_orientation_classify=False,
                use_doc_unwarping=False,
                use_textline_orientation=False,
            )
        except TypeError:
            _OCR_ENGINE = PaddleOCR(use_angle_cls=False, lang="en")
    return _OCR_ENGINE


def _extract_predictions(engine, image):
    """Normalize PaddleOCR 3.x and 2.x prediction formats."""
    import numpy as np

    array = np.asarray(image)
    if hasattr(engine, "predict"):
        predictions = engine.predict(array)
        for prediction in predictions or []:
            payload = prediction
            if hasattr(payload, "json"):
                payload = payload.json
                if callable(payload):
                    payload = payload()
            if isinstance(payload, dict) and isinstance(payload.get("res"), dict):
                payload = payload["res"]
            if isinstance(payload, dict):
                texts = payload.get("rec_texts", []) or []
                scores = payload.get("rec_scores", []) or []
                for index, text in enumerate(texts):
                    score = float(scores[index]) if index < len(scores) else 0.0
                    yield str(text), max(0.0, min(1.0, score))
        return

    predictions = engine.ocr(array, cls=False) or []
    for page in predictions:
        for item in page or []:
            try:
                text, score = item[1]
                yield str(text), max(0.0, min(1.0, float(score)))
            except (IndexError, TypeError, ValueError):
                continue


def recognize_image(request: CaptchaOCRRequest) -> dict:
    """OCR an authorized image and return filtered text with confidence."""
    image = decode_image(request.image_base64)
    engine = _get_ocr_engine()
    fragments = []
    for text, confidence in _extract_predictions(engine, image):
        if confidence < request.min_confidence:
            continue
        if request.mode == "numeric":
            cleaned = "".join(re.findall(r"\d+", text))
        else:
            cleaned = "".join(re.findall(r"[A-Za-z0-9]+", text))
        if cleaned:
            fragments.append({"text": cleaned, "confidence": round(confidence, 4)})

    combined = "".join(item["text"] for item in fragments)
    average = sum(item["confidence"] for item in fragments) / len(fragments) if fragments else 0.0
    return {
        "success": True,
        "engine": "PaddleOCR",
        "mode": request.mode,
        "text": combined,
        "confidence": round(average, 4),
        "regions": fragments,
    }


def detect_challenge(html: str = "", status_code: int | None = None) -> dict:
    """Classify known challenge markup without interacting with the challenge."""
    source = (html or "").lower()
    provider = None
    challenge_type = None
    evidence = []

    signatures = [
        ("recaptcha", "captcha", (r"google\.com/recaptcha", r"g-recaptcha", r"recaptcha/api2", r"recaptcha/api/siteverify")),
        ("hcaptcha", "captcha", (r"hcaptcha\.com", r"h-captcha", r"hcaptcha-response")),
        ("cloudflare", "turnstile", (r"cf-turnstile", r"challenges\.cloudflare\.com/turnstile", r"cf-turnstile-response")),
        ("cloudflare", "browser_challenge", (r"cf_chl_", r"__cf_chl_tk", r"challenge-platform", r"just a moment\.\.\.")),
    ]

    for candidate, kind, patterns in signatures:
        hits = [pattern for pattern in patterns if re.search(pattern, source)]
        if hits:
            provider, challenge_type, evidence = candidate, kind, hits
            break

    if provider:
        return {
            "detected": True,
            "provider": provider,
            "challenge_type": challenge_type,
            "confidence": 0.99 if len(evidence) > 1 else 0.92,
            "evidence": evidence,
            "recommended_action": "pause_and_request_authorized_human_review",
        }

    if status_code in (403, 429):
        return {
            "detected": True,
            "provider": "unknown",
            "challenge_type": "access_block",
            "confidence": 0.70,
            "evidence": [f"http_{status_code}"],
            "recommended_action": "stop_and_review_site_access_policy",
        }

    return {
        "detected": False,
        "provider": None,
        "challenge_type": None,
        "confidence": 0.0,
        "evidence": [],
        "recommended_action": "continue",
    }


def annotate_crawl_result(result: dict) -> dict:
    """Attach a compact challenge classification to a Crawl4AI result."""
    if os.getenv("CAPTCHA_DETECTION_ENABLED", "true").lower() != "true":
        result["captcha_detection"] = {
            "detected": False, "provider": None, "challenge_type": None,
            "confidence": 0.0, "evidence": [], "recommended_action": "disabled",
        }
        return result

    html = result.get("html") or result.get("cleaned_html") or ""
    result["captcha_detection"] = detect_challenge(html=html, status_code=result.get("status_code"))
    return result
