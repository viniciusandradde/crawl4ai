import base64
import io

from PIL import Image

from captcha_intelligence import (
    CaptchaOCRRequest,
    decode_image,
    detect_challenge,
    annotate_crawl_result,
)


def image_payload():
    image = Image.new("RGB", (16, 16), "white")
    buffer = io.BytesIO()
    image.save(buffer, format="PNG")
    return base64.b64encode(buffer.getvalue()).decode()


def test_detects_recaptcha_structural_markers():
    result = detect_challenge('<div class="g-recaptcha"></div><script src="https://www.google.com/recaptcha/api.js"></script>')
    assert result["detected"] is True
    assert result["provider"] == "recaptcha"
    assert result["recommended_action"] == "pause_and_request_authorized_human_review"


def test_detects_hcaptcha():
    result = detect_challenge('<div class="h-captcha"></div>')
    assert result["provider"] == "hcaptcha"


def test_detects_cloudflare_turnstile():
    result = detect_challenge('<div class="cf-turnstile"></div>')
    assert result["provider"] == "cloudflare"
    assert result["challenge_type"] == "turnstile"


def test_http_block_is_not_mislabelled_as_captcha():
    result = detect_challenge("", 429)
    assert result["detected"] is True
    assert result["challenge_type"] == "access_block"
    assert result["provider"] == "unknown"


def test_normal_page_continues():
    result = detect_challenge("<html><body>Public article</body></html>", 200)
    assert result["detected"] is False
    assert result["recommended_action"] == "continue"


def test_decode_valid_png():
    image = decode_image(image_payload())
    assert image.size == (16, 16)


def test_rejects_invalid_base64():
    request = CaptchaOCRRequest(image_base64="not-base64")
    try:
        decode_image(request.image_base64)
    except ValueError as exc:
        assert "base64" in str(exc).lower()
    else:
        raise AssertionError("Invalid base64 should be rejected")


def test_annotates_crawl_result():
    result = {"html": '<div class="cf-turnstile"></div>', "status_code": 200}
    annotated = annotate_crawl_result(result)
    assert annotated["captcha_detection"]["provider"] == "cloudflare"
