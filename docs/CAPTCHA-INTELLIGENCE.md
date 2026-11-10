# Captcha Intelligence — Technical Specification

**Status:** implementation draft  
**Target:** Crawl4AI Docker API (deploy/docker)  
**Mode:** integrated module; no additional network service  
**OCR:** numeric and alphanumeric; authorized images only

## 1. Objective

Add challenge awareness and optional OCR to the existing FastAPI service. The feature must not solve, evade, or automate third-party anti-bot challenges. It classifies challenge markup, annotates crawl results, and provides OCR for images supplied by callers who own them or have permission to process them.

## 2. Architecture

- captcha_intelligence.py: structural detector, bounded image decoder, lazy OCR adapter.
- server.py: authenticated REST endpoint POST /captcha/ocr and status endpoint GET /captcha/status.
- api.py: annotate normal and streaming crawl results with captcha_detection.
- PaddleOCR: optional in-process OCR engine, initialized on first request.
- Existing Redis, browser pool, Playwright and Crawl4AI remain unchanged.

## 3. Detection behavior

Recognized structural signatures:
- Google reCAPTCHA: g-recaptcha, google.com/recaptcha, recaptcha/api2.
- hCaptcha: h-captcha, hcaptcha.com, hcaptcha-response.
- Cloudflare Turnstile: cf-turnstile, challenges.cloudflare.com/turnstile.
- Cloudflare browser challenge: cf_chl_, __cf_chl_tk, challenge-platform.

HTTP 403/429 without a known provider is reported as access_block, not as a verified CAPTCHA. The module returns a recommended action to pause and request authorized human review. It never clicks, submits, retries around, or solves the challenge.

## 4. OCR API

### POST /captcha/ocr

Authentication: existing Crawl4AI token/JWT gate.

Request:
~~~json
{
  "image_base64": "<base64 PNG/JPEG/WEBP/BMP>",
  "mode": "numeric",
  "min_confidence": 0.4
}
~~~

- mode=numeric: retain digits only.
- mode=alphanumeric: retain Latin letters and digits.
- Max decoded image: 2 MiB.
- Max dimensions: 16 megapixels.
- No remote image URL fetching.
- No image is persisted.
- PaddleOCR is loaded lazily and only when CAPTCHA_OCR_ENABLED=true.

Response:
~~~json
{
  "success": true,
  "engine": "PaddleOCR",
  "mode": "numeric",
  "text": "12345",
  "confidence": 0.97,
  "regions": [{"text": "12345", "confidence": 0.97}]
}
~~~

### GET /captcha/status

Returns feature flags and whether the OCR dependency is importable; does not expose credentials or model internals.

## 5. Configuration

- CAPTCHA_DETECTION_ENABLED=true (default): annotate crawl responses.
- CAPTCHA_OCR_ENABLED=false (default): enable only after installing the optional OCR requirements.
- CAPTCHA_OCR_ENABLED=true: activate OCR endpoint.

Install optional dependencies:
~~~bash
pip install -r deploy/docker/requirements-captcha-ocr.txt
~~~

For container builds, use the build argument INSTALL_CAPTCHA_OCR=true. OCR models may be downloaded on first initialization; provision outbound model access or pre-cache models in the image. Validate RAM and image-build size before production rollout.

## 6. Security

- Existing token_dep protects OCR and status routes.
- SlowAPI rate limiting applies to OCR.
- Base64 and image size/dimension limits prevent unbounded allocation.
- Pillow verifies the image before conversion.
- Only raster formats PNG/JPEG/WEBP/BMP are accepted.
- OCR uses threadpool execution so model inference does not block the event loop.
- No remote URL is accepted by OCR.
- Do not log image bytes or extracted text.
- Challenge detection does not access challenge frames or execute third-party scripts.
- Never disable egress controls, browser sandboxing, authentication, or host validation for this feature.

## 7. Observability

Crawl responses include:
~~~json
"captcha_detection": {
  "detected": true,
  "provider": "cloudflare",
  "challenge_type": "turnstile",
  "confidence": 0.92,
  "evidence": ["cf-turnstile"],
  "recommended_action": "pause_and_request_authorized_human_review"
}
~~~

Do not include raw HTML or page contents in the detector metadata.

## 8. Acceptance criteria

1. Known provider markup is classified correctly.
2. 403/429 is reported as an access block, not a confirmed CAPTCHA.
3. Normal pages are not flagged.
4. Both streaming and non-streaming crawl outputs include detection metadata.
5. OCR supports numeric and alphanumeric filtering.
6. Invalid base64, unsupported image formats, oversized images and excessive dimensions are rejected.
7. OCR disabled or dependency missing returns a controlled 503.
8. Routes are authenticated and rate-limited.
9. Existing crawl endpoints and defaults remain backward-compatible except for the additive metadata field.
10. Unit tests pass without PaddleOCR installed.

## 9. Rollout

1. Merge only after CI and manual Docker build validation.
2. Deploy with detection enabled and OCR disabled.
3. Observe false positives and memory use.
4. Install optional OCR dependency and enable OCR in a staging deployment.
5. Enable OCR in production after load and security checks.
