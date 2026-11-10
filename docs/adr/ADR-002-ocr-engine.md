# ADR-002 — OCR engine and input boundaries

- **Status:** Accepted for implementation
- **Date:** 2026-11-10

## Decision

Select PaddleOCR under Apache-2.0 as the primary OCR engine. Accept base64-encoded PNG, JPEG, WEBP and BMP images only; do not fetch caller-provided remote image URLs.

Support numeric and alphanumeric output filters. Keep OCR disabled by default and require explicit installation plus CAPTCHA_OCR_ENABLED=true.

## Rationale

PaddleOCR provides general-purpose text detection and recognition, making it suitable for both numeric and alphanumeric text images without coupling the service to a CAPTCHA-vendor solver. Its optional installation avoids imposing a large ML dependency on every scraping deployment.

## Security

Limit decoded image bytes to 2 MiB and dimensions to 16 megapixels. Do not persist image content or log recognized text. Run inference outside the FastAPI event loop.
