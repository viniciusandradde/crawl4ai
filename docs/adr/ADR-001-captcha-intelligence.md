# ADR-001 — Integrated Captcha Intelligence module

- **Status:** Accepted for implementation
- **Date:** 2026-11-10

## Context

The existing WebScrap deployment is a single FastAPI service backed by Crawl4AI, Playwright, Redis and a browser pool. A separate OCR microservice would add network, deployment and authentication complexity.

## Decision

Implement Captcha Intelligence as an internal Python module in deploy/docker, expose authenticated REST endpoints through the existing FastAPI app, and annotate both streaming and non-streaming crawl results.

Use PaddleOCR as an optional, lazily initialized OCR engine. Keep the default Docker image free of OCR model dependencies unless the build operator explicitly opts in.

The module detects third-party challenge providers and pauses the workflow for authorized human review. It does not bypass or solve third-party CAPTCHA systems.

## Consequences

- Reuses existing API authentication, rate limiting, logging and deployment.
- No new container or service discovery.
- OCR dependencies increase image size and memory only when enabled.
- PaddleOCR model initialization can add first-request latency.
- Detection metadata is additive and does not change existing result fields.
