# A3 — Crawler

Captures the public pages in the frontier with Crawlee's
`AdaptivePlaywrightCrawler`, then metamorphs into the diff/evidence stage.

## What it preserves per page
- `content_sha256` — sha256 of normalized visible text (drives change detection)
- `html_sha256` — sha256 of raw html (tamper fingerprint)
- raw html → named KV store (`html_key`)
- full-page screenshot → named KV store (`screenshot_key`)

## Cost / politeness controls
- `maxRequestsPerCrawl` = `max_pages` (hard cost cap)
- `maxConcurrency` = 3 (polite, not maxing rate limits)
- `renderingTypeDetectionRatio` = 0.25 (browser only when needed)
- blocks `media/font/websocket/manifest/other` resource types
- same-hostname link expansion only (never wanders off vetted seeds)

## ⛔ Compliance boundary (do not "fix" by adding evasion)
On `401 / 403 / 429` the crawler pushes a `backoff_for_human_review` record and
**aborts**. It does **not** rotate fingerprints, swap proxies, or solve captchas.
The backoff record IS the deliverable: a human reviews the block. This is
enforced in `failedRequestHandler` (and a secondary check in `requestHandler`).
See the boundary comments in `src/main.js`.

## Human config
- `DIFF_ACTOR_ID` env → `roger_1of1/mirrortrace-diff-evidence`.

## Apify notes
- Default 60 rps / 200 rps KV — low concurrency keeps us well under.
- Requires the Playwright/Chromium base image (see Dockerfile).
