# AUX — Metadata Exposure Scanner (EXIF / XMP / IPTC / PDF info)

An **auxiliary** Apify actor for MirrorTrace (Self Footprint Audit Pro). It answers
one compliant self-footprint question:

> *"What is leaking out of the files I've already published publicly?"*

People routinely post photos and PDFs without realizing the file itself carries
**GPS coordinates**, a **camera / phone serial**, the **editing software**, an
**author name**, or an **embedded contact email**. This actor downloads the
subject's *own* public assets, extracts that embedded metadata, and reports each
leak as a typed module-event the rest of the pipeline can use.

It is the OPPOSITE of stalking tooling: it only ever describes the **subject's own
published exposure**, and it is hard-gated so it cannot be turned on anyone else.

## What it does

1. Routes the run through the canonical `shared/scope.js` `validateScope` gate,
   passing the **real asset hostnames** so private-social hosts (Instagram /
   Facebook / Tinder / …) and laundered intents are rejected before any byte is
   fetched.
2. Additionally restricts to `scope_type ∈ {self, public_figure}` — extracting
   embedded metadata is a **dual-use** technique, allowed only for these scopes.
   It **fails closed** for everything else.
3. Downloads each asset once, logged-out. `401/403` → skipped (we never bypass a
   login); `429` → back off and stop (we never evade rate limits).
4. Parses metadata from the **real bytes** with `exifr`. A clean file produces
   **no events** — never a fabricated one.
5. Maps leaks into the **frozen** `shared/detectors/event-types.js` vocabulary via
   `makeEvent()` (an unknown/forbidden type throws):
   - EXIF GPS → `PII_GEO_HINT_PUBLIC` (coarsened to ~1 km on purpose).
   - Author/Artist email → `PII_EMAIL_PUBLIC` + a **k-anonymity** `email_hash_prefix`
     correlation key (the plaintext address never leaves the machine).
   - Author/Artist name → `SELF_USERNAME`.
   - Camera make/model/serial + software → `PII_HANDLE_PUBLIC` (device fingerprint).
   - Aggregate → `EXPOSURE_SUMMARY`, scored with the product's only model,
     `shared/scoring.js` `exposureScore`.

Events carry `{ event_type, source_module, data, confidence, visibility, risk,
source_url, meta }` plus host/`email_hash_prefix` co-occurrence keys, so the
SpiderFoot-style correlation engine clusters a metadata leak alongside the
subject's other self-exposure events.

## Input

| Field | Type | Notes |
|---|---|---|
| `scope_type` | enum `self` \| `public_figure` | Required. Prohibited scopes are absent from the enum by construction. |
| `asset_urls` | string[] | Direct `https` URLs to images/PDFs you own (or a public figure's public assets). |
| `subject_label` | string | Label for reporting only. |
| `case_id` / `case_store_name` | string | Optional; joins the shared case. |

## Output

A dataset of `module_event` records plus a `METADATA_SUMMARY` key-value record
framed as a Blacklight-style self-exposure inspector ("what a third party
trivially learns about YOU from your own published files").

## Reference patterns applied

- **Crawlee / Scrapy pipeline + middleware** — each asset URL is a request;
  *download → parse → map-to-event → push* is a linear item-pipeline, and the
  scope gate is the first middleware that can drop a request before any fetch.
- **SpiderFoot OSINT modules + correlation engine** — every result is a typed
  module-event carrying a host/email co-occurrence key for clustering.
- **Have I Been Pwned k-anonymity** — an embedded author email is emitted only as
  its 5-char SHA-1 prefix (via `shared/aux/kanon.js`), never plaintext.
- **The Markup "Blacklight"** — output is framed as the subject's own exposure to
  fix, not surveillance of anyone else.

## Compliance / red lines

- No tracking of private individuals; no romance / gender / sexuality / intimacy /
  live-location inference (no such event type exists to emit).
- No private-social scraping; no login / captcha / rate-limit / ban bypass.
- **NO FAKE DATA**: every event is built from real extracted bytes; empty input or
  a clean file yields an empty result.

## Run locally

```bash
cd actors/metadata-exposure
npm install
# Provide input via Apify CLI or an INPUT.json in the default key-value store.
npm start
```
