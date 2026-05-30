# AUX — Public-Archive Self-Exposure Audit (Wayback → STIX)

An **auxiliary** MirrorTrace actor. It answers one compliant question about the
**SELF subject**:

> *"What did I publish, then delete — but which still lives in a **public web
> archive** anyone can pull up?"*

A live-only footprint audit misses this entirely. The Internet Archive's Wayback
Machine keeps **public** snapshots of pages forever, so an old page that exposed
your email, phone, or a former handle is still trivially retrievable until you
request its removal. This actor surfaces exactly those archived exposures and
packages each as portable, takedown-ready evidence.

## What it does

1. **Scope-gate (fail-closed, before any network call).** Routes the run through
   the canonical `shared/scope.js` `validateScope`, then restricts to
   `scope_type ∈ {self, public_figure}`. Enumerating every archived snapshot under
   a URL prefix is a **dual-use** technique, so `consented` / `brand` /
   `safety_evidence` are refused here. A private-person / stalking query (or a
   laundered one hidden in `subject_label`) is dropped **before** any fetch.
2. **List archived snapshots.** Queries the public **Wayback CDX Server API** for
   snapshots under your `subject_url`, deduped by content digest and bounded by
   `max_snapshots`.
3. **(Optional) scan snapshot text for your PII.** With `scan_snapshot_pii`, each
   **public** snapshot is fetched, reduced to clean text (Website-Content-Crawler
   style), and run through the **shared** `pii-detector` — no PII regexes are
   reinvented here.
4. **Emit STIX-ready evidence.** Every result is a typed `module_event` carrying
   the **true** archive capture time + content digest, so
   `shared/enrich/stix-evidence.js` wraps each as a **STIX 2.1 Observed Data**
   object whose `first_observed` / `last_observed` are the *real* capture time —
   ready to export to a takedown desk, OpenCTI, or MISP.

## Input

| field | type | notes |
|---|---|---|
| `scope_type` | enum `self` \| `public_figure` | prohibited/non-applicable scopes are **absent from the enum** |
| `subject_url` | string (required) | a URL/host you own, e.g. `https://example.com` |
| `match_prefix` | boolean (default `true`) | list everything under the prefix vs. exact URL |
| `max_snapshots` | int 1–500 (default 50) | bounded, polite |
| `scan_snapshot_pii` | boolean (default `false`) | fetch + shared-PII-scan each snapshot |
| `subject_label`, `case_id`, `case_store_name` | string | reporting / pipeline wiring |

## Output

Dataset records (`record_type: "archive_event"`): one `SELF_PROFILE_URL` per
archived snapshot (with `meta.observed_at`, `meta.content_digest`,
`meta.original_url`), optional `PII_*_PUBLIC` events for PII found inside
snapshots, and one `EXPOSURE_SUMMARY`. A `record_type: "archive_summary"` key is
written to the run KV store.

## Compliance / red lines

- **Public data only.** Documented Wayback CDX index + public snapshot replay
  URLs. On `429`/`403` we **back off** — we never bypass auth, captcha, or limits.
- **No fake data.** Empty archive ⇒ zero events. An unparseable CDX row ⇒ no
  event. Nothing is ever fabricated.
- **No inference.** There is no field or code path for romance/intimacy/gender,
  third-private-party identity, follower/like scraping, or live location. The
  frozen `EVENT_TYPES` vocabulary has no slot for any of it.

## Reference patterns applied

- **OpenCTI / MISP + STIX 2.1 evidence-object model.** A Wayback CDX row is an
  *observation of a URL at a time with a content digest* — i.e. a STIX 2.1
  **Observed Data** SDO (`first_observed` / `last_observed` / `number_observed` +
  an `objects` bag). Emitting that standard shape lets a finding round-trip into
  OpenCTI/MISP or a SIEM. (OASIS STIX 2.1 Observed Data SDO; OpenCTI/MISP STIX 2.1
  interop.)
- **Apify Website Content Crawler + RAG Web Browser ingestion.** A bounded, polite
  fetch of **public** web content (snapshot cap, `429`/`403` backoff, URL → clean
  text), each item mapped into a typed record — WCC's "turn a URL into clean text
  for downstream processing", applied to archived snapshots, then handed to the
  shared detector. (`apify/website-content-crawler`, `apify/rag-web-browser`.)
- **SpiderFoot event-driven OSINT modules.** Every result is a typed
  `module_event` so the shared correlation engine links an archived exposure to
  the same surface found live. (`github.com/smicallef/spiderfoot`.)
- **Internet Archive Wayback CDX Server API** — the public snapshot index.

## Deploy

`actorId` stays a placeholder / `deployed: false` until live-account wiring (the
last step). Run the offline self-test with no network:

```
node shared/aux/archive-finding_selftest.js
```
