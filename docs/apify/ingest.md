# Apify Website Content Crawler + RAG Web Browser — scope-gated self-audit ingestion

**Capability:** the **real ingestion source** for a self-audit. The subject's
**own** public footprint is fetched with two Apify first-party actors —
[`apify/website-content-crawler`](https://apify.com/apify/website-content-crawler)
(page crawl → clean text/markdown + evidence handles) and
[`apify/rag-web-browser`](https://apify.com/apify/rag-web-browser) (public Google
search **or** single-URL fetch → top-N markdown for context) — and every request
re-asserts the existing scope gate **before any fetch input is built**.

**Status:** real config + pure input-builder + real item-pipeline mapping + 20
self-tests. **NOT deployed.** `actorId`s are placeholders (`<PLACEHOLDER:…>`,
`deployed:false`); the live `actorId` + `APIFY_TOKEN` are wired by the operator at
the **last** step. No credentials in the repo; without a token the client
dry-runs (no network, no fabricated rows).

## Why this is the OPPOSITE of a stalking crawler

Ingestion is where a stalking tool would point a crawler at someone else. Here the
**first thing** `buildIngestPlan()` does is call the real `shared/scope.js`
`validateScope()` (read-only — Codex owns that file) and **refuse to build any
actor input** for a rejected subject. A private-individual / romance-laundered /
login-walled query is therefore dropped *before a single fetch input exists*. Two
doors, both must open: `validateScope` **and** this ingestion policy.

Extra compliance floors the builder enforces:

- **`respectRobotsTxtFile` is forced `true`** even if the caller passes `false`
  (anti-evasion — same floor as the proxy policy).
- **`maxCrawlPages` / `maxCrawlDepth` are clamped DOWN to caps**, never up
  (anti-dragnet; a self-audit reads your own surface, it does not deep-mine).
- The crawl is **confined to the subject's own hosts** via `includeUrlGlobs`, and
  the item-pipeline **re-asserts the host on every row** so a discovered link or a
  metamorph cannot smuggle a non-vetted host downstream.
- A **RAG free-text/name search is a dual-use discovery chokepoint**: allowed only
  for `scope=self|public_figure`. For `consented|brand|safety_evidence` the RAG
  `query` must be a **concrete URL** the operator already holds, never a name
  search.

## Files

| File | Role |
|---|---|
| `integrations/ingest/ingest.config.json` | Honest config: placeholder actorIds (`deployed:false`), WCC/RAG defaults, anti-dragnet caps, forced robots override, name-search scope allow-list. |
| `integrations/ingest/ingest-policy.js` | Pure, zero-I/O planner: scope-gate-first ordered guards → exact WCC/RAG actor input; plus the row-mapper + Scrapy-style item-pipeline (WCC row → detector artifacts → module_events → STIX 2.1 Observed Data). |
| `integrations/ingest/ingest-client.js` | Live-or-dry-run client. Builds the exact `run-sync-get-dataset-items` request; without `APIFY_TOKEN` returns it with `started:false` and makes no network call. |
| `integrations/ingest/_selftest.js` | 20 checks: scope-gate-first drop, name-search chokepoint, robots-forced, caps-clamp, WCC-row → STIX, host re-assertion, failed-page handling, dry-run honesty. |

## The two actors (input + output we wire)

### `apify/website-content-crawler` — primary self-audit crawl

Input we build (subset, from the actor's
[input schema](https://apify.com/apify/website-content-crawler/input-schema)):
`startUrls` (from vetted targets), `crawlerType`, `includeUrlGlobs` (host
confinement), `maxCrawlDepth`, `maxCrawlPages`, `saveMarkdown`, `saveHtmlAsFile`,
`saveScreenshots`, `removeCookieWarnings`, `requestTimeoutSecs`,
`respectRobotsTxtFile:true` (forced), optional pass-through `proxyConfiguration`.

Per-page output rows we map: `url`, `crawl.loadedUrl`, `text`, `markdown`,
`metadata.title`, `metadata.canonicalUrl`, `htmlUrl`, `screenshotUrl`, and `error`
on a failed page (we surface it as `page_error` and detect nothing).

### `apify/rag-web-browser` — public context pass

Input we build: `query` (phrase **or** URL), `maxResults` (clamped), `outputFormats`
(`markdown`), `requestTimeoutSecs`. Both actors also support **Apify Standby**, so
this layer composes with the existing standby real-time gate.

## Reference architectures (how a mature system wires this)

**1. Apify Website Content Crawler + RAG Web Browser.** WCC is purpose-built to
turn a site into clean, LLM-ready `markdown`/`text` per page with `htmlUrl` /
`screenshotUrl` evidence handles and an explicit `error` field on failed pages;
RAG Web Browser runs a Google search (or fetches one URL) and returns the top-N
pages as markdown for a RAG/LLM step, and is designed to run in **Standby** for
low-latency real-time use
([apify/website-content-crawler](https://apify.com/apify/website-content-crawler),
[apify/rag-web-browser](https://apify.com/apify/rag-web-browser)). We borrow their
exact input contracts and per-row output shapes, and map the rows onto the
**existing** detector `ARTIFACT_KINDS` so the real detector modules run on real
crawl output — no parallel detection logic, no fabricated rows.

**2. OpenCTI / MISP + STIX 2.1.** An exposure finding is a STIX 2.1 **Observed
Data** SDO — "the raw data was observed at a particular time", with
`first_observed` / `last_observed` and an `objects` bag of cyber-observables that
"document the facts … and do not capture the who, when, or why"
([OASIS STIX 2.1](https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html)).
OpenCTI ingests STIX 2.1 **bundles** via its workers, and the MISP↔OpenCTI
connector round-trips them (a `to_ids` attribute now exports **both** an Indicator
and an Observed Data, linked by a Relationship)
([OpenCTI docs](https://docs.opencti.io/latest/usage/data-model/),
[OpenCTI MISP connector](https://github.com/OpenCTI-Platform/connectors/blob/master/external-import/misp/README.md)).
The terminal pipeline stage reuses `shared/enrich/stix-evidence.js` verbatim to
emit, per detected event, that Observed Data object (and `toBundle` for the report
package) — so a user can hand a single self-exposure finding to a takedown request
or a SIEM. We do **not** re-encode STIX here.

## Live wiring (the last step, do not block on it)

1. Deploy / reference the two actors and set `actorId` in `ingest.config.json`.
2. Provide `APIFY_TOKEN`.
3. The client's `run-sync-get-dataset-items` request returns **real** dataset rows;
   `ingestRowsToBundle(plan, rows)` maps them to a STIX 2.1 bundle.

Until then everything dry-runs and the self-tests prove the fail-closed behavior
on real logic — never on fabricated scraped data.
