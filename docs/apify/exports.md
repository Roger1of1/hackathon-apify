# Apify Dataset Views + Exports (compliant, marking-scoped)

This capability wires the Ex-Ditector evidence/capture datasets into Apify's
**dataset views** (the Console output-tab projection declared in
`.actor/actor.json`) and Apify's **dataset export API**
(`GET /v2/datasets/{id}/items` with `format` / `fields` / `omit` / `clean` /
`flatten`). It is the read/share side of the pipeline: how an audit result
LEAVES the platform.

Refs:
- Dataset schema / views: <https://docs.apify.com/platform/actors/development/actor-definition/dataset-schema>
- actor.json: <https://docs.apify.com/platform/actors/development/actor-definition/actor-json>
- Export items API: <https://docs.apify.com/api/v2/dataset-items-get>

## Why this is the next capability

Prior rounds wired **Webhooks** (is a SUCCEEDED run actually healthy?) and
**Schedules** (paced, anti-compulsion re-audits). Both produce data INTO
datasets. Nothing yet governs how that data comes back OUT. A raw evidence
dataset holds real public URLs, screenshot/HTML storage keys, status codes, and
case ids. Handing that verbatim to a third party (a shared link, a Slack/Make/n8n
relay, a CSV emailed to a friend) over-shares far past what the audit subject
consented to. So the export path needs a redaction chokepoint, and dataset views
give us a native place to declare the shareable projection.

## The one rule

**Raw locators never leave TLP:RED.** `url`, `html_key`, `screenshot_key`,
`note`, `subject_label`, `target_urls`, `authorization_evidence_url`,
`subject_token` are operator-only. Shareable bands (TLP:AMBER / TLP:GREEN) keep
only content/HTML **hashes**, coarse **status**, **change** flags, and
**timestamps** — enough to PROVE "a public page changed" without revealing
WHERE or a viewable artifact. This is also Closure-Mode-friendly: a shared
"something changed" summary has no clickable destination to spiral on.

Enforcement is fail-closed and double-walled:
1. Per-`(record_type, marking)` positive allow-list (`FIELD_POLICY`).
2. An independent `NEVER_SHARE_BELOW_RED` tripwire applied on top, so even a
   future mis-edit to an allow-list cannot leak a raw locator at a shareable
   marking.
3. The export `fields` sent to Apify are **derived** from policy, never trusted
   from the caller, and `omit` is also sent (Apify resolves `omit` over `fields`
   when they conflict — the tripwire wins server-side too).
4. Unknown marking / unknown record_type / unsupported format => refuse (empty
   or `{error}`), never widen to "all fields".

## Files

| File | Role |
|------|------|
| `integrations/exports/redaction-policy.js` | Marking bands + per-field allow-list + `redactRecord` / `exportQueryFor`. The compliance chokepoint. |
| `integrations/exports/dataset-views.config.json` | Declarative views (transformation + display) per actor, each tagged with a `marking`. |
| `integrations/exports/export-client.js` | Real `GET /v2/datasets/{id}/items` client. INERT (dry-run) without `APIFY_TOKEN`; re-redacts JSON rows client-side as a backstop. |
| `integrations/exports/sync-dataset-views.js` | Computes the merge of the config into each actor's `.actor/actor.json` `storages.dataset.views`. Dry-run by default; `--write` is an actor-owner action. |
| `integrations/exports/datapackage.js` | Portable **Frictionless Data Package** emitter. WRAPS `redaction-policy.js` and serializes the redacted rows into a self-contained `datapackage.json` + per-record-type CSV resources the subject OWNS. |
| `integrations/exports/test-exports.js` | Self-test (12 assertions). Lives here, not under `test/`. |
| `integrations/exports/test-datapackage.js` | Self-test for the package emitter (11 assertions). Lives here, not under `test/`. |

## Portable evidence package (Frictionless / Datasette) — the subject OWNS it

The export client streams a marking-scoped projection over the API. But the
product promise is stronger: the audit subject should be able to **walk away with
their evidence** in an open standard, not have it locked in a dashboard.
`datapackage.js` emits a [Frictionless Tabular Data Package](https://specs.frictionlessdata.io/data-package/):
a self-describing `datapackage.json` descriptor plus one tabular **CSV resource
per `record_type`**, each with a [Table Schema](https://specs.frictionlessdata.io/table-schema/)
of typed fields. It opens offline and imports unchanged into Datasette / SQLite /
pandas / OpenRefine.

It is the publish-side bookend to the redaction policy and **cannot widen it**:

- Every raw row is run through `redactRecord(row, marking)` first; a row that
  redacts to `null` is dropped (never half-emitted). At a non-RED marking the
  **Table Schema itself** is built from `allowedFields(type, marking)`, so it
  physically cannot name `url` / `html_key` / `screenshot_key` / `note`.
- **No fake data:** zero real rows ⇒ zero resources + an explicit
  `meta.note: "no findings — empty evidence package"`. No sample rows are injected.
- **Citable + reproducible (Datasette model):** the descriptor records provenance
  (`created`, marking, source dataset/actor id) and a deterministic
  `x-content-sha256` fingerprint over the whole bundle, so a citation pins an
  exact run. It can embed the **Self-Exposure Grade ledger** (see
  [grade.md](grade.md)) as its own resource, so a third party can re-derive the
  A–F letter from the published rows.
- **Pure + offline:** `buildDataPackage()` does no I/O and needs no token; an
  opt-in `writeDataPackage(pkg, outDir)` is the only thing that touches disk, and
  only when the caller passes an explicit directory.

```bash
# Build + inspect a portable package (pure, no token, no network)
node -e "const {buildDataPackage}=require('./integrations/exports/datapackage'); \
  const p=buildDataPackage([{record_type:'capture',case_id:'c1',url:'https://example.com/me',content_sha256:'a'.repeat(64),status_code:200,captured_at:'2026-05-30T00:00:00.000Z'}],{marking:'TLP:GREEN',now:'2026-05-30T00:00:00.000Z'}); \
  console.log(p.files['datapackage.json'])"

# Self-test
node integrations/exports/test-datapackage.js
```

Reference: Frictionless Data Package <https://specs.frictionlessdata.io/data-package/>,
Tabular Data Resource <https://specs.frictionlessdata.io/tabular-data-resource/>,
Datasette portable/citable publishing <https://datasette.io/>.

## Usage

```bash
# Preview the dataset views that would be merged into each actor.json
node integrations/exports/sync-dataset-views.js

# Apply them (actor-owner action; edits actors/*/.actor/actor.json)
node integrations/exports/sync-dataset-views.js --write

# Plan / perform a marking-scoped export (dry-run prints the exact request URL)
node integrations/exports/export-client.js <datasetId> TLP:GREEN csv
APIFY_TOKEN=... node integrations/exports/export-client.js <datasetId> TLP:GREEN json

# Self-test
node integrations/exports/test-exports.js
```

Without `APIFY_TOKEN`, `export-client.js` returns the exact request it WOULD
send and fetches nothing — no fabricated rows, honoring the no-fake-data rule.
This repo ships no credentials and asserts no deployment.

## Reference architectures borrowed

**OpenCTI / MISP + STIX evidence object model.** OpenCTI publishes knowledge
through TAXII 2.1 collections, each filtered to a subset and gated by
`marking-definition` (TLP) so a consumer only ever receives what their marking
allows — "data segregation" on the way out
(<https://docs.opencti.io/latest/deployment/connectors/>,
<https://medium.com/@julien.richard/opencti-data-sharing-6da7dc045d14>). MISP-STIX
similarly separates restricted raw **indicators** from more-shareable
**observable** fingerprints
(<https://www.misp-project.org/2026/03/16/misp-stix_indicator_and_observable_fingerprinting.html/>).
Our markings + per-marking views are exactly that pattern: raw locators stay
RED, observable **hashes** can travel to GREEN.

**Apify RAG Web Browser + Website Content Crawler.** Those actors deliberately
publish a thin, stable, typed projection of a crawl (`url`, `title`,
`markdown`/`content`, `crawled_at`) so a downstream RAG/vector pipeline reads a
predictable shape instead of the raw DOM
(<https://apify.com/apify/website-content-crawler/input-schema>,
<https://apify.com/apify/rag-web-browser/input-schema>). A dataset **view** is
that same "post-extraction, consumer-facing projection" contract — we expose a
pre-redacted view, never the wide internal capture record.
