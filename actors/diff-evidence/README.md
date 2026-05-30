# A5 — Diff & Evidence Index

Turns raw captures into a verifiable, change-only evidence index, then metamorphs
into the report builder.

## Behavior
- Loads this case's `capture` records from the inherited default dataset.
- For each URL, compares the current `content_sha256` against the last known
  value in the named baseline KV store `mirrortrace-baseline-<caseId>`.
- Emits an immutable evidence-index entry **only for real changes**:
  - `new` — first time we've seen this URL
  - `changed` — content hash differs from baseline
  - unchanged URLs are skipped entirely (no fabricated "activity")
- Each entry: `{ url, timestamp, content_sha256, html_sha256, screenshot_key, html_key, change }`.
- Updates the baseline to the current hashes so the **next** run diffs against today.
- Writes the full run index to `EVIDENCE_INDEX` in the case KV store for the report.

## Honesty
If the crawl was blocked/aborted and produced no captures, the index is empty and
the summary says so. Nothing is invented.

## Human config
- `REPORT_ACTOR_ID` env → `roger_1of1/mirrortrace-report-builder`.
