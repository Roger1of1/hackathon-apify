# A6 — Report Builder

The terminal stage. Renders the audit in three formats and stores them in the
case KV store.

## Outputs (named keys in `ex-ditector-case`)
- `report.md` — Obsidian-flavored Markdown (frontmatter, callouts, per-item sections)
- `report.csv` — one row per evidence item
- `report.json` / `REPORT` — full machine-readable bundle
- `OUTPUT` (run default KV) — same JSON bundle for the run

## Scoring (compliant only)
Uses **only** `shared/scoring.js`:
- `exposure_score` — how discoverable the footprint is
- `evidence_quality_score` — how defensible/preservable the evidence is
- `actionability_score` — how much the user can do about it
- `distress_risk_score` — wellbeing signal for compulsive checking

There is **no** romantic/jealousy/availability score — the scoring module does
not expose one, so it cannot be rendered.

## Closure Mode
When `distress_risk_score >= 50`, the Markdown report includes a **Closure Mode**
callout: a wellbeing intervention nudging the user toward scheduled reads instead
of compulsive manual checking — the product's stated anti-compulsion purpose.

## Honesty
Every number derives from real captured/diffed data. An empty crawl yields an
empty index and the report says so; a backed-off crawl is flagged.
