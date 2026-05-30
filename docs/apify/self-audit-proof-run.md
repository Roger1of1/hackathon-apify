# Apify capability: Local Actor run → produced report (the end-to-end PROOF)

**Capability wired this round:** an **Apify CLI local-run / Crawlee local-dataset
shaped end-to-end run** that takes a captured-input fixture all the way to the
report the web dashboard renders — *proof over surface area*. No new Actor; this
deepens what already exists by closing the one confirmed gap: the web app fetched
`web/data/example-report.json`, but nothing produced it. Now a real run does.

> **No deploy claim.** Nothing here is deployed to the Apify platform. This is the
> *local* run contract (`apify run` against local storage) that the platform run
> mirrors 1:1, so live wiring is a last, mechanical step.

---

## What runs

```
node integrations/run-self-audit.js [--purge] [--quiet]
```

Pipeline (all REAL modules, no mocks):

```
integrations/fixtures/self-audit-fixture.json   (SYNTHETIC / TEMPLATE input)
        │
        ▼  shared/detectors/index.js  runDetectors()        ← real detectors
        ▼  shared/enrich/severity.js  rankBySeverity/batch   ← real enrichment
        ▼  integrations/grade/exposure-grade.js (read-only)  ← real A–F grade
        ▼  shape report
        ├─► web/data/example-report.json   (the file web/app.js already fetches)
        ├─► web/data/example-report.js     (file:// fallback → window.__MIRRORTRACE_REPORT__)
        ├─► integrations/storage/key_value_stores/default/INPUT.json   (Apify KVS)
        └─► integrations/storage/datasets/default/00000000N.json       (Crawlee rows)
```

The grade hero in the dashboard now shows a **real letter** computed from real
findings (current fixture → **F**, score 12/100). With no produced report present
(e.g. `file://` with fetch blocked and no JS fallback), the hero stays in its
honest **"no grade yet"** state — it never invents an "A".

## Why these on-disk artifacts (the two reference architectures)

### 1. Apify CLI local run — `apify run`
The CLI executes an Actor against **local storage**: the run's input is read from
the **default key-value store** at `storage/key_value_stores/default/INPUT.json`,
results are appended to the **default dataset**, and `--purge` clears local stores
before a run. The runner mirrors this exactly (`writeInput` → `INPUT.json` in a
default-KVS layout; `--purge` empties the local dirs), so the same fixture drops
into a real Actor's `INPUT.json` with zero reshaping.
- https://docs.apify.com/cli/docs/reference (`apify run`, `--purge`)
- https://docs.apify.com/platform/storage/key-value-store (`INPUT.json`, store id `default`)
- https://docs.apify.com/academy/deploying-your-code/inputs-outputs

### 2. Crawlee local Dataset + on-fixture (no-mock) testing
Crawlee's `Dataset.pushData(item)` writes each result row as a separate JSON file
under `{CRAWLEE_STORAGE_DIR}/datasets/default/{INDEX}.json`, and the default
dataset is auto-created. The runner writes one numbered JSON per **real finding**
in that same shape, so a third party can **recompute the grade from the published
rows** (a Frictionless/Datasette-style reproducibility property the grade module
already promises). The self-test borrows Crawlee/Apify's testing discipline:
drive the pipeline over a **real local sample, no mocks**, and assert on real
output.
- https://crawlee.dev/js/docs/introduction/saving-data (`Dataset.pushData`)
- https://crawlee.dev/js/api/core/class/Dataset (default dataset, local JSON rows)
- https://crawlee.dev/js/docs/guides/result-storage

## NO FAKE DATA — exactly where the line is

- The **only** invented content is the **input** fixture, clearly labelled
  `SYNTHETIC / TEMPLATE` and using reserved `.invalid` / `example.*` hosts that
  can never resolve. It is a stand-in for a *capture*, not for *results*.
- Every **finding** is the real output of `shared/detectors` over that fixture;
  every **deduction** is what `exposure-grade.js` computes from those findings.
  The self-test asserts each breakdown category traces to a real finding, the
  totals reconcile, and the run is deterministic.
- **No data ⇒ no grade.** An empty capture yields `grade:null` (not a default
  "A"). A non-`self` scope, or a stalking-shaped input, is **refused** by the real
  `shared/scope.js` gate and never graded.

## Compliance / red lines

- Grade is produced via `gradeForScopedRun`, which routes the input through the
  **real** `shared/scope.js`; only an allowed `scope_type=self` run is graded.
- Published finding rows carry **no raw PII value** — only
  `event_type / risk / visibility / confidence / source_url / severity_band`.
- This agent wrote **only** `integrations/**`, `docs/apify/**`. `shared/scope.js`
  and `exposure-grade.js` are required **read-only** (never rewritten).

## Verify

```
node integrations/run-self-audit.js --purge     # produce the report + local stores
node integrations/run-self-audit_selftest.js    # 28 assertions (determinism, traceability, no-data)
npm test && npm run test:modules                # full suites stay GREEN
```
