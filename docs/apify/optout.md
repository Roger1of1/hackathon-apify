# Data-broker opt-out (scope-gated, Apify-driven)

**Capability added this round:** a scope-gated **data-broker opt-out workflow** —
the one genuinely-unbuilt, market-proven self-protection pattern in the proposal —
plus a **CI aggregator** that finally runs the repo's orphaned module self-tests.

> Removing yourself from people-search / data-broker sites (Spokeo, Whitepages,
> BeenVerified, …) is the single most-recommended concrete self-protection step in
> consumer-privacy guidance (EFF, Privacy Rights Clearinghouse, the California
> *Delete Act* / DROP registry). A broker opt-out is the **literal opposite of
> stalking**: it is a first-person *"remove the listing about ME"* request, valid
> **only** for the subject's own listing.

Nothing here is deployed. All actor/task ids are placeholders; live-account wiring
is the last step. No listing data is fabricated.

---

## Files

| File | Role |
| --- | --- |
| `integrations/optout/optout-policy.js` | Pure input-builder: scope-gate-first → self-only → confirm real listings → emit STIX + erasure + propose paced re-check. |
| `integrations/optout/broker-registry.template.json` | **TEMPLATE** of known brokers' **public opt-out URL + method**. `is_template:true`. Contains **no listing/person data**. |
| `integrations/optout/_selftest.js` | Proves scope-gate-first, self-only refusal, template-honesty, reuse, and the paced re-check. |
| `integrations/run-module-selftests.js` | Aggregating CI runner that discovers & spawns every `*_selftest.js`. |

---

## The pipeline (fail-closed, first objection drops)

`buildOptOutPlan(input, opts)` runs an ordered guard chain; the first guard that
objects **drops the request and builds nothing**:

1. **Scope gate (Door 1).** Calls the **real `shared/scope.js` `validateScope()`**
   (read-only — Codex owns that file). A private-individual / stalking input is
   refused here, before any registry or listing logic. → `refusal: scope_rejected`.
2. **Self-only narrowing (Door 2).** Even an *accepted* scope is narrowed: a broker
   opt-out is permitted **only for `scope=self` or `scope=consented`** (a real,
   authorized data subject). `public_figure` / `brand` / `safety_evidence` are
   refused — you do not "delete" a third party from a broker.
   → `refusal: not_a_self_removal_scope`.
3. **Confirm real listings.** A "listing" exists **only** when a **real
   `module_event`** (from the existing detectors, fed by real WCC crawl output)
   has a `source_url` host matching a broker in the **template** registry. Empty /
   non-broker events → empty plan. → `refusal: no_confirmed_self_listings`.
4. **Build.** Per confirmed listing, emit a **STIX 2.1 Observed Data** object, a
   **GDPR Art.17 erasure** draft, the broker's **public opt-out route**, and a
   **proposed paced Apify re-check**.

`scopes_allowed_self_removal = ["self", "consented"]`.

---

## Reuse — not duplication

- **STIX 2.1 Observed Data** is produced by reusing
  `shared/enrich/stix-evidence.js` (`toObservedData` / `toBundle`) **verbatim**.
  The self-test asserts the emitted object **byte-matches** that module's output.
- **The erasure request** is produced by reusing `shared/aux/takedown-letter.js`
  (`buildTakedownPlan`). A broker host is **never** passed as an owned host, so the
  builder routes it to **GDPR erasure + CCPA delete + search de-index** — exactly a
  data-broker opt-out — as a clearly-labelled `is_template:true` draft.

---

## Re-check cadence (Closure-Mode-friendly)

A removed broker listing frequently **reappears** (brokers re-acquire data). The
healthy answer is not to refresh the page daily — it is a **paced, automated
re-check**:

- **Schedule.** `proposeRecheck()` derives a cron from the **real
  `integrations/schedules/cadence-policy.js`** (`evaluateCadence`), so the
  anti-compulsion floor applies: higher `distress_risk_score` → **slower** cadence,
  never faster. `scope=consented` is **not** auto-schedulable (the schedules policy
  restricts auto re-audit to `self|public_figure`), so consented opt-outs get a
  **manual** re-check recommendation instead of a cron — fail-closed.
- **Webhook.** Proposes an `ACTOR.RUN.SUCCEEDED` webhook
  (`integrations/webhooks`) that compares the new run's STIX Observed Data per
  `listing_url` against the prior run and **re-flags a reappeared listing**
  (a `number_observed++` / `last_observed` bump — STIX-style, not a duplicate
  identity).

Nothing is deployed; `recheck.schedule.deployed` and `recheck.webhook.deployed`
are `false`.

---

## Reference architecture #1 — OASIS STIX 2.1 Observed Data + OpenCTI/MISP interop

A confirmed broker listing is precisely a STIX 2.1 **Observed Data** SDO — *"the
raw data was observed at a particular time"* — here, the subject's PII observed
public on `broker.host` at time *T*, with `first_observed` / `last_observed` and a
content hash for tamper-evidence (OASIS STIX 2.1, §Observed Data). Emitting the
standard SDO makes the exposure **portable into OpenCTI/MISP** exactly as those
platforms round-trip bundles: MISP-STIX exports an Observed Data linked by a
Relationship, and OpenCTI workers ingest STIX 2.1 bundles
(`docs.opencti.io`, `github.com/OpenCTI-Platform/connectors`). The **re-check** is
the OpenCTI *"last_observed bump"* — a re-sighted observable is **updated, not
duplicated** — which is exactly how a reappeared listing is re-flagged here.

## Reference architecture #2 — Apify Website Content Crawler + RAG Web Browser

Detecting and **re-checking** a broker listing ingests through the **existing**
WCC/RAG path (`integrations/ingest`): `apify/website-content-crawler` crawls the
subject's **own** broker listing URL → clean text + `htmlUrl`/`screenshotUrl`
evidence handles + an `error` field on a failed page; `apify/rag-web-browser`
performs the dual-use **name-search discovery** step (allowed only for
`scope=self|public_figure`, enforced upstream). This module does **not**
re-implement crawling — it **consumes** the `module_event`s that
`integrations/ingest/ingest-policy.js` already produces from **real** WCC rows, and
proposes the actor + schedule that re-runs that same WCC ingest on a paced cadence.
`respectRobotsTxtFile` stays **forced on** and pages/depth clamped **down**
upstream (anti-evasion / anti-dragnet).

---

## CI aggregator — `integrations/run-module-selftests.js`

The default `npm test` (`test/run-compliance-tests.js`, owned by Codex) only
exercises the scope-rejection fixtures; it did **not** run the ~dozen real
`*_selftest.js` modules, so their green status was **unverified by CI**. The new
aggregator **discovers** every `*_selftest.js` in the repo (recursive `fs` walk,
skipping `node_modules`/`.git`/`web`/`demo`/`docs`) and **spawns each in its own
`node` process** (so one module's `process.exit` cannot mask another's), then
reports a single aggregate pass/fail. Finding **zero** tests is treated as a
failure (a CI guard that silently passes when it discovers nothing is worse than
useless).

It is **collision-safe**: it lives in `integrations/` (this agent's subtree), does
**not** modify `test/` or any self-test, and does **not** edit the shared
`package.json`. Wire it as a **new, additive** npm script (the one-line
operator/Codex step) without touching the existing `test` script:

```jsonc
// package.json → "scripts"
"test:modules": "node integrations/run-module-selftests.js"
```

Or run it directly:

```bash
node integrations/run-module-selftests.js
```

```
run-module-selftests: OK — all <N> module self-test(s) passed
```
