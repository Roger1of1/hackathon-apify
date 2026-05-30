# Apify Webhooks + Output-Health Receiver

**Capability added this round:** Apify run **Webhooks** wired to a real
**output-health receiver** — the piece that decides whether a finished run
actually produced trustworthy, compliant output before anyone is told their
audit is "ready".

> Status: **NOT deployed.** This repo ships no credentials. Every id/secret below
> is a placeholder the operator fills at deploy time.

---

## Why output-health, not just "succeeded"

Apify fires [`ACTOR.RUN.SUCCEEDED`](https://docs.apify.com/platform/integrations/webhooks/events)
when a run *process exits cleanly*. For this product that is **not** the same as
"the audit is real and complete". A run can exit `SUCCEEDED` while it:

- produced an **empty** dataset / missing `OUTPUT` (nothing was captured),
- emitted **only** `backoff_for_human_review` records — i.e. every source returned
  401/403/429 and the crawler **stopped instead of evading** (a *compliance
  outcome*, by design — see `actors/crawler/src/main.js`),
- produced a report whose required compliant score fields are missing/malformed.

Reporting any of those to the user as "your audit is ready" would be a quiet form
of **fake data** — the one thing this product must never do. So the webhook layer
adds an honesty gate: **success ≠ valid output.**

The verdict is computed by `integrations/webhooks/output-health.js`
(`evaluateOutputHealth`) and only ever rounds **down**:

| verdict | meaning | routed as |
| --- | --- | --- |
| `healthy` | real captures and/or well-formed report present | notify user: audit ready |
| `degraded` | real output **plus** some compliance backoffs | notify user: partial |
| `compliance_stop` | only backoff records — we stopped, no evasion | human review (takedown/data request) |
| `empty` | clean exit, nothing real produced | flag; **never** "ready" |
| `malformed` | output present but required score fields missing | human review |
| `failed` | run did not succeed | alert |
| `unknown` | could not inspect output | inspect manually (never guessed up) |

The required score fields are exactly those in `shared/scoring.js`
(`exposure_score`, `evidence_quality_score`, `actionability_score`,
`distress_risk_score`) — no foreign/romantic/intimacy scores are ever accepted.

---

## How a mature system wires this — two reference architectures

This design borrows concrete patterns from two well-known systems.

### SpiderFoot — typed events + a correlation pass
[SpiderFoot](https://github.com/smicallef/spiderfoot) automates OSINT with a
**publisher/subscriber, event-driven engine**: every discovered datum is a *typed
event*, modules subscribe only to event types they care about, and (since v4) a
declarative **correlation engine** reasons over the accumulated events to surface
patterns.

We mirror that shape at the *run* level instead of the *finding* level:
- `summarizeDataset()` buckets a run's dataset items by `record_type`
  (`capture` / `backoff_for_human_review` / `report` / …) — the same "type every
  finding" discipline SpiderFoot applies to OSINT events.
- `evaluateOutputHealth()` is a small **correlation pass** over those typed
  counts + the run status + OUTPUT shape, producing a single declarative verdict
  — analogous to a SpiderFoot correlation rule firing on a pattern of events.

### The Markup — Blacklight — a "show your work" inspector
[Blacklight](https://themarkup.org/blacklight) is a real-time privacy *inspector*:
it visits a site headless, runs a fixed battery of concrete tests, and **reports
exactly what it observed** (which trackers, who got the data) rather than a vague
score. ([How they built it](https://themarkup.org/blacklight/2020/09/22/how-we-built-a-real-time-privacy-inspector).)

We adopt that stance: every verdict carries `reasons[]` and `dataset_summary`
(the observed counts). A `healthy`/"ready" claim is therefore always **backed by
evidence** the user can see — never an unexplained green light. The same ethos
drives the web "self-exposure inspector" panel in `web/`.

---

## Components (in `integrations/webhooks/`)

| file | role |
| --- | --- |
| `output-health.js` | pure verdict engine (no deps); `evaluateOutputHealth`, `summarizeDataset`, `missingScoreFields` |
| `verify.js` | fail-closed auth: URL secret token + optional HMAC-SHA256 over the **raw** body (constant-time compare) |
| `receiver.js` | HTTP receiver (Node `http`, no deps): auth → idempotency → fetch artifacts → health → compliant routing |
| `register-webhooks.js` | idempotent `POST /v2/webhooks` registration (inert without `APIFY_TOKEN`; dry-runs by default) |
| `payload-template.json` | the Apify payload template (template vars per docs) |
| `webhooks.config.json` | the four webhooks this product expects |
| `test-output-health.js` | zero-dep tests for the above |

---

## Setup (operator)

1. **Run the receiver** (or fold `handleWebhook` into your own server):
   ```bash
   APIFY_WEBHOOK_SECRET=your-url-secret \
   APIFY_TOKEN=your-read-token \
   node integrations/webhooks/receiver.js
   # listens on :4477 at /apify-webhook/<secret>
   ```
   - No `APIFY_WEBHOOK_SECRET`/`APIFY_WEBHOOK_HMAC_SECRET` → **all requests
     rejected** (fail closed).
   - No `APIFY_TOKEN` → health is reported as `unknown`, never guessed up.

2. **Register the webhooks** (fill placeholders in `webhooks.config.json` first):
   ```bash
   APIFY_TOKEN=... WEBHOOK_RECEIVER_URL=https://your-host/apify-webhook/your-url-secret \
   node integrations/webhooks/register-webhooks.js
   ```
   Without a token (or with placeholders still present) it **dry-runs** and prints
   the exact `POST /v2/webhooks` body it would send — no live calls.

### Verification (how we trust the caller)
- **URL secret token** — Apify's documented method: register the target as
  `https://host/apify-webhook/<secret>`; the receiver only accepts a matching
  secret. (Per [Apify webhook docs](https://docs.apify.com/platform/integrations/webhooks/actions):
  *"include a secret token in the webhook URL so that only Apify can invoke it."*)
- **HMAC (optional, defense in depth)** — `HMAC-SHA256(rawBody, secret)`, compared
  constant-time. **Footgun honored:** the HMAC is computed on the **raw bytes**
  before any JSON parse; `receiver.js` passes the untouched `Buffer` to `verify.js`.

### Idempotency
Apify can deliver a webhook more than once and advises idempotent handlers. The
receiver dedupes on `X-Apify-Webhook-Dispatch-Id`; a duplicate returns
`{ ok: true, duplicate: true }` without re-processing. `register-webhooks.js`
uses a stable `idempotencyKey` per webhook so re-running updates rather than
duplicates.

---

## Event subscriptions

| event type | run status | our handling |
| --- | --- | --- |
| `ACTOR.RUN.SUCCEEDED` | `SUCCEEDED` | run output-health; only `healthy`/`degraded` reach the user |
| `ACTOR.RUN.FAILED` | `FAILED` | alert |
| `ACTOR.RUN.TIMED_OUT` | `TIMED-OUT` | alert + check for excessive compliance backoff |
| `ACTOR.RUN.ABORTED` | `ABORTED` | often a compliance STOP → human review, not failure-to-hide |

(Event-type names and the `TIMED-OUT` status spelling per
[Apify event docs](https://docs.apify.com/platform/integrations/webhooks/events).)

---

## Compliance notes
- The receiver **reads** run output to verify it; it performs **no** crawling and
  makes **no** inference about people. It only counts `record_type`s and checks
  the presence of the compliant score fields.
- `compliance_stop` is surfaced as a first-class, honest outcome — the product
  never papers over a 401/403/429 block, and never tells the user an audit
  "succeeded" when in fact every source told us to stop.
- Nothing here is deployed; it activates only with the operator's own
  `APIFY_TOKEN` and secrets.

## Tests
```bash
node --check integrations/webhooks/output-health.js
node integrations/webhooks/test-output-health.js
```
