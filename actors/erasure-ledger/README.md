# Ex-Ditector AUX — Erasure-Request Ledger / Removal Tracker

The piece that makes removal requests **actionable over time**. The other aux
actors *draft* the requests:

- `actors/takedown-generator` → GDPR Art.17 erasure / CCPA delete / de-index letters
- `actors/broker-optout` → data-broker opt-out routes

This actor turns those drafted requests into a single **trackable ledger** — one
row per request — and answers the two questions the subject actually has next:

1. **"When is the controller legally overdue?"** It computes the statutory
   response deadline from the date you actually submitted the request.
2. **"When should I check back?"** It gives **one** scheduled re-check date per
   request (the day after the legal deadline), so you verify removal on the
   deadline instead of compulsively re-checking — **Closure Mode**.

## What it is NOT

It fetches nothing, analyses no third party, and invents no outcome. A row is
marked `removed` **only** when a later re-scan (a different actor) confirms the
exposure is gone — never by this actor. No findings in → empty ledger out.

## Compliance boundary

- **Scope gate first.** Every run routes through `shared/scope.js` `validateScope`
  and is then restricted to `scope_type ∈ {self, public_figure}`. Tracking your
  *own* removals is inherently first-person; we fail **closed** for any other
  scope, and the gate's free-text laundering scan runs over `subject_label`, so a
  laundered intent ("track my ex's removals") is rejected exactly as the web and
  other actor paths reject it.
- The `scope_type` enum in `input_schema.json` deliberately **omits**
  `consented`, `brand`, and `safety_evidence` — they cannot run this actor.
- **NO FAKE DATA.** Deadlines are deterministic date arithmetic from a real
  `submitted_at` you supply; with no submission date the clock is honestly marked
  `clock_started: false`. The whole ledger is `is_template: true` and nothing is
  sent, scheduled, or removed automatically.

## Reuse (zero duplication)

`src/main.js` calls `shared/aux/erasure-ledger.js#buildErasureLedger`, which
**reuses** `shared/aux/takedown-letter.js#buildTakedownPlan` to derive the
requests. This actor does not re-implement letter drafting, statute selection, or
event clustering. It can also fold in a previously-produced `broker_optout_plan`
(read from a KV store) whose erasure letters share the same packet shape.

## Statutory clocks (the real legal windows)

| Request kind   | Respond window | Extension | Basis |
| -------------- | -------------- | --------- | ----- |
| `gdpr_erasure` | 30 days        | +60 days  | GDPR Art. 12(3): without undue delay, within one month; extendable by two further months. Overdue → Art. 77 (supervisory authority) / Art. 79 (judicial remedy). |
| `ccpa_delete`  | 45 days        | +45 days  | Cal. Civ. Code §1798.130: respond within 45 days; extendable by a further 45. |
| `search_deindex` | — (policy) | —         | Provider policy process, not a statute → no statutory clock; gets a calm 30-day calendar re-check. |

## Input (see `input_schema.json`)

- `scope_type` — **`self` or `public_figure` only.**
- `events` / `findings_dataset_name` — the subject's real `module_events`.
- `submitted_at` — map of `{ "<host>|<request_kind>": "<ISO date>" }`; only real
  dates start a statutory clock.
- `broker_plan_store_name` / `broker_plan_key` — optional KV source for a
  `broker_optout_plan` to fold in.
- `owned_hosts`, `subject_name`, `subject_label`, `case_id`, `case_store_name`.

## Output

- One `erasure_ledger_row` dataset record per request (status, `deadline`,
  `recheck_on`).
- One `erasure_ledger_summary` record with `request_count`, `overdue_count`,
  `next_recheck_on`, and a **template** Apify re-scan `recheck_schedule_proposal`.
- A KV snapshot `ERASURE_LEDGER`.

## Reference patterns applied

- **DeleteMe / Aura data-broker opt-out workflow** — the consolidated removal
  dashboard: one row per request with a status lifecycle and a scheduled re-check
  cadence, so the subject tracks every removal in one place instead of manually
  re-checking each site.
- **GDPR Article 17 (Right to be Forgotten) erasure-request automation** — the
  statutory deadline clock surfaced when a request is logged (Art.12(3) one month
  +2; CCPA/CPRA §1798.130 45 days +45), with the Art.77/79 escalation when overdue.

## Run / verify

```sh
# Pure-logic self-test for the underlying module (no Apify runtime needed):
node shared/aux/erasure-ledger_selftest.js

# Syntax check:
node --check actors/erasure-ledger/src/main.js
```
