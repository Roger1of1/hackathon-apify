# Compliant Notification Dispatch — Slack / Make / n8n / Zapier (Closure Mode in the last mile)

This wires in the **Apify native Integrations** capability: an actor/task can fan
a run event (`ACTOR.RUN.SUCCEEDED` / `FAILED` / `TIMED_OUT` / `ABORTED`) out to
**Slack, Make.com, n8n, Zapier, or a generic HTTP webhook**, each with a
Handlebars message template over the run document
([Slack](https://docs.apify.com/platform/integrations/slack),
[Zapier](https://docs.apify.com/platform/integrations/zapier),
[n8n](https://docs.apify.com/platform/integrations/n8n),
[Make](https://docs.apify.com/platform/integrations/make)).
This is the **last mile**: how an audit result actually leaves Apify and reaches
a human.

For a normal scraper you'd template `{{resource.defaultDatasetId}}` into a Slack
message with a clickable Console link. For **this** product that is actively
harmful, so the dispatch goes through a policy chokepoint instead.

Files:

| File | Role |
|------|------|
| `integrations/notify/notify-policy.js` | The pure decision engine. `decideNotification(req)` returns a frozen `dispatch`/`payload` decision. |
| `integrations/notify/notify.config.json` | Template: per-platform Apify Integration config + the channel-agnostic payload contract. |
| `integrations/notify/_selftest.js` | Self-test (auto-discovered by `run-module-selftests.js`). |

## Why a chokepoint (the two dangers)

1. **Leak.** The run document + dataset carry raw locators (public URLs,
   screenshot/html storage keys, subject labels). Piping them verbatim into a
   Slack channel or a Zapier "email this to a friend" zap leaks more than the
   subject consented to.
2. **Compulsion.** The product's core identity is **Closure Mode** — reduce
   compulsive checking. A real-time *"🔴 new change, click here"* ping is a
   slot-machine notification, the exact dopamine loop we exist to break.

`decideNotification()` enforces both, and **re-uses** existing modules rather than
re-implementing policy:

- **No leak** → `integrations/exports/redaction-policy.js`. Every change row is
  run through `redactRecord(row, marking)`. External channels default to
  **TLP:GREEN** (the widest / least-trusting band) and **TLP:RED is refused
  outright** to any external sink, so `url` / `html_key` / `screenshot_key` /
  `subject_label` physically cannot leave the platform. What *does* leave is a
  thin **prove-it-changed** shape: a content hash, a change flag, a coarse status,
  a timestamp — never a *where*.
- **Success ≠ announcement** → `integrations/webhooks/output-health.js`. We only
  ever announce "ready" when the run produced real, healthy output. An
  EMPTY / MALFORMED / FAILED / COMPLIANCE-STOP run yields `kind:"not_ready"` (or
  `"compliance_stop"`) and **`dispatch:false`** — never a fake "your audit is
  ready". This is the **NO-FAKE-DATA** rule in the notification layer.
- **Anti-compulsion pacing** → `integrations/schedules/cadence-policy.js`. The
  minimum gap between notifications is the same distress-aware floor that paces
  re-audits: there is **no high-frequency option**, and a higher
  `distress_risk_score` makes the floor **slower, never faster**. A second send
  inside the floor is **suppressed** (`dispatch:false`, with `suppressed_until`).

## Reference architectures borrowed

**Mozilla HTTP Observatory / SecurityHeaders** — Observatory does not ping you on
every header change; it reports a single stable **letter** you act on and *shows
its work* rather than nagging
([scoring](https://developer.mozilla.org/en-US/observatory/docs/tests_and_scoring),
[SecurityHeaders](https://securityheaders.com/)). We mirror that: the
notification headline is the **Self-Exposure grade letter** plus a count of what
changed — a calm digest, not a stream of per-event alarms.

**GOV.UK Design System** — the green notification banner confirms *"the thing you
were expecting has happened"*, and the guidance explicitly says to use
notifications **sparingly** because people miss and tire of frequent ones;
reassurance and *"what happens next"* beat raw alerts
([notification banner](https://design-system.service.gov.uk/components/notification-banner/),
[confirmation pages](https://design-system.service.gov.uk/patterns/confirmation-pages/)).
We adopt that voice: the **default and most common** notification is a calm
*"no change — nothing to do"*; a change notification states plainly **what** and
**what-next**, with **no clickable target** (`payload.clickable_target` is always
`null`).

## The four notification kinds

| Kind | When | Voice |
|------|------|-------|
| `no_change` | healthy run, nothing changed | reassurance: *"looks the same — nothing to do, you don't need to keep checking"* |
| `digest` | healthy run, N changes | calm digest: *"N items changed; review when you have a quiet moment — no rush, not an emergency"* |
| `compliance_stop` | a source blocked us (401/403/429) | *"paused for human review by design; no automated retry will hammer it"* |
| `not_ready` | empty / malformed / failed output | **not dispatched**; we never announce a result that isn't real |

## What never dispatches (fail-closed)

- run output health is empty / malformed / failed / unknown,
- scope is not auto-schedulable (consented / brand / safety_evidence),
- inside the distress-aware anti-compulsion floor since the last notification,
- `TLP:RED` to an external channel,
- unknown channel or unknown marking.

## How an operator wires it (the LAST step)

1. On the **report-builder** actor/task, add an Apify **Slack/Make/n8n/Zapier**
   integration for `ACTOR.RUN.SUCCEEDED`.
2. Have the integration call `decideNotification()` (in a tiny glue actor or an
   n8n Function node) with the run's `{status, eventType, datasetItems, output}`,
   the subject's `scope_type` + `distress_risk_score`, the `last_notified_at`, the
   `grade` letter, and the REAL change rows.
3. Dispatch the returned `payload` **only if** `dispatch === true`. Map
   `payload.title / text / what_next / grade / change_count` onto the platform's
   message; **do not** add a Console/dataset link.

No credentials live here; nothing is auto-deployed (`deployed:false`).
`decideNotification()` performs **no network I/O** and **fabricates no data** — it
only shapes a payload from real inputs, and given a bad/empty run it refuses to
announce anything.
