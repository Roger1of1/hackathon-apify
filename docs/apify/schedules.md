# Apify Schedules — paced re-audit cadence (Closure Mode in cron)

**Capability added this round:** Apify [**Schedules**](https://docs.apify.com/platform/schedules)
— recurring, **rate-limited-by-design** re-audits of a user's own footprint (or a
genuine public figure), driven by a policy engine instead of a person hitting
refresh.

> Status: **NOT deployed.** This repo ships no credentials. Every id/secret/token
> in `schedules.config.json` is a `<PLACEHOLDER>` the operator fills at deploy
> time. `register-schedules.js` is inert (dry-run) without `APIFY_TOKEN`.

---

## Why schedules, and why they are *floors* not *triggers*

MirrorTrace's **Closure Mode** exists to **reduce compulsive checking**. The
healthy alternative to refreshing a search 40x/day is: the platform does **one
paced, low-frequency sweep** and the person gets a single digest. So our
scheduler is the inverse of a "run as often as possible" cron. It enforces a
**minimum spacing** between re-audits, and the more distress a person is in, the
**slower** we schedule — never faster.

Concretely (`integrations/schedules/cadence-policy.js`):

| cadence | minimum spacing | notes |
| --- | --- | --- |
| `closure` | weekly | the recommended healthy default |
| `weekly` | weekly | |
| `daily` / `business_daily` | daily | a ceiling, not a target |

There is **no hourly / minutely / "realtime" option** — those cadences are
*rejected*, by design. Apify's own minimum interval is 1 minute; our product
minimum is daily-or-slower.

**Anti-compulsion floor.** `distressFloorMinutes()` maps
`distress_risk_score` (one of the compliant scores in `shared/scoring.js`) to a
minimum spacing: high distress (≥0.66) ⇒ at most every **2 weeks**; medium ⇒
weekly; low ⇒ daily. The effective interval is always the **slower** of
(requested cadence, distress floor).

---

## Scope gate — recurring monitoring is dual-use, so it fails closed

A schedule that quietly re-watches someone on a timer is a textbook dual-use
risk. We therefore restrict **scheduling** to the same chokepoint the rest of the
product uses for dual-use techniques:

```
SCHEDULABLE_SCOPES = ['self', 'public_figure']
```

`consented`, `brand`, and `safety_evidence` are valid `scope_type`s elsewhere but
**cannot be auto-scheduled** here: consented/brand runs are human-initiated;
safety-evidence preservation is event-driven and human-reviewed, never a cron.
`evaluateCadence()` is fail-closed — an unknown or non-schedulable scope returns
`{ allowed:false }` and **no cron is generated**. At run time the actor still
passes the real `shared/scope.js` `validateScope` gate: **two doors, both must
open.**

---

## How a mature system wires this — two reference architectures

### Scrapy / Crawlee — ordered pipeline + middleware that can DROP
Scrapy processes every scraped item through an **ordered chain** of components,
and any **Item Pipeline** stage may `raise DropItem` so the item never reaches
persistence; spider/downloader **middlewares** are sorted by a numeric `order`
and run as a fixed, declarative chain
([architecture](https://docs.scrapy.org/en/latest/topics/architecture.html),
[spider middleware](https://docs.scrapy.org/en/latest/topics/spider-middleware.html)).

We mirror that shape twice:
- `evaluateCadence()` is an **ordered guard pipeline** — scope-gate → known-cadence
  → distress floor → platform floor → cron build. The **first stage that objects
  DROPS the schedule** (`{allowed:false}`) and nothing downstream runs, including
  cron generation. A short-circuiting middleware, applied to *scheduling*.
- `register-schedules.js` re-runs every config entry back through that pipeline
  before any `POST /v2/schedules` — so a hand-edited `schedules.config.json` is
  treated like a spider's raw output that the **item pipeline can still reject**.
  The cron is **always re-derived from policy**, never trusted from the file.

### Have I Been Pwned — k-anonymity (carry the minimum token, not the identity)
HIBP's range-query model never accepts a full secret: the client sends only the
**first 5 characters of a SHA-1 hash** and finishes matching locally, so the
service learns the minimum
([Troy Hunt on SHA-1 + k-anonymity](https://www.troyhunt.com/understanding-have-i-been-pwneds-use-of-sha-1-and-k-anonymity/),
[Cloudflare](https://blog.cloudflare.com/validating-leaked-passwords-with-k-anonymity/)).

We borrow that stance for **schedule naming**. A schedule is a long-lived,
operator-visible object; naming it after a person would turn the scheduler into a
dossier. `safeScheduleName()` therefore accepts only a **short, non-identifying
`subject_token`** (e.g. a 5-char hash prefix) and **rejects** anything that looks
like an email, a long handle, or a name. Schedules carry the minimum token,
never the identity.

---

## Components (in `integrations/schedules/`)

| file | role |
| --- | --- |
| `cadence-policy.js` | pure, zero-dep policy engine; `evaluateCadence`, `distressFloorMinutes`, `buildCron`, `safeScheduleName` |
| `schedules.config.json` | TEMPLATE of expected schedules (placeholders only; cron shown for review is generated, not hand-typed) |
| `register-schedules.js` | idempotent `POST /v2/schedules`; re-validates cadence via policy; dry-runs without a token |
| `test-schedules.js` | zero-dep tests (scope gate, no-high-frequency, distress floor, k-anon naming, cron determinism) |

## Apify platform constraints honored
- Standard **5-field cron**, minimum interval 1 minute (we stay far above it).
- Each schedule may reference **at most 10 actors + 10 tasks**
  ([Apify schedule limits](https://docs.apify.com/platform/schedules)).
- `timezone: "UTC"`, `isExclusive: true` (no overlapping re-audit runs).

## Setup (operator)
1. Fill `schedules.config.json`: replace `<EX_DITECTOR_*_TASK_ID>` with your real
   Actor **task** ids and `<SUBJECT_TOKEN>` with a short non-identifying token.
2. Register:
   ```bash
   APIFY_TOKEN=... node integrations/schedules/register-schedules.js
   ```
   Without a token (or with placeholders present) it **dry-runs** and prints the
   exact `POST /v2/schedules` body + the policy-derived cron and floor.

## Compliance notes
- No high-frequency / "realtime" cadence exists; higher distress ⇒ slower.
- Only `self` / `public_figure` may be scheduled; everything else fails closed.
- No identity in schedule names (k-anonymous token only).
- **No fake data:** the scheduler creates no runs and fabricates no results; it
  only emits validated schedule definitions. Nothing here is deployed.

## Tests
```bash
node --check integrations/schedules/cadence-policy.js
node integrations/schedules/test-schedules.js
```
