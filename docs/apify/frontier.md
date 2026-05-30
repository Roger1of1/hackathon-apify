# Apify Request Queue — the compliant self-audit "frontier"

**Capability added this round:** the Apify **Request Queue** — the platform's
server-side, *deduplicated, lockable, resumable* URL frontier. It is the one
managed-storage primitive the rest of the integrations had not yet wired
(ingest, standby, webhooks, schedules, exports, proxy, notify, mcp were already
covered). Nothing here is deployed: `queueId` is a placeholder, no network call
is made, no dedup result is fabricated.

| File | Role |
|---|---|
| `integrations/frontier/frontier.config.json` | TEMPLATE config: named-queue layout, caps, lock, forced robots override. No credentials. |
| `integrations/frontier/frontier-policy.js` | Pure, zero-I/O planner: scope-gate → canonicalize → dedup → cap → build request batch. |
| `integrations/frontier/frontier-client.js` | LIVE-or-DRY-RUN client: turns a plan into the exact Request Queue API descriptors; no token ⇒ dry run, no network. |
| `integrations/frontier/frontier_selftest.js` | 26 real assertions (auto-discovered by `npm run test:modules`). |

## Why a request queue is a *compliance* primitive here (not a perf trick)

A request queue is normally an engineering convenience. In a self-audit tool it
is a **red-line enforcer**:

- **`uniqueKey` dedup → minimum-disclosure.** Apify dedupes server-side on
  `uniqueKey`; a second add with a key already present returns the existing
  request and adds nothing. We set `uniqueKey` to the *canonicalized URL*, so the
  **same public surface is fetched at most once per audit** — we never re-pull a
  page we already hold.
- **`max_queue_size` → anti-dragnet.** The frontier is **bounded**. Once it holds
  the cap (200) of distinct surfaces, further enqueues are **refused** (clamped to
  zero), never grown. A self-audit reads a bounded own-surface; it does not crawl
  the open web.
- **Scope re-asserted at enqueue → the same chokepoint as ingest.** Every URL is
  routed through `shared/scope.js` `validateScope()` (read-only require) *before*
  it may enter the queue, and any host in `PRIVATE_SOCIAL_HOSTS` is **refused
  entry** (a second door behind the gate). A queue can never widen scope.
- **`lockSecs` head-and-lock → politeness, not evasion.** One client owns the head
  request for `lockSecs`, so two parallel crawl clients never hit the same surface
  at once. This **slows** concurrent pressure on a target host; `lockSecs` is
  clamped *down*, never up.
- **`respectRobotsTxtFile` forced true** in every request's `userData`, even if a
  caller tries to turn it off — the same anti-evasion floor as `ingest.config`
  and the proxy policy.

## Apify Request Queue API v2 (what the client builds, what the operator fires)

The client emits these descriptors but **does not send them** (dry run / no
deployed queue). Wiring the live token is a one-line change at the last deploy
step:

```
# 1) Create / get a NAMED queue (named queues persist; default queues are wiped per run)
POST https://api.apify.com/v2/request-queues?name={name}&token={APIFY_TOKEN}

# 2) Batch-add — ≤25 requests/call, server-side uniqueKey dedup
POST https://api.apify.com/v2/request-queues/{queueId}/requests/batch?token={APIFY_TOKEN}
body = [{ url, uniqueKey, method, userData }, ...]
# response.processedRequests[].wasAlreadyPresent is the REAL dedup signal

# 3) Head-and-lock — one client owns the head for lockSecs (politeness)
POST https://api.apify.com/v2/request-queues/{queueId}/head/lock?lockSecs={n}&token={APIFY_TOKEN}
```

Apify docs:
<https://docs.apify.com/platform/storage/request-queue>,
<https://docs.apify.com/api/v2/storage-request-queues>,
<https://docs.apify.com/api/v2/request-queue-requests-batch-post> (≤25/call),
<https://docs.apify.com/api/client/js/reference/class/RequestQueueClient>
(head-and-lock).

## Reference architectures — how a mature system wires a frontier

This round must cite **two** reference architectures; both are *frontier*
designs, so the borrow is concrete.

### Reference architecture #1 — Apify Request Queue (platform + API v2 client)
We borrow Apify's contracts verbatim rather than re-inventing a queue: the
`{ url, uniqueKey, method, userData }` request shape, **server-side uniqueKey
dedup** (`wasAlreadyPresent`/`wasAlreadyHandled`), the **≤25-per-call batch-add**
limit, and **head-and-lock with `lockSecs`** for single-flight politeness. The
client builds the exact descriptors that API would receive; it never simulates a
queue. Per Apify's own guidance, a **named** queue persists across runs while the
unnamed default queue is wiped per run — so we name one queue per audited subject
(carrying a non-reversible `subject_token`, never a raw label/URL) to isolate
each subject's frontier with no cross-subject bleed.

### Reference architecture #2 — Crawlee / Scrapy frontier + dupefilter
Crawlee's `RequestQueue` and Scrapy's scheduler both put a **deduped, resumable
frontier** at the centre of a polite crawl. A canonical request fingerprint
(Scrapy's `request_fingerprint`, Crawlee's default `uniqueKey` derivation)
guarantees each URL is scheduled exactly once, and a **bounded** scheduler plus
per-domain politeness throttle the crawl (Crawlee `maxRequestsPerCrawl`, Scrapy
`DEPTH_LIMIT` / `CLOSESPIDER_*` / `AUTOTHROTTLE`). We mirror that essence:
**canonicalize → fingerprint (`uniqueKey`) → bounded enqueue → polite head-lock.**
The one thing a generic crawler frontier does *not* have, and we add, is the
**scope gate at the mouth of the queue** — so this frontier is provably
*own-surface only*, not an open-web spider.
refs: <https://crawlee.dev/js/api/core/class/RequestQueue>,
<https://docs.scrapy.org/en/latest/topics/settings.html> (DUPEFILTER, DEPTH_LIMIT, AUTOTHROTTLE).

## No-fake-data stance

- No `APIFY_TOKEN` ⇒ the client **dry-runs**: it returns the API descriptors it
  *would* send with `usedNetwork:false`, `deployed:false`, and a redacted
  `<MISSING_APIFY_TOKEN>` token. It never claims a queue was created, never
  invents queue state, and never fabricates a `wasAlreadyPresent` flag — those
  only exist after a real call.
- A refused subject (prohibited scope, laundered stalking intent, or a
  private-social host) yields **zero** enqueueable requests and `descriptors:null`
  (fail-closed).

Verify: `node integrations/frontier/frontier_selftest.js` (26 checks) or
`npm run test:modules`.
