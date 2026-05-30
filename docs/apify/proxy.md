# Apify Proxy — compliant, availability-only policy

**Capability:** Apify Proxy (datacenter + residential groups, country targeting),
wired as an **availability-only** transport policy — never as an evasion tool.

**Status:** real config + real policy code + 29 self-tests. **NOT deployed.** No
credentials in the repo; `APIFY_PROXY_PASSWORD` / `APIFY_TOKEN` are supplied by the
operator at deploy time.

## Why a proxy at all (and why this is not a stalking feature)

A proxy is the single most-abused part of any crawler: it is the exact tool an
evasion/stalking pipeline reaches for to defeat IP bans, rate limits, geo walls,
and captcha. Ex-Ditector uses Apify Proxy for the **opposite** reason —
**availability only**:

- **IP diversity** so we are a polite, non-hammering client of a *public* page;
- **geo-correct rendering** of the **user's own** page as their region sees it.

It is never used to look "more human", to outlast a ban, or to get behind a login
wall. `integrations/proxy/proxy-policy.js` encodes that line and refuses anything
else *before any fetch*.

## Files

| File | Role |
| --- | --- |
| `integrations/proxy/proxy.config.json` | Declares allowed/denied groups, coarse geo allow-list, session limits, and the fail-closed `compliance_floor`. |
| `integrations/proxy/proxy-policy.js` | Pure, zero-I/O decision pipeline. `decideProxy()` + `classifyResponse()`. Reads the **real** `shared/scope.js` gate (read-only). |
| `integrations/proxy/proxy-client.js` | Dry-run-safe wrapper. `prepareProxy()` builds the live URL only when a credential is present; otherwise a redacted dry run, no network. |
| `integrations/proxy/_selftest.js` | 29 assertions. Run: `node integrations/proxy/_selftest.js`. |
| `docs/apify/proxy.md` | This doc. |

## The decision pipeline (ordered guards, fail-closed)

`decideProxy(input)` runs an **ordered guard pipeline**; the first guard that
objects **drops** the request and nothing downstream runs:

1. **scope gate** — the real `shared/scope.js validateScope` must accept the
   subject. A stalking / private-individual / romance-inference subject is
   dropped here, before any proxy is built.
2. **evasion gate** — any evasion intent (flags like `bypass_ban`,
   `solve_captcha`, `rotate_until_pass`, or free text like *"rotate until it stops
   blocking me"* / *"look more human"*) is a hard refusal.
3. **group gate** — denied groups (e.g. `GOOGLE_SERP`) refused; unknown groups
   refused.
4. **residential gate** — `RESIDENTIAL` is dual-use, so it is restricted to
   `scope=self|public_figure` **and** requires a written `geo_justification`.
   `consented` / `brand` / `safety_evidence` get **datacenter only**.
5. **geo gate** — country must be on a coarse allow-list; **US-state /
   subdivision targeting is disabled** (finer geo serves no availability purpose
   and edges toward profiling).
6. **build** — emit `{ useApifyProxy, apifyProxyGroups, apifyProxyCountry }` plus
   the `compliance_floor`.

Two doors, both must open: `validateScope` **and** this proxy policy.

## Reference architecture #1 — Crawlee / Scrapy proxy + session management

Crawlee's `ProxyConfiguration` rotates proxy URLs (round-robin, or sticky via a
`sessionId` so `newUrl(sessionId)` returns a stable IP), supports **tiered proxy
lists** that *upshift* to higher-quality proxies "whenever the crawler encounters
a problem with the current proxy on the given domain", and its `SessionPool`
**auto-retires** a session on `401/403/429` and swaps in a fresh IP to *keep
scraping*.

- Crawlee proxy management: <https://crawlee.dev/js/docs/guides/proxy-management>
- Tiered proxies (block-driven upshift): <https://crawlee.dev/blog/proxy-management-in-crawlee>
- Session management (retire on 401/403/429): <https://crawlee.dev/js/docs/guides/session-management>
- Scrapy item pipeline / `DropItem` (ordered components, any stage drops):
  <https://docs.scrapy.org/en/latest/topics/architecture.html>

**What we borrow:** the mechanics — `sessionId`-stable proxy URLs, block
detection, a group/tier ladder, the ordered-pipeline-with-drop pattern.

**The inversion that makes it compliant:** the same `401/403/429` that makes
Crawlee *retire-and-rotate to a fresh IP* makes **us** declare a
**`compliance_stop`** (`classifyResponse()` in `proxy-policy.js`). Detection
happens exactly like Crawlee; the **reflex is to stop**, never to chase a fresh
IP past a defense. The "tier ladder" here only steps datacenter → residential for
documented **geo-accuracy**, never to defeat a block. At most **one** retry, and
only for genuine transport faults (`ECONNRESET` / timeout / socket hangup) where
no block signal was present — a block status is never a retryable fault.

## Reference architecture #2 — Have I Been Pwned k-anonymity range query

HIBP carries the **minimum** identifying token off the client: only the first
**5 chars** of a SHA-1 hash are sent; the rest stays local and matching finishes
client-side, so the service learns the minimum.

- Troy Hunt on SHA-1 + k-anonymity:
  <https://www.troyhunt.com/understanding-have-i-been-pwneds-use-of-sha-1-and-k-anonymity/>

**What we borrow:** the **minimum-disclosure** stance for proxy *selection*. Geo
targeting is coarse (**country only**; US-state/subdivision deliberately
disabled), and any logged/returned proxy URL is **redacted** — password stripped,
only the k-anonymous `groups-…,country-…` visible (`buildRedactedProxyUrl()`).
The live credential is built in memory at fetch time and never logged. A proxy
decision should reveal the minimum, never become a tracking fingerprint.

## `compliance_floor` (fail-closed, enforced by the fetch layer)

| Field | Meaning |
| --- | --- |
| `retire_on_block: true` | A `401/403/407/429/451/503` is a **compliance stop** for that subject (human review), **not** a fresh-IP retry loop. |
| `max_proxy_retries: 1` | One retry, transport faults only; a block status is never retryable. |
| `honor_robots`, `honor_rate_limit_headers` | The crawler must obey robots/ToS and rate-limit headers. |
| `no_captcha_solving`, `no_login_walls` | Categorically off. |

## NO-FAKE-DATA & dry-run honesty

`prepareProxy()` never claims a fetch happened and never invents a response.
Without `APIFY_PROXY_PASSWORD` it returns `mode: "dry_run"` with the **redacted**
URL it *would* build, `usedNetwork: false`, and **no** usable proxy URL. A refused
request yields **no** proxy URL at all.

## Apify Proxy reference

- Proxy usage / `useApifyProxy`, `apifyProxyGroups`, `apifyProxyCountry`:
  <https://docs.apify.com/platform/proxy/usage>
- Residential proxy (`groups: ['RESIDENTIAL']`, `countryCode`):
  <https://docs.apify.com/platform/proxy/residential-proxy>
