# The MCP whitelist IS the red line (protocol-layer enforcement)

MirrorTrace exposes its compliance planners to AI agents over the **Model Context
Protocol (MCP)**. The single design rule of `mcp/server.js`: an AI-agent caller
**must not be able to bypass the red lines**. This document explains the two
controls that make the MCP surface a wall, not a side-door.

---

## 1. The whitelist is the enforcement point

Apify's MCP server turns each **whitelisted** Actor's input schema into **one MCP
tool** an agent can call (the `--actors` flag locally, or the hosted scope chooser).
A tool that is **not** in the whitelist is **absent from `tools/list`** — so the
agent has **no tool to call**. We make that the red line:

> **Prohibited capabilities are absent by construction.** Private-social scraping,
> follower enumeration, people-search of strangers, reverse-phone lookup, live-
> location tracking, and romance/intimacy inference have **no tool** in `mcp/server.js`.
> There is no handler to reach.

This is stronger than a runtime check inside a handler: there is nothing to call.

### Made testable: the denylist + `assertWhitelistClean()`

"Absent by construction" is a guarantee only if it can't silently regress. So
`mcp/server.js` keeps an explicit **`DENYLISTED_ACTORS`** list (plus
`PROHIBITED_CAPABILITY_PATTERNS`) and:

- **`assertWhitelistClean()`** scans the exposed tool **identities** (names) and
  throws if any matches a denylisted capability or a prohibited-capability pattern.
- It runs **at module load** — requiring the server **fails closed** if the
  whitelist is ever dirtied (e.g. a future PR adds an `instagram-followers-scraper`
  tool). The server cannot start with a prohibited tool present.
- `mcp/server_selftest.js` proves: (a) no exposed tool is a denylisted capability,
  (b) a representative private-scraping tool (`private-social-scraper`) is **not
  callable**, and (c) adding a dirty tool makes `assertWhitelistClean()` throw.

> Note on scope: the guard flags the tool's **identity (name)**, not prose inside a
> description. Compliant tools legitimately *name* prohibited capabilities in order
> to **refuse or remediate** them — e.g. `plan_broker_optout` removes "people-search
> listings"; `compliance_docs` enumerates the red lines. Flagging descriptions would
> punish honesty. `isDenylistedActor(name)` is the helper an operator uses so they
> never pass a denylisted name to the real Apify MCP `--actors` flag.

---

## 2. Every gated tool fails closed through the canonical scope gate

The whitelist controls *which* tools exist; the **scope gate** controls what an
allowed tool will *do*. Every planner tool routes its subject through the **real**
`shared/scope.js` `validateScope()` **first** (`gateFor`), before touching any
planner. A prohibited `scope_type`, a laundered/stalking free-text prompt, or a
private-social host **fails closed** and returns the gate's own refusal — never a
result. It is the **same gate** the web path (`window.MirrorTrace.runPolicyGate`),
the Standby endpoint, and every actor use. The MCP surface is not a weaker door; it
is the same wall.

---

## 3. The exposed tool surface (compliant only)

| Tool | What it does | Red-line posture |
|---|---|---|
| `compliance_docs` | Read-only: allowed scopes, red lines, browser-only data flow, identity tiering, the denylist | Produces **no** footprint data; reaches no planner |
| `audit_scope_check` | Pre-flight: is this subject/intent in scope? Returns the gate decision only | Gate-only; never emits footprint data |
| `plan_broker_optout` | **Self-only** data-broker erasure plan (DeleteMe/Aura model) from listings the user confirmed | Gate + self-only; refuses public_figure/brand/other |
| `build_takedown_letter` | GDPR Art.17 / CCPA-delete erasure **template** from the user's own findings + STIX provenance | Gate-checked; sends nothing |

(Round directive surface: **policy-gate / report / opt-out / takedown / docs**.)

### Physically absent (the red line, by name)

```
instagram-followers-scraper        facebook-friends-scraper
instagram-private-profile-scraper  tiktok-follower-scraper
people-search                      person-locator
reverse-phone-lookup               romantic-interest-finder
live-location-tracker              private-social-scraper      stalkerware
```

None of these is a tool. An agent cannot call what does not exist.

---

## 4. Browser-only data flow (no central honeypot)

The MCP tools are **planners over the user's own confirmed inputs** — pure functions,
**zero network**, **zero fabricated data**. They produce plans/templates the user
acts on, never a scraped dossier. The exposure report/graph (Part 2) is built
**transiently in the browser** and **never persisted to a MirrorTrace server**
(see `docs/apify/exposure-map.md`). So even the *output* of a compliant audit never
becomes a server-side store of people's exposure data.

---

## 5. Operator deploy notes (last step)

- Wiring a **live transport** (Streamable HTTP — SSE was removed 2026-04-01;
  `mcp.apify.com`) and an **Apify token** is the operator's last step. Nothing here
  claims to be deployed.
- When configuring the real Apify MCP server's `--actors` whitelist, pass **only**
  the compliant first-party actors this product uses, and run every candidate name
  through `isDenylistedActor(name)` first.

## Refs (verified May 2026)

- Apify MCP server — input-schema → tool, whitelist/scope chooser:
  https://docs.apify.com/platform/integrations/mcp
- `apify/apify-mcp-server` (`--actors` whitelist; keep a small core tool set):
  https://github.com/apify/apify-mcp-server
- DeleteMe / Aura authorization-gated, self-only broker removal.
- GDPR Article 17 (Reg. (EU) 2016/679) RTBF erasure channel.
