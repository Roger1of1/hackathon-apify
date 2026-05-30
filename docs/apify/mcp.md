# Apify MCP tool-server — the gate-enforcing AI-agent surface

**Capability wired this round:** a real, tested **MCP tool registry/dispatcher**
(`mcp/server.js`) that exposes the product's existing
compliance planners to AI agents as a small set of tools — and forces every one
of those tools through the same canonical scope gate that guards the web and
actor paths. It is the one untouched first-class Apify surface, now wired with
**zero duplication and zero new subsystem**.

- Registry/dispatcher: [`mcp/server.js`](../../mcp/server.js)
- Self-test (auto-discovered by `npm run test:modules`): [`mcp/server_selftest.js`](../../mcp/server_selftest.js)
- Remote client config (whitelist): [`mcp/client-config.example.json`](../../mcp/client-config.example.json)
- Configurator notes: [`mcp/configurator-notes.md`](../../mcp/configurator-notes.md)

> **Not deployed.** `deployed: false`. There is no live transport, no Apify token,
> and no network call in this layer. Wiring a live Streamable-HTTP transport + an
> Apify token is the operator's **last** step.

---

## Why this, and why it is safe

The hard requirement: **an AI-agent caller must not be able to bypass the red
lines through the tool layer.** An agent that can call tools is exactly the actor
most likely to launder a stalking request ("just look up this person for me").

So every tool handler does the same thing the web button and every actor do:

1. **Gate first.** The handler calls the **real** `validateScope()` from
   [`shared/scope.js`](../../shared/scope.js) (read-only `require`, never
   rewritten) *before* it touches a planner. The gate runs the scope_type
   allow-list, the natural-language **intent scan** (catches laundered/stalking
   `freeText` under an innocent `scope_type`), and the private-social-host block.
2. **Fail closed.** On any refusal the tool returns the gate's *own* refusal
   payload (`reasons` / `violated_red_lines` / `alternatives`) with
   `refused_by: "shared/scope.js::validateScope"` — **never** a result. No planner
   runs; no data is produced.
3. **Reuse, never re-implement.** On a pass it calls the existing planner and
   returns its output **unchanged**. The self-test asserts the server's output is
   byte-identical to calling the planner directly — proof of reuse, not a copy.

This server is the **local, gate-enforcing counterpart** of the remote Apify MCP
server's `?tools=` whitelist: the whitelist keeps private-scraping *actors*
physically uncallable; this server keeps prohibited *intent* uncallable.

## The three tools

| Tool | What it does | Gate behaviour |
|---|---|---|
| `audit_scope_check` | Pre-flight: returns the scope-gate decision **only** — never any footprint data. Call it first to self-check a subject/intent. | Rejects prohibited scope_type, laundered stalking `freeText`, private-social hosts. |
| `plan_broker_optout` | **Self-only** data-broker opt-out plan (DeleteMe/Aura pattern) over the user's **confirmed** listings → STIX 2.1 record + GDPR Art.17 erasure draft + paced re-check proposal. Reuses `buildBrokerOptOutPlan`. | Gate front-door **and** the planner's internal self-only rule: `public_figure` / `brand` / another person is refused (`broker_optout_requires_self`). |
| `build_takedown_letter` | GDPR Art.17 RTBF / CCPA-delete erasure letters (a **template**, nothing sent) + a STIX 2.1 evidence bundle, from the user's **own** findings. Reuses `buildTakedownPlan` + `toBundle`. | Gate front-door (scope + intent + host). |

Each tool declares a JSON-Schema `inputSchema`, matching the Apify-MCP contract so
an agent knows the exact arguments and return shape. `listTools()` ↔ `tools/list`;
`callTool(name, args)` ↔ `tools/call`; an unknown tool **fails closed**.

---

## Reference architectures we borrowed from

A mature system does not invent a bespoke "let an AI call our tools" surface — it
mirrors how the proven products gate first-person remediation, and how the
platform exposes tools to agents.

### 1) DeleteMe / Aura — data-broker opt-out workflow → `plan_broker_optout`

DeleteMe and Aura both gate every removal on two things we copied exactly:

- **Explicit authorization, self-only.** You authorize the service to act *on your
  behalf*, and it only ever removes **the subscriber's own** record — you cannot
  opt a third party out of a broker. We mirror this: `plan_broker_optout` is
  `scope_type` **self only** (or `consented` *with* `authorization_evidence_url`
  — the DeleteMe "authorization" step). A `public_figure` subject *passes the
  generic gate* yet is **still refused** by the planner's self-only rule, which
  the self-test proves.
- **Scan → confirm → opt-out, then re-check on reappearance.** DeleteMe scans,
  surfaces matches, files opt-outs, and re-runs every cycle because brokers
  re-list. We never scrape brokers to *discover* listings; the plan acts only on
  listings the user **confirmed are about them**, and proposes a *paced*
  reappearance re-check (slowest cadence — anti-compulsion), not a daily scrape.

  Sources: [Aura data-removal service](https://www.aura.com/data-removal-service),
  [DeleteMe vs. Aura (Security.org)](https://www.security.org/data-removal/deleteme-vs-aura/).

### 2) GDPR Article 17 — Right to be Forgotten erasure automation → `build_takedown_letter`

A first-person erasure is a **data-subject request** sent to the third-party
controller (the broker / host) under **GDPR Art.17 (Reg. (EU) 2016/679)**.
`build_takedown_letter` and the `erasure_plan` inside `plan_broker_optout` reuse
[`shared/aux/takedown-letter.js`](../../shared/aux/takedown-letter.js), which —
with `ownedHosts` left empty so a broker is never mistaken for a surface the user
controls — routes a third-party host to the **Art.17 + CCPA-delete + de-index**
channel. The letter is an explicit **template** the user verifies and sends; this
server sends nothing, and attaches a STIX 2.1 bundle for erasure-request
provenance.

### 3) Apify MCP server — how the platform exposes tools to agents

The Apify MCP server loads each Actor's input schema and turns it into one MCP
tool, so the agent knows the exact arguments and return; the `?tools=` query
parameter whitelists which actors an agent may call (our compliance control), and
transport moved **SSE → Streamable HTTP on 2026-04-01**. This server follows the
same contract (`inputSchema` per tool, `tools/list` / `tools/call`) as the local,
gate-enforcing counterpart of that remote whitelist.

  Sources: [Apify MCP server docs](https://docs.apify.com/platform/integrations/mcp),
  [apify/apify-mcp-server (GitHub)](https://github.com/apify/apify-mcp-server).

---

## What the self-test proves (`mcp/server_selftest.js`, 17 checks, green)

1. **Fail closed on prohibited scope_type** — every tool rejects e.g. `private_person_tracking`.
2. **Fail closed on laundered / stalking `freeText`** — innocent `scope_type:"self"`
   + a stalking prompt is rejected by the intent scan (same as the web path).
3. **Private-social host blocked** — even with a clean `scope_type`.
4. **Self-only for broker opt-out** — `public_figure` (which *passes* the generic
   gate) is still refused by the reused planner (`broker-optout.js`).
5. **Consented without `authorization_evidence_url`** is refused.
6. **Reuse, not re-implement** — refusal payload is byte-identical to
   `validateScope()`; happy-path output is byte-identical to the planners.
7. **`audit_scope_check` never emits footprint data** — decision keys only.

Run it standalone: `node mcp/server_selftest.js`. It is auto-discovered by
[`integrations/run-module-selftests.js`](../../integrations/run-module-selftests.js)
(globs `*_selftest.js`) and therefore by `npm run test:modules`.

## Connecting (operator, last step)

Use the remote Apify MCP endpoint with the **compliance whitelist** from
[`mcp/client-config.example.json`](../../mcp/client-config.example.json): only
compliant actors are listed in `?tools=`, so private-scraping actors are
physically uncallable. The local `mcp/server.js` registry is the gate-enforcing
layer for the product's own planners — wire a Streamable-HTTP / stdio transport
adapter to `listTools()` / `callTool()` when going live.
