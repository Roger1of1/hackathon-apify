# Apify Actor Standby + Metamorph — the gate as a real-time API

**Capability added this round:** Apify
[**Actor Standby**](https://docs.apify.com/platform/actors/development/programming-interface/standby)
(run an Actor as a real-time HTTP API) wired together with
[**Metamorph**](https://docs.apify.com/platform/actors/development/programming-interface/metamorph)
(transform one run into the next Actor, in the **same** run, preserving storages).

Together these turn the **policy gate** into a warm, real-time front door: hand it
**one** subject over HTTP, it runs the **real** scope gate, and only on a pass does
the run **metamorph** into the audit pipeline. A rejected subject returns `HTTP 403`
with legal alternatives and **never** starts a run.

> Status: **NOT deployed.** This repo ships no credentials. `apify.metamorph`
> fires only on the platform (`APIFY_IS_AT_HOME=1`) against a real target
> `actorId`; every id in `chain.config.json` is a `<PLACEHOLDER>`. Off-platform
> the endpoint returns the **plan** with `started:false` and performs no side
> effect — no fabricated runs (NO-FAKE-DATA).

---

## Files

| File | Role |
| --- | --- |
| `integrations/standby/server.js` | Real zero-dep `http` Standby server. Routes `GET /`, `GET /healthz` (readiness probe), `POST /inspect`. Lazily requires the `apify` SDK and metamorphs only on-platform. |
| `integrations/standby/chain-policy.js` | Pure decision layer. `planMetamorph(input)` → `reject` \| `metamorph` \| `complete`. Reads the **real** `shared/scope.js`. |
| `integrations/standby/chain.config.json` | The metamorph DAG: `policy-gate → discovery → crawler → diff-evidence → report-builder`. Single entry; every stage `reasserts_scope`. |
| `integrations/standby/client.js` | Calls `/inspect`; dry-runs (local plan, no request) without `APIFY_STANDBY_URL`. |
| `integrations/standby/test-standby.js` | Zero-dep tests, incl. a live in-process server. `node integrations/standby/test-standby.js`. |

---

## How a mature system wires this — the two reference architectures

### SpiderFoot — OSINT module graph + correlation/edge gating

[SpiderFoot](https://github.com/smicallef/spiderfoot) is built as a **graph of
modules** where each module declares what event types it consumes and produces,
and the engine only lets data flow along permitted edges — a module never runs on
data it is not entitled to consume. We apply that exact property to **actor
chaining**:

- `chain.config.json` is the module graph. The metamorph edges
  (`metamorph_to`) are the only permitted flows between stages.
- The "gate between modules" is `validateScope`, and crucially it is
  **re-asserted on every hop** (`reasserts_scope: true` on each stage; the
  forwarded payload carries `scope_type` so a stage that finds it missing fails
  closed). A metamorph can therefore never smuggle a subject downstream that an
  earlier stage would have refused — the SpiderFoot "no injecting data into an
  arbitrary module" guarantee, expressed for a metamorph chain.
- `planMetamorph(input, { fromStage })` refuses any entry that is **not** the
  declared `entry` stage (`gate_bypass_attempt`), mirroring SpiderFoot's refusal
  to start a scan mid-graph.

### The Markup — Blacklight (single real-time self-exposure inspector)

[Blacklight](https://themarkup.org/blacklight) is a **single real-time endpoint**:
you give it **one** subject (a site that is yours / public) and it inspects it,
then explains what it found. Standby gives the gate exactly that shape:

- `POST /inspect` takes **one** subject — no batch, no list-of-people, no
  enumeration of strangers. That shape is itself a compliance control: there is
  no API surface for "scan these 500 handles".
- The response is either *inspecting* (the audit started) or a **plain-language
  refusal with legal alternatives** — Blacklight's "here's what this means for
  you" framing, applied to the gate decision.
- Standby keeps the gate **warm** so the inspector answers immediately, the way
  Blacklight feels like an instant web tool rather than a batch job.

---

## Request / response contract

`POST /inspect` body (one subject you are entitled to audit):

```json
{ "scope_type": "self",
  "subject_label": "My public profile",
  "target_urls": ["https://example.com/your-public-profile"] }
```

| Outcome | HTTP | Body |
| --- | --- | --- |
| Gate rejected (stalking / private person / laundering) | `403` | `{ "decision":"reject", "reasons":[...], "alternatives":[...] }` |
| Gate passed, on-platform | `202` | `{ "decision":"inspecting", "started":true, "target_stage":"discovery" }` |
| Gate passed, off-platform / placeholder id | `202` | `{ "decision":"would_inspect", "started":false, "target_stage":"discovery", "reason":"..." }` |
| Readiness probe | `200` | `{ "status":"ready" }` |

---

## Platform notes (from current Apify docs)

- Standby Actors **must run an HTTP server**; Apify proxies user requests to it
  and uses a **readiness probe** before routing traffic. We read
  `ACTOR_WEB_SERVER_PORT` and expose `GET /healthz`.
- Metamorph **stops the current container and starts the target image in the same
  run**, preserving default storages; the new input is stored under
  `INPUT-METAMORPH-1`. The next stage must read input via `Actor.getInput()` (it
  picks the metamorph key automatically) and then re-assert scope.
- Compliance posture: Standby is used purely to make the **self-audit** responsive;
  it does **not** add any new data source and is gated by `shared/scope.js` like
  every other entry point. No login/captcha/rate-limit evasion is involved.

## How to run locally

```bash
# pure + endpoint tests (zero deps)
node integrations/standby/test-standby.js

# start the Standby server locally (off-platform: gate works, metamorph is inert)
ACTOR_WEB_SERVER_PORT=4321 node integrations/standby/server.js
# in another shell:
curl -s localhost:4321/inspect -d '{"scope_type":"self","target_urls":["https://example.com/me"]}'
curl -s localhost:4321/inspect -d '{"scope_type":"self","subject_label":"track my ex","target_urls":["https://x/y"]}'  # -> 403
```
