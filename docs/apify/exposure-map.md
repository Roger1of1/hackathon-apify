# Exposure Map (Part 2) — Apify-fed, browser-only

The **Exposure Map** is MirrorTrace's #1 deliverable: a radial node graph where the
**center node is "you"** and every surrounding node is **one source/site that exposes
information about you** (a forum, a data-broker, a breach, a public page). It is the
*opposite* of a stalking tool — it audits **your own** public digital footprint and
makes the exposure easier to understand.

This document covers the **data layer** the Apify integration produces. Rendering
(SVG, the calm severity-ring radial layout, subtle settle motion, `prefers-reduced-motion`
static fallback, the "切换查看" list toggle, keyboard/aria) lives in the `web/` subtree.

---

## 1. What the graph means

| Visual | Meaning | Source of truth |
|---|---|---|
| **Center node** (`id: "self"`) | You, the self subject | `opts.subjectLabel` (no PII required) |
| **Source node** (`id: "src:<host>"`) | One site/source that exposes info about you | grouped by `source_url` host |
| **Node colour tier** — green / yellow / red | Severity of the *worst* finding at that source | `shared/enrich/severity.js` band → 3-tier |
| **Node size** (`finding_count`, `size_weight` 0..1) | How much info that source holds about you | count of distinct findings at the source |
| **Radial edge** (`kind: "exposes"`) | center → each source | one per source |
| **Correlation edge** (`kind: "correlates"`) | two **different** sources share the **same identifier** | `shared/enrich/cluster-keys.js` |

**Tier mapping** (NOT a new scoring axis — derived from the canonical severity band):

```
red    = band critical | high   (email+phone+address / breach-grade sensitive)
yellow = band medium
green  = band low | info         (only low/public trivia)
```

A source node takes its **worst** finding's tier: one red finding makes the whole
source red. That is the honest, scary truth a first-time visitor must grasp in seconds.

### The correlation edges are the point

Cross-source `correlates` edges appear only when two **distinct** sources carry the
**same** email-hash-prefix, handle, or leaked-secret fingerprint. This is the
Maltego/SpiderFoot "this is all the same person" picture — the most valuable insight
Part 2 delivers. The edge records the identifier **kind** (`shared: "email_prefix"`),
**never the value** (no plaintext email/phone ever touches an edge).

---

## 2. Data flow — Apify in, browser-only out

```
 "run my audit now"  (Apify Actor Standby, POST /inspect)        integrations/standby
        │  scope gate (shared/scope.js) — fail closed
        ▼
 Apify RAG Web Browser  +  Website Content Crawler               integrations/ingest
   (find where your name/email/handle appears publicly; crawl
    your own surfaces → clean text/markdown + evidence handles)
        │  run-sync-get-dataset-items  →  dataset rows
        ▼   ⟵ fired BY THE BROWSER with the USER'S OWN Apify token
 rowsToGraph(plan, rows)                              integrations/exposure-map/feed-policy.js
   → ingestRowsToBundle  (REAL rows → module_events, host re-assert, STIX)
   → buildExposureGraph  (events → nodes + edges)     integrations/exposure-map/exposure-graph.js
        ▼
 EXPOSURE MAP graph  — assembled IN THE BROWSER, rendered by web/
```

### Browser-only, zero server storage (locked privacy decision)

The product must **not** become a second data-leak site. Therefore:

- The exposure graph is built **transiently in the user's browser** from their own
  findings and is **never persisted to a MirrorTrace server**. Our backend stores
  **no** user exposure data — there is no central honeypot/dossier store.
- The Apify run is **fired by the browser** with the **user's own** Apify token
  (`run-sync-get-dataset-items`), so dataset rows land in the browser. The
  `apify_run_request` descriptor `feed-policy.js` returns has `fired_by: "browser"`
  and a redacted `<USER_APIFY_TOKEN>` — we never receive or store the rows.
- Client storage: **in-memory or `sessionStorage` only**, purged on tab close.
  **Never** `localStorage`-persist findings; **never** POST findings to a server.
- `exposure-graph.js` and the transform in `feed-policy.js` perform **zero I/O and
  zero network** — there is literally no code path that could write the graph
  anywhere. That is what makes "lives only in the browser, purged on close"
  enforceable rather than a promise.

`exposure-graph.js` is dual-loadable so the *same* tested code runs in both places:
- **Node**: `const { buildExposureGraph } = require('.../exposure-graph.js')`
- **Browser** `<script>` (file://-safe, no bundler/CDN): sets
  `window.MirrorTrace.buildExposureGraph`.

---

## 3. Identity-verification tiering (locked decision)

Building the exposure graph **pulls and correlates your PII into a dossier** — the
**sensitive** tier. It therefore requires a **verified email/handle from one-click
OAuth (Google/GitHub)**. Low-sensitivity actions (viewing scope-gated public
name-search results; the k-anonymity breach check) need **no** verification and do
not go through this planner.

`planExposureFeed()` enforces the tier as a **gate UX**:
- no `verified_identity` → `outcome: "requires_signin"` (`live_oauth_wired: false`).
  This is honest: **live OAuth is the operator's last wiring step** (like the Apify
  token). The planner **never fabricates a successful sign-in** and **never starts a
  run** without verification.
- intended flow: **OAuth 2.0 PKCE public-client** (browser-only, no client secret).

---

## 4. Red lines (enforced upstream, fail-closed)

Every feed routes through `buildIngestPlan` → **`shared/scope.js` (read-only)** first.
A private-individual / stalking / romance-laundered request is **refused before any
Apify run is planned** (`outcome: "refused"`). Source nodes are minted only for the
self subject's own findings — never for a third party. `scope_type` enum is
`self | consented | public_figure | brand | safety_evidence` only.

---

## 5. Files

| File | Role |
|---|---|
| `integrations/exposure-map/exposure-graph.js` | Pure events → graph (nodes/edges). Node + browser. |
| `integrations/exposure-map/feed-policy.js` | Scope+identity-gated feed planner; `rowsToGraph` transform. |
| `integrations/exposure-map/exposure-map.config.json` | Browser-only data-flow + tier-mapping + sensitivity contract. |
| `integrations/exposure-map/_selftest.js` | Proves nodes/tiers/sizes/edges/correlation + gating. |

## 6. Reference architectures (cited, borrowed)

- **Maltego / SpiderFoot** entity-link graphs — entities (hosts/accounts/emails)
  linked by shared-identity edges; node weight = observation count. We borrow the
  link model, never their free-form person-pivoting.
  (docs.maltego.com ; github.com/smicallef/spiderfoot)
- **The Markup — Blacklight** privacy inspector report — turn a scan into a small,
  plain, ranked, immediately-graspable view; every node carries a one-line `why` +
  `suggested_action`, and the graph degrades to the same ranked list. (themarkup.org/blacklight)
- **Apify RAG Web Browser + Website Content Crawler** — the discovery/crawl actors
  that feed the graph (reused via `integrations/ingest`).
- **Apify Actor Standby** — the real-time "run my audit now" entry (reused via
  `integrations/standby`). (docs.apify.com/platform/actors/development/programming-interface/standby)
- **OAuth 2.0 PKCE public-client flow** — the intended verified-identity source
  (browser-only, no client secret).
