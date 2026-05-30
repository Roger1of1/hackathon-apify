# Ex-Ditector AUX — Data-Broker Opt-Out (self-only)

Auxiliary Apify actor for the [Ex-Ditector / Self Footprint Audit Pro](../../README.md)
toolkit. It turns *"I found MY OWN listing on a people-search / data-broker site"*
into a concrete, reviewable removal workflow — the compliant, self-only rebuild of
what DeleteMe / Privacy Bee style services do.

It is the **opposite** of an ex-stalking tool: it can only ever act on the
**requester's own** broker listings, it **scrapes nothing**, and it **sends
nothing**. It emits a plan you review and act on yourself.

---

## What it does

Given a list of broker listings **you have personally confirmed are about you**,
the actor produces, per confirmed listing:

1. **A STIX 2.1 Observed Data object** — *"this listing about ME is public at URL
   U, observed at T"* is literally a STIX Observed Data object. We **reuse**
   [`shared/enrich/stix-evidence.js`](../../shared/enrich/stix-evidence.js) (and
   `shared/enrich/stix-indicator.js` for an Indicator + OpenCTI/MISP interop
   bundle) — STIX logic is **not duplicated** here.
2. **A ready-to-send erasure request** — a data broker is a *third party* holding
   your PII, so we **reuse** [`shared/aux/takedown-letter.js`](../../shared/aux/takedown-letter.js)
   to draft a **GDPR Art. 17** erasure + **CCPA** delete + search **de-index**
   request (not a self-removal checklist — a broker is not a surface you control).
3. **An Apify re-check proposal** — a paced
   [Schedule](../../integrations/schedules) + [Webhook](../../integrations/webhooks)
   that re-reads the broker's **own public surface** to detect a **removed listing
   that REAPPEARED**, ingested through the existing gated/capped
   [WCC + RAG path](../../integrations/ingest) (`apify/website-content-crawler`
   for a known opt-out URL, `apify/rag-web-browser` for a public name search).
   This is **Closure-Mode-friendly**: one paced sweep instead of compulsive manual
   re-checking. The actor only *proposes* it; nothing is scheduled or fetched here.

The plan also surfaces each broker's **own public opt-out URL + method** so you can
file the removal yourself.

---

## Compliance boundary (hard red lines)

- **Scope-gate-first.** Every run is routed through the canonical
  [`shared/scope.js`](../../shared/scope.js) `validateScope()` **before** anything
  else, and is then hard-restricted to `scope_type ∈ {self, consented}`. A broker
  opt-out is a **first-person erasure** — you cannot opt a public figure, a brand,
  or another person out of a broker. Those scopes are **refused at runtime** and
  are **absent from the input-schema enum** (two doors).
- **No scraping, no fake data.** The actor performs **no network fetch**. A listing
  only becomes actionable when **you** set `confirmed_self: true`. The
  [broker registry](../../shared/aux/broker-registry.js) is a clearly-labeled
  **TEMPLATE** of brokers' *public* opt-out contact points — zero scraped listings,
  zero *"you were found here"* data. Unknown brokers and unconfirmed listings are
  skipped, never invented.
- **No** romance / gender / sexuality / intimacy / live-location pathway anywhere.

`consented` is accepted **only** with a written `authorization_evidence_url`, which
the scope gate already enforces.

---

## Known-broker registry (TEMPLATE)

`broker_id` must be one of the entries in
[`shared/aux/broker-registry.js`](../../shared/aux/broker-registry.js). At authoring
time: `spokeo`, `whitepages`, `beenverified`, `radaris`, `acxiom`. Each entry holds
the broker's **own public opt-out URL** and documented method — **verify each URL is
current before relying on it** (brokers move these). The registry contains **no
listing data**.

---

## Input

| Field | Type | Notes |
| --- | --- | --- |
| `scope_type` | string (`self` \| `consented`) | **required**. Enum omits all other scopes by design. |
| `subject_label` | string | Your name, for the erasure letter. Omitted → explicit `[[ FILL IN ]]` placeholder (never fabricated). |
| `authorization_evidence_url` | string | **Required for `consented`** — a URL to written consent. |
| `confirmed_listings` | array | `[{ "broker_id": "spokeo", "listing_url": "https://www.spokeo.com/Your-Name/123", "confirmed_self": true }]`. A listing without `confirmed_self: true` is skipped. |
| `case_id` / `case_store_name` | string | Optional pipeline wiring (shared KV store). |

### Example

```json
{
  "scope_type": "self",
  "subject_label": "Jane Doe",
  "confirmed_listings": [
    { "broker_id": "spokeo", "listing_url": "https://www.spokeo.com/Jane-Doe/123", "confirmed_self": true },
    { "broker_id": "whitepages", "listing_url": "https://www.whitepages.com/name/Jane-Doe", "confirmed_self": true }
  ]
}
```

A `public_figure` / `brand` / stalking request, or a listing without
`confirmed_self`, is **refused or skipped** — see the self-test for proofs.

---

## Output

- **Dataset** — one `broker_optout_action` record per confirmed listing (with its
  `stix_observed_data`), one `broker_erasure_request` per broker (GDPR/CCPA letters),
  and one `broker_recheck_proposal` per distinct broker.
- **Key-value store** — `BROKER_OPTOUT_SUMMARY` (counts, STIX bundle, OpenCTI/MISP
  interop bundle, honest TEMPLATE banner) or `BROKER_OPTOUT_REFUSAL` on refusal.

Nothing is scraped, sent, or removed. Verify every opt-out URL and every drafted
letter before acting.

---

## Tests

```bash
node shared/aux/broker-optout_selftest.js   # standalone
npm run test:modules                        # via the aggregating CI runner
npm test                                     # compliance / scope-rejection gate
```

The self-test proves: scope-gate-first, self-only refusal of non-self subjects,
template honesty (no fabricated listings; empty in → empty out), and reuse of
`stix-evidence.js` + `takedown-letter.js`.

---

## Reference architectures applied

- **OASIS STIX 2.1 Observed Data + OpenCTI / MISP interop** — reused via
  `shared/enrich/stix-evidence.js` (`toObservedData` / `toBundle`) and
  `shared/enrich/stix-indicator.js` (`toInteropBundle`).
- **Apify Website Content Crawler + RAG Web Browser ingestion** — the re-check
  proposal ingests the broker's own public surface through `integrations/ingest/*`,
  paced by `integrations/schedules` (cadence=closure) and alerted by
  `integrations/webhooks`.
