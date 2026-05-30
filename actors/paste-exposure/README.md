# Ex-Ditector AUX — Public-Paste Self-Exposure Scan

An **auxiliary** Apify actor for *Self Footprint Audit Pro*. It answers one
compliant, self-focused question:

> **"Are MY OWN identifiers (email / domain / handle) sitting in a PUBLIC paste
> dump right now?"**

Public paste sites (Pastebin & friends) are a well-known leak channel that is
**distinct** from the surfaces other actors already cover:

| Actor | Question it answers |
|---|---|
| `breach-check` | Is my credential in a **named breach corpus** (HIBP)? |
| `gh-leak-scan` | Did I commit a secret to **my own GitHub**? |
| **`paste-exposure`** (this actor) | Is my identifier sitting in a **public paste** right now? |

This split mirrors *Have I Been Pwned*, which ingests **"Pastes"** as a separate
data source from breaches precisely because they are a different exposure
channel (haveibeenpwned.com/Pastes).

## What it does

1. Routes the run through the canonical `shared/scope.js` gate, then enforces a
   second **dual-use restriction**: identifier search is allowed **only** for
   `scope_type ∈ {self, public_figure}`.
2. Auto-classifies each supplied identifier as `email` / `domain` / `handle`.
3. Queries a **documented PUBLIC paste-search index** (PSBDMP by default;
   override with `PASTE_INDEX_BASE`) for each identifier and reads only the
   PUBLIC metadata it returns.
4. Emits a typed `module_event` per **real** hit (and one `EXPOSURE_SUMMARY`),
   ready for the SpiderFoot-style correlation engine and the report builder.

## Compliance boundary (hard red lines)

- **Scope-gated**: `self` / `public_figure` only. `consented` / `brand` /
  `safety_evidence` cannot run this actor; prohibited scopes are absent from the
  input-schema enum.
- **Public data only**: documented public search/metadata endpoints. We never
  log in, solve a captcha, or defeat a rate limit — on `403/429` we back off and
  stop.
- **No fake data**: every event points at a **real** public paste URL. A failed
  or unavailable index produces **no event**, never a fabricated paste/hit/count.
- **Privacy**: a matched email is carried **only** as its HIBP k-anonymity SHA-1
  prefix (`meta.email_hash_prefix`) plus a masked hint (`j***@e***.com`) — the
  plaintext address is never stored or emitted. The paste **body** is never
  stored or echoed; only its public URL + coarse metadata.
- **No inference**: no romance / gender / intimacy / person inference. A paste
  hit is a security-hygiene fact about the subject's **own** published
  identifier.

## Input (see `.actor/input_schema.json`)

| Field | Type | Notes |
|---|---|---|
| `scope_type` | enum `self`/`public_figure` | required |
| `self_identifiers` | string[] | emails / domains / handles you own (auto-classified) |
| `self_emails` / `self_domains` / `self_handles` | string[] | optional explicit lists, merged in |
| `subject_label` | string | reporting label only |
| `max_pastes_per_identifier` | int 1–100 | politeness/cost bound (default 20) |
| `case_id` / `case_store_name` | string | shared-case wiring (best-effort) |

## Output

Dataset records are typed module-events (`record_type:"module_event"`):

- `PII_EMAIL_PUBLIC` — your email found in a public paste (carries hash prefix +
  masked hint, **no plaintext**).
- `PII_HANDLE_PUBLIC` — your handle found in a public paste.
- `SELF_PROFILE_URL` — your domain found in a public paste.
- `EXPOSURE_SUMMARY` — real tallies for the whole scan.

A `PASTE_EXPOSURE_SUMMARY` key-value record is also written for the report
builder.

## Configuration

| Env var | Purpose |
|---|---|
| `PASTE_INDEX_BASE` | Override the public paste-index base URL (e.g. point at your own licensed/self-hosted index). Defaults to a real public service. |

## Reference patterns applied

- **SpiderFoot** event-driven OSINT-module + correlation model — every finding is
  a typed `module_event` with provenance and correlation keys, linked by shared
  surface/identifier, never by person. (github.com/smicallef/spiderfoot)
- **HIBP "Pastes"** data source + **k-anonymity** email model — search the public
  paste channel by identifier, return only metadata, keep emails as a hash
  prefix. (haveibeenpwned.com/Pastes; Troy Hunt, *Understanding HIBP's Use of
  SHA-1 and k-Anonymity*)
- **Apify RAG Web Browser / Website Content Crawler** — bounded, polite queries
  with caps + backoff, each real hit pushed to the dataset as a typed record.

## NB

The default index (`psbdmp.ws`) is a real public service; **no Apify account or
API key is required to build/test this actor**. Live-account wiring is the very
last step. Run the offline shaper self-test with:

```
node shared/aux/paste-exposure-finding_selftest.js
```
