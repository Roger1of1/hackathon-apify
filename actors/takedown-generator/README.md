# Ex-Ditector AUX — Takedown / Removal-Letter Generator

Closes the loop from **audit** to **action**. The other Ex-Ditector actors tell
you *what* of your own public footprint is exposed; this actor turns those real
findings into **ready-to-review removal requests** you can sign and send.

It fetches nothing, analyses no third party, and produces no new intelligence. It
only reformats the typed `module_event` records your audit already produced into
the standard legal request shapes.

## What it drafts

For each finding (clustered by host), it picks the route(s) that actually apply:

| Finding | Drafted request |
| --- | --- |
| Your PII (email/phone/postal/handle) on a **third-party** host | **GDPR Art. 17 erasure** + **CCPA/CPRA delete** + **Google "Results about you" de-index** |
| Your PII on a host **you control** (`owned_hosts`) | **Self-remediation checklist** (just remove/redact it) |
| GPS / device serial / author embedded in a file you published | **Self-remediation** (strip EXIF before re-upload) |
| Trackers / cookies / fingerprinting on a site you control | **Self-remediation** (remove the script) |
| A leaked secret, or a breach-range hit on your credential | **Credential-rotation guidance** (no one can "take down" a credential — you rotate it) |

## Compliance boundary

- **Scope-gated** through the shared `validateScope()` chokepoint, then further
  restricted to `scope_type ∈ {self, public_figure}`. A takedown is inherently
  first-person ("remove information about **ME**"). `consented` / `brand` /
  `safety_evidence` are refused here; the input-schema enum omits them entirely.
- The gate's free-text laundering scan runs over `subject_label` / `subject_name`,
  so a laundered intent (e.g. "draft a letter to *track my ex*") is rejected.
- **No romance / gender / sexuality / intimacy / live-location** pathway. It reads
  the **frozen** `EVENT_TYPES` enum and ignores anything outside it.

## NO FAKE DATA

- Every letter is a **deterministic template** filled only from fields that exist
  in the real events. Anything we don't have (your name, contact, exact URL) is an
  explicit `[[ FILL IN ]]` placeholder — never fabricated.
- Each draft is marked `is_template: true` with a visible review banner. **Nothing
  is sent. Nothing is removed automatically.** No findings in → empty plan out.
- These drafts are **not legal advice**. Review every fact and the recipient
  before sending.

## Input

| Field | Type | Notes |
| --- | --- | --- |
| `scope_type` | enum `self` \| `public_figure` | required |
| `findings_dataset_name` | string | Apify dataset of `module_event`s from the other actors |
| `events` | array | inline `module_event`s (offline/composed runs); non-events dropped |
| `owned_hosts` | string[] | hosts you control → self-remediation instead of a letter |
| `subject_name` | string | fills the requester name; blank → `[[ FILL IN ]]` |
| `case_id` / `case_store_name` / `subject_label` | string | shared-case plumbing |

## Output

- One dataset record per **takedown packet** (a host cluster with its drafted
  letters, `why_it_matters`, `top_risk`, statute refs), plus a
  `takedown_plan_summary` record.
- A `TAKEDOWN_PLAN` key-value snapshot for the case.

## Reference patterns applied

- **SpiderFoot correlation engine** — events are clustered by co-occurrence key
  (host / email-prefix / handle) via `shared/enrich/cluster-keys.js`, the same
  correlation the report builder uses, so one request covers every leak on one
  host instead of spamming a letter per raw event.
- **The Markup "Blacklight" self-exposure inspector** — each packet carries a
  plain-language *"why this matters to **you**"* line in your own voice, matching
  Blacklight's self-audit framing rather than bare legalese.

## Run / test

```bash
node --check actors/takedown-generator/src/main.js
node shared/aux/takedown-letter_selftest.js   # pure-logic self-test
npm test                                       # repo compliance gate (stays green)
```
