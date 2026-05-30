# AUX — Breach Exposure Check (k-anonymity)

An **auxiliary** Ex-Ditector actor that orbits the core self-footprint pipeline.
It answers one compliant question about the **SELF subject**: *are my own
credentials already exposed in public breach corpora?* — so the user can rotate
passwords and turn on MFA. It is the opposite of an attack tool: it only ever
looks at credentials the operator **owns** (or a genuine public figure's
publicly-listed contact), and it does so without ever transmitting the secret.

## What it does

| Input | Technique | What leaves the machine |
| --- | --- | --- |
| `candidate_passwords` (yours) | HIBP **Pwned Passwords** range API, k-anonymity | only the first **5 hex chars** of each SHA-1 hash |
| `self_emails` (yours) | local SHA-1 → `email_hash_prefix` correlation probe | nothing (prefix kept for clustering) |
| `enable_account_breach_lookup` (self only) | authenticated HIBP `breachedaccount` | the email, **only** if `HIBP_API_KEY` is set |

Every result is emitted as a **typed module-event** and the run writes a
Blacklight-style `BREACH_SUMMARY` (self-exposure inspector) to the default KV
store.

## Hard compliance boundaries (enforced in code)

1. **Scope-gated.** Every run is routed through the canonical
   `shared/scope.js` `validateScope`, then further restricted to
   `scope_type ∈ {self, public_figure}` only. Credential enumeration is a
   **dual-use** technique, so `consented` / `brand` / `safety_evidence` are
   refused here even though they are valid product scopes elsewhere. The
   `input_schema.json` enum omits every prohibited scope and exposes only
   `self` and `public_figure`.
2. **k-anonymity — secrets never leave in full.** Passwords and emails are
   hashed locally; only a 5-char SHA-1 prefix is sent (`shared/aux/kanon.js`).
   `Add-Padding: true` hides which prefix was queried from a network observer.
3. **No fake data.** If `HIBP_API_KEY` is unset, the authenticated account
   lookup is **skipped** and reported as `skipped_no_api_key` — never a
   fabricated breach. HIBP padding suffixes (count `0`) are excluded so injected
   padding can never become a false hit.
4. **No identity / romance / gender / intimacy inference.** A breach hit is a
   security-hygiene fact about the subject's **own** credentials, nothing else.
5. **Backs off, never evades.** On `429` it stops and records a `BACKOFF`
   event rather than hammering or rotating fingerprints.

## Output: typed module-events

```jsonc
{ "event_type": "PASSWORD_EXPOSED",  "source_module": "aux:breach-check",
  "confidence": 80, "data": { "credential_label": "password #1", "breach_count": 12345 } }
{ "event_type": "EMAIL_HASH_PROBE",  "email_hash_prefix": "A1B2C", "confidence": 100 }
{ "event_type": "ACCOUNT_BREACHED",  "data": { "breach_name": "...", "data_classes": ["Passwords"] } }
```

## Reference patterns applied

- **SpiderFoot** (OSINT module + correlation engine): findings are typed
  module-events `{event_type, source_module, data, confidence}` carrying an
  `email_hash_prefix` co-occurrence key, so the Track-A correlation engine
  (`shared/correlation.js`) can link a credential exposure into the SELF
  subject's self-exposure cluster — exactly how SpiderFoot's correlation engine
  links events that share an entity.
- **The Markup "Blacklight"** (privacy / self-exposure inspector): the
  `BREACH_SUMMARY` is framed as *"what a third party could trivially learn about
  this subject's credential hygiene"*, an audit of the SELF, never surveillance
  of anyone else.
- **HIBP Pwned Passwords k-anonymity** + padding (Troy Hunt): the password range
  model and the `Add-Padding` privacy enhancement.

## Local run

```bash
HIBP_API_KEY=...optional... apify run --input '{
  "scope_type": "self",
  "self_emails": ["me@example.com"],
  "candidate_passwords": ["a-password-I-use"],
  "enable_account_breach_lookup": false
}'
```

`HIBP_API_KEY` is required **only** for the authenticated account lookup; the
password range check and email probes work without any key.
