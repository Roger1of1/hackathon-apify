# MirrorTrace AUX — Public GitHub Leak Scan

Auxiliary Apify actor for **Self Footprint Audit Pro**. It audits the SELF
subject's **own public GitHub footprint** for credentials they accidentally
committed — API keys, tokens, private-key blocks, high-entropy `.env`
assignments — so the subject can **rotate** them. It is a self-audit, not
surveillance of anyone else.

## What it does

1. Confirms the public GitHub profile actually exists (no profile → no event).
2. Lists the account's **public, owner, non-fork** repositories (most-recently
   pushed first, capped by `max_repos`).
3. Reads each repo's default-branch tree and fetches **small, text/config-like**
   files (`.env`, `*.yml`, `*.json`, source, etc., capped by
   `max_files_per_repo`).
4. Optionally scans the account's **public gists**.
5. Runs the shared, redacting, entropy-gated secret detector over each file and
   emits typed `module_event`s.

## Compliance boundary (hard red lines)

- **Scope-gated.** Every run passes `shared/scope.js` `validateScope`, then is
  further restricted to `scope_type ∈ {self, public_figure}`. Account/repo
  enumeration is a **dual-use** technique, so `consented` / `brand` /
  `safety_evidence` are intentionally **absent from the input-schema enum** and
  rejected in code. Prohibited scopes never reach the scan.
- **Public data only.** Uses GitHub's documented public REST API + public raw
  file content. It **never** bypasses authentication, captcha, or rate limits.
  On `403`/`429` rate-limit responses it **backs off** and stops.
- **`GITHUB_TOKEN` (optional)** is used **only** to raise the subject's own rate
  limit — never to reach private data; private/fork repos are skipped
  defensively.
- **No identity / romance / gender / intimacy inference.** A leaked key is a
  security-hygiene fact about the subject's OWN credential.
- **No fake data.** Every emitted event is built from a real fetched artifact.
  Secrets are **redacted** to a fingerprint + masked hint by the shared detector
  before any event exists — the plaintext is never stored or transmitted.

## Output — typed `module_event`s

All events use the frozen vocabulary in `shared/detectors/event-types.js`
(`makeEvent` throws on anything outside it), so the SpiderFoot-style correlation
engine (`shared/correlation.js`) can cluster them by **host / handle / secret
fingerprint** — never by person:

| event_type           | meaning                                                |
|----------------------|--------------------------------------------------------|
| `SELF_USERNAME`      | the confirmed public GitHub handle                     |
| `SELF_PROFILE_URL`   | a public repo / gist surface the subject controls      |
| `SECRET_LEAK_PUBLIC` | a self-committed secret (redacted fingerprint + hint)  |
| `EXPOSURE_SUMMARY`   | real run counts; risk = high only if a secret was found |

A `GH_LEAK_SUMMARY` key-value record gives a Blacklight-style "what a third party
could trivially learn about my credential hygiene" summary.

## Input

See [`.actor/input_schema.json`](.actor/input_schema.json). Key fields:
`scope_type` (`self`|`public_figure`), `github_handle`, `max_repos`,
`max_files_per_repo`, `include_gists`.

## Reference patterns applied

- **SpiderFoot** module/event + correlation-engine model — every result is a
  typed event with provenance and honest confidence, carrying co-occurrence keys
  for downstream clustering.
- **GitHub secret scanning / TruffleHog / gitleaks** — "scan public repos &
  gists for committed credentials", reframed as a SELF-audit; the actor **reuses**
  the shared `secret-leak-detector` rather than reimplementing patterns.
- **Apify Website Content Crawler / RAG Web Browser** — a bounded, polite crawl
  (caps + backoff), each fetched artifact pushed to the dataset as a typed
  record.

## Local check

```bash
node --check src/main.js
node ../../shared/aux/github-leak-finding_selftest.js
```
