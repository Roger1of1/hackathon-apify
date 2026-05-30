# Ex-Ditector AUX — Certificate-Transparency Exposure Self-Check

> **Auxiliary** actor in the Ex-Ditector *Self Footprint Audit Pro* toolkit. It
> answers one compliant, high-leverage question about **a domain you own**:
> *"Which hostnames have I already published to the public Certificate
> Transparency logs, and which of them name sensitive internal services I forgot
> were reachable?"*

This is the **opposite** of reconnaissance against another person. It only ever
reads **your own** public footprint and tells you how to shrink it.

## What it does

Every TLS certificate ever issued for your domain is published, by design, to
public append-only **Certificate Transparency** logs (RFC 6962). Anyone can read
them. This actor reads them **for you** via the public **crt.sh** JSON index and:

1. Enumerates every in-scope hostname your certificates have published
   (apex, subdomains, and `*.` wildcards).
2. Flags **risky** hostnames whose labels suggest a sensitive service
   (`admin`, `staging`, `dev`, `vpn`, `internal`, `git`, `jenkins`, `grafana`,
   `phpmyadmin`, …) with a cited, plain-English reason (OWASP sensitive-subdomain
   surface).
3. Grades the overall exposure surface **A–F**, with every deduction traced to a
   cited reason.
4. Emits typed module-events keyed by `domain` so the correlation engine can
   cluster a leaked `admin.example.com` here with that host's exposure elsewhere
   (e.g. the email-auth or attack-surface actors).

Then **act on it**: decommission the host, put it behind auth/VPN, or rename and
re-scope the certificate.

## Compliance boundary (hard red lines)

- **Scope-gated.** Subdomain enumeration is a recognised **dual-use** technique,
  so every run routes through `shared/scope.js` `validateScope` **and** is further
  restricted to `scope_type ∈ {self, public_figure}`. The prohibited scopes are
  intentionally **absent from the input enum**. The free-text laundering scan runs
  over `subject_label`, so a prohibited intent ("find my ex's servers") is rejected
  even under a legal-looking scope.
- **Public CT logs only.** RFC 6962 logs are public by design. There is **no login
  wall, no captcha bypass, no private social graph, no person-tracking, and no
  romance/gender/sexuality/intimacy inference**. Rate limits are honored — the
  actor backs off on HTTP 429 rather than evading them.
- **No fake data.** If the CT index returns nothing, the summary is honestly
  `record_status: "not_found"` and graded as such. No hostname is ever invented,
  and an out-of-scope name returned by the index is **dropped, never reported**.

## Input

| field | required | meaning |
|---|---|---|
| `scope_type` | ✅ | `self` or `public_figure` only (enum) |
| `domain` | ✅ | the registrable domain you own, e.g. `example.com` |
| `ct_index_url` | | public CT index base, defaults to `https://crt.sh/` (https only) |
| `subject_label` | | human label; scanned by the compliance gate |
| `case_id` / `case_store_name` | | optional linkage to a shared Ex-Ditector case |

## Output

A dataset of typed module-events:

- `CT_HOSTNAME_EXPOSED` — one published hostname (with `risky` flag + advice)
- `CT_WILDCARD_EXPOSED` — a `*.` wildcard cert was issued
- `CT_RISKY_HOSTNAME` — a hostname whose label suggests a sensitive service
- `CT_EXPOSURE_SUMMARY` — roll-up + A–F grade (also saved to
  `CT_EXPOSURE_SUMMARY` in the default key-value store)

Each event carries `{ record_type, event_type, source_module, domain, confidence,
data }` plus `case_id`.

## Run locally

```bash
apify run -p           # uses .actor/input_schema.json + your INPUT.json
# or, for the pure parsing/grading core (no network, no Apify account needed):
node shared/aux/ct-log-finding_selftest.js
```

> Connecting a live Apify account is the **last** step; the logic, schema, and
> grading above are real and unit-tested today.

## Reference patterns applied

- **RFC 6962 Certificate Transparency + crt.sh** public JSON index
  (`?identity=%.<domain>&output=json`) — the canonical public way to read a
  domain's own issued certificates.
- **SpiderFoot `sfp_crt`** CT-enumeration model — typed, `domain`-keyed module
  events that the correlation engine can cluster.
- **The Markup "Blacklight"** self-exposure framing — output is "hostnames *you*
  published + fixes for the risky ones", never recon of a third party.
- **OWASP sensitive-subdomain** heuristics + **GOV.UK** plain-language advice —
  risky labels are flagged with a cited, plain-English remediation.
