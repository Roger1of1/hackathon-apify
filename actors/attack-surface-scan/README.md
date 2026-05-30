# MirrorTrace AUX — Public Attack-Surface Self-Scan (CT logs + WHOIS)

Auxiliary actor in the **Self Footprint Audit Pro** toolkit. It audits a domain
**you own** for what a stranger can trivially discover about its public attack
surface, so you can lock it down:

1. **Subdomain discovery via Certificate Transparency.** Reads the **public**
   crt.sh JSON view (Certificate Transparency, RFC 6962) for every certificate
   ever issued under your apex and inventories the hostnames — surfacing
   forgotten `dev.`, `staging.`, `admin.`, `vpn.` style hosts you may not realize
   are internet-discoverable.
2. **Public WHOIS / RDAP registrant-email check.** Looks at the **public** RDAP
   record for your domain to detect a registrant email you leaked into WHOIS, so
   you can enable registrar privacy. The email is reduced to a k-anonymity SHA-1
   prefix + a masked display (`j***e@domain`); the full address is never stored.

It is the OPPOSITE of reconnaissance against a third party: it is a **self
inventory** of *your own* domain.

## Why this is compliant

- **Scope-gated.** Every run routes through the canonical `shared/scope.js`
  `validateScope` and is then restricted to `scope_type ∈ {self, public_figure}`.
  Subdomain enumeration is a dual-use attack-surface technique, allowed only for
  those scopes — `consented` / `brand` / `safety_evidence` are absent from the
  input enum and refused. You must **also** assert `i_own_this_domain=true`.
- **Public sources only.** Certificate Transparency logs and public WHOIS are
  deliberately published for auditing. No login is bypassed, no captcha or
  rate-limit is evaded, no ports are scanned, no private host is touched. The
  actor backs off on HTTP 429 rather than hammering.
- **Self inventory only.** Certificate SANs are filtered with `belongsToDomain`
  to hosts under *your* apex; a cert that merely shares a SAN with someone
  else's domain can never leak that third party's host into the output.
- **No prohibited inference.** No romance / gender / sexuality / intimacy /
  relationship inference, no live location, no third-party identity resolution.
  The only personal datum touched is *your own* registrant email, and it is
  k-anonymized.
- **No fake data.** A host or email is emitted only if it actually appears in the
  CT / WHOIS response. A redacted WHOIS record or an empty CT result yields an
  empty inventory — never an invented surface.

## Input

| Field | Type | Notes |
|------|------|------|
| `scope_type` | enum `self` \| `public_figure` | dual-use restricted; prohibited scopes omitted |
| `domain` | string | apex domain you own, e.g. `example.com` |
| `i_own_this_domain` | boolean | **required true** — ownership assertion |
| `check_whois` | boolean | also check public RDAP for a leaked registrant email (default true) |
| `max_subdomains` | integer | cap on reported hosts (default 200) |
| `case_id`, `case_store_name`, `subject_label` | string | case wiring / reporting |

## Output

Typed `module_event` records from the frozen vocabulary in
`shared/detectors/event-types.js`, pushed to the default dataset:

- `SELF_PROFILE_URL` — one per discovered subdomain (`risk: medium` when the
  label looks like a non-production surface).
- `PII_EMAIL_PUBLIC` — your registrant email exposed in WHOIS, carrying
  `meta.email_hash_prefix` (correlation key) and a masked display.
- `EXPOSURE_SUMMARY` — counts of subdomains / sensitive surfaces / whois exposure.

These flow into the SpiderFoot-style correlation engine and the report builder
like every other module's events. A `ATTACK_SURFACE_SUMMARY` record is also
written to the default key-value store.

## Reference patterns applied

- **OWASP Amass / Subfinder** attack-surface-management subdomain discovery via
  Certificate Transparency (crt.sh) — reframed as a *self* inventory.
- **The Markup "Blacklight"** self-exposure framing: output is "what a third
  party could trivially learn about *my* surface", with concrete fix advice.
- **SpiderFoot** event-driven modules + correlation engine: every result is a
  typed, frozen-vocabulary `module_event`.

## Local checks

```sh
node --check actors/attack-surface-scan/src/main.js
node shared/aux/asm-finding_selftest.js
```
