# MirrorTrace AUX — Email-Auth Posture Self-Check

**How easily can someone spoof email from a domain you own — right now?**

This auxiliary actor audits the **PUBLIC** email-authentication posture of a domain
the SELF subject **owns** (or a genuine `public_figure`'s public domain) and grades
its spoofability **A–F**, with every point deduction traced to a cited RFC. It fills
a genuine gap: none of the other MirrorTrace actors cover email spoofability, which
is one of the most consequential parts of a person's or brand's public footprint.

It reads only records that are **public in DNS by design** — there is no login wall,
no private data, no person-tracking, and no romance/gender/intimacy inference.

## What it checks (and the rubric it grades against)

| Record  | RFC      | What a weak/absent value means |
|---------|----------|--------------------------------|
| SPF     | RFC 7208 | Who may send as your domain. `+all` (authorizes *anyone*) is graded **worse than no SPF**. |
| DMARC   | RFC 7489 | Whether spoofed mail is rejected/quarantined and whether you get reports. `p=none` is monitor-only. |
| DKIM    | RFC 6376 | Cryptographic signing. Selectors are **not enumerable from DNS**, so supply your selector name(s); with none, DKIM is reported **`unknown`** (never a fake failure). |
| MX      | —        | Whether the domain receives mail (context for the above). |
| MTA-STS | RFC 8461 | Whether inbound TLS can be downgrade-stripped. |
| DNSSEC  | —        | Whether the resolver returns DNSSEC-validated answers (AD bit). |

The grading rubric is inspired by **Internet.nl**, **Hardenize**, and **NIST SP 800-177
(Trustworthy Email)**, and the output is framed in the **The Markup "Blacklight"**
self-exposure style: *"this is what an attacker could trivially do in your name, with
fixes"* — never as surveillance of anyone.

## Compliance boundary (hard red lines)

1. **Scope-gated.** Every run routes through `shared/scope.js` `validateScope`, and is
   additionally restricted to `scope_type ∈ {self, public_figure}`. The prohibited
   scopes are absent from the input enum. The free-text laundering scan still runs over
   `subject_label`, so a disguised stalking request is rejected even under a legal scope.
2. **Public DNS only.** Lookups use DNS-over-HTTPS (RFC 8484, `application/dns-json`)
   against a single public resolver. Rate limits are **honored** — on HTTP 429 the actor
   backs off rather than evading.
3. **NO FAKE DATA.** An absent record yields `record_status: "not_found"` and the real
   risk is graded; a passing record is **never** fabricated. DKIM with no selector is
   `unknown`, not a fabricated failure.

## Input

```json
{
  "scope_type": "self",
  "domain": "example.com",
  "dkim_selectors": ["google", "selector1"],
  "doh_resolver": "https://cloudflare-dns.com/dns-query",
  "subject_label": "My personal domain"
}
```

`scope_type` ∈ `{self, public_figure}` and `domain` are required.

## Output

Typed module-events pushed to the actor's dataset, each carrying a `domain`
co-occurrence key for the SpiderFoot-style correlation engine
(`shared/correlation.js`), plus an `EMAIL_AUTH_SUMMARY` record (also stored under the
`EMAIL_AUTH_SUMMARY` key) with the A–F grade, the spoofable flag, and the cited
deductions. Example summary `data`:

```json
{
  "subject_label": "My personal domain",
  "scope_type": "self",
  "score": 45,
  "band": "F",
  "spoofable": true,
  "deductions": [
    { "points": 25, "code": "spf_absent",  "reason": "No SPF record (RFC 7208): ..." },
    { "points": 30, "code": "dmarc_absent","reason": "No DMARC record (RFC 7489): ..." }
  ],
  "posture": { "spf": "not_found", "dmarc": "not_found", "dkim": "unknown_no_selectors", "mx": "present", "mta_sts": "not_found", "dnssec": "not_validated" }
}
```

## Run it locally (Apify CLI)

Real Apify SDK; runnable with the Apify CLI against your own domain — no third-party
account needed beyond a public resolver:

```bash
# from repo root
apify run -p   # uses INPUT.json in the actor's default key-value store;
               # results land in the local dataset under apify_storage/
```

Provide an `INPUT.json` like the example above. The pure parsing/grading core lives in
`shared/aux/email-auth-finding.js` and is fully unit-tested by
`shared/aux/email-auth-finding_selftest.js` (auto-run by `npm run test:modules`).
