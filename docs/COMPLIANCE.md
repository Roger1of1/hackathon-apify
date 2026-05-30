# MirrorTrace (合规版) — COMPLIANCE.md

> **Status:** Normative. This is the governing red-line document for the product. Every
> module (collectors, MCP tools, UI, storage) must conform.
> **Disclaimer:** This document describes product policy and references publicly stated
> platform positions. It is **not legal advice**. Where law or platform ToS is referenced,
> consult counsel and the primary source before relying on it.

---

## 0. Purpose & one-sentence frame

MirrorTrace helps a user **audit their OWN public footprint**, **preserve public evidence
that involves themselves**, **monitor sources they are legitimately entitled to monitor**
(consented individuals, public figures, brands), and **reduce compulsive checking** of those
sources.

It is **not** a people-search tool, a non-consensual tracking workflow, a "find out who they're dating" tool, or a
private-social scraper. Those use cases are out of scope by design and are actively rejected
by the Policy Gate (A0), not merely discouraged.

---

## 1. The scope_type model

Every job MUST declare a `scope_type`. There is no "default/unscoped" job. A0 rejects any job
missing or failing scope validation.

| `scope_type`     | Meaning                                                                 | Subject must be… | Typical input |
|------------------|-------------------------------------------------------------------------|------------------|---------------|
| `self`           | The user audits their own public footprint                              | The authenticated user | Own handle / own export |
| `consented`      | A third party who gave verifiable, revocable consent to be monitored    | A consenting adult, with a consent record on file | Consent token + URL |
| `public_figure`  | A genuine public figure acting in a public capacity                     | Notable person/official acting publicly | Official/public account |
| `brand`          | A company, product, or brand                                            | An organization, not a person | Brand account / news page |
| `safety_evidence`| Preserving public material that involves/targets the user (e.g. harassment of the user) | Evidence about the user themselves | Single public URL |

### Hard exclusions baked into the enum

There is **deliberately no scope_type** for:
- "non-consenting private person", "crush", "coworker", "acquaintance", "someone I met"
- any **private individual** who is not the user and has not consented
- any **dating-app / romance / gender** objective

If the requested target does not cleanly map to one of the five scopes above, the **default
outcome is rejection**. The absence of a "private person" scope is the primary structural
control (see THREAT-MODEL.md).

---

## 2. Prohibited analysis (`prohibited_analysis`)

These analysis *objectives* are forbidden **regardless of scope_type or data source**. Even on
a `self` job, the engine will not perform them.

| Token                     | Forbidden because |
|---------------------------|-------------------|
| `romance_inference`       | Inferring dating/relationship status of a person — core stalking enabler |
| `gender_from_image`       | Pseudoscientific, discriminatory, and an inference the subject did not consent to |
| `dating_app_presence`     | "Is X on Tinder/Bumble/…" — surveillance of intimate life; violates dating-app ToU |
| `private_person_tracking` | Aggregating/monitoring a non-consenting private individual |

A0 scans both the structured request **and** free text (multilingual) for these objectives.
E.g. `查看私人账号互动并推断关系` maps to `romance_inference` + `private_person_tracking` and is
rejected.

---

## 3. The red-line matrix (CAN DO / CANNOT DO)

### 3.1 Data source

| | CAN DO | CANNOT DO |
|---|---|---|
| **Official APIs** | Use platform official APIs within their ToS and rate limits | Use APIs to enrich a profile of a non-consenting private person |
| **User export** | Ingest the user's own data export (e.g. their own download-your-info archive) | Ingest someone else's export obtained without their consent |
| **Single manual public URL** | Fetch a single, user-supplied, publicly reachable URL (no login) | Crawl/spider outward from it, enumerate, or paginate a person's feed |
| **Public web** | Read genuinely public pages (news, company sites, public GitHub) | Scrape gated content, defeat robots/anti-bot, or harvest at scale |
| **Private / gated** | — | Access anything behind login, follow-walls, or privacy settings |

### 3.2 Social platforms

| | CAN DO | CANNOT DO |
|---|---|---|
| Instagram / Facebook (Meta) | Official API for owned/consented assets; user's own export; one public URL view | Automated scraping of profiles, friends, likes, comments (see PLATFORM-POLICY-MATRIX.md) |
| X / Twitter | Official API within tier limits | Scrape timelines/followers; bulk collection |
| LinkedIn | Official API for owned data; one public profile URL view | Automated profile scraping / connection harvesting |
| Tinder / Bumble / dating apps | **Nothing.** No collection of any kind | Any lookup, presence check, or scraping — forbidden by ToU and by us |

### 3.3 Analysis target

| | CAN DO | CANNOT DO |
|---|---|---|
| Self | Full footprint audit, exposure surface, leak detection | — |
| Consented adult (record on file) | Monitor agreed public sources | Exceed consented scope; persist after consent revoked |
| Public figure (public capacity) | Track public statements, official posts | Track their private life, home, family, location |
| Brand / org | Mentions, reputation, product news | Re-identify individual employees as a backdoor |
| Private individual (non-consenting) | — | **Anything.** Hard red line |

### 3.4 Output

| | CAN DO | CANNOT DO |
|---|---|---|
| Reports | Exposure summary, evidence bundle (own/safety), reputation digest | Produce a "dossier" on a private person |
| Inferences | Factual, source-cited public findings | Romance/gender/sexuality/health inference |
| Alerts | Digest, anti-doomscroll batching | Real-time "they just posted" stalker pings |
| Location | — | Never derive or display a person's real-time location/whereabouts |

### 3.5 Automation

| | CAN DO | CANNOT DO |
|---|---|---|
| Scheduling | Low-frequency, batched, rate-limited checks of allowed sources | High-frequency polling that mimics surveillance |
| Anti-bot | Respect robots.txt, rate limits, and platform controls | Rotate IPs, solve CAPTCHAs, spoof clients to evade controls |
| Backoff | **Compliant backoff** (see §4) | Treat a block as a challenge to bypass |

---

## 4. "Compliant backoff, not evasion" principle

When the product encounters a control — a login wall, robots.txt disallow, rate limit,
CAPTCHA, 403, or privacy setting — the **only** correct response is to **stop and surface a
compliant alternative**. The product must never:

- rotate IPs/user-agents to look like a different client,
- solve or outsource CAPTCHAs,
- replay session cookies to reach gated content,
- paginate around a follow-wall, or
- retry aggressively to brute through a rate limit.

Encountering a control is a **signal that this path is not permitted**, not an obstacle to
route around. The collector returns `blocked_by_platform_control` and A0/UI offers a lawful
path: use the official API, ask the user to upload their own export, or supply a single public
URL. Backoff is exponential, bounded, and logged. This principle is what separates an audit
tool from a scraper.

---

## 5. A0 Policy Gate — enforcement flow

A0 sits in front of **every** job and **every** MCP tool call. Nothing reaches a collector
without passing it.

```
request ──▶ A0 POLICY GATE ──▶ (pass) ──▶ MCP tool whitelist ──▶ collector
                  │
                  ├─ 1. scope_type present & ∈ {self,consented,public_figure,brand,safety_evidence}?
                  ├─ 2. target resolves to a subject permitted by that scope?
                  │       (consented ⇒ valid consent record; public_figure ⇒ public-capacity check)
                  ├─ 3. objective free of prohibited_analysis tokens? (structured + free-text, multilingual)
                  ├─ 4. data source ∈ {official_api, user_export, single_public_url}?
                  ├─ 5. no private-individual signal? (named non-public person, dating context,
                  │       "private person / crush / coworker", romance/gender intent)
                  └─ on ANY fail ──▶ REJECT (reason + compliant alternatives), write audit log
```

- A0 is **fail-closed**: ambiguous ⇒ reject.
- Rejections always include `reason` and `expected_alternatives` so the user is redirected to a
  lawful action, never just blocked.
- A0 decisions (pass and reject) are written to the immutable audit log (see
  PRIVACY-AND-RETENTION.md §6).

The canonical set of cases A0 MUST reject is encoded in `demo/reject-cases.json` and verified
by the T10 suite in `demo/reject-cases.test.md`. The canonical set of safe targets is in
`demo/allowed-urls.json`.

---

## 6. Defense in depth (layers, summarized)

1. **Schema layer** — enum makes "private person" unrepresentable.
2. **A0 Policy Gate** — semantic + free-text rejection, fail-closed.
3. **MCP tool whitelist** — collectors only expose `official_api`, `user_export`,
   `single_public_url`; no generic crawler tool exists.
4. **Demo data rules** — only own-public/synthetic targets ship (see `allowed-urls.json`).
5. **Human review** — `safety_evidence` and `consented` onboarding require human sign-off.
6. **Audit + retention** — short default retention, deletion on demand, full audit trail.

See THREAT-MODEL.md for how each misuse vector maps to these controls, and the residual risk we
are honest about.
