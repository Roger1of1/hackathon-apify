# PLATFORM-POLICY-MATRIX.md

> **Disclaimer:** This matrix summarizes **general, publicly stated** platform positions on
> automated access and scraping, and maps them to what Ex-Ditector permits. Platform terms
> change frequently and differ by jurisdiction and product surface. This is **not legal
> advice**; always check the current primary source (the linked ToS/Developer Policy) and
> consult counsel before relying on any row.
>
> **Product rule of thumb:** Ex-Ditector only ever uses one of three access modes —
> **(A) official API** within ToS, **(B) the user's own data export**, or
> **(C) a single, manually supplied public URL viewed once, no login.** It never operates a
> crawler/spider, never logs in to scrape, and never evades platform controls
> (see COMPLIANCE.md §4 "compliant backoff, not evasion").

---

## Legend

- **Official API** — platform-sanctioned, authenticated, rate-limited programmatic access under
  the platform's Developer/Platform Terms.
- **User-export** — the data-subject downloads their own data from the platform and uploads it.
- **Single manual URL** — one publicly reachable URL the user pastes; fetched once; no
  crawling, pagination, or login.
- **Forbidden** — Ex-Ditector will not do this, both because platform terms generally prohibit
  it and because our own red lines do.

---

## Matrix

| Platform | What ToS/Policy generally says about automated access / scraping (public position) | Authorized vs unauthorized distinction | Ex-Ditector ALLOWS | Ex-Ditector FORBIDS |
|---|---|---|---|---|
| **Instagram / Facebook (Meta)** | Meta's Terms and Platform/Developer policies generally prohibit accessing or collecting data from its services using automated means (bots, scrapers, crawlers) **without prior written permission**. Meta has publicly taken an **anti-scraping** stance and pursued legal action against unauthorized scrapers, while distinguishing **authorized crawling** (e.g. permitted via robots.txt / agreements / official APIs) from **unauthorized scraping** (automated collection without permission). | Authorized: official Graph/Marketing APIs for assets you own/manage, or crawling Meta expressly permits. Unauthorized: any automated collection of profiles, friends, posts, likes, comments without permission. | (A) Graph API for **owned/managed** assets; (B) user's own "Download Your Information" export; (C) single public URL viewed once. | Automated scraping of any profile/feed/likes/comments; harvesting friends/followers; logging in to collect; collecting on private/non-owned accounts. |
| **Tinder (Match Group)** | Tinder's Terms of Use generally **prohibit** the use of **robots, spiders, crawlers, scrapers, or other automated means** to access the service or collect/data-mine information, and separately **prohibit using the service to stalk, harass, intimidate, or harm** another person. Dating-profile data is intimate personal data. | No authorized scraping path exists for third-party data. Even the official surface is for personal dating use, not intelligence-gathering. | **Nothing.** No access mode is enabled for Tinder or any dating app. | All access: presence checks ("is X on Tinder"), profile lookups, scraping, data-mining, AND any stalking/harassment use. Doubly forbidden: by Tinder ToU and by our `dating_app_presence` / `romance_inference` prohibitions. |
| **X / Twitter** | X's terms and Developer Agreement & Policy generally **restrict scraping** and require automated access to go through the **official API** within the licensed tier and rate limits; off-platform crawling/scraping is generally disallowed. | Authorized: official API within your access tier. Unauthorized: scraping timelines, followers, search results outside the API. | (A) Official API within tier limits (public-figure/brand/own use); (B) user's own X data archive export; (C) single public post/profile URL viewed once. | Scraping timelines/followers/search; bulk collection; building a private-person profile via API. |
| **LinkedIn** | LinkedIn's User Agreement generally **prohibits scraping** and the use of bots/automated methods to access the site or copy data without permission; LinkedIn has actively litigated against scrapers. (Note: legal status of scraping *public* pages has been contested in court; this does not change LinkedIn's ToS prohibition or our policy.) | Authorized: official LinkedIn APIs / partner programs for owned data. Unauthorized: automated profile/connection scraping. | (A) Official API for owned data; (B) user's own LinkedIn data export; (C) single public profile/company URL viewed once. | Automated profile scraping; connection/contact harvesting; enriching a private person. |
| **Public web (general sites)** | Governed per-site by each site's ToS and **robots.txt**. Genuinely public, robots-permitted pages may be read; many sites' terms prohibit automated bulk collection. Always respect robots.txt and rate limits. | Authorized: reading public, robots-permitted content at human scale. Unauthorized: ignoring robots.txt, mass crawling, defeating anti-bot. | (C) Single public URL (news article, company/product page, public GitHub release, user's own page); respects robots.txt & rate limits. | Spidering outward; ignoring robots.txt; bulk harvesting; defeating anti-bot / CAPTCHAs. |

---

## Cross-cutting rules

1. **No login-to-scrape, ever.** If content requires authentication or is behind a privacy
   setting, it is out of scope — independent of platform.
2. **robots.txt and rate limits are respected**, never circumvented. A disallow is a stop, not
   a challenge (COMPLIANCE.md §4).
3. **Dating apps are categorically excluded** at all three access modes. There is no compliant
   way for this product to touch dating-app data.
4. **Public ≠ free-to-aggregate.** Even where a single public page is viewable, building a
   monitored *profile of a private person* is forbidden by our scope model regardless of
   platform terms (see PRIVACY-AND-RETENTION.md §2).
5. When a platform offers an **official user-export**, prefer it over any fetch: it is the most
   ToS-clean and most privacy-respecting path for `self` jobs.

---

## Primary sources to verify (check current versions)

- Meta — Terms of Service; Platform Terms; Developer Policies; Meta's public statements on
  scraping and enforcement actions.
- Tinder — Terms of Use (prohibited activities: automated access/scraping/data-mining; and
  prohibited conduct: stalking/harassment).
- X / Twitter — Terms of Service; Developer Agreement & Policy.
- LinkedIn — User Agreement; Professional Community Policies; LinkedIn Developer terms.
- Target site's own `/robots.txt` and Terms for any public-web URL.

*(URLs intentionally not hard-coded here because they move; the responsible engineer/counsel
should pull the live primary source each release.)*
