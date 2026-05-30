# API readiness audit

Run:

```bash
node integrations/api-readiness.js
```

This is a no-network audit. It distinguishes **code-ready** from **live-wired**:

- GitHub remote can be configured while push still depends on local auth.
- Apify actor code can be real while CLI login or `APIFY_TOKEN`, actor IDs, task
  IDs, schedule IDs, and webhook URLs are still pending.
- The audit checks whether `~/.apify/auth.json` exists after `apify login`; it never
  reads or prints the credential contents.
- OAuth can be policy-enforced while the real PKCE client IDs/token exchange are
  not wired.
- MCP can have a tested local registry while the remote Apify MCP whitelist still
  needs a real token and actor names.

Current expected status in this repo, without operator secrets, is:

```text
overall = code_ready_credentials_pending
```

That is intentional honesty. The product must not claim "live connected" until
`integrations/api-readiness.js` reports `overall = live_ready`.


## Known dependency audit tail

Verified on 2026-05-30 with:

```bash
npm audit --omit=dev --json
```

The lockfile currently reports **7 moderate** transitive findings and **0 high /
critical** findings through one upstream chain:

```text
@crawlee/playwright -> @crawlee/utils -> file-type@20.5.0
```

The underlying advisories are `GHSA-5v7r-6r5c-r473` and
`GHSA-j47w-4g3g-c36v`. The npm automatic fix proposes a forced Crawlee downgrade,
while a direct `file-type` override crosses a major-version boundary. Neither is
applied blindly. Re-evaluate when Crawlee publishes a compatible dependency update,
or validate a targeted override in an isolated runtime test before adopting it.

`integrations/api-readiness.js` exposes this as
`checks.dependency_audit.status = known_upstream_tail`.

When CLI authentication and the core Metamorph environment are present, the report uses `operator_setup_pending`: the cloud core is connected, while schedule, webhook, OAuth, or remote MCP handoff can still remain.
