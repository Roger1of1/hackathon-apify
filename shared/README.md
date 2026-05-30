# shared/

Canonical, dependency-free modules reused by every MirrorTrace actor. **This is
the compliance chokepoint** — the red lines live here, not scattered across
actors.

| File | Purpose |
|------|---------|
| `scope.js` | `ALLOWED_SCOPES`, `PROHIBITED_ANALYSIS`, `validateScope(input)`. The allow-list and the rejection logic. Frozen so callers cannot widen it at runtime. |
| `hashing.js` | `sha256`, `normalizeText`, `hashPage` — content + html evidence hashing. |
| `scoring.js` | The ONLY scoring model: `exposure_score`, `evidence_quality_score`, `actionability_score`, `distress_risk_score`. No romantic/jealousy/availability scores exist. |
| `schemas.js` | Builders for the records that flow between actors (case, decision log, capture, backoff, evidence index). |

## How actors consume `shared/`

Each actor's `src/main.js` requires shared modules via a relative path
(`../../../shared/...`) for **local development** from the monorepo root.

For the **Apify build**, every actor's `Dockerfile` ALSO copies the repo's
`shared/` directory into the image. Because Apify uses the **repo root** (or the
configured build context) when building, the `shared/` folder must be present in
the build context. If you deploy each actor folder in isolation, run the helper
below first to vendor `shared/` into the actor:

```bash
# from repo root, before `apify push` of a single actor
cp -R shared actors/<actor-name>/shared
```

The require path `require('../../../shared/scope.js')` resolves the same whether
`shared/` sits at the repo root (local dev / monorepo build) — the Dockerfiles
are written assuming the **repo root is the Docker build context**.
