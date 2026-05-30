# A0 — Policy Gate

The mandatory front door of MirrorTrace. No crawl runs without passing here.

## What it does
1. Validates `scope_type` against the frozen allow-list in `shared/scope.js`
   (`self | consented | public_figure | brand | safety_evidence`).
2. Rejects prohibited scopes / analyses (`romance_inference`,
   `gender_from_image`, `dating_app_presence`, `private_person_tracking`, …) with
   a **structured rejection that lists legal alternative tasks**.
3. Requires `authorization_evidence_url` when `scope_type === 'consented'`.
4. Blocks login-walled private-social hosts (Instagram/Facebook/Tinder/…).
5. **On reject** → writes an immutable decision log, sets `OUTPUT`, fails the run
   honestly (no fake "success").
   **On allow** → writes an immutable `CASE` record + decision log into the named
   KV store `mirrortrace-case`, then `Actor.metamorph()` into the discovery actor.
   Storage is inherited across metamorph, so the case travels downstream.

## Two run modes
- **Normal run** — reads `Actor.getInput()`, decides, metamorphs or rejects.
- **Standby** — when `ACTOR_STANDBY_PORT` is set, boots an HTTP server:
  - `GET /` → liveness `{ "status": "ready" }`
  - `POST /` with a JSON scope payload → the structured decision (200 allow /
    422 reject). **Never crawls, never metamorphs** — a cheap pre-flight check.

## Human config required
- `DISCOVERY_ACTOR_ID` env var → set to `YOUR_USERNAME/mirrortrace-discovery`.
- Provide a real `APIFY_TOKEN` in the platform (or `apify login`) to run.

## Try the rejection locally
```bash
node -e "console.log(JSON.stringify(require('../../shared/scope.js').validateScope({scope_type:'private_person_tracking'}),null,2))"
```

## Apify notes
- Metamorph stores the new input under `INPUT-METAMORPH-1`; downstream reads it
  via `Actor.getInput()`.
- KV write rate limit ~200 rps — we write only a few records per run.
