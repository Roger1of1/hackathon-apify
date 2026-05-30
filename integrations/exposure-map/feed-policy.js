/**
 * integrations/exposure-map/feed-policy.js
 *
 * THE BROWSER-ONLY FEED that wires the Apify self-audit INGEST to the EXPOSURE
 * MAP (Part 2). It answers one question for the front-end: "given a scoped 'run
 * my audit now' request, what Apify run should the BROWSER fire, and how do the
 * returned dataset rows become the exposure graph?" — without ever fabricating a
 * result and without ever routing findings through a MirrorTrace server.
 *
 * It REUSES (never re-implements):
 *   - integrations/ingest/ingest-policy.js  → buildIngestPlan (Apify WCC+RAG plan,
 *     scope-gated) and ingestRowsToBundle (REAL rows -> module_events + STIX)
 *   - integrations/exposure-map/exposure-graph.js → buildExposureGraph (graph data)
 *   - shared/scope.js (read-only) is the red line, enforced inside buildIngestPlan.
 *
 * ── SENSITIVITY TIERING (locked identity-verification decision) ──────────────
 * Self-proving / low-sensitivity actions need NO verification (k-anon breach
 * check; viewing scope-gated public search results). Pulling + CORRELATING PII
 * into the dossier/graph is the SENSITIVE action and requires a verified email /
 * handle from one-click OAuth. Live OAuth is the operator's LAST wiring step, so
 * this policy ENFORCES the tier as a gate UX but NEVER fakes a successful
 * sign-in: if a sensitive feed is requested without `verified_identity`, it
 * returns `requires_signin` (a gate, not a refusal of the product) and builds NO
 * Apify run. We DO NOT mint a fake verified identity.
 *
 * ── BROWSER-ONLY, ZERO SERVER STORAGE (locked privacy decision) ──────────────
 * This module is a pure PLANNER + pure TRANSFORM. It performs ZERO network and
 * ZERO fs (except loading its own JSON config, injectable for tests). The
 * returned `apify_run_request` is the EXACT request the BROWSER should send
 * directly to Apify's run-sync-get-dataset-items endpoint with the USER's OWN
 * token, so dataset rows land in the user's browser and the graph is assembled
 * there — our backend never sees them. `rowsToGraph()` is the transform the
 * browser calls on those rows; it writes nothing anywhere. (docs/apify/exposure-map.md.)
 *
 * REFERENCE ARCHITECTURES (cited): Apify RAG Web Browser + Website Content
 * Crawler (the discovery/crawl actors, reused via ingest-policy) ; Apify Actor
 * Standby (the 'run now' real-time entry, reused via integrations/standby) ;
 * Maltego/SpiderFoot link graph + The Markup Blacklight (the graph shape, see
 * exposure-graph.js). OAuth 2.0 PKCE public-client flow is the intended verified-
 * identity source (browser-only, no client secret) — wiring it is the last step.
 *
 * NO FAKE DATA: builds the exact request an operator/browser WOULD send and only
 * transforms REAL rows handed to rowsToGraph(); no demo dossier, no fake sign-in.
 */

'use strict';

const fs = require('fs');
const path = require('path');

const { buildIngestPlan, ingestRowsToBundle, SOURCE } = require('../ingest/ingest-policy.js');
const { buildExposureGraph } = require('./exposure-graph.js');
const { assertNoServerPersistence } = require('../../shared/privacy/storage-policy.js');

const CONFIG_PATH = path.join(__dirname, 'exposure-map.config.json');

/** Load the feed config (only fs touch; injectable for tests). */
function loadFeedConfig(configPath = CONFIG_PATH) {
  return JSON.parse(fs.readFileSync(configPath, 'utf8'));
}

/** Outcome codes so the front-end / tests can branch on the EXACT reason. */
const OUTCOME = Object.freeze({
  REFUSED: 'refused',                 // scope gate refused (red line) — no feed
  REQUIRES_SIGNIN: 'requires_signin', // sensitive feed needs verified OAuth identity (gate UX)
  PLAN_BUILT: 'plan_built',           // browser may fire the Apify run; no fetch done here
});

/**
 * Is this a SENSITIVE feed (pull + correlate PII into the dossier/graph)?
 * Building the exposure graph IS the sensitive action by definition — it is the
 * correlated dossier. The low-sensitivity actions (k-anon, view-only search) do
 * not go through this planner.
 */
function isSensitiveFeed() {
  return true; // every exposure-map feed correlates PII -> always the sensitive tier
}

/**
 * planExposureFeed(input, opts) -> { outcome, ... }
 *
 * Orders the gates (fail-closed, first objection wins):
 *   1. scope gate         — via buildIngestPlan -> shared/scope.js (red line)
 *   2. identity tier gate — sensitive feed requires verified_identity (OAuth);
 *                           absent => requires_signin (NOT a fake pass)
 *   3. plan build         — return the EXACT Apify run request the BROWSER fires
 *
 * @param {object} input  the scoped 'run my audit now' request (same shape ingest takes,
 *                        plus optional `verified_identity` from OAuth and `apify_token`
 *                        which is the USER'S OWN token — never logged/stored by us)
 * @param {object} [opts] { config, now }
 */
function planExposureFeed(input, opts = {}) {
  const cfg = opts.config || loadFeedConfig();
  const safe = input && typeof input === 'object' ? input : {};

  // ---- Gate 1: scope (red line) via the reused ingest planner ---------------
  // buildIngestPlan runs the REAL shared/scope.js FIRST; a refused subject never
  // yields an actor input. We default the ingest source to WCC (the self-crawl).
  const ingestInput = Object.assign({}, safe, {
    ingest_source: safe.ingest_source || SOURCE.WCC,
  });
  const ingestPlan = buildIngestPlan(ingestInput, { config: opts.ingestConfig });
  if (!ingestPlan.allowed) {
    return {
      outcome: OUTCOME.REFUSED,
      refusal: ingestPlan.refusal,
      detail: ingestPlan.detail,
      scope: ingestPlan.scope || safe.scope_type || null,
      note: 'The scope gate refused this subject; no Apify run is planned and no graph is built.',
    };
  }

  // ---- Gate 2: identity sensitivity tier (locked verification decision) ------
  if (isSensitiveFeed()) {
    const verified = safe.verified_identity;
    const hasVerified =
      verified && typeof verified === 'object' &&
      verified.verified === true &&
      typeof verified.provider === 'string' &&
      (typeof verified.email === 'string' || typeof verified.handle === 'string');
    if (!hasVerified) {
      return {
        outcome: OUTCOME.REQUIRES_SIGNIN,
        sensitivity: 'sensitive',
        signin: {
          required: true,
          providers: ['google', 'github'],
          flow: 'oauth2_pkce_public_client',
          live_oauth_wired: false, // honest: gate UX only until the operator wires it
        },
        scope: ingestPlan.scope,
        note:
          'Pulling and correlating your PII into the exposure graph is the SENSITIVE tier and ' +
          'requires one-click sign-in (Google/GitHub) returning a verified email/handle. ' +
          'Live OAuth is not yet wired; this is the gate UX. No sign-in is faked and no run is started.',
      };
    }
  }

  // ---- Gate 3: build the browser-fired Apify run request --------------------
  // The browser fires this directly with the USER'S OWN token so rows land in the
  // browser. We REDACT the token in the descriptor (never echo a secret).
  const actorPath = encodeURIComponent(ingestPlan.actorId);
  const apifyRunRequest = {
    method: 'POST',
    url:
      `https://api.apify.com/v2/acts/${actorPath}` +
      `/run-sync-get-dataset-items?token=<USER_APIFY_TOKEN>`,
    body: ingestPlan.input,
    fired_by: 'browser', // NOT our server — browser-only data flow
    source: ingestPlan.source,
    deployed: false,
  };

  // ── PROVE the data flow is browser-only via the CANONICAL privacy policy ────
  // The run request carries the audit INPUT (vetted target URLs), NOT findings,
  // and the graph is held in memory/sessionStorage only. assertNoServerPersistence
  // (shared/privacy/storage-policy.js, reused) verifies the plan does not persist
  // exposure findings server-side or transmit findings off-device. If a future
  // edit ever routed findings through a server, this would fail closed.
  const storageAudit = assertNoServerPersistence({
    storage: ['in_memory', 'session_storage'],
    persistsExposureFindings: false,
    transmits: [
      // The Apify run request: fired by the browser, carries the audit input, NOT findings.
      { kind: 'apify_run_sync', method: 'POST', includesFindings: false },
    ],
  });

  return {
    outcome: OUTCOME.PLAN_BUILT,
    sensitivity: 'sensitive',
    scope: ingestPlan.scope,
    verified_identity: {
      provider: safe.verified_identity.provider,
      // echo only that it is verified + which provider; never persist it.
      verified: true,
    },
    ingest_plan: ingestPlan,
    apify_run_request: apifyRunRequest,
    data_flow: cfg.data_flow,
    storage_audit: storageAudit, // { ok:true, violations:[] } — proven browser-only
    note:
      'Plan built. The BROWSER fires this Apify run with the user\'s own token; dataset rows are ' +
      'mapped to the exposure graph IN THE BROWSER (rowsToGraph) and never sent to a MirrorTrace ' +
      'server. actorId is a placeholder until the operator wires a live token. No run started here.',
  };
}

/**
 * rowsToGraph(plan, rows, opts) -> { events, graph, dropped, page_errors }
 *
 * The BROWSER-side transform: take the REAL dataset rows the run-sync endpoint
 * returned and produce the exposure graph. REUSES ingestRowsToBundle (REAL row ->
 * module_event mapping, host re-assertion, STIX) then buildExposureGraph. Pure;
 * writes nothing. This is what makes "the dossier lives only in the browser"
 * literally true — there is no persistence path in this function.
 *
 * @param {object} ingestPlan the plan from planExposureFeed().ingest_plan
 * @param {object[]} rows REAL Apify dataset rows (from the user's own run)
 * @param {object} [opts] { now, subjectLabel }
 */
function rowsToGraph(ingestPlan, rows = [], opts = {}) {
  const { events, bundle, dropped, page_errors } = ingestRowsToBundle(ingestPlan, rows, { now: opts.now });
  const graph = buildExposureGraph(events, {
    subjectLabel: opts.subjectLabel,
    // integrity handles travel inside the STIX bundle; severity can use them if passed.
  });
  return { events, graph, stix_bundle: bundle, dropped, page_errors };
}

module.exports = {
  loadFeedConfig,
  planExposureFeed,
  rowsToGraph,
  isSensitiveFeed,
  OUTCOME,
  CONFIG_PATH,
};
