/**
 * integrations/webhooks/receiver.js
 *
 * A small, self-contained HTTP receiver for Apify run webhooks for MirrorTrace.
 *
 * What it does, in order, for every incoming POST:
 *   1) Captures the RAW body bytes (needed for HMAC verification).
 *   2) Authenticates the caller (URL secret token and/or HMAC) via verify.js.
 *      Unauthenticated requests are rejected 401 — we fail closed.
 *   3) Deduplicates on the Apify dispatch id header
 *      (`X-Apify-Webhook-Dispatch-Id`) so duplicate deliveries are idempotent,
 *      exactly as Apify's docs advise ("design your code to be idempotent").
 *   4) Optionally fetches the run's default dataset + OUTPUT from the Apify API
 *      (only if APIFY_TOKEN is set) so it can judge OUTPUT HEALTH — because an
 *      Apify "SUCCEEDED" event means the process exited cleanly, NOT that real,
 *      compliant output exists. output-health.js makes that honest call.
 *   5) Routes by verdict WITHOUT fabricating anything:
 *        healthy        → "audit ready" signal (logged; wire to your notifier)
 *        degraded       → "partial — some sources blocked us" signal
 *        compliance_stop→ human-review queue (a compliance outcome, not a bug)
 *        empty/malformed→ DO NOT tell the user it is ready; flag for review
 *        failed         → alert
 *
 * ── DESIGN LINEAGE ──────────────────────────────────────────────────────────
 * SpiderFoot (https://github.com/smicallef/spiderfoot): event-driven engine that
 *   types every finding and runs a correlation pass. Here, the receiver is the
 *   "engine glue": it turns each webhook into typed run-summary counts and lets
 *   output-health.js correlate them into a verdict.
 * The Markup's Blacklight (https://themarkup.org/blacklight): a real-time
 *   inspector that REPORTS what it actually observed. Every verdict we emit
 *   carries the observed counts + reasons, so a "ready" claim is always backed
 *   by evidence — never an empty success.
 *
 * Runs with Express if installed; otherwise falls back to Node's built-in http
 * so it works offline with zero `npm install`. No fake data, no implicit trust.
 * ─────────────────────────────────────────────────────────────────────────────
 */

'use strict';

const http = require('http');
const { authenticate } = require('./verify.js');
const { evaluateOutputHealth, HEALTH } = require('./output-health.js');

const PORT = Number(process.env.PORT || process.env.WEBHOOK_PORT || 4477);
const PATH_PREFIX = '/apify-webhook';
const URL_SECRET = process.env.APIFY_WEBHOOK_SECRET || '';
const HMAC_SECRET = process.env.APIFY_WEBHOOK_HMAC_SECRET || '';
const APIFY_TOKEN = process.env.APIFY_TOKEN || '';
const APIFY_API = process.env.APIFY_API_BASE || 'https://api.apify.com';

// Idempotency: remember dispatch ids we've already processed. Bounded LRU-ish
// set so a long-running receiver does not grow unbounded.
const seenDispatchIds = new Set();
const SEEN_CAP = 5000;
function rememberDispatch(id) {
  if (!id) return false; // no id → cannot dedupe; treat as new
  if (seenDispatchIds.has(id)) return true; // duplicate
  seenDispatchIds.add(id);
  if (seenDispatchIds.size > SEEN_CAP) {
    // Drop oldest-ish (Set preserves insertion order).
    const first = seenDispatchIds.values().next().value;
    seenDispatchIds.delete(first);
  }
  return false;
}

/**
 * Fetch helper using global fetch (Node 18+). Returns parsed JSON or null on any
 * problem — we NEVER throw the pipeline off course over a fetch hiccup, and we
 * NEVER fabricate a body. A null means "could not inspect", which output-health
 * treats as UNKNOWN rather than HEALTHY.
 */
async function apiGetJson(path) {
  if (!APIFY_TOKEN || typeof fetch !== 'function') return null;
  try {
    const res = await fetch(`${APIFY_API}${path}`, {
      headers: { Authorization: `Bearer ${APIFY_TOKEN}` },
    });
    if (!res.ok) return null;
    return await res.json();
  } catch {
    return null;
  }
}

/**
 * Given the Apify webhook payload, fetch the run's dataset items + OUTPUT so we
 * can judge output health. Returns { datasetItems, output, datasetFetched,
 * outputFetched }. When no token is configured we simply do not fetch — the
 * verdict will be honest about not having inspected.
 */
async function fetchRunArtifacts(resource) {
  const datasetId = resource && resource.defaultDatasetId;
  const kvStoreId = resource && resource.defaultKeyValueStoreId;

  let datasetItems;
  let output;
  let datasetFetched = false;
  let outputFetched = false;

  if (datasetId) {
    const items = await apiGetJson(`/v2/datasets/${datasetId}/items?clean=true&limit=1000`);
    if (Array.isArray(items)) {
      datasetItems = items;
      datasetFetched = true;
    }
  }
  if (kvStoreId) {
    const out = await apiGetJson(`/v2/key-value-stores/${kvStoreId}/records/OUTPUT`);
    if (out && typeof out === 'object') {
      output = out;
      outputFetched = true;
    }
  }
  return { datasetItems, output, datasetFetched, outputFetched };
}

/**
 * Compliant routing of a verdict. This function ONLY produces an honest action
 * descriptor; it does not pretend to deliver anything. Wire the returned action
 * to your real notifier (Slack/email/Make/n8n) — see docs/apify/webhooks.md.
 *
 * Crucially: empty/malformed/failed verdicts are NEVER routed as "audit ready".
 */
function routeVerdict(verdict, ctx) {
  const base = {
    case_event: ctx.eventType,
    run_id: ctx.runId,
    actor_id: ctx.actorId,
    health: verdict.health,
    reasons: verdict.reasons,
    dataset_summary: verdict.dataset_summary,
  };
  switch (verdict.health) {
    case HEALTH.HEALTHY:
      return { ...base, action: 'notify_user_audit_ready', user_facing: true };
    case HEALTH.DEGRADED:
      return { ...base, action: 'notify_user_partial', user_facing: true,
        note: 'Some sources blocked us; delivered evidence is real but incomplete.' };
    case HEALTH.COMPLIANCE_STOP:
      return { ...base, action: 'queue_human_review_compliance_stop', user_facing: false,
        note: 'Sources returned 401/403/429; we STOPPED (no evasion). Consider a takedown/data request.' };
    case HEALTH.EMPTY:
      return { ...base, action: 'flag_empty_do_not_claim_ready', user_facing: false,
        note: 'Clean exit but no real output — NOT reported to the user as a finished audit.' };
    case HEALTH.MALFORMED:
      return { ...base, action: 'queue_human_review_malformed', user_facing: false,
        note: 'Report missing required compliant score fields.' };
    case HEALTH.FAILED:
      return { ...base, action: 'alert_run_failed', user_facing: false };
    default:
      return { ...base, action: 'inspect_manually_unknown', user_facing: false };
  }
}

/**
 * Core handler, transport-agnostic: takes the raw body string, headers, and the
 * URL secret pulled from the path, returns { statusCode, body }.
 * Exported so it can be unit-tested without binding a socket.
 */
async function handleWebhook({ rawBody, headers, urlSecretProvided }) {
  // 1) Authenticate (fail closed).
  const auth = authenticate({
    urlSecretProvided,
    urlSecretExpected: URL_SECRET,
    rawBody,
    signatureHeader: headers['x-mirrortrace-signature'] || headers['x-apify-webhook-signature'],
    hmacSecret: HMAC_SECRET,
  });
  if (!auth.authentic) {
    return { statusCode: 401, body: { ok: false, error: 'unauthenticated', reason: auth.reason } };
  }

  // 2) Parse payload (only after auth). Reject non-JSON.
  let payload;
  try {
    payload = JSON.parse(rawBody || '{}');
  } catch {
    return { statusCode: 400, body: { ok: false, error: 'invalid_json' } };
  }

  // 3) Idempotency on Apify dispatch id.
  const dispatchId = headers['x-apify-webhook-dispatch-id'] || (payload.eventData && payload.eventData.webhookDispatchId);
  if (rememberDispatch(dispatchId)) {
    return { statusCode: 200, body: { ok: true, duplicate: true, dispatch_id: dispatchId } };
  }

  const resource = payload.resource || {};
  const eventType = payload.eventType || '';
  const ctx = { eventType, runId: resource.id || null, actorId: resource.actId || null };

  // 4) Inspect real output (only if APIFY_TOKEN configured; otherwise honest UNKNOWN).
  const artifacts = await fetchRunArtifacts(resource);

  // 5) Output-health correlation pass.
  const verdict = evaluateOutputHealth({
    status: resource.status,
    eventType,
    ...artifacts,
  });

  // 6) Compliant routing (no fabrication).
  const action = routeVerdict(verdict, ctx);

  return {
    statusCode: 200,
    body: { ok: true, auth_method: auth.method, verdict, action },
  };
}

/** Pull the secret from a path like /apify-webhook/<secret>. */
function urlSecretFromPath(pathname) {
  if (!pathname || !pathname.startsWith(PATH_PREFIX)) return '';
  const rest = pathname.slice(PATH_PREFIX.length).replace(/^\//, '');
  return rest.split('/')[0] || '';
}

/** Start a plain Node http server (no deps). Used as the offline fallback too. */
function startServer(port = PORT) {
  const server = http.createServer((req, res) => {
    if (req.method !== 'POST') {
      res.writeHead(405, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ ok: false, error: 'method_not_allowed' }));
      return;
    }
    let url;
    try {
      url = new URL(req.url, `http://localhost:${port}`);
    } catch {
      res.writeHead(400);
      res.end();
      return;
    }
    if (!url.pathname.startsWith(PATH_PREFIX)) {
      res.writeHead(404, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ ok: false, error: 'not_found' }));
      return;
    }
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', async () => {
      const rawBuf = Buffer.concat(chunks);
      const lowerHeaders = {};
      for (const [k, v] of Object.entries(req.headers)) lowerHeaders[k.toLowerCase()] = v;
      const result = await handleWebhook({
        rawBody: rawBuf, // pass Buffer so HMAC sees exact bytes
        headers: lowerHeaders,
        urlSecretProvided: urlSecretFromPath(url.pathname),
      });
      res.writeHead(result.statusCode, { 'content-type': 'application/json' });
      res.end(JSON.stringify(result.body));
    });
  });
  server.listen(port, () => {
    // eslint-disable-next-line no-console
    console.log(`[mirrortrace] Apify webhook receiver listening on :${port}${PATH_PREFIX}/<secret>`);
    if (!URL_SECRET && !HMAC_SECRET) {
      // eslint-disable-next-line no-console
      console.warn('[mirrortrace] WARNING: no APIFY_WEBHOOK_SECRET / APIFY_WEBHOOK_HMAC_SECRET set — all requests will be rejected (fail-closed).');
    }
    if (!APIFY_TOKEN) {
      // eslint-disable-next-line no-console
      console.warn('[mirrortrace] Note: APIFY_TOKEN not set — output-health cannot fetch dataset/OUTPUT and will report UNKNOWN rather than guessing HEALTHY.');
    }
  });
  return server;
}

// handleWebhook expects rawBody as string OR Buffer; verify.js handles both.
module.exports = { handleWebhook, routeVerdict, startServer, urlSecretFromPath };

// CLI entry: `node integrations/webhooks/receiver.js`
if (require.main === module) {
  startServer();
}
