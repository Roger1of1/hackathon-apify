/**
 * integrations/ingest/ingest-client.js
 *
 * The thin LIVE-or-DRY-RUN client for the self-audit ingestion layer. It takes a
 * request, runs the pure scope-gated planner (ingest-policy.js), and:
 *   - WITHOUT APIFY_TOKEN  -> DRY-RUNS: returns the EXACT actor run request it
 *     WOULD send (method/url/body) with started:false, performs NO network call
 *     and fabricates NO crawl rows. (NO-FAKE-DATA, same stance as the proxy /
 *     exports / schedules clients in this repo.)
 *   - WITH APIFY_TOKEN     -> returns the same live request descriptor; the
 *     actual fetch + dataset read is the operator's LAST deploy step. We do NOT
 *     ship a fetch here because actorIds are placeholders and nothing is deployed.
 *
 * Run-actor-synchronously endpoint shape (Apify API v2), documented for the
 * operator so wiring the live token is a one-line change at deploy time:
 *   POST https://api.apify.com/v2/acts/{actorId}/run-sync-get-dataset-items
 *        ?token={APIFY_TOKEN}
 *   body = the actor input built by ingest-policy.buildIngestPlan().input
 * The dataset items returned by that endpoint are the REAL rows that
 * ingest-policy.ingestRowsToBundle() then maps to STIX 2.1 Observed Data.
 *
 * Ref: Apify Website Content Crawler + RAG Web Browser (the two actors), OpenCTI
 * /MISP STIX 2.1 interop for the evidence shape — see ingest-policy.js header.
 */

'use strict';

const { buildIngestPlan } = require('./ingest-policy.js');

/** Build the Apify API run request descriptor for an accepted plan (no fetch). */
function runRequestFor(plan, token) {
  const actorPath = encodeURIComponent(plan.actorId);
  // run-sync-get-dataset-items returns dataset rows directly — ideal for the
  // map-to-STIX step. Token is redacted in the returned descriptor.
  return {
    method: 'POST',
    url:
      `https://api.apify.com/v2/acts/${actorPath}` +
      `/run-sync-get-dataset-items?token=${token ? '<APIFY_TOKEN>' : '<MISSING_APIFY_TOKEN>'}`,
    body: plan.input,
    source: plan.source,
    deployed: false,
  };
}

/**
 * planAndDescribe(input, opts) -> { started:false, plan|refusal, request? }
 *
 * Pure-ish: reads process.env.APIFY_TOKEN (or opts.token) only to decide the
 * descriptor wording. Never fetches. Never fabricates rows.
 */
function planAndDescribe(input, opts = {}) {
  const token = opts.token || process.env.APIFY_TOKEN || null;
  const plan = buildIngestPlan(input, opts);

  if (!plan.allowed) {
    return {
      started: false,
      mode: 'refused',
      refusal: plan.refusal,
      detail: plan.detail,
      scope: plan.scope || null,
    };
  }

  const request = runRequestFor(plan, token);
  return {
    started: false, // NEVER true here — actorIds are placeholders, nothing deployed.
    mode: token ? 'live_request_built_not_sent' : 'dry_run_no_token',
    plan,
    request,
    note: token
      ? 'A live run request was constructed but NOT sent (actorId is a placeholder; ' +
        'wiring the deployed actorId + sending is the operator\'s last step).'
      : 'No APIFY_TOKEN present: dry-run only. The exact request that WOULD be sent ' +
        'is returned for inspection. No network call, no fabricated rows.',
  };
}

module.exports = { planAndDescribe, runRequestFor };
