/**
 * integrations/frontier/frontier-client.js
 *
 * Thin LIVE-or-DRY-RUN client for the Apify Request Queue ('frontier') layer.
 * It takes an audit input, runs the pure scope-gated planner (frontier-policy.js),
 * and:
 *   - WITHOUT APIFY_TOKEN  -> DRY-RUNS: returns the EXACT Request Queue API call
 *     descriptors it WOULD send (create-queue, batch-add, head-and-lock) with
 *     started:false, performs NO network call and fabricates NO queue/dedup
 *     state. (NO-FAKE-DATA — same stance as the proxy / exports / ingest /
 *     schedules clients in this repo.)
 *   - WITH APIFY_TOKEN     -> returns the same descriptors with the token marked
 *     present; the actual fetch is the operator's LAST deploy step. We do NOT
 *     ship a live fetch here because the queueId is a placeholder and nothing is
 *     deployed.
 *
 * Apify Request Queue API v2 endpoints, documented for the operator so wiring the
 * live token is a one-line change at deploy time:
 *   - Create named queue:
 *       POST https://api.apify.com/v2/request-queues?name={name}&token={t}
 *       (https://docs.apify.com/api/v2/request-queues-post)
 *   - Batch-add (≤25 requests/call, server-side uniqueKey dedup):
 *       POST https://api.apify.com/v2/request-queues/{queueId}/requests/batch?token={t}
 *       body = [{ url, uniqueKey, method, userData }, ...]
 *       (https://docs.apify.com/api/v2/request-queue-requests-batch-post)
 *   - Head-and-lock (politeness: one client owns the head for lockSecs):
 *       POST https://api.apify.com/v2/request-queues/{queueId}/head/lock?lockSecs={n}&token={t}
 *       (https://docs.apify.com/api/client/js/reference/class/RequestQueueClient)
 *
 * The batch response's processedRequests[].wasAlreadyPresent flags are the REAL
 * dedup signal — they come from the live API, never from this client.
 */

'use strict';

const { buildEnqueuePlan, splitBatches } = require('./frontier-policy.js');

const API_BASE = 'https://api.apify.com/v2';

function tokenMark(token) {
  return token ? '<APIFY_TOKEN>' : '<MISSING_APIFY_TOKEN>';
}

/**
 * Build the ordered list of API call descriptors for an accepted plan (no fetch).
 * Returns { create, batches: [...], headLock } — every descriptor carries a
 * redacted token and an explicit `would_send` flag.
 */
function requestDescriptorsFor(plan, token, opts = {}) {
  const queueId = plan.queueId;
  const qId = encodeURIComponent(queueId);
  const name = opts.queueName || '<PLACEHOLDER:exditector-selfaudit-{subject_token}>';

  const create = {
    purpose: 'create_or_get_named_queue',
    method: 'POST',
    url: `${API_BASE}/request-queues?name=${encodeURIComponent(name)}&token=${tokenMark(token)}`,
    body: null,
    would_send: true,
    _note: 'Named queues persist across runs; unnamed default queues are wiped per run.',
  };

  const batches = splitBatches(plan.requests, plan.caps.max_enqueue_batch).map((reqs, i) => ({
    purpose: 'batch_add_requests',
    index: i,
    method: 'POST',
    url: `${API_BASE}/request-queues/${qId}/requests/batch?token=${tokenMark(token)}`,
    body: reqs, // [{ url, uniqueKey, method, userData }] — ≤25 per call
    count: reqs.length,
    would_send: true,
    _dedup: 'Server-side dedup on uniqueKey; response.processedRequests[].wasAlreadyPresent is the truth.',
  }));

  const headLock = {
    purpose: 'head_and_lock',
    method: 'POST',
    url: `${API_BASE}/request-queues/${qId}/head/lock?lockSecs=${plan.lockSecs}&token=${tokenMark(token)}`,
    body: null,
    would_send: true,
    _note: `One client owns the head request for ${plan.lockSecs}s — politeness, not evasion.`,
  };

  return { create, batches, headLock };
}

/**
 * enqueue(input, opts) -> result
 *
 * Runs the policy, then prepares the Request Queue API descriptors. Pure decision
 * + env read; NO network. The caller (an Apify actor) performs the actual adds at
 * deploy time and MUST honor respectRobotsTxtFile in each request's userData.
 */
function enqueue(input, opts = {}) {
  const env = opts.env || process.env;
  const plan = buildEnqueuePlan(input, opts);

  if (!plan.allowed) {
    return {
      ok: false,
      mode: 'refused',
      refusal: plan.refusal,
      detail: plan.notes || 'Frontier enqueue refused at the policy boundary.',
      scope_reasons: plan.scope_reasons,
      violated_red_lines: plan.violated_red_lines,
      alternatives: plan.alternatives,
      dedup: plan.dedup,
      usedNetwork: false,
      // A refusal NEVER yields enqueueable requests, dry-run or otherwise.
      descriptors: null,
    };
  }

  const token = env.APIFY_TOKEN;
  const descriptors = requestDescriptorsFor(plan, token, opts);

  if (!token) {
    return {
      ok: true,
      mode: 'dry_run',
      detail:
        'APIFY_TOKEN is not set — DRY RUN. No queue was created and no request was ' +
        'enqueued; no network call was made. These are the API calls that WOULD be ' +
        'sent. wasAlreadyPresent dedup flags only exist after a real call.',
      scope_type: plan.scope_type,
      queueId: plan.queueId,
      requests: plan.requests,
      dedup: plan.dedup,
      lockSecs: plan.lockSecs,
      descriptors,
      usedNetwork: false,
      deployed: false,
    };
  }

  // Token present but queueId is still a placeholder and nothing is deployed:
  // we return the live-shaped descriptors WITHOUT firing them. Honest stance —
  // the actual fetch is the operator's last deploy step.
  return {
    ok: true,
    mode: 'prepared_live',
    detail:
      'APIFY_TOKEN present. Live request descriptors prepared but NOT sent here — ' +
      'the queueId is a placeholder and nothing is deployed. The operator fires ' +
      'these at the last deploy step.',
    scope_type: plan.scope_type,
    queueId: plan.queueId,
    requests: plan.requests,
    dedup: plan.dedup,
    lockSecs: plan.lockSecs,
    descriptors,
    usedNetwork: false,
    deployed: false,
  };
}

module.exports = {
  enqueue,
  requestDescriptorsFor,
};
