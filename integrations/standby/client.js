/**
 * integrations/standby/client.js
 *
 * Thin client for the policy-gate Standby real-time API. REAL fetch, INERT
 * without an endpoint: if APIFY_STANDBY_URL is unset it DRY-RUNS — it computes
 * the same plan locally (chain-policy.js) and prints what the call WOULD return,
 * sending nothing and fabricating no run. This mirrors the dry-run posture of
 * the schedules/exports clients in this repo.
 *
 * Standby endpoints are reached at the actor's Standby URL with the user's
 * Apify token (header `Authorization: Bearer <token>` or `?token=`), e.g.
 *   https://<actor-standby-host>/inspect
 * (https://docs.apify.com/platform/actors/development/programming-interface/standby)
 *
 * Usage:
 *   node integrations/standby/client.js                       # dry run, default self subject
 *   APIFY_STANDBY_URL=... APIFY_TOKEN=... node integrations/standby/client.js
 */

'use strict';

const { planMetamorph } = require('./chain-policy.js');

const DEFAULT_SUBJECT = {
  scope_type: 'self',
  subject_label: 'My public profile',
  target_urls: ['https://example.com/your-public-profile'],
};

/**
 * inspect(subject, opts) -> result
 * Live when opts.baseUrl (or APIFY_STANDBY_URL) is set; otherwise dry: returns
 * the locally-computed plan tagged { dryRun: true }.
 */
async function inspect(subject, opts = {}) {
  const baseUrl = opts.baseUrl || process.env.APIFY_STANDBY_URL || '';
  const token = opts.token || process.env.APIFY_TOKEN || '';

  if (!baseUrl) {
    // DRY RUN: same decision the server would make, no network, no run started.
    const plan = planMetamorph(subject, { chain: opts.chain });
    return { dryRun: true, plan };
  }

  const url = baseUrl.replace(/\/+$/, '') + '/inspect';
  const headers = { 'content-type': 'application/json' };
  if (token) headers.authorization = `Bearer ${token}`;
  const res = await fetch(url, {
    method: 'POST',
    headers,
    body: JSON.stringify(subject),
  });
  const json = await res.json().catch(() => ({}));
  return { dryRun: false, http_status: res.status, response: json };
}

async function main() {
  const subject = DEFAULT_SUBJECT;
  const result = await inspect(subject);
  if (result.dryRun) {
    console.log('[standby client] APIFY_STANDBY_URL not set — DRY RUN (no request sent).');
    console.log('  subject:', JSON.stringify(subject));
    console.log('  plan:', JSON.stringify(result.plan, null, 2));
  } else {
    console.log(`[standby client] HTTP ${result.http_status}`);
    console.log(JSON.stringify(result.response, null, 2));
  }
}

if (require.main === module) {
  main().catch((err) => {
    console.error('[standby client] error:', err.message);
    process.exitCode = 1;
  });
}

module.exports = { inspect, DEFAULT_SUBJECT };
