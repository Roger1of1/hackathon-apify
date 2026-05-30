/**
 * A2 — Discovery
 *
 * Builds the incremental work list for a case using a NAMED Request Queue. The
 * Policy Gate metamorphed into us, so we inherit its storage: the immutable
 * CASE record lives in the named KV store `mirrortrace-case`.
 *
 * "Incremental" = the named queue is reused across runs for the same case, and
 * Crawlee de-duplicates by uniqueKey, so re-running discovery only adds genuinely
 * new URLs instead of re-queuing everything. That keeps repeated audits cheap and
 * avoids re-hitting sources we already have.
 *
 * We do NOT crawl here. We only validate scope ONE MORE TIME (defense in depth —
 * never trust that the gate ran), enqueue seeds, then metamorph into the crawler.
 *
 * Apify rate facts honored: queue ops cap ~400 rps; we enqueue a bounded set
 * (<= max_pages) so we stay far under.
 */

'use strict';

const { Actor, log } = require('apify');
const { validateScope } = require('../../../shared/scope.js');
const { makeDiscoveryRecord } = require('../../../shared/schemas.js');

// HUMAN CONFIG: set CRAWLER_ACTOR_ID to "roger_1of1/mirrortrace-crawler".
const CRAWLER_ACTOR_ID = process.env.CRAWLER_ACTOR_ID || 'roger_1of1/mirrortrace-crawler';

Actor.main(async () => {
  // Input arrives either from the Policy Gate metamorph (INPUT-METAMORPH-1, read
  // transparently by getInput) or, in dev, directly.
  const input = (await Actor.getInput()) || {};
  const caseStoreName = input.case_store_name || 'mirrortrace-case';

  // Defense in depth: re-validate. If someone invokes discovery directly,
  // bypassing the gate, we still refuse prohibited scopes.
  const validation = validateScope(input);
  if (!validation.allowed) {
    log.error('Discovery refused: scope failed re-validation (gate may have been bypassed).', {
      reasons: validation.reasons,
    });
    await Actor.setValue('OUTPUT', {
      allowed: false,
      stage: 'discovery',
      reasons: validation.reasons,
      alternatives: validation.alternatives,
    });
    await Actor.fail(`Discovery rejected scope: ${validation.reasons.join(' ')}`);
    return;
  }

  // Pull the case-of-record written by the gate (authorization-of-record).
  const caseStore = await Actor.openKeyValueStore(caseStoreName);
  const caseRecord = await caseStore.getValue('CASE');
  if (!caseRecord) {
    log.error('No CASE record found — discovery must run after the Policy Gate.');
    await Actor.fail('Missing CASE record; run the Policy Gate first.');
    return;
  }

  const caseId = caseRecord.case_id;
  const targets = validation.normalized.target_urls;
  const maxPages = typeof input.max_pages === 'number' ? input.max_pages : 50;

  // NAMED request queue keyed by case so discovery is incremental across runs.
  // Crawlee dedupes by uniqueKey (default = the URL), so re-enqueuing a seen URL
  // is a no-op — exactly the "incremental" behavior we want.
  const queueName = `mirrortrace-frontier-${caseId}`;
  const requestQueue = await Actor.openRequestQueue(queueName);

  let added = 0;
  let skipped = 0;
  for (const url of targets) {
    if (added >= maxPages) {
      log.info(`Reached max_pages (${maxPages}); stopping enqueue.`);
      break;
    }
    const { wasAlreadyPresent } = await requestQueue.addRequest({
      url,
      userData: { caseId, depth: 0, source: 'seed' },
    });
    if (wasAlreadyPresent) {
      skipped += 1;
    } else {
      added += 1;
      // Record each newly discovered URL for the audit trail.
      await Actor.pushData(makeDiscoveryRecord({ caseId, url, source: 'seed', depth: 0 }));
    }
  }

  log.info('Discovery complete.', { caseId, queueName, added, skipped, targets: targets.length });

  // Hand the frontier to the crawler via metamorph. Pass the queue NAME so the
  // crawler opens the same named queue (storage is inherited).
  await Actor.metamorph(CRAWLER_ACTOR_ID, {
    case_id: caseId,
    case_store_name: caseStoreName,
    queue_name: queueName,
    scope_type: validation.normalized.scope_type,
    max_pages: maxPages,
    checks_per_day: input.checks_per_day || 0,
  });
});
