/**
 * A0 — Policy Gate
 *
 * The mandatory entry point for the entire MirrorTrace pipeline. NOTHING crawls
 * until this actor says yes. Responsibilities:
 *
 *   1. Validate scope_type against the frozen allow-list (shared/scope.js).
 *   2. Reject prohibited scopes / analyses with a STRUCTURED rejection that
 *      lists legal ALTERNATIVE tasks (never a bare "no").
 *   3. Require authorization_evidence_url when scope_type === 'consented'.
 *   4. Block private-social / login-walled hosts.
 *   5. On reject  -> write an immutable decision log, push the rejection, exit.
 *      On allow    -> write an immutable CASE record + decision log into a NAMED
 *                     key-value store, then Actor.metamorph() into the discovery
 *                     actor. Storage (datasets/KV/queues) is INHERITED by the
 *                     target actor across metamorph, so the case travels with it.
 *
 * Runs in two modes:
 *   - Normal run  : reads Actor.getInput(), decides, metamorphs or rejects.
 *   - Standby     : long-lived HTTP server on process.env.ACTOR_STANDBY_PORT that
 *                   validates posted inputs WITHOUT running a crawl — a cheap,
 *                   always-on compliance check / pre-flight endpoint.
 *
 * Apify facts honored here:
 *   - Metamorph stores the new input under INPUT-METAMORPH-1; the target actor
 *     reads it transparently via Actor.getInput(), so we just pass the object.
 *   - KV write rate limit ~200 rps; we write a handful of records, well under it.
 */

'use strict';

const http = require('http');
const { Actor, log } = require('apify');
const { validateScope } = require('../../../shared/scope.js');
const { makeCaseRecord, makeDecisionLog } = require('../../../shared/schemas.js');

// Named KV store that carries the case across metamorph into downstream actors.
const CASE_STORE_NAME = 'mirrortrace-case';

// The actor we metamorph INTO on a successful gate. Configure via env so the
// same image works whether you deploy under your own account namespace or not.
// HUMAN CONFIG: set DISCOVERY_ACTOR_ID to "roger_1of1/mirrortrace-discovery".
const DISCOVERY_ACTOR_ID = process.env.DISCOVERY_ACTOR_ID || 'roger_1of1/mirrortrace-discovery';

/**
 * Generate a stable-ish case id. Uses the run id when present so the case is
 * traceable back to the Apify run that opened it; falls back to a timestamp.
 */
function makeCaseId() {
  const runId = process.env.ACTOR_RUN_ID;
  const stamp = Date.now().toString(36);
  return runId ? `case_${runId}` : `case_${stamp}`;
}

/**
 * Core decision routine, shared by normal-run and standby paths.
 * Returns the validation result; in normal-run mode the caller acts on it.
 * Does NOT itself metamorph (so it can be reused safely by the HTTP server,
 * where metamorph would be wrong).
 */
async function decide(input) {
  return validateScope(input || {});
}

/**
 * Persist the audit trail. Always writes a decision log; on allow also writes
 * the immutable case record. Returns the caseId (or null on reject).
 */
async function recordDecision(caseStore, validation, input) {
  const runId = process.env.ACTOR_RUN_ID || null;
  const actorId = process.env.ACTOR_ID || null;

  if (!validation.allowed) {
    const logRec = makeDecisionLog({ caseId: null, decision: 'reject', validation, runId });
    // Decision logs are append-only by convention: key includes a timestamp so
    // we never overwrite a prior decision.
    await caseStore.setValue(`decision-${Date.now()}`, logRec);
    await Actor.pushData(logRec); // also surfaces in the default dataset for visibility
    return null;
  }

  const caseId = makeCaseId();
  const caseRecord = makeCaseRecord({
    caseId,
    scope_type: validation.normalized.scope_type,
    target_urls: validation.normalized.target_urls,
    subject_label: validation.normalized.subject_label,
    authorization_evidence_url: validation.normalized.authorization_evidence_url,
    runId,
    actorId,
  });

  // The case record is the authorization-of-record. Write once under a stable
  // key; downstream actors read 'CASE' from this named store.
  await caseStore.setValue('CASE', caseRecord);
  const logRec = makeDecisionLog({ caseId, decision: 'allow', validation, runId });
  await caseStore.setValue(`decision-${Date.now()}`, logRec);
  await Actor.pushData(logRec);

  return caseId;
}

/**
 * Build the input object handed to the discovery actor via metamorph. We pass
 * ONLY the normalized, already-validated fields plus the case id — never the
 * raw caller input, so nothing un-vetted leaks downstream.
 */
function buildDiscoveryInput(caseId, validation, originalInput) {
  return {
    case_id: caseId,
    case_store_name: CASE_STORE_NAME,
    scope_type: validation.normalized.scope_type,
    target_urls: validation.normalized.target_urls,
    subject_label: validation.normalized.subject_label,
    // Carry through optional cost/wellbeing knobs that downstream actors use.
    max_pages: typeof originalInput.max_pages === 'number' ? originalInput.max_pages : 50,
    checks_per_day: typeof originalInput.checks_per_day === 'number' ? originalInput.checks_per_day : 0,
  };
}

/**
 * Standby HTTP server: a stateless compliance pre-flight. POST a candidate
 * input as JSON, get back the structured decision. It NEVER crawls and NEVER
 * metamorphs — it only tells you whether a scope would be accepted, so a UI can
 * check before spending a real run.
 */
function startStandbyServer(port) {
  const server = http.createServer(async (req, res) => {
    // Liveness probe Apify uses to keep the Standby actor warm.
    if (req.method === 'GET') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ status: 'ready', service: 'mirrortrace-policy-gate' }));
      return;
    }
    if (req.method !== 'POST') {
      res.writeHead(405, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Use POST with a JSON scope payload.' }));
      return;
    }

    let body = '';
    req.on('data', (chunk) => {
      body += chunk;
      // Defensive cap so a hostile client cannot exhaust memory.
      if (body.length > 1_000_000) req.destroy();
    });
    req.on('end', async () => {
      let parsed;
      try {
        parsed = body ? JSON.parse(body) : {};
      } catch {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Body must be valid JSON.' }));
        return;
      }
      const validation = await decide(parsed);
      res.writeHead(validation.allowed ? 200 : 422, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        allowed: validation.allowed,
        scope_type: validation.scope_type,
        reasons: validation.reasons,
        violated_red_lines: validation.violated_red_lines,
        alternatives: validation.alternatives,
      }, null, 2));
    });
  });

  server.listen(port, () => {
    log.info(`Policy Gate Standby server listening on port ${port}`);
  });
  return server;
}

Actor.main(async () => {
  // Standby mode: Apify sets ACTOR_STANDBY_PORT. Boot the HTTP server and stay up.
  const standbyPort = process.env.ACTOR_STANDBY_PORT;
  if (standbyPort) {
    startStandbyServer(Number(standbyPort));
    // Keep the process alive for the platform; do not exit.
    await new Promise(() => {});
    return;
  }

  // Normal run mode.
  const input = (await Actor.getInput()) || {};
  log.info('Policy Gate received input', { scope_type: input.scope_type });

  const validation = await decide(input);
  const caseStore = await Actor.openKeyValueStore(CASE_STORE_NAME);
  const caseId = await recordDecision(caseStore, validation, input);

  if (!validation.allowed) {
    // Honest failure: we do NOT pretend to crawl. We surface exactly why and
    // what the user may legally do instead, then exit non-zero.
    log.warning('Policy Gate REJECTED this run.', {
      reasons: validation.reasons,
      violated_red_lines: validation.violated_red_lines,
    });
    await Actor.setValue('OUTPUT', {
      allowed: false,
      reasons: validation.reasons,
      violated_red_lines: validation.violated_red_lines,
      alternatives: validation.alternatives,
    });
    await Actor.fail(
      `Scope rejected: ${validation.reasons.join(' ')} | Legal alternatives: ${validation.alternatives.join(' ')}`,
    );
    return;
  }

  // PASS. Metamorph into the discovery actor. Storage (this named KV, the
  // default dataset, request queues) is inherited by the target, so the CASE
  // record we just wrote is readable there.
  const discoveryInput = buildDiscoveryInput(caseId, validation, input);
  log.info('Policy Gate APPROVED. Metamorphing into discovery actor.', {
    caseId,
    target: DISCOVERY_ACTOR_ID,
  });
  await Actor.metamorph(DISCOVERY_ACTOR_ID, discoveryInput);
});
