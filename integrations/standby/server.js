/**
 * integrations/standby/server.js
 *
 * REAL Actor Standby web server for the Ex-Ditector policy gate, INERT outside
 * the Apify platform. Actor Standby keeps the gate warm in the background and
 * proxies user HTTP requests to this server, so the product behaves like a
 * real-time API: hand it ONE subject, get back either "inspecting" (the run
 * metamorphs into the audit pipeline) or a plain-language refusal.
 * (https://docs.apify.com/platform/actors/development/programming-interface/standby)
 *
 * Design borrows from the two assigned reference architectures:
 *  - The Markup's Blacklight: a single real-time self-exposure inspector
 *    endpoint that takes one subject and inspects it. POST /inspect is exactly
 *    that shape — no batch, no list of people.
 *  - SpiderFoot: a module graph where data only flows through permitted edges.
 *    Here the only edge OUT of the standby endpoint is "metamorph to the next
 *    chain stage", and only after validateScope passes (chain-policy.js).
 *
 * Compliance / NO-FAKE-DATA posture:
 *  - The gate is the REAL shared/scope.js. A rejected subject NEVER starts the
 *    pipeline; it returns HTTP 403 with legal alternatives.
 *  - The metamorph is performed by the real apify SDK ONLY when running on the
 *    platform (require('apify') succeeds AND APIFY_IS_AT_HOME=1). Off-platform
 *    the endpoint returns the PLAN (202 with the target stage) and performs no
 *    side effect — it never fabricates a started run.
 *
 * Env:
 *   ACTOR_WEB_SERVER_PORT  port to listen on (set by Apify Standby; default 4321 local)
 *   APIFY_IS_AT_HOME       "1" on the platform; gates the real metamorph
 */

'use strict';

const http = require('http');
const { planMetamorph, loadChain, isPlaceholderId } = require('./chain-policy.js');

const DEFAULT_PORT = 4321;

/** Read the JSON body of a request, bounded so a request cannot exhaust memory. */
function readBody(req, maxBytes = 256 * 1024) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on('data', (c) => {
      size += c.length;
      if (size > maxBytes) {
        reject(new Error('request body too large'));
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on('end', () => {
      const raw = Buffer.concat(chunks).toString('utf8').trim();
      if (!raw) return resolve({});
      try {
        resolve(JSON.parse(raw));
      } catch (e) {
        reject(new Error('body is not valid JSON'));
      }
    });
    req.on('error', reject);
  });
}

function send(res, status, obj) {
  const body = JSON.stringify(obj, null, 2);
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'content-length': Buffer.byteLength(body),
  });
  res.end(body);
}

/**
 * Try to obtain the real Apify SDK and perform a metamorph. Returns:
 *   { performed: true, ... }   on a real platform metamorph
 *   { performed: false, reason } when off-platform / SDK absent (dry, no side effect)
 * NEVER fabricates a started run.
 */
async function tryMetamorph(plan) {
  const atHome = process.env.APIFY_IS_AT_HOME === '1';
  if (!atHome) {
    return { performed: false, reason: 'not running on Apify platform (APIFY_IS_AT_HOME!=1)' };
  }
  if (isPlaceholderId(plan.targetActorId)) {
    return { performed: false, reason: `target actorId is a placeholder (${plan.targetActorId})` };
  }
  let Actor;
  try {
    // Optional dependency: present only inside the actor image. Required lazily
    // so this module loads (and tests run) with zero dependencies installed.
    ({ Actor } = require('apify'));
  } catch (e) {
    return { performed: false, reason: 'apify SDK not installed in this environment' };
  }
  // Real hand-off. Apify stores the new input under INPUT-METAMORPH-1; the next
  // stage reads it via Actor.getInput() and re-asserts scope.
  await Actor.metamorph(plan.targetActorId, plan.normalizedInput);
  return { performed: true, targetActorId: plan.targetActorId, targetStage: plan.targetStage };
}

/**
 * The single request handler. Routes:
 *   GET  /            -> service descriptor (what this endpoint does)
 *   GET  /healthz     -> readiness probe for Apify Standby
 *   POST /inspect     -> gate one subject; metamorph into the pipeline or refuse
 */
async function handle(req, res, opts = {}) {
  const url = req.url.split('?')[0];

  if (req.method === 'GET' && (url === '/healthz' || url === '/readiness')) {
    return send(res, 200, { status: 'ready' });
  }

  if (req.method === 'GET' && (url === '/' || url === '')) {
    const chain = opts.chain || loadChain();
    return send(res, 200, {
      service: 'ex-ditector-policy-gate (Standby)',
      what: 'Hand me ONE subject you are entitled to audit; I gate it and start your audit, or refuse with legal alternatives.',
      entry: chain.entry,
      method: 'POST /inspect',
      example_body: {
        scope_type: 'self',
        subject_label: 'My public profile',
        target_urls: ['https://example.com/your-public-profile'],
      },
      red_lines: 'No private-individual tracking, no romance/intimacy inference, no private-social scraping, no login/rate-limit evasion.',
    });
  }

  if (req.method === 'POST' && url === '/inspect') {
    let input;
    try {
      input = await readBody(req);
    } catch (e) {
      return send(res, 400, { decision: 'reject', http_status: 400, reasons: [e.message] });
    }

    let plan;
    try {
      plan = planMetamorph(input, { chain: opts.chain });
    } catch (e) {
      return send(res, 500, { decision: 'error', reasons: [e.message] });
    }

    if (plan.decision === 'reject') {
      return send(res, plan.http_status, {
        decision: 'reject',
        reasons: plan.reasons,
        violated_red_lines: plan.violated_red_lines,
        alternatives: plan.alternatives,
      });
    }

    if (plan.decision === 'complete') {
      return send(res, 200, { decision: 'complete', reasons: plan.reasons });
    }

    // decision === 'metamorph'
    const result = await tryMetamorph(plan);
    if (result.performed) {
      // The container is being torn down by metamorph; this response may race
      // the handoff, but it never claims success without a real metamorph.
      return send(res, 202, {
        decision: 'inspecting',
        started: true,
        target_stage: plan.targetStage,
        message: `Audit started — run metamorphed into "${plan.targetStage}".`,
      });
    }
    // Off-platform / placeholder: return the PLAN, no fabricated run.
    return send(res, 202, {
      decision: 'would_inspect',
      started: false,
      target_stage: plan.targetStage,
      target_actor_id: plan.targetActorId,
      reason: result.reason,
      note: 'Gate PASSED. Real metamorph happens only on the Apify platform with a real target actorId.',
    });
  }

  return send(res, 404, { decision: 'reject', reasons: [`no route ${req.method} ${url}`] });
}

function createServer(opts = {}) {
  return http.createServer((req, res) => {
    handle(req, res, opts).catch((e) => {
      try {
        send(res, 500, { decision: 'error', reasons: [e.message] });
      } catch (_) {
        /* response already sent */
      }
    });
  });
}

function start() {
  const port = Number(process.env.ACTOR_WEB_SERVER_PORT) || DEFAULT_PORT;
  const server = createServer();
  server.listen(port, () => {
    // eslint-disable-next-line no-console
    console.log(`[standby] ex-ditector policy gate listening on :${port} (POST /inspect)`);
  });
  return server;
}

if (require.main === module) {
  start();
}

module.exports = { createServer, handle, tryMetamorph, readBody, start, DEFAULT_PORT };
