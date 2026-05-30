/**
 * integrations/standby/test-standby.js
 *
 * Self-contained, zero-dependency tests for the Standby + metamorph capability.
 * Lives in integrations/ (my subtree) — NOT in test/ (Codex owns that).
 * Run: `node integrations/standby/test-standby.js`
 *
 * Properties asserted (the ones that keep this capability compliant):
 *  - The Standby /inspect endpoint runs the REAL scope gate: a stalking / private
 *    -individual subject is rejected with HTTP 403 and NEVER yields a metamorph.
 *  - A legitimate scope=self subject PASSES and yields a metamorph plan whose
 *    target is the next chain stage (discovery), carrying the gate's NORMALIZED
 *    input (not the raw body).
 *  - Off-platform the endpoint never claims a started run (started:false) — no
 *    fabricated success (NO-FAKE-DATA).
 *  - Entering mid-chain (bypassing the gate) is refused (gate_bypass_attempt).
 *  - The chain manifest is single-entry and every stage re-asserts scope.
 */

'use strict';

const assert = require('assert');
const http = require('http');
const { createServer } = require('./server.js');
const { planMetamorph, loadChain, nextStage } = require('./chain-policy.js');
const { inspect } = require('./client.js');

let pass = 0;
let fail = 0;
function check(name, fn) {
  Promise.resolve()
    .then(fn)
    .then(() => {
      pass += 1;
      console.log(`  PASS  ${name}`);
    })
    .catch((err) => {
      fail += 1;
      console.log(`  FAIL  ${name}: ${err.message}`);
    });
}

/** POST JSON to an in-process server and resolve { status, json }. */
function post(server, path, body) {
  return new Promise((resolve, reject) => {
    const addr = server.address();
    const payload = JSON.stringify(body);
    const req = http.request(
      {
        host: '127.0.0.1',
        port: addr.port,
        path,
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'content-length': Buffer.byteLength(payload),
        },
      },
      (res) => {
        let data = '';
        res.on('data', (c) => (data += c));
        res.on('end', () => {
          let json = {};
          try {
            json = JSON.parse(data);
          } catch (_) {
            /* leave {} */
          }
          resolve({ status: res.statusCode, json });
        });
      },
    );
    req.on('error', reject);
    req.end(payload);
  });
}

// Inputs. STALKING input uses a prohibited text pattern the real gate rejects.
const STALKING = {
  scope_type: 'self',
  subject_label: 'track a private person and find everywhere they post',
  target_urls: ['https://example.com/someone-elses-profile'],
};
const SELF_OK = {
  scope_type: 'self',
  subject_label: 'My public profile',
  target_urls: ['https://example.com/your-public-profile'],
};

async function main() {
  console.log('\nintegrations/standby/test-standby.js');

  // --- pure plan layer ----------------------------------------------------
  check('plan: stalking subject is rejected, no metamorph target', () => {
    const plan = planMetamorph(STALKING);
    assert.strictEqual(plan.decision, 'reject');
    assert.strictEqual(plan.http_status, 403);
    assert.ok(!plan.targetActorId, 'rejected plan must not expose a metamorph target');
    assert.ok(Array.isArray(plan.alternatives), 'rejection should offer alternatives array');
  });

  check('plan: legit self subject metamorphs to the discovery stage', () => {
    const chain = loadChain();
    const plan = planMetamorph(SELF_OK);
    assert.strictEqual(plan.decision, 'metamorph');
    assert.strictEqual(plan.targetStage, nextStage(chain, chain.entry).key);
    assert.strictEqual(plan.targetStage, 'discovery');
    // forwards the gate's normalized payload, not the raw body
    assert.ok(plan.normalizedInput && plan.normalizedInput.scope_type === 'self');
    assert.ok(!('subject_label' in plan.normalizedInput) || typeof plan.normalizedInput.subject_label === 'string');
  });

  check('plan: entering mid-chain (bypassing the gate) is refused', () => {
    const plan = planMetamorph(SELF_OK, { fromStage: 'crawler' });
    assert.strictEqual(plan.decision, 'reject');
    assert.ok(plan.violated_red_lines.includes('gate_bypass_attempt'));
  });

  // --- chain manifest -----------------------------------------------------
  check('chain: single entry + every stage re-asserts scope', () => {
    const chain = loadChain();
    assert.strictEqual(chain.entry, 'policy-gate');
    for (const stage of chain.stages) {
      assert.strictEqual(stage.reasserts_scope, true, `${stage.key} must re-assert scope`);
    }
    // terminal stage has no onward metamorph
    const terminal = chain.stages[chain.stages.length - 1];
    assert.strictEqual(terminal.metamorph_to, null);
  });

  // --- client dry-run (no fabricated run) ---------------------------------
  check('client dry-run: stalking subject -> reject plan, no run', async () => {
    const r = await inspect(STALKING, { baseUrl: '' });
    assert.strictEqual(r.dryRun, true);
    assert.strictEqual(r.plan.decision, 'reject');
  });

  check('client dry-run: self subject -> metamorph plan, started not claimed', async () => {
    const r = await inspect(SELF_OK, { baseUrl: '' });
    assert.strictEqual(r.dryRun, true);
    assert.strictEqual(r.plan.decision, 'metamorph');
    assert.ok(!('started' in r.plan), 'dry plan must not claim a started run');
  });

  // --- live in-process Standby server -------------------------------------
  const server = createServer();
  await new Promise((res) => server.listen(0, '127.0.0.1', res));
  try {
    const reject = await post(server, '/inspect', STALKING);
    check('endpoint: stalking subject -> HTTP 403, no metamorph', () => {
      assert.strictEqual(reject.status, 403);
      assert.strictEqual(reject.json.decision, 'reject');
      assert.ok(!reject.json.started, 'a rejected request must never start a run');
    });

    const ok = await post(server, '/inspect', SELF_OK);
    check('endpoint: self subject -> 202, off-platform started:false (no fake run)', () => {
      assert.strictEqual(ok.status, 202);
      assert.strictEqual(ok.json.decision, 'would_inspect');
      assert.strictEqual(ok.json.started, false);
      assert.strictEqual(ok.json.target_stage, 'discovery');
    });

    const health = await new Promise((resolve, reject) => {
      const addr = server.address();
      http
        .get({ host: '127.0.0.1', port: addr.port, path: '/healthz' }, (res) => {
          let d = '';
          res.on('data', (c) => (d += c));
          res.on('end', () => resolve({ status: res.statusCode, body: d }));
        })
        .on('error', reject);
    });
    check('endpoint: /healthz readiness probe -> 200 ready', () => {
      assert.strictEqual(health.status, 200);
      assert.ok(/ready/.test(health.body));
    });
  } finally {
    // give the async checks above a tick, then close + report.
    setTimeout(() => {
      server.close();
      setTimeout(() => {
        console.log(`\n  ${pass} passed, ${fail} failed`);
        if (fail > 0) process.exitCode = 1;
      }, 50);
    }, 100);
  }
}

main().catch((err) => {
  console.error('test harness error:', err.message);
  process.exitCode = 1;
});
