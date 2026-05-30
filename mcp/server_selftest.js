/**
 * mcp/server_selftest.js
 *
 * Zero-dependency self-test for the Apify MCP tool-server (mcp/server.js).
 * Run directly:   node mcp/server_selftest.js
 * Auto-discovered by integrations/run-module-selftests.js (globs *_selftest.js)
 * and therefore by `npm run test:modules`.
 *
 * PROVES THE LOAD-BEARING GUARANTEE: an AI-agent caller cannot bypass the red
 * lines through the MCP tool layer. Specifically:
 *   (1) FAIL-CLOSED ON PROHIBITED SCOPE — every tool rejects a scope_type that is
 *       not in the allow-list (e.g. private_person_tracking).
 *   (1b) FAIL-CLOSED ON LAUNDERED / STALKING freeText — a request with scope_type
 *       "self" but a stalking prompt is rejected by the natural-language intent
 *       scan, exactly as on the web (window.MirrorTrace.runPolicyGate) and actor
 *       paths.
 *   (2) SELF-ONLY for broker opt-out — a broker opt-out for a public_figure /
 *       brand / another person is refused (DeleteMe/Aura authorization model).
 *   (3) REUSE, NOT RE-IMPLEMENT — the handlers call the SAME exported gate and
 *       planners (shared/scope.js, broker-optout.js, takedown-letter.js,
 *       stix-evidence.js); proven by identity of refusal payloads/plan output.
 *
 * REFERENCE ARCHITECTURES (cited per round directive):
 *   - DeleteMe / Aura data-broker opt-out: authorization-gated, self-only removal,
 *     act only on confirmed listings (aura.com/data-removal-service).
 *   - GDPR Article 17 RTBF erasure-request automation: third-party data-subject
 *     erasure channel, drafted as a template the user sends (Reg. (EU) 2016/679).
 *   - Apify MCP server contract (tools/list + tools/call, Streamable HTTP since
 *     2026-04-01): docs.apify.com/platform/integrations/mcp.
 *
 * NO FAKE DATA: asserts real refusals and real planner reuse; no mocks of the gate.
 */

'use strict';

const assert = require('assert');

const server = require('./server.js');
const { listTools, callTool } = server;

// The REAL modules the server must reuse — imported here independently so we can
// assert the server's output is byte-identical to calling them directly (= reuse).
const { validateScope } = require('../shared/scope.js');
const { buildBrokerOptOutPlan } = require('../shared/aux/broker-optout.js');
const { buildTakedownPlan } = require('../shared/aux/takedown-letter.js');

const NOW = '2026-01-01T00:00:00.000Z';

let failures = 0;
function t(name, fn) {
  try {
    fn();
    console.log(`  PASS  ${name}`);
  } catch (err) {
    failures += 1;
    console.error(`  FAIL  ${name}`);
    console.error(`        ${err && err.message ? err.message : err}`);
  }
}

const TOOL_NAMES = ['audit_scope_check', 'plan_broker_optout', 'build_takedown_letter'];

// ── tools/list contract ──────────────────────────────────────────────────────
t('listTools() exposes exactly the three gated tools with inputSchema', () => {
  const tools = listTools();
  const names = tools.map((x) => x.name).sort();
  assert.deepStrictEqual(names, [...TOOL_NAMES].sort());
  for (const tdef of tools) {
    assert.ok(tdef.description && typeof tdef.description === 'string', `${tdef.name} has a description`);
    assert.strictEqual(tdef.inputSchema.type, 'object', `${tdef.name} declares an object inputSchema`);
  }
});

t('callTool() on an unknown tool fails closed', () => {
  const r = callTool('scrape_private_followers', { scope_type: 'self' });
  assert.strictEqual(r.ok, false);
  assert.strictEqual(r.refused, true);
  assert.match(r.refused_by, /callTool/);
});

// ── (1) FAIL-CLOSED ON PROHIBITED scope_type — for EVERY tool ─────────────────
for (const name of TOOL_NAMES) {
  t(`${name}: rejects prohibited scope_type "private_person_tracking" (fail closed)`, () => {
    const r = callTool(name, {
      scope_type: 'private_person_tracking',
      subject_label: 'a private person',
      target_urls: ['https://example.com/x'],
    });
    assert.strictEqual(r.ok, false, 'must not return ok:true');
    assert.strictEqual(r.refused, true, 'must be a refusal');
    assert.ok(
      /scope|disallowed|self|broker_optout_requires_self/i.test(JSON.stringify(r.violated_red_lines || r.reasons)),
      'refusal must cite a scope/self red line',
    );
    assert.strictEqual(r.result, undefined, 'no planner result on refusal');
  });

  t(`${name}: rejects laundered/stalking freeText under scope_type="self"`, () => {
    const r = callTool(name, {
      scope_type: 'self',
      subject_label: 'me',
      target_urls: ['https://example.com/x'],
      // scope_type looks innocent; the PROMPT is stalking → intent scan must catch it.
      freeText: 'track a private person girlfriend and alert me whenever this person posts',
    });
    assert.strictEqual(r.ok, false, 'laundered stalking prompt must be refused');
    assert.strictEqual(r.refused, true);
    assert.ok(
      JSON.stringify(r.violated_red_lines || []).includes('prohibited_intent') ||
        /private person|track/i.test(JSON.stringify(r.reasons || [])),
      'refusal must come from the natural-language intent scan',
    );
  });

  t(`${name}: rejects private-social host even with a clean scope_type`, () => {
    const r = callTool(name, {
      scope_type: 'self',
      subject_label: 'me',
      target_urls: ['https://www.instagram.com/someone/followers'],
    });
    assert.strictEqual(r.ok, false, 'private-social host must be blocked');
    assert.strictEqual(r.refused, true);
  });
}

// ── (1c) The refusal IS the canonical gate's output (REUSE, not re-implement) ──
t('refusal payload mirrors shared/scope.js::validateScope verbatim (reuse)', () => {
  const args = { scope_type: 'private_person_tracking', subject_label: 'a private person', target_urls: ['https://example.com/x'] };
  const r = callTool('audit_scope_check', args);
  const gate = validateScope({
    scope_type: args.scope_type,
    subject_label: args.subject_label,
    target_urls: args.target_urls,
  });
  assert.strictEqual(gate.allowed, false, 'sanity: the real gate rejects this');
  // The server returns the gate's OWN reasons / violated_red_lines / alternatives.
  assert.deepStrictEqual(r.reasons, gate.reasons);
  assert.deepStrictEqual(r.violated_red_lines, gate.violated_red_lines);
  assert.deepStrictEqual(r.alternatives, gate.alternatives);
  assert.match(r.refused_by, /shared\/scope\.js/);
});

// ── (2) SELF-ONLY for broker opt-out ─────────────────────────────────────────
t('plan_broker_optout: refuses public_figure (self-only, DeleteMe/Aura model)', () => {
  // public_figure PASSES the generic scope gate, so this proves the SELF-ONLY rule
  // (not merely the scope allow-list) is enforced through the tool.
  const passesGate = validateScope({
    scope_type: 'public_figure',
    target_urls: ['https://example.com/x'],
  });
  assert.strictEqual(passesGate.allowed, true, 'sanity: public_figure passes the generic gate');

  const r = callTool('plan_broker_optout', {
    scope_type: 'public_figure',
    subject_label: 'A Mayor',
    confirmed_listings: [{ broker_id: 'spokeo', listing_url: 'https://www.spokeo.com/x', confirmed_self: true }],
  });
  assert.strictEqual(r.ok, false, 'public_figure broker opt-out must be refused');
  assert.strictEqual(r.refused, true);
  assert.match(r.refused_by, /broker-optout\.js/, 'refusal comes from the reused planner');
  assert.ok(
    JSON.stringify(r.violated_red_lines || []).includes('broker_optout_requires_self'),
    'must cite the self-only red line',
  );
});

t('plan_broker_optout: rejects consented WITHOUT authorization_evidence_url', () => {
  const r = callTool('plan_broker_optout', {
    scope_type: 'consented',
    subject_label: 'Friend',
    confirmed_listings: [{ broker_id: 'spokeo', listing_url: 'https://www.spokeo.com/x', confirmed_self: true }],
  });
  assert.strictEqual(r.ok, false, 'consented w/o written authorization must be refused');
  assert.strictEqual(r.refused, true);
});

// ── (2b) HAPPY PATH for self, and proof it REUSES the planner verbatim ────────
t('plan_broker_optout: self happy-path output equals buildBrokerOptOutPlan (reuse)', () => {
  const args = {
    scope_type: 'self',
    subject_label: 'Jane Q',
    confirmed_listings: [{ broker_id: 'spokeo', listing_url: 'https://www.spokeo.com/x', confirmed_self: true }],
    now: NOW,
  };
  const r = callTool('plan_broker_optout', args);
  assert.strictEqual(r.ok, true, 'self broker opt-out must be allowed');
  assert.strictEqual(r.result.record_type, 'broker_optout_plan');
  assert.strictEqual(r.result.is_template, true, 'template honesty preserved');

  const direct = buildBrokerOptOutPlan(
    {
      scope_type: args.scope_type,
      subject_label: args.subject_label,
      confirmed_listings: args.confirmed_listings,
    },
    { now: NOW },
  );
  assert.strictEqual(
    JSON.stringify(r.result),
    JSON.stringify(direct),
    'server must return the planner output unchanged (no duplication / re-implementation)',
  );
});

// ── (3) build_takedown_letter reuses takedown-letter.js + attaches STIX ───────
t('build_takedown_letter: self happy-path reuses buildTakedownPlan + STIX bundle', () => {
  const events = [
    {
      event_type: 'PII_HANDLE_PUBLIC',
      source_module: 'mcp_selftest',
      data: { broker: 'Spokeo' },
      confidence: 1,
      visibility: 'INDEXED',
      risk: 'HIGH',
      source_url: 'https://www.spokeo.com/x',
      meta: { is_data_broker: true },
    },
  ];
  const r = callTool('build_takedown_letter', { scope_type: 'self', subject_label: 'Jane Q', events, now: NOW });
  assert.strictEqual(r.ok, true);
  assert.strictEqual(r.takedown_plan.record_type, 'takedown_plan');
  assert.strictEqual(r.takedown_plan.is_template, true, 'letters are a template; nothing sent');
  assert.strictEqual(r.evidence_bundle.type, 'bundle', 'STIX 2.1 bundle attached for Art.17 provenance');

  const direct = buildTakedownPlan({ events, ownedHosts: [], subjectName: 'Jane Q' });
  assert.strictEqual(
    JSON.stringify(r.takedown_plan),
    JSON.stringify(direct),
    'takedown plan must be the reused planner output, unchanged',
  );
});

// ── audit_scope_check is gate-only: it must NEVER emit footprint data ─────────
t('audit_scope_check: in-scope self returns a decision only, no footprint data', () => {
  const r = callTool('audit_scope_check', {
    scope_type: 'self',
    subject_label: 'me',
    target_urls: ['https://example.com/me'],
  });
  assert.strictEqual(r.ok, true);
  assert.strictEqual(r.allowed, true);
  assert.strictEqual(r.scope_type, 'self');
  // It exposes only the gate's normalized echo — never findings / scraped output.
  assert.deepStrictEqual(Object.keys(r).sort(), ['allowed', 'normalized', 'note', 'ok', 'scope_type', 'tool'].sort());
});

console.log(`\nmcp server self-test: ${failures === 0 ? 'OK' : failures + ' FAILURE(S)'}`);
process.exit(failures === 0 ? 0 : 1);
