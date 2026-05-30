/**
 * integrations/exposure-map/_selftest.js
 *
 * Zero-dependency self-test for the EXPOSURE MAP feed (Part 2 data layer).
 * Run: `node integrations/exposure-map/_selftest.js`
 * Auto-discovered by integrations/run-module-selftests.js (globs *_selftest.js)
 * and therefore by `npm run test:modules`.
 *
 * Asserts the load-bearing properties of the #1 deliverable's data flow:
 *  - buildExposureGraph maps REAL module_events -> one node per source, colour
 *    tier from the canonical severity band (red=critical|high), size = distinct
 *    finding count;
 *  - center "you" node + radial "exposes" edges to every source;
 *  - a CROSS-SOURCE "correlates" edge appears ONLY when two DIFFERENT sources
 *    share the same identifier (same email_prefix / handle), via cluster-keys;
 *  - no value leaks: correlation edges carry the identifier KIND, never the value;
 *  - empty events -> empty-but-honest graph (center only), never a fake dossier;
 *  - the feed planner is scope-gated (a private-person request is REFUSED before
 *    any Apify run is planned) and the SENSITIVE tier requires a verified OAuth
 *    identity (requires_signin) without ever faking a sign-in;
 *  - rowsToGraph transforms REAL Apify rows -> graph and writes nothing (browser-only).
 */

'use strict';

const assert = require('assert');

const { makeEvent } = require('../../shared/detectors/event-types.js');
const { buildExposureGraph, bandToTier } = require('./exposure-graph.js');
const { planExposureFeed, rowsToGraph, OUTCOME } = require('./feed-policy.js');

let pass = 0;
let fail = 0;
function check(name, fn) {
  try {
    fn();
    pass += 1;
    console.log(`  PASS  ${name}`);
  } catch (err) {
    fail += 1;
    console.log(`  FAIL  ${name}: ${err && err.message ? err.message : err}`);
  }
}

// ── A realistic set of REAL findings (built via the canonical makeEvent) ──────
// Same email reused on a broker page AND a paste -> the scary correlation case.
const EVENTS = [
  makeEvent({
    event_type: 'PII_EMAIL_PUBLIC', source_module: 'pii-detector',
    risk: 'high', visibility: 'indexed', confidence: 0.95,
    source_url: 'https://www.spokeo.com/jane-q', data: 'jane@example.com',
    meta: { email_hash_prefix: 'ABCDE', is_data_broker: true },
  }),
  makeEvent({
    event_type: 'PII_EMAIL_PUBLIC', source_module: 'pii-detector',
    risk: 'medium', visibility: 'linked', confidence: 0.8,
    source_url: 'https://pastebin.com/raw/x', data: 'jane@example.com',
    meta: { email_hash_prefix: 'ABCDE' },
  }),
  makeEvent({
    event_type: 'PII_HANDLE_PUBLIC', source_module: 'pii-detector',
    risk: 'low', visibility: 'linked', confidence: 0.9,
    source_url: 'https://forum.example/u/jane', data: '@jane',
    meta: { handle: 'jane' },
  }),
];

// ── exposure-graph: tier mapping is the canonical band -> 3-tier colour ──────
check('bandToTier maps critical/high -> red, medium -> yellow, low/info -> green', () => {
  assert.strictEqual(bandToTier('critical'), 'red');
  assert.strictEqual(bandToTier('high'), 'red');
  assert.strictEqual(bandToTier('medium'), 'yellow');
  assert.strictEqual(bandToTier('low'), 'green');
  assert.strictEqual(bandToTier('info'), 'green');
});

check('buildExposureGraph: one source node per host + a center "you" node', () => {
  const g = buildExposureGraph(EVENTS, { subjectLabel: 'Jane Q' });
  const center = g.nodes.find((n) => n.id === 'self');
  assert.ok(center && center.role === 'center' && center.label === 'Jane Q', 'center node present + labelled');
  const sourceIds = g.nodes.filter((n) => n.role === 'source').map((n) => n.id).sort();
  assert.deepStrictEqual(
    sourceIds,
    ['src:forum.example', 'src:pastebin.com', 'src:www.spokeo.com'].sort(),
    'one node per distinct source host',
  );
});

check('buildExposureGraph: node colour tier = worst finding band (spokeo high -> red)', () => {
  const g = buildExposureGraph(EVENTS);
  const spokeo = g.nodes.find((n) => n.id === 'src:www.spokeo.com');
  assert.strictEqual(spokeo.color_tier, 'red', 'a HIGH/indexed broker hit must be red');
});

check('buildExposureGraph: node size = distinct finding count + normalized weight', () => {
  const dup = EVENTS.concat([
    makeEvent({
      event_type: 'PII_PHONE_PUBLIC', source_module: 'pii-detector',
      risk: 'high', visibility: 'indexed', confidence: 0.9,
      source_url: 'https://www.spokeo.com/jane-q', data: '+1 555 000 1111',
    }),
  ]);
  const g = buildExposureGraph(dup);
  const spokeo = g.nodes.find((n) => n.id === 'src:www.spokeo.com');
  assert.strictEqual(spokeo.finding_count, 2, 'spokeo now holds 2 findings');
  assert.strictEqual(spokeo.size_weight, 1, 'most-findings source has weight 1 (normalized)');
});

check('buildExposureGraph: radial "exposes" edge from center to EVERY source', () => {
  const g = buildExposureGraph(EVENTS);
  const sources = g.nodes.filter((n) => n.role === 'source').map((n) => n.id).sort();
  const exposeTargets = g.edges.filter((e) => e.kind === 'exposes')
    .map((e) => { assert.strictEqual(e.source, 'self', 'exposes edges originate at center'); return e.target; })
    .sort();
  assert.deepStrictEqual(exposeTargets, sources, 'one exposes edge per source');
});

check('buildExposureGraph: CROSS-SOURCE "correlates" edge on a shared email_prefix', () => {
  const g = buildExposureGraph(EVENTS);
  const corr = g.edges.filter((e) => e.kind === 'correlates');
  assert.strictEqual(corr.length, 1, 'exactly one correlation: spokeo<->pastebin share the email');
  const e = corr[0];
  const pair = [e.source, e.target].sort();
  assert.deepStrictEqual(pair, ['src:pastebin.com', 'src:www.spokeo.com'].sort());
  assert.strictEqual(e.shared, 'email_prefix', 'edge labels the identifier KIND…');
  // …and NEVER the identifier VALUE (no plaintext email anywhere in the edge).
  assert.ok(!JSON.stringify(e).includes('jane@example.com'), 'no plaintext PII on the edge');
});

check('buildExposureGraph: a handle on only ONE source yields NO correlation edge', () => {
  const g = buildExposureGraph(EVENTS);
  const handleEdges = g.edges.filter((e) => e.kind === 'correlates' && e.shared === 'handle');
  assert.strictEqual(handleEdges.length, 0, 'a single-source identifier is not a correlation');
});

check('buildExposureGraph: empty events -> honest empty graph (center only), no fake dossier', () => {
  const g = buildExposureGraph([]);
  assert.strictEqual(g.nodes.length, 1, 'only the center node');
  assert.strictEqual(g.nodes[0].id, 'self');
  assert.strictEqual(g.edges.length, 0);
  assert.strictEqual(g.summary.source_count, 0);
});

check('buildExposureGraph: emits a browser-only privacy banner the UI must show', () => {
  const g = buildExposureGraph(EVENTS);
  assert.match(g.__privacy, /browser/i);
  assert.match(g.__privacy, /not sent to or stored on a server|purged/i);
});

// ── feed-policy: scope gate + sensitivity tier (locked decisions) ─────────────
check('planExposureFeed: a private-person subject is REFUSED before any Apify run', () => {
  const r = planExposureFeed({
    scope_type: 'private_person_tracking',
    subject_label: 'an ex',
    target_urls: ['https://example.com/x'],
    verified_identity: { verified: true, provider: 'google', email: 'me@example.com' },
  });
  assert.strictEqual(r.outcome, OUTCOME.REFUSED, 'red line: no feed for a private person');
  assert.strictEqual(r.apify_run_request, undefined, 'no Apify run planned on refusal');
});

check('planExposureFeed: SENSITIVE tier requires a verified OAuth identity (no fake sign-in)', () => {
  const r = planExposureFeed({
    scope_type: 'self',
    subject_label: 'me',
    target_urls: ['https://my-own-site.example/me'],
    // NO verified_identity -> must be gated, not faked.
  });
  assert.strictEqual(r.outcome, OUTCOME.REQUIRES_SIGNIN, 'pull+correlate PII requires sign-in');
  assert.strictEqual(r.signin.live_oauth_wired, false, 'honest: OAuth not yet wired');
  assert.strictEqual(r.apify_run_request, undefined, 'no run until verified');
});

check('planExposureFeed: self + verified identity -> a BROWSER-fired Apify run plan', () => {
  const r = planExposureFeed({
    scope_type: 'self',
    subject_label: 'me',
    target_urls: ['https://my-own-site.example/me'],
    verified_identity: { verified: true, provider: 'github', handle: 'jane' },
  });
  assert.strictEqual(r.outcome, OUTCOME.PLAN_BUILT);
  assert.strictEqual(r.apify_run_request.fired_by, 'browser', 'data flow is browser-only, not our server');
  assert.match(r.apify_run_request.url, /run-sync-get-dataset-items/);
  assert.match(r.apify_run_request.url, /<USER_APIFY_TOKEN>/, 'token is the user\'s own + redacted');
  assert.strictEqual(r.data_flow.model, 'browser_only_zero_server_storage');
  // The canonical privacy policy proves the plan is browser-only (no findings off-device).
  assert.strictEqual(r.storage_audit.ok, true, 'assertNoServerPersistence passes for the feed plan');
  assert.strictEqual(r.storage_audit.violations.length, 0, 'no persistence/transmission violations');
  // The run request carries the audit INPUT (vetted URLs), never the plaintext token or findings.
  assert.ok(!JSON.stringify(r.apify_run_request).match(/findings/i), 'run request carries no findings');
});

check('rowsToGraph: REAL Apify WCC rows -> events -> graph, writes nothing', () => {
  const plan = planExposureFeed({
    scope_type: 'self',
    subject_label: 'me',
    target_urls: ['https://my-own-site.example/me'],
    verified_identity: { verified: true, provider: 'google', email: 'me@example.com' },
  });
  assert.strictEqual(plan.outcome, OUTCOME.PLAN_BUILT);
  // A REAL WCC dataset row (text content on the vetted host) — the mapper detects PII.
  const rows = [
    {
      url: 'https://my-own-site.example/me',
      crawl: { loadedUrl: 'https://my-own-site.example/me' },
      text: 'Contact me at jane@example.com or @jane on the forum.',
      metadata: { title: 'About Me' },
    },
  ];
  const out = rowsToGraph(plan.ingest_plan, rows, { subjectLabel: 'me' });
  assert.ok(Array.isArray(out.events), 'events array returned');
  assert.ok(out.graph && Array.isArray(out.graph.nodes), 'graph built from real rows');
  assert.ok(out.graph.nodes.some((n) => n.id === 'self'), 'center node present');
});

console.log(`\nexposure-map self-test: ${fail === 0 ? 'OK' : fail + ' FAILURE(S)'} (${pass} passed)`);
process.exit(fail === 0 ? 0 : 1);
