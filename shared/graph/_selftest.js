#!/usr/bin/env node
/**
 * shared/graph/_selftest.js
 *
 * Dependency-free self-test for the Exposure Map builder. Run with:
 *   node shared/graph/_selftest.js
 * Auto-discovered by integrations/run-module-selftests.js (npm run test:modules).
 *
 * Proves the model on TWO honest inputs:
 *   1. The REAL produced report web/data/example-report.json (unmodified). We
 *      assert what is actually TRUE of it: one node per distinct source host, the
 *      hostless breach finding becomes its own origin node, tiers map from the
 *      report's own severity_band, exposes edges fan out from center, and — since
 *      that report genuinely has only ONE web host — there is NO fabricated
 *      cross-source link. (Honesty: we do not pretend a correlation that isn't
 *      in the data.)
 *   2. A clearly-labelled SYNTHETIC multi-source report built from the SAME
 *      finding shape across THREE hosts, where two hosts publish the SAME email
 *      and a third shares a handle. This exercises multi-tier node coverage
 *      (red/yellow/green) and the `shared-identifier` cross-source edges — the
 *      Maltego/SpiderFoot correlation picture. Nothing here is presented as real
 *      data; it is a structural fixture for the linking logic.
 *
 * NO FAKE DATA: the builder is pure and operates only on the findings handed in.
 */

'use strict';

const assert = require('assert');
const path = require('path');
const { emailHashKey } = require('../aux/kanon.js');
const { buildExposureGraph, tierForBand } = require('./build-exposure-graph.js');

let pass = 0;
function t(name, fn) {
  try { fn(); pass += 1; console.log(`  PASS  ${name}`); }
  catch (e) { console.error(`  FAIL  ${name}: ${e.message}`); process.exitCode = 1; }
}

console.log('[exposure-graph] real example-report.json');

const example = require(path.join(__dirname, '..', '..', 'web', 'data', 'example-report.json'));
const g = buildExposureGraph(example);

t('center is the self subject', () => {
  assert.strictEqual(g.center.id, 'self');
  assert.ok(typeof g.center.label === 'string' && g.center.label.length > 0);
});

t('one node per distinct source host (+ hostless breach origin gets its own node)', () => {
  const hostNode = g.nodes.find((n) => n.id === 'host:self-demo.example');
  const breachNode = g.nodes.find((n) => n.id === 'origin:breach_range_detector');
  assert.ok(hostNode, 'expected a node for self-demo.example');
  assert.ok(breachNode, 'expected the hostless breach finding to become an origin node');
  // No duplicate source nodes.
  assert.strictEqual(new Set(g.nodes.map((n) => n.id)).size, g.nodes.length);
});

t('node tiers map from the report severity_band (critical/high->red, medium->yellow)', () => {
  const hostNode = g.nodes.find((n) => n.id === 'host:self-demo.example');
  const breachNode = g.nodes.find((n) => n.id === 'origin:breach_range_detector');
  // host carries critical findings -> red
  assert.strictEqual(hostNode.severityTier, 'red');
  // breach finding is medium-band -> yellow
  assert.strictEqual(breachNode.severityTier, 'yellow');
});

t('infoCount = distinct findings at a source; findingRefs point back into report.findings', () => {
  const hostNode = g.nodes.find((n) => n.id === 'host:self-demo.example');
  assert.strictEqual(hostNode.infoCount, hostNode.findingRefs.length);
  assert.strictEqual(hostNode.infoCount, 9); // 9 of 10 findings live on the host
  // every ref resolves to a real finding on that host
  for (const ref of hostNode.findingRefs) {
    const f = example.findings[ref];
    assert.ok(f, `findingRef ${ref} must resolve`);
  }
});

t('every source has a center -> source exposes edge', () => {
  const exposes = g.edges.filter((e) => e.kind === 'exposes');
  assert.strictEqual(exposes.length, g.nodes.length);
  assert.ok(exposes.every((e) => e.from === 'self'));
  const targets = new Set(exposes.map((e) => e.to));
  assert.ok(g.nodes.every((n) => targets.has(n.id)));
});

t('NO fabricated cross-source link: the real report has only one web host', () => {
  // honest negative: the example genuinely cannot correlate two hosts.
  assert.strictEqual(g.edges.filter((e) => e.kind === 'shared-identifier').length, 0);
  assert.strictEqual(g.meta.shared_identifier_links, 0);
});

t('nodes are deterministically ordered (severityScore desc, then host)', () => {
  for (let i = 1; i < g.nodes.length; i += 1) {
    assert.ok(g.nodes[i - 1].severityScore >= g.nodes[i].severityScore,
      'nodes must be sorted by severityScore desc');
  }
  // builder is deterministic: same input -> identical model
  assert.deepStrictEqual(buildExposureGraph(example), g);
});

t('legend explains color/size/edges so the map is self-describing', () => {
  assert.ok(Array.isArray(g.legend.color) && g.legend.color.length === 3);
  assert.ok(g.legend.color.some((c) => c.tier === 'red'));
  assert.ok(typeof g.legend.size === 'string');
  assert.ok(g.legend.edges.some((e) => e.kind === 'shared-identifier'));
});

t('empty report -> center only (no fabricated spokes)', () => {
  const empty = buildExposureGraph({ findings: [] });
  assert.strictEqual(empty.center.id, 'self');
  assert.deepStrictEqual(empty.nodes, []);
  assert.deepStrictEqual(empty.edges, []);
  assert.strictEqual(empty.meta.source_count, 0);
  // missing/garbage input is handled without throwing
  assert.strictEqual(buildExposureGraph(null).nodes.length, 0);
  assert.strictEqual(buildExposureGraph({}).nodes.length, 0);
});

// ───────────────────────────────────────────────────────────────────────────
// SYNTHETIC multi-source fixture (clearly labelled) — exercises multi-tier node
// coverage AND the shared-identifier correlation edges. Built from the SAME
// report finding shape; presented as a structural fixture, not as real data.
// ───────────────────────────────────────────────────────────────────────────
console.log('[exposure-graph] SYNTHETIC multi-source correlation fixture (labelled)');

const SHARED_EMAIL = 'jane@example.com';
const EMAIL_PREFIX = emailHashKey(SHARED_EMAIL).email_hash_prefix;

const syntheticReport = {
  __label: 'SYNTHETIC FIXTURE for shared/graph/_selftest.js — NOT a real audit',
  generated_at: '2026-05-30T00:00:00.000Z',
  findings: [
    // host A (forum): publishes the shared email + a handle. critical -> red.
    { event_type: 'PII_EMAIL_PUBLIC', source_module: 'pii_detector', risk: 'high', visibility: 'indexed', confidence: 0.95, source_url: 'https://forum.example/u/jane', severity_band: 'critical', data: SHARED_EMAIL },
    { event_type: 'PII_HANDLE_PUBLIC', source_module: 'pii_detector', risk: 'low', visibility: 'linked', confidence: 0.6, source_url: 'https://forum.example/u/jane', severity_band: 'medium', meta: { handle: 'jane' } },
    // host B (broker): publishes the SAME email. medium -> yellow.
    { event_type: 'PII_EMAIL_PUBLIC', source_module: 'pii_detector', risk: 'medium', visibility: 'linked', confidence: 0.9, source_url: 'https://broker.example/listing/123', severity_band: 'medium', data: SHARED_EMAIL },
    // host C (blog): shares the SAME handle as host A; only low trivia -> green.
    { event_type: 'PII_HANDLE_PUBLIC', source_module: 'pii_detector', risk: 'low', visibility: 'linked', confidence: 0.55, source_url: 'https://blog.example/about', severity_band: 'low', meta: { handle: 'jane' } },
  ],
};

const sg = buildExposureGraph(syntheticReport);

t('produces multiple nodes spanning red, yellow and green tiers', () => {
  const tiers = new Set(sg.nodes.map((n) => n.severityTier));
  assert.ok(sg.nodes.length >= 3, `expected >=3 source nodes, got ${sg.nodes.length}`);
  assert.ok(tiers.has('red'), 'expected a red node');
  assert.ok(tiers.has('yellow'), 'expected a yellow node');
  assert.ok(tiers.has('green'), 'expected a green node');
});

t('shared-identifier edge links the two hosts publishing the SAME email', () => {
  const sharedEmail = sg.edges.filter((e) => e.kind === 'shared-identifier' && e.via === 'email');
  assert.ok(sharedEmail.length >= 1, 'expected at least one shared-identifier (email) edge');
  const pair = sharedEmail.find((e) =>
    (e.from === 'host:broker.example' && e.to === 'host:forum.example')
    || (e.from === 'host:forum.example' && e.to === 'host:broker.example'));
  assert.ok(pair, 'forum and broker must be linked by the shared email');
});

t('shared-identifier edge links the two hosts sharing the SAME handle', () => {
  const sharedHandle = sg.edges.filter((e) => e.kind === 'shared-identifier' && e.via === 'handle');
  assert.ok(sharedHandle.length >= 1, 'expected a shared-identifier (handle) edge');
});

t('cross-source edges never leak the identifier VALUE (only via=email/handle)', () => {
  for (const e of sg.edges.filter((x) => x.kind === 'shared-identifier')) {
    assert.ok(e.via === 'email' || e.via === 'handle');
    // the email prefix / handle text must NOT appear on the edge
    assert.ok(!JSON.stringify(e).includes(EMAIL_PREFIX));
    assert.ok(!JSON.stringify(e).includes(SHARED_EMAIL));
    assert.ok(!JSON.stringify(e).toLowerCase().includes('jane'));
  }
});

t('shared-identifier edges are deterministic and de-duplicated', () => {
  const again = buildExposureGraph(syntheticReport);
  assert.deepStrictEqual(again.edges, sg.edges);
  const ids = sg.edges
    .filter((e) => e.kind === 'shared-identifier')
    .map((e) => `${e.from}|${e.to}|${e.via}`);
  assert.strictEqual(new Set(ids).size, ids.length, 'no duplicate cross-source edges');
});

t('tierForBand projection matches the locked mapping', () => {
  assert.strictEqual(tierForBand('critical'), 'red');
  assert.strictEqual(tierForBand('high'), 'red');
  assert.strictEqual(tierForBand('medium'), 'yellow');
  assert.strictEqual(tierForBand('low'), 'green');
  assert.strictEqual(tierForBand('info'), 'green');
});

console.log(`\nOK — exposure-graph self-test, ${pass} passed.`);
