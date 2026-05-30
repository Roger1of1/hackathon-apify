/**
 * test/regression/exposure-graph-verification_selftest.js
 *
 * ADDITIVE regression guard (verifier pass). Auto-discovered by
 * integrations/run-module-selftests.js (matches *_selftest.js). It hardens two
 * load-bearing contracts of the Exposure Map "Part 2" deliverable WITHOUT
 * touching production logic:
 *
 *   1) buildExposureGraph is DETERMINISTIC + HONEST:
 *        - identical input -> byte-identical JSON (stable layout/ordering),
 *        - an empty report yields the center node only (no fabricated spokes),
 *        - cross-source links appear ONLY when an identifier is genuinely reused.
 *   2) requiredVerification FAILS CLOSED:
 *        - sensitive actions require 'sign_in',
 *        - unknown actions default to 'sign_in' (never 'none'),
 *        - isVerificationSatisfied never passes a sensitive action without a real
 *          verified identity (no fabricated sign-in).
 *
 * Pure, no network, no fixtures written. Exits non-zero on any failure.
 */

'use strict';

const assert = require('assert');
const { buildExposureGraph } = require('../../shared/graph/build-exposure-graph.js');
const {
  requiredVerification,
  isVerificationSatisfied,
} = require('../../shared/identity/verification-tiers.js');

let passed = 0;
function ok(label, cond) {
  assert.ok(cond, label);
  passed += 1;
  console.log('  ok  ' + label);
}

// ── 1) buildExposureGraph determinism + honesty ──────────────────────────────

const report = {
  generated_at: '2026-05-30T00:00:00Z',
  findings: [
    { event_type: 'PII_EMAIL_PUBLIC', source_module: 'pii_detector', risk: 'high',
      visibility: 'indexed', confidence: 0.9, source_url: 'https://forum.example/u/x',
      data: 'sam@example.com', severity_band: 'high' },
    { event_type: 'PII_EMAIL_PUBLIC', source_module: 'pii_detector', risk: 'high',
      visibility: 'indexed', confidence: 0.9, source_url: 'https://broker.example/p/9',
      data: 'sam@example.com', severity_band: 'high' },
    { event_type: 'SELF_PROFILE_URL', source_module: 'accounts_detector', risk: 'low',
      visibility: 'indexed', confidence: 0.5, source_url: 'https://blog.example/about',
      severity_band: 'low' },
  ],
};

const g1 = buildExposureGraph(report, { selfLabel: 'You' });
const g2 = buildExposureGraph(report, { selfLabel: 'You' });
ok('buildExposureGraph is deterministic (identical input -> identical JSON)',
  JSON.stringify(g1) === JSON.stringify(g2));

ok('center node is the self subject', g1.center && g1.center.id === 'self');

ok('one node per distinct host source (forum, broker, blog = 3)',
  g1.nodes.length === 3);

ok('every source has a center->source "exposes" edge',
  g1.nodes.every((n) => g1.edges.some((e) => e.kind === 'exposes' && e.from === 'self' && e.to === n.id)));

ok('the reused email yields exactly one cross-source shared-identifier edge',
  g1.edges.filter((e) => e.kind === 'shared-identifier' && e.via === 'email').length === 1);

ok('shared-identifier edge never leaks the raw value (via names the kind only)',
  g1.edges.filter((e) => e.kind === 'shared-identifier')
    .every((e) => e.via === 'email' || e.via === 'handle'));

const empty = buildExposureGraph({ findings: [] });
ok('empty report -> center only, NO fabricated source nodes',
  empty.nodes.length === 0 && empty.edges.length === 0 && empty.center.id === 'self');

const junk = buildExposureGraph(null);
ok('null/junk report fails safe to an honest empty graph',
  junk && Array.isArray(junk.nodes) && junk.nodes.length === 0);

// A single source touching a handle, with no second source, must NOT correlate.
const solo = buildExposureGraph({
  findings: [
    { event_type: 'PII_HANDLE_PUBLIC', source_module: 'pii_detector', risk: 'medium',
      visibility: 'indexed', confidence: 0.8, source_url: 'https://only.example/u',
      data: '@lonely', severity_band: 'medium' },
  ],
});
ok('a handle on only ONE source yields NO correlation edge (no invented links)',
  solo.edges.filter((e) => e.kind === 'shared-identifier').length === 0);

// ── 2) requiredVerification fails closed (no fabricated sign-in) ──────────────

ok('public_search (self-proving) requires no sign-in',
  requiredVerification('public_search') === 'none');
ok('kanon_breach_check (k-anonymity, self-proving) requires no sign-in',
  requiredVerification('kanon_breach_check') === 'none');

ok('build_correlation_graph (sensitive) requires sign_in',
  requiredVerification('build_correlation_graph') === 'sign_in');
ok('pull_pii (sensitive) requires sign_in',
  requiredVerification('pull_pii') === 'sign_in');

ok('UNKNOWN action fails CLOSED to sign_in (never "none")',
  requiredVerification('totally_made_up_action') === 'sign_in');

ok('sensitive action is NOT satisfied without an identity (no fabricated sign-in)',
  isVerificationSatisfied('build_correlation_graph', null).ok === false);
ok('sensitive action is NOT satisfied by a fake/unverified identity object',
  isVerificationSatisfied('build_correlation_graph', { verified: false, email: 'a@b.c' }).ok === false);
ok('sensitive action IS satisfied only by a REAL verified identity',
  isVerificationSatisfied('build_correlation_graph', { verified: true, email: 'a@b.c', provider: 'google' }).ok === true);
ok('self-proving action is always satisfied (tier none)',
  isVerificationSatisfied('public_search', null).ok === true);

console.log('\nexposure-graph + verification regression self-test: OK (' + passed + ' checks passed)');
