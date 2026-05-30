#!/usr/bin/env node
/**
 * shared/identity/verification-tiers_selftest.js
 *
 * Dependency-free self-tests for the tiered identity-verification policy.
 * Run:  node shared/identity/verification-tiers_selftest.js
 *
 * NO FAKE DATA: these tests verify the REAL policy mapping and that the module
 * NEVER fabricates a sign-in — a sensitive action with no real verified identity
 * stays unsatisfied.
 */

'use strict';

const assert = require('assert');
const {
  VERIFICATION,
  ACTIONS,
  ACTION_POLICY,
  requiredVerification,
  verificationPolicyFor,
  isVerificationSatisfied,
} = require('./verification-tiers.js');

let pass = 0;
function t(name, fn) {
  try { fn(); pass += 1; console.log(`  PASS  ${name}`); }
  catch (e) { console.error(`  FAIL  ${name}: ${e.message}`); process.exitCode = 1; }
}

console.log('[verification-tiers / self-proving actions → none]');
t('public_search requires none', () => {
  assert.strictEqual(requiredVerification('public_search'), VERIFICATION.NONE);
});
t('kanon_breach_check requires none', () => {
  assert.strictEqual(requiredVerification('kanon_breach_check'), VERIFICATION.NONE);
});

console.log('[verification-tiers / sensitive actions → sign_in]');
for (const a of ['pull_pii', 'build_correlation_graph', 'confirm_broker_listing', 'enable_monitoring']) {
  t(`${a} requires sign_in`, () => {
    assert.strictEqual(requiredVerification(a), VERIFICATION.SIGN_IN);
  });
}

console.log('[verification-tiers / policy integrity]');
t('every action has a tier, sensitive flag, and rationale', () => {
  for (const a of ACTIONS) {
    const p = ACTION_POLICY[a];
    assert.ok(p.tier === VERIFICATION.NONE || p.tier === VERIFICATION.SIGN_IN, `${a} tier`);
    assert.strictEqual(typeof p.sensitive, 'boolean', `${a} sensitive`);
    assert.ok(typeof p.rationale === 'string' && p.rationale.length > 20, `${a} rationale`);
    // sensitivity and tier must agree
    assert.strictEqual(p.sensitive, p.tier === VERIFICATION.SIGN_IN, `${a} tier/sensitive agree`);
  }
});
t('exactly the expected action keys exist', () => {
  assert.deepStrictEqual(
    [...ACTIONS].sort(),
    ['build_correlation_graph', 'confirm_broker_listing', 'enable_monitoring',
      'kanon_breach_check', 'public_search', 'pull_pii'].sort(),
  );
});

console.log('[verification-tiers / unknown action fails closed]');
t('unknown action defaults to sign_in (fail closed)', () => {
  assert.strictEqual(requiredVerification('look_up_random_stranger'), VERIFICATION.SIGN_IN);
  const p = verificationPolicyFor('look_up_random_stranger');
  assert.strictEqual(p.known, false);
  assert.strictEqual(p.tier, VERIFICATION.SIGN_IN);
});

console.log('[verification-tiers / isVerificationSatisfied — never fabricates sign-in]');
t('none-tier action is satisfied without any identity', () => {
  assert.strictEqual(isVerificationSatisfied('public_search', null).ok, true);
  assert.strictEqual(isVerificationSatisfied('kanon_breach_check', undefined).ok, true);
});
t('sign_in action is NOT satisfied without a real verified identity', () => {
  assert.strictEqual(isVerificationSatisfied('build_correlation_graph', null).ok, false);
  assert.strictEqual(isVerificationSatisfied('pull_pii', {}).ok, false);
  // unverified or empty identity must not pass
  assert.strictEqual(isVerificationSatisfied('pull_pii', { verified: false, email: 'a@b.c' }).ok, false);
  assert.strictEqual(isVerificationSatisfied('pull_pii', { verified: true }).ok, false);
});
t('sign_in action IS satisfied by a real verified identity object', () => {
  const r = isVerificationSatisfied('build_correlation_graph',
    { verified: true, email: 'me@example.com', provider: 'google' });
  assert.strictEqual(r.ok, true);
  assert.strictEqual(r.tier, VERIFICATION.SIGN_IN);
  const r2 = isVerificationSatisfied('enable_monitoring',
    { verified: true, handle: 'rogerk', provider: 'github' });
  assert.strictEqual(r2.ok, true);
});

console.log(`\nverification-tiers self-test: ${pass} checks passed`);
