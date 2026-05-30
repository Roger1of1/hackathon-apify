#!/usr/bin/env node
/**
 * shared/detectors/breach-range-contract_selftest.js
 *
 * Dependency-free self-tests for the HIBP k-anonymity split contract. Run with:
 *   node shared/detectors/breach-range-contract_selftest.js
 *
 * NO FAKE DATA: real SHA-1 split, honest synthetic inputs, no fabricated breach
 * counts. We prove the privacy MECHANIC (what leaves vs. stays local), not a hit.
 */

'use strict';

const assert = require('assert');
const crypto = require('crypto');
const {
  HASH_ALGO, HASH_HEX_LEN, PREFIX_LEN, SUFFIX_LEN, RANGE_BUCKETS,
  splitForRangeQuery, proveLocalOnly, kAnonymityQuality,
} = require('./breach-range-contract.js');
const { kAnonPair, sha1Hex } = require('../aux/kanon.js');

let pass = 0;
function t(name, fn) {
  try { fn(); pass += 1; console.log(`  PASS  ${name}`); }
  catch (e) { console.error(`  FAIL  ${name}: ${e.message}`); process.exitCode = 1; }
}

console.log('[breach-range-contract / constants]');
t('split constants match HIBP: SHA-1, 5/35, 16^5 buckets', () => {
  assert.strictEqual(HASH_ALGO, 'SHA-1');
  assert.strictEqual(HASH_HEX_LEN, 40);
  assert.strictEqual(PREFIX_LEN, 5);
  assert.strictEqual(SUFFIX_LEN, 35);
  assert.strictEqual(PREFIX_LEN + SUFFIX_LEN, HASH_HEX_LEN);
  assert.strictEqual(RANGE_BUCKETS, 1048576);
});

console.log('[breach-range-contract / splitForRangeQuery]');
t('reuses aux/kanon.js EXACTLY — UI/actor/module can never drift', () => {
  const secret = 'correct horse battery staple';
  const s = splitForRangeQuery(secret);
  const k = kAnonPair(secret);
  // Same split as the canonical kanon helper.
  assert.strictEqual(s.prefix, k.prefix);
  assert.strictEqual(s.suffix, k.suffix);
  assert.strictEqual(s.full, k.hash);
});

t('only the 5-char prefix is marked "sent"; 35-char suffix is "kept"', () => {
  const s = splitForRangeQuery('hunter2');
  assert.strictEqual(s.sent, s.prefix);
  assert.strictEqual(s.kept, s.suffix);
  assert.strictEqual(s.sent.length, 5);
  assert.strictEqual(s.kept.length, 35);
  // The transmitted part is a hash slice, never the secret itself.
  assert.ok(!s.sent.includes('hunter2'));
  assert.ok(!s.kept.includes('hunter2'));
});

t('disclosure text states what crosses the network', () => {
  const s = splitForRangeQuery('p@ssw0rd');
  assert.ok(s.disclosure.includes(s.prefix));
  assert.ok(/never leave/i.test(s.disclosure));
});

t('full hash equals real SHA-1 of the secret (uppercase hex)', () => {
  const secret = 'rotate-me-please';
  const s = splitForRangeQuery(secret);
  const expected = crypto.createHash('sha1').update(secret, 'utf8').digest('hex').toUpperCase();
  assert.strictEqual(s.full, expected);
  assert.strictEqual(s.full, sha1Hex(secret));
});

t('empty / non-string secret throws (no silent fabrication)', () => {
  assert.throws(() => splitForRangeQuery(''));
  assert.throws(() => splitForRangeQuery(null));
  assert.throws(() => splitForRangeQuery(123));
});

console.log('[breach-range-contract / proveLocalOnly]');
t('proves prefix+suffix recombines to the full hash, secret stays local', () => {
  const p = proveLocalOnly('my-real-password');
  assert.strictEqual(p.secret_stays_local, true);
  assert.strictEqual(p.only_prefix_sent, true);
  assert.strictEqual(p.recombines_to_full_hash, true);
  assert.strictEqual(p.sent_length, 5);
  assert.strictEqual(p.kept_length, 35);
});

console.log('[breach-range-contract / kAnonymityQuality]');
t('large real bucket -> strong/anonymous; honest read of k', () => {
  const q = kAnonymityQuality(812);
  assert.strictEqual(q.k, 812);
  assert.strictEqual(q.band, 'strong');
  assert.strictEqual(q.anonymous, true);
});

t('~100 floor -> adequate & anonymous; below 100 -> not anonymous', () => {
  assert.strictEqual(kAnonymityQuality(100).band, 'adequate');
  assert.strictEqual(kAnonymityQuality(100).anonymous, true);
  assert.strictEqual(kAnonymityQuality(50).band, 'weak');
  assert.strictEqual(kAnonymityQuality(50).anonymous, false);
});

t('bucket of 1 -> "none" (no anonymity set); empty -> "none" with no hit', () => {
  const one = kAnonymityQuality(1);
  assert.strictEqual(one.band, 'none');
  assert.strictEqual(one.anonymous, false);
  const zero = kAnonymityQuality(0);
  assert.strictEqual(zero.band, 'none');
  assert.strictEqual(zero.anonymous, false);
});

t('missing bucket size -> "unknown", never a fabricated number', () => {
  for (const bad of [undefined, null, NaN, -3, 'lots']) {
    const q = kAnonymityQuality(bad);
    assert.strictEqual(q.k, null);
    assert.strictEqual(q.band, 'unknown');
    assert.strictEqual(q.anonymous, false);
  }
});

console.log(`\nOK — breach-range-contract self-tests, ${pass} passed.`);
