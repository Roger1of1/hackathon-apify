#!/usr/bin/env node
/**
 * shared/enrich/breach-evidence_selftest.js
 *
 * Dependency-free self-tests for the breach-evidence enrichment. Run with:
 *   node shared/enrich/breach-evidence_selftest.js
 *
 * NO FAKE DATA: real BREACH_RANGE_HIT events produced by the actual detector,
 * honest synthetic bucket sizes; no fabricated breach hits or counts.
 */

'use strict';

const assert = require('assert');
const { EVENT_TYPES, makeEvent } = require('../detectors/event-types.js');
const { detectBreachInRange, toRange } = require('../detectors/breach-range-detector.js');
const {
  isBreachHit, observedBucketSize, breachEvidence, enrichBreachEvents,
} = require('./breach-evidence.js');

let pass = 0;
function t(name, fn) {
  try { fn(); pass += 1; console.log(`  PASS  ${name}`); }
  catch (e) { console.error(`  FAIL  ${name}: ${e.message}`); process.exitCode = 1; }
}

// Build a REAL breach hit the way the detector does: hash a self credential,
// then hand the detector a bucket that genuinely contains that suffix.
function realBreachHit({ bucket_size, breach_count = 1234 } = {}) {
  const { suffix } = toRange('a-credential-i-am-auditing');
  const rangeMap = new Map([[suffix.toUpperCase(), breach_count]]);
  const [ev] = detectBreachInRange({ suffix, rangeMap, scope_type: 'self' });
  assert.ok(ev, 'detector should emit a hit for a suffix present in the bucket');
  if (typeof bucket_size === 'number') ev.meta = { ...ev.meta, bucket_size };
  return ev;
}

console.log('[breach-evidence / guards]');
t('isBreachHit only matches BREACH_RANGE_HIT module_events', () => {
  assert.strictEqual(isBreachHit(realBreachHit()), true);
  const pii = makeEvent({ event_type: EVENT_TYPES.PII_EMAIL_PUBLIC, source_module: 'pii_detector', data: 'a@b.com' });
  assert.strictEqual(isBreachHit(pii), false);
  assert.strictEqual(isBreachHit(null), false);
  assert.strictEqual(isBreachHit({ event_type: EVENT_TYPES.BREACH_RANGE_HIT }), false);
});

t('observedBucketSize reads meta.bucket_size / k / range_bucket_size, else null', () => {
  assert.strictEqual(observedBucketSize(realBreachHit({ bucket_size: 400 })), 400);
  const ev = realBreachHit();
  ev.meta = { ...ev.meta, k: 250 };
  assert.strictEqual(observedBucketSize(ev), 250);
  const ev2 = realBreachHit();
  assert.strictEqual(observedBucketSize(ev2), null); // none recorded -> honest null
});

console.log('[breach-evidence / breachEvidence combine]');
t('healthy bucket -> no confidence penalty, clean rationale', () => {
  const be = breachEvidence(realBreachHit({ bucket_size: 500 }));
  assert.ok(be && be.ok);
  assert.strictEqual(be.kanon.band, 'strong');
  assert.strictEqual(be.kanon.anonymous, true);
  // event confidence is 0.99; strong anonymity caps at 1.0 -> unchanged
  assert.ok(be.effective_confidence >= 0.98, `expected ~0.99, got ${be.effective_confidence}`);
  assert.ok(/clean security-hygiene/i.test(be.rationale));
});

t('degenerate bucket of 1 -> confidence CAPPED, privacy-compromised caveat', () => {
  const be = breachEvidence(realBreachHit({ bucket_size: 1 }));
  assert.strictEqual(be.kanon.band, 'none');
  // 0.99 capped by 0.6 -> < 0.6
  assert.ok(be.effective_confidence < 0.6, `expected capped <0.6, got ${be.effective_confidence}`);
  assert.ok(/privacy-compromised/i.test(be.rationale));
});

t('unknown bucket -> capped to 0.8 factor, honest "not recorded" rationale', () => {
  const be = breachEvidence(realBreachHit()); // no bucket size recorded
  assert.strictEqual(be.kanon.band, 'unknown');
  assert.strictEqual(be.kanon.k, null);
  // 0.99 * 0.8 ~= 0.79
  assert.ok(be.effective_confidence <= 0.8 && be.effective_confidence > 0.7,
    `expected ~0.79, got ${be.effective_confidence}`);
  assert.ok(/cannot be asserted|not recorded/i.test(be.rationale));
});

t('anonymity is a CAP, never a booster (effective <= base confidence)', () => {
  for (const size of [1, 50, 100, 500, undefined]) {
    const ev = realBreachHit(typeof size === 'number' ? { bucket_size: size } : {});
    const be = breachEvidence(ev);
    assert.ok(be.effective_confidence <= ev.confidence + 1e-9,
      `effective ${be.effective_confidence} must not exceed base ${ev.confidence}`);
  }
});

t('carries the non-secret breach_count, never the credential', () => {
  const be = breachEvidence(realBreachHit({ bucket_size: 300, breach_count: 5050 }));
  assert.strictEqual(be.breach_count, 5050);
  const blob = JSON.stringify(be);
  assert.ok(!blob.includes('a-credential-i-am-auditing'), 'secret must never appear in the evidence note');
});

t('non-breach event -> breachEvidence returns null', () => {
  const pii = makeEvent({ event_type: EVENT_TYPES.PII_EMAIL_PUBLIC, source_module: 'pii_detector', data: 'a@b.com' });
  assert.strictEqual(breachEvidence(pii), null);
});

console.log('[breach-evidence / enrichBreachEvents batch]');
t('annotates only breach events, passes others through untouched', () => {
  const pii = makeEvent({ event_type: EVENT_TYPES.PII_EMAIL_PUBLIC, source_module: 'pii_detector', data: 'a@b.com' });
  const breach = realBreachHit({ bucket_size: 400 });
  const out = enrichBreachEvents([pii, breach]);
  assert.strictEqual(out.length, 2);
  assert.strictEqual(out[0]._breach_evidence, undefined); // PII untouched
  assert.ok(out[0] === pii || JSON.stringify(out[0]) === JSON.stringify(pii));
  assert.ok(out[1]._breach_evidence && out[1]._breach_evidence.ok);
  assert.strictEqual(out[1]._breach_evidence.kanon.k, 400);
});

t('empty / non-array input -> empty array, no throw', () => {
  assert.deepStrictEqual(enrichBreachEvents([]), []);
  assert.deepStrictEqual(enrichBreachEvents(null), []);
});

console.log(`\nOK — breach-evidence self-tests, ${pass} passed.`);
