#!/usr/bin/env node
/**
 * shared/enrich/finding-confidence_selftest.js
 *
 * Dependency-free self-tests for the Observatory-style per-finding TRUST score.
 * Run: node shared/enrich/finding-confidence_selftest.js
 *
 * NO FAKE DATA: every demerit is derived from a REAL signal on the event
 * (validator verdict, detector confidence, corroboration count from real
 * source_urls, real preservation handles, real last-seen ISO). The baseline-100
 * + weighted-deduction mechanic is taken from Mozilla Observatory's published
 * methodology (MDN Tests & Scoring; mozilla/http-observatory grade.py).
 */

'use strict';

const assert = require('assert');
const { EVENT_TYPES, VISIBILITY, RISK, makeEvent } = require('../detectors/event-types.js');
const {
  BASELINE, DEMERITS, gradeForScore, findingConfidence, enrichConfidence,
} = require('./finding-confidence.js');

let pass = 0;
function t(name, fn) {
  try { fn(); pass += 1; console.log(`  PASS  ${name}`); }
  catch (e) { console.error(`  FAIL  ${name}: ${e.message}`); process.exitCode = 1; }
}

const NOW = '2026-05-30T00:00:00.000Z';
const daysAgo = (n) => new Date(Date.parse(NOW) - n * 24 * 3600 * 1000).toISOString();

function email(value, url = 'https://me.example/contact', confidence = 0.95) {
  return makeEvent({
    event_type: EVENT_TYPES.PII_EMAIL_PUBLIC, source_module: 'pii_detector',
    data: value, confidence, visibility: VISIBILITY.INDEXED, risk: RISK.MEDIUM, source_url: url,
  });
}
const fullIntegrity = { content_sha256: 'a', html_sha256: 'b', html_key: 'k', screenshot_key: 's' };

console.log('[confidence / Observatory baseline-100 + weighted demerits]');
t('a pristine, corroborated, preserved, fresh finding scores A (with bonus)', () => {
  const r = findingConfidence(email('jane@gmail.com'), {
    now: NOW, corroborations: 3, integrity: fullIntegrity, last_observed: daysAgo(2),
  });
  // No demerits; bonus applies because score>=90 & corroborated & preserved & fresh.
  assert.strictEqual(r.demerits.length, 0);
  assert.strictEqual(r.bonuses.length, 1);
  assert.strictEqual(r.trust, 100);
  assert.strictEqual(r.grade, 'A');
});
t('a SUPPRESSED finding (example.com) is heavily demerited to a low grade', () => {
  const r = findingConfidence(email('jane@example.com'), {
    now: NOW, corroborations: 1, integrity: fullIntegrity,
  });
  const codes = r.demerits.map((d) => d.code);
  assert.ok(codes.includes('SUPPRESSED'), 'suppressed demerit applied');
  // 100 - 70 (suppress) - 10 (single sighting) = 20 -> E/F band, never trusted.
  assert.ok(r.trust <= 20, `trust should be low, got ${r.trust}`);
  assert.ok(['E', 'F'].includes(r.grade));
});
t('low detector confidence imposes the documented LOW_CONFIDENCE demerit', () => {
  const r = findingConfidence(email('jane@gmail.com', 'https://me.example', 0.5), {
    now: NOW, corroborations: 2, integrity: fullIntegrity, last_observed: daysAgo(1),
  });
  const codes = r.demerits.map((d) => d.code);
  assert.ok(codes.includes('LOW_CONFIDENCE'));
  assert.strictEqual(r.trust, BASELINE - DEMERITS.LOW_CONFIDENCE.points);
});
t('very low confidence is a bigger demerit than merely low', () => {
  assert.ok(DEMERITS.VERY_LOW_CONFIDENCE.points > DEMERITS.LOW_CONFIDENCE.points);
  const r = findingConfidence(email('x@gmail.com', 'https://me.example', 0.2), {
    now: NOW, corroborations: 2, integrity: fullIntegrity, last_observed: daysAgo(1),
  });
  assert.ok(r.demerits.map((d) => d.code).includes('VERY_LOW_CONFIDENCE'));
});

console.log('[confidence / single sighting, preservation, staleness]');
t('single sighting subtracts SINGLE_SIGHTING points', () => {
  const r = findingConfidence(email('jane@gmail.com'), {
    now: NOW, corroborations: 1, integrity: fullIntegrity, last_observed: daysAgo(1),
  });
  assert.ok(r.demerits.map((d) => d.code).includes('SINGLE_SIGHTING'));
});
t('no preservation handles => NO_PRESERVATION demerit', () => {
  const r = findingConfidence(email('jane@gmail.com'), { now: NOW, corroborations: 2 });
  assert.ok(r.demerits.map((d) => d.code).includes('NO_PRESERVATION'));
});
t('stale last_observed => STALE demerit; fresh one does not', () => {
  const stale = findingConfidence(email('jane@gmail.com'), {
    now: NOW, corroborations: 2, integrity: fullIntegrity, last_observed: daysAgo(200),
  });
  assert.ok(stale.demerits.map((d) => d.code).includes('STALE'));
  const fresh = findingConfidence(email('jane@gmail.com'), {
    now: NOW, corroborations: 2, integrity: fullIntegrity, last_observed: daysAgo(3),
  });
  assert.ok(!fresh.demerits.map((d) => d.code).includes('STALE'));
});
t('NO FAKE DATA: missing last_observed is NOT treated as stale', () => {
  const r = findingConfidence(email('jane@gmail.com'), {
    now: NOW, corroborations: 2, integrity: fullIntegrity, // no last_observed
  });
  assert.ok(!r.demerits.map((d) => d.code).includes('STALE'));
});

console.log('[confidence / Observatory bonus gate ≥ 90]');
t('bonus is withheld when pre-bonus score is below 90 (Observatory rule)', () => {
  // Single sighting (-10) keeps pre-bonus at 90? 100-10=90 -> still >=90, so to
  // force <90 use low confidence too.
  const r = findingConfidence(email('jane@gmail.com', 'https://me.example', 0.5), {
    now: NOW, corroborations: 3, integrity: fullIntegrity, last_observed: daysAgo(1),
  });
  // 100 - 25 (low conf) = 75 < 90 => no bonus even though corroborated+preserved.
  assert.strictEqual(r.bonuses.length, 0);
  assert.strictEqual(r.trust, 75);
});

console.log('[confidence / GRADE_CHART mapping mirrors Observatory steps]');
t('grade bands map score → A..F deterministically', () => {
  assert.strictEqual(gradeForScore(100), 'A');
  assert.strictEqual(gradeForScore(90), 'A');
  assert.strictEqual(gradeForScore(85), 'B');
  assert.strictEqual(gradeForScore(70), 'C');
  assert.strictEqual(gradeForScore(55), 'D');
  assert.strictEqual(gradeForScore(40), 'E');
  assert.strictEqual(gradeForScore(10), 'F');
});

console.log('[confidence / batch enrichment counts corroboration honestly]');
t('enrichConfidence derives corroboration from distinct real source_urls', () => {
  const a = email('dup@gmail.com', 'https://me.example/a');
  const b = email('dup@gmail.com', 'https://me.example/b');
  const out = enrichConfidence([a, b], {
    now: NOW,
    integrityByUrl: { 'https://me.example/a': fullIntegrity, 'https://me.example/b': fullIntegrity },
    lastObservedByUrl: { 'https://me.example/a': daysAgo(1), 'https://me.example/b': daysAgo(1) },
  });
  // Same email on 2 distinct surfaces => corroborations=2 => no SINGLE_SIGHTING.
  for (const ev of out) {
    assert.ok(!ev._confidence.demerits.map((d) => d.code).includes('SINGLE_SIGHTING'));
  }
});
t('enrichConfidence drops non-events and annotates valid ones', () => {
  const out = enrichConfidence([email('jane@gmail.com'), { nope: 1 }], { now: NOW });
  assert.strictEqual(out.length, 1);
  assert.ok(out[0]._confidence && typeof out[0]._confidence.trust === 'number');
});
t('invalid event => trust 0 / grade F, never throws', () => {
  const r = findingConfidence({ record_type: 'nope' }, { now: NOW });
  assert.strictEqual(r.trust, 0);
  assert.strictEqual(r.grade, 'F');
});

console.log(`\nOK — finding-confidence self-test: ${pass} checks passed, ${process.exitCode ? 'with failures' : '0 failures'}.`);
if (process.exitCode) process.exit(process.exitCode);
