#!/usr/bin/env node
/**
 * shared/enrich/freshness_selftest.js
 *
 * Dependency-free self-tests for temporal freshness/decay enrichment. Run:
 *   node shared/enrich/freshness_selftest.js
 *
 * NO FAKE DATA: every freshness verdict is derived from REAL observation
 * timestamps passed in; a finding with no recorded history gets `unknown` and a
 * fabricated age is NEVER produced.
 */

'use strict';

const assert = require('assert');
const { EVENT_TYPES, VISIBILITY, RISK, makeEvent, isModuleEvent } = require('../detectors/event-types.js');
const {
  LIFECYCLE, temporalBounds, findingFreshness, enrichFreshness,
  toObservedDataWithFreshness, closureBuckets,
} = require('./freshness.js');

let pass = 0;
function t(name, fn) {
  try { fn(); pass += 1; console.log(`  PASS  ${name}`); }
  catch (e) { console.error(`  FAIL  ${name}: ${e.message}`); process.exitCode = 1; }
}

const NOW = '2026-05-30T00:00:00.000Z';
const daysAgo = (n) => new Date(Date.parse(NOW) - n * 24 * 3600 * 1000).toISOString();

function emailEvent(url = 'https://me.example/contact') {
  return makeEvent({
    event_type: EVENT_TYPES.PII_EMAIL_PUBLIC,
    source_module: 'pii_detector',
    data: 'me@example.com',
    confidence: 0.9,
    visibility: VISIBILITY.INDEXED,
    risk: RISK.MEDIUM,
    source_url: url,
  });
}

console.log('[freshness / temporalBounds — honest extraction]');
t('observed_at list yields first, last, and real count', () => {
  const b = temporalBounds({ observed_at: [daysAgo(40), daysAgo(2), daysAgo(40)] });
  assert.ok(b.first < b.last);
  assert.strictEqual(b.count, 3);
});
t('single bound becomes both first and last (single sighting)', () => {
  const b = temporalBounds({ first_observed: daysAgo(5) });
  assert.strictEqual(b.first, b.last);
  assert.strictEqual(b.count, 1);
});
t('no history => null bounds and zero count (no invention)', () => {
  const b = temporalBounds({});
  assert.strictEqual(b.first, null);
  assert.strictEqual(b.last, null);
  assert.strictEqual(b.count, 0);
});

console.log('[freshness / findingFreshness — lifecycle from real recency (HIBP/STIX model)]');
t('confirmed recently => LIVE + action_now', () => {
  const fr = findingFreshness(emailEvent(), { now: NOW, history: { observed_at: [daysAgo(30), daysAgo(3)] } });
  assert.strictEqual(fr.lifecycle, LIFECYCLE.LIVE);
  assert.strictEqual(fr.action_now, true);
  assert.ok(fr.recency > 90);
});
t('last seen long ago => STALE + Closure-Mode note + not action_now', () => {
  const fr = findingFreshness(emailEvent(), { now: NOW, history: { observed_at: [daysAgo(120), daysAgo(90)] } });
  assert.strictEqual(fr.lifecycle, LIFECYCLE.STALE);
  assert.strictEqual(fr.action_now, false);
  assert.ok(/Closure Mode|stop re-checking/i.test(fr.note));
  assert.strictEqual(fr.recency, 0);
});
t('between thresholds => DECAYING', () => {
  const fr = findingFreshness(emailEvent(), { now: NOW, history: { observed_at: [daysAgo(40), daysAgo(30)] } });
  assert.strictEqual(fr.lifecycle, LIFECYCLE.DECAYING);
});
t('NO FAKE DATA: no history => UNKNOWN with null age, never a guessed date', () => {
  const fr = findingFreshness(emailEvent(), { now: NOW });
  assert.strictEqual(fr.lifecycle, LIFECYCLE.UNKNOWN);
  assert.strictEqual(fr.basis, 'unknown');
  assert.strictEqual(fr.age_days, null);
  assert.strictEqual(fr.first_observed, null);
});
t('age_days and days_since_last_seen reflect the real bounds', () => {
  const fr = findingFreshness(emailEvent(), { now: NOW, history: { observed_at: [daysAgo(50), daysAgo(5)] } });
  assert.strictEqual(Math.round(fr.age_days), 50);
  assert.strictEqual(Math.round(fr.days_since_last_seen), 5);
});
t('custom thresholds override defaults', () => {
  const fr = findingFreshness(emailEvent(), {
    now: NOW, history: { observed_at: [daysAgo(5)] }, thresholds: { liveWithinDays: 1, staleAfterDays: 3 },
  });
  assert.strictEqual(fr.lifecycle, LIFECYCLE.STALE);
});
t('invalid input => UNKNOWN/invalid, no throw', () => {
  const fr = findingFreshness({ not: 'an event' }, { now: NOW });
  assert.strictEqual(fr.basis, 'invalid');
});

console.log('[freshness / enrichFreshness — batch sort live-first, stale-last]');
t('sorts live findings above stale ones', () => {
  const live = emailEvent('https://me.example/live');
  const stale = emailEvent('https://me.example/stale');
  const out = enrichFreshness([stale, live], {
    now: NOW,
    historyById: {
      [`PII_EMAIL_PUBLIC::https://me.example/live::me@example.com`]: { observed_at: [daysAgo(2)] },
      [`PII_EMAIL_PUBLIC::https://me.example/stale::me@example.com`]: { observed_at: [daysAgo(100)] },
    },
  });
  assert.strictEqual(out[0].source_url, 'https://me.example/live');
  assert.strictEqual(out[0]._freshness.lifecycle, LIFECYCLE.LIVE);
  assert.strictEqual(out[out.length - 1]._freshness.lifecycle, LIFECYCLE.STALE);
});

console.log('[freshness / STIX 2.1 temporal reuse]');
t('toObservedDataWithFreshness fills REAL first/last/number_observed', () => {
  const od = toObservedDataWithFreshness(emailEvent(), {
    now: NOW, history: { observed_at: [daysAgo(30), daysAgo(10), daysAgo(3)] },
  });
  assert.strictEqual(od.type, 'observed-data');
  assert.strictEqual(od.spec_version, '2.1');
  assert.strictEqual(od.number_observed, 3);
  assert.ok(od.first_observed < od.last_observed, 'bounds must reflect real sightings, not the export clock');
  assert.ok(od.x_freshness && od.x_freshness.lifecycle === LIFECYCLE.LIVE);
});
t('unknown-history STIX object keeps base clock but flags basis=unknown', () => {
  const od = toObservedDataWithFreshness(emailEvent(), { now: NOW });
  assert.strictEqual(od.x_freshness.basis, 'unknown');
});
t('invalid event => null STIX object', () => {
  assert.strictEqual(toObservedDataWithFreshness({ nope: 1 }, { now: NOW }), null);
});

console.log('[freshness / closureBuckets — the two lists Closure Mode renders]');
t('partitions act_now vs can_stop_checking honestly; unknown => review', () => {
  const liveE = emailEvent('https://me.example/a');
  const staleE = emailEvent('https://me.example/b');
  const unknownE = emailEvent('https://me.example/c');
  const buckets = closureBuckets([liveE, staleE, unknownE], {
    now: NOW,
    historyById: {
      [`PII_EMAIL_PUBLIC::https://me.example/a::me@example.com`]: { observed_at: [daysAgo(1)] },
      [`PII_EMAIL_PUBLIC::https://me.example/b::me@example.com`]: { observed_at: [daysAgo(200)] },
      // /c has no history on purpose
    },
  });
  assert.strictEqual(buckets.act_now.length, 1);
  assert.strictEqual(buckets.act_now[0].source_url, 'https://me.example/a');
  assert.strictEqual(buckets.can_stop_checking.length, 1);
  assert.strictEqual(buckets.can_stop_checking[0].source_url, 'https://me.example/b');
  assert.strictEqual(buckets.review.length, 1);
  assert.strictEqual(buckets.review[0].source_url, 'https://me.example/c');
});

console.log(`\nOK — freshness enrichment self-test: ${pass} checks passed, ${process.exitCode ? 'with failures' : '0 failures'}.`);
if (process.exitCode) process.exit(process.exitCode);
