#!/usr/bin/env node
/**
 * shared/enrich/stix-indicator_selftest.js
 *
 * Dependency-free self-tests for the STIX 2.1 Indicator + based-on interop
 * layer. Run with:  node shared/enrich/stix-indicator_selftest.js
 *
 * Proves the OpenCTI/MISP interop contract:
 *   - every finding yields Indicator(pattern) --based-on--> Observed Data
 *   - the STIX patterning expression is well-formed
 *   - secrets/PII are NEVER emitted in a pattern (redacted to k-anon prefix/token)
 *   - identical patterns dedupe to ONE Indicator across many sightings
 *
 * NO FAKE DATA: events are built with the real makeEvent constructor; nothing
 * here fabricates a scraped result, and every Indicator is marked x_data_status
 * 'template' unless a real crawl populated the event.
 */

'use strict';

const assert = require('assert');
const { EVENT_TYPES, makeEvent } = require('../detectors/event-types.js');
const { rangeOf } = require('./k-anonymity.js');
const {
  buildPattern,
  patternValueFor,
  toIndicator,
  toIndicatorPair,
  toInteropBundle,
  indicatorTypesFor,
} = require('./stix-indicator.js');

const NOW = '2026-05-30T00:00:00.000Z';

let pass = 0;
function t(name, fn) {
  try { fn(); pass += 1; console.log(`  PASS  ${name}`); }
  catch (e) { console.error(`  FAIL  ${name}: ${e.message}`); process.exitCode = 1; }
}

function evUrl() {
  return makeEvent({
    event_type: EVENT_TYPES.SELF_PROFILE_URL,
    source_module: 'username-enum',
    data: 'https://me.example/contact',
    confidence: 0.9,
    visibility: 'indexed',
    risk: 'low',
    source_url: 'https://me.example/contact',
  });
}

function evSecret() {
  return makeEvent({
    event_type: EVENT_TYPES.SECRET_LEAK_PUBLIC,
    source_module: 'secret-leak',
    data: 'AKIA-super-secret-key-value-do-not-leak',
    confidence: 0.95,
    visibility: 'indexed',
    risk: 'high',
    source_url: 'https://me.example/repo/config',
  });
}

function evEmail() {
  return makeEvent({
    event_type: EVENT_TYPES.PII_EMAIL_PUBLIC,
    source_module: 'pii',
    data: 'me@example.com',
    confidence: 0.8,
    visibility: 'indexed',
    risk: 'medium',
    source_url: 'https://me.example/about',
  });
}

console.log('[stix-indicator / pattern shape]');

t('buildPattern emits a well-formed STIX pattern for a url', () => {
  const { pattern, shape } = buildPattern(evUrl());
  assert.strictEqual(shape.sco, 'url');
  assert.strictEqual(pattern, "[url:value = 'https://me.example/contact']");
});

t('indicator_types are honest: a PII exposure is benign, not malicious', () => {
  assert.deepStrictEqual(indicatorTypesFor(EVENT_TYPES.PII_EMAIL_PUBLIC), ['benign']);
  assert.deepStrictEqual(indicatorTypesFor(EVENT_TYPES.SECRET_LEAK_PUBLIC), ['compromised']);
  assert.deepStrictEqual(indicatorTypesFor(EVENT_TYPES.TRACKER_FINGERPRINTING), ['anomalous-activity']);
});

console.log('[stix-indicator / RED LINE: no secret or PII in the pattern]');

t('secret value is redacted to the k-anon hash prefix, never the plaintext', () => {
  const ev = evSecret();
  const { pattern, value_info } = buildPattern(ev);
  assert.strictEqual(value_info.redacted, true);
  // the plaintext secret must NOT appear anywhere in the exported pattern
  assert.ok(!pattern.includes('AKIA-super-secret'), 'plaintext secret leaked into pattern!');
  // it should be the real HIBP-style prefix of the secret's hash
  const expectedPrefix = rangeOf(ev.data).prefix;
  assert.ok(pattern.includes(expectedPrefix), 'pattern should carry the k-anon hash prefix');
  assert.strictEqual(pattern, `[x-credential-exposure:hash_prefix = '${expectedPrefix}']`);
});

t('PII email is redacted to a non-reversible token, never the raw address', () => {
  const ev = evEmail();
  const { pattern, value_info } = buildPattern(ev);
  assert.strictEqual(value_info.redacted, true);
  assert.ok(!pattern.includes('me@example.com'), 'raw PII leaked into pattern!');
  assert.ok(pattern.startsWith("[email-addr:value = 'redacted:"), 'PII should be redacted token');
});

t('patternValueFor honors a detector-supplied hash_prefix in meta', () => {
  const ev = makeEvent({
    event_type: EVENT_TYPES.BREACH_RANGE_HIT,
    source_module: 'breach-range',
    data: null,
    confidence: 0.9,
    risk: 'high',
    meta: { hash_prefix: 'A94AB' },
  });
  const vi = patternValueFor(ev, 'credential-exposure');
  assert.strictEqual(vi.value, 'A94AB');
  assert.strictEqual(vi.redacted, true);
});

console.log('[stix-indicator / Indicator SDO]');

t('toIndicator produces a valid STIX 2.1 indicator SDO', () => {
  const ind = toIndicator(evUrl(), { now: NOW });
  assert.strictEqual(ind.type, 'indicator');
  assert.strictEqual(ind.spec_version, '2.1');
  assert.strictEqual(ind.pattern_type, 'stix');
  assert.strictEqual(ind.pattern_version, '2.1');
  assert.strictEqual(ind.valid_from, NOW);
  assert.ok(ind.id.startsWith('indicator--'));
  assert.strictEqual(ind.x_data_status, 'template');
});

t('toIndicator is deterministic given the same input + clock', () => {
  const a = toIndicator(evUrl(), { now: NOW });
  const b = toIndicator(evUrl(), { now: NOW });
  assert.deepStrictEqual(a, b);
});

t('toIndicator returns null for a non-event', () => {
  assert.strictEqual(toIndicator({ foo: 1 }), null);
  assert.strictEqual(toIndicator(null), null);
});

console.log('[stix-indicator / based-on pair]');

t('toIndicatorPair links Indicator --based-on--> Observed Data', () => {
  const pair = toIndicatorPair(evUrl(), { now: NOW });
  assert.ok(pair.indicator && pair.observed_data && pair.relationship);
  assert.strictEqual(pair.relationship.relationship_type, 'based-on');
  assert.strictEqual(pair.relationship.source_ref, pair.indicator.id);
  assert.strictEqual(pair.relationship.target_ref, pair.observed_data.id);
  assert.strictEqual(pair.observed_data.type, 'observed-data');
});

t('pair forwards integrity handles into the Observed Data sighting', () => {
  const pair = toIndicatorPair(evUrl(), {
    now: NOW,
    integrity: { content_sha256: 'abc', html_key: 'k/123.html' },
  });
  assert.strictEqual(pair.observed_data.x_integrity.content_sha256, 'abc');
  assert.strictEqual(pair.observed_data.x_integrity.html_key, 'k/123.html');
});

console.log('[stix-indicator / interop bundle]');

t('toInteropBundle yields a STIX bundle of indicator+observed+relationship', () => {
  const bundle = toInteropBundle([evUrl(), evSecret()], { now: NOW });
  assert.strictEqual(bundle.type, 'bundle');
  assert.strictEqual(bundle.spec_version, '2.1');
  const types = bundle.objects.map((o) => o.type).sort();
  assert.ok(types.includes('indicator'));
  assert.ok(types.includes('observed-data'));
  assert.ok(types.includes('relationship'));
});

t('identical patterns dedupe to ONE Indicator across multiple sightings', () => {
  // same url exposure seen on two different source surfaces
  const a = makeEvent({
    event_type: EVENT_TYPES.SELF_PROFILE_URL, source_module: 'username-enum',
    data: 'https://me.example/contact', source_url: 'https://search.example/a',
  });
  const b = makeEvent({
    event_type: EVENT_TYPES.SELF_PROFILE_URL, source_module: 'username-enum',
    data: 'https://me.example/contact', source_url: 'https://search.example/b',
  });
  const bundle = toInteropBundle([a, b], { now: NOW });
  const indicators = bundle.objects.filter((o) => o.type === 'indicator');
  const observed = bundle.objects.filter((o) => o.type === 'observed-data');
  const rels = bundle.objects.filter((o) => o.type === 'relationship');
  assert.strictEqual(indicators.length, 1, 'one reusable detection pattern');
  assert.strictEqual(observed.length, 2, 'two distinct sightings');
  assert.strictEqual(rels.length, 2, 'each sighting based-on the one indicator');
  for (const r of rels) assert.strictEqual(r.source_ref, indicators[0].id);
});

t('bundle skips non-events without throwing', () => {
  const bundle = toInteropBundle([null, { foo: 1 }, evUrl()], { now: NOW });
  assert.strictEqual(bundle.objects.filter((o) => o.type === 'indicator').length, 1);
});

t('NO FAKE DATA: empty input -> empty, well-formed bundle', () => {
  const bundle = toInteropBundle([], { now: NOW });
  assert.strictEqual(bundle.type, 'bundle');
  assert.deepStrictEqual(bundle.objects, []);
});

console.log(`\nOK — stix-indicator self-tests, ${pass} passed.`);
