#!/usr/bin/env node
/**
 * shared/detectors/broker-listing-detector_selftest.js
 *
 * Dependency-free self-tests for the data-broker listing-confirmation detector.
 * Run with:  node shared/detectors/broker-listing-detector_selftest.js
 *
 * NO FAKE DATA: every assertion runs the REAL detector against honestly hand-
 * written synthetic broker-page text. The "broker page" fixtures are clearly
 * synthetic strings I authored — not scraped or fabricated results. The whole
 * point of several tests is to prove the detector emits NOTHING when a match is
 * not genuinely corroborated, i.e. that it cannot invent a listing.
 */

'use strict';

const assert = require('assert');
const { EVENT_TYPES, isModuleEvent } = require('./event-types.js');
const {
  detectBrokerListing,
  buildProbes,
  phrasePresent,
  ALLOWED_SCOPES,
  FIELD,
} = require('./broker-listing-detector.js');
const { runDetectors, ARTIFACT_KINDS } = require('./index.js');
const { knownBrokerIds } = require('../aux/broker-registry.js');

let pass = 0;
function t(name, fn) {
  try { fn(); pass += 1; console.log(`  PASS  ${name}`); }
  catch (e) { console.error(`  FAIL  ${name}: ${e.message}`); process.exitCode = 1; }
}

// A synthetic, hand-authored people-search result page for the SELF subject.
const SELF_PAGE_TEXT = [
  'Spokeo people search results',
  'Jane Q Doe, age 34, lives in Portland, Oregon.',
  'Known emails: jqdoe@... | Related: handle @janeqdoe',
  'Phone ending in 4821. View full report.',
].join('\n');

const SELF_IDENTITY = {
  full_name: 'Jane Q Doe',
  city: 'Portland',
  state: 'Oregon',
  age: 34,
  email: 'jqdoe@example.com',
  handle: '@janeqdoe',
  phone: '+1 503 555 4821',
};

console.log('[broker-listing-detector]');

t('confirms a corroborated SELF listing on a known broker and emits a valid event', () => {
  const events = detectBrokerListing({
    broker_id: 'spokeo',
    text: SELF_PAGE_TEXT,
    url: 'https://www.spokeo.com/Jane-Doe/Oregon/Portland',
    scope_type: 'self',
    identity: SELF_IDENTITY,
  });
  assert.strictEqual(events.length, 1, 'expected exactly one listing hit');
  const ev = events[0];
  assert.ok(isModuleEvent(ev));
  assert.strictEqual(ev.event_type, EVENT_TYPES.BROKER_LISTING_HIT);
  assert.strictEqual(ev.data.broker_id, 'spokeo');
  assert.strictEqual(ev.risk, 'high');
  assert.strictEqual(ev.visibility, 'indexed');
  // Name anchor must be present plus >=1 corroborator.
  assert.ok(ev.meta.matched_fields.includes(FIELD.NAME));
  assert.ok(ev.meta.corroborators >= 1);
  // Hand-off hooks for the existing planners are present.
  assert.ok(ev.meta.optout_url && /spokeo/.test(ev.meta.optout_url));
  assert.strictEqual(ev.meta.optout_method, 'web_form');
  assert.strictEqual(ev.meta.jurisdiction_hint, 'us');
  assert.ok(ev.confidence >= 0.55 && ev.confidence <= 0.97);
});

t('does NOT echo the subject PII values back into the event (field NAMES only)', () => {
  const [ev] = detectBrokerListing({
    broker_id: 'spokeo', text: SELF_PAGE_TEXT, scope_type: 'self', identity: SELF_IDENTITY,
  });
  const blob = JSON.stringify(ev);
  // The full email and full phone must never appear in the emitted event.
  assert.ok(!blob.includes('jqdoe@example.com'), 'full email leaked into event');
  assert.ok(!blob.includes('5034821') && !blob.includes('503 555 4821'), 'full phone leaked');
  // matched_fields are field NAMES, not values.
  assert.ok(ev.meta.matched_fields.every((f) => Object.values(FIELD).includes(f)));
});

t('emits NOTHING when only a common name token is present (no corroboration ⇒ no fabricated listing)', () => {
  const events = detectBrokerListing({
    broker_id: 'spokeo',
    text: 'Jane Q Doe wrote a guest post about gardening. No location, no contact.',
    scope_type: 'self',
    identity: SELF_IDENTITY,
  });
  assert.deepStrictEqual(events, [], 'a lone name must not trigger a listing hit');
});

t('emits NOTHING when corroborators are present but the name is absent', () => {
  const events = detectBrokerListing({
    broker_id: 'spokeo',
    text: 'Someone in Portland, Oregon, age 34, handle @janeqdoe is mentioned.',
    scope_type: 'self',
    identity: SELF_IDENTITY,
  });
  assert.deepStrictEqual(events, [], 'corroborators without the name anchor must not match');
});

t('refuses (zero events) for a prohibited scope — dual-use gate', () => {
  for (const scope of ['consented', 'brand', 'safety_evidence', undefined, 'ex', 'crush']) {
    const events = detectBrokerListing({
      broker_id: 'spokeo', text: SELF_PAGE_TEXT, scope_type: scope, identity: SELF_IDENTITY,
    });
    assert.deepStrictEqual(events, [], `scope ${scope} must yield no events`);
  }
});

t('allows public_figure scope (a public figure auditing their OWN broker exposure)', () => {
  const events = detectBrokerListing({
    broker_id: 'spokeo', text: SELF_PAGE_TEXT, scope_type: 'public_figure', identity: SELF_IDENTITY,
  });
  assert.strictEqual(events.length, 1);
  assert.ok(ALLOWED_SCOPES.has('public_figure'));
});

t('emits NOTHING for an unknown broker id (no documented opt-out surface ⇒ never guess)', () => {
  const events = detectBrokerListing({
    broker_id: 'totally-made-up-broker', text: SELF_PAGE_TEXT, scope_type: 'self', identity: SELF_IDENTITY,
  });
  assert.deepStrictEqual(events, []);
  // sanity: the broker we DO use is in the real registry
  assert.ok(knownBrokerIds().includes('spokeo'));
});

t('emits NOTHING on empty text or empty identity', () => {
  assert.deepStrictEqual(
    detectBrokerListing({ broker_id: 'spokeo', text: '', scope_type: 'self', identity: SELF_IDENTITY }), [],
  );
  assert.deepStrictEqual(
    detectBrokerListing({ broker_id: 'spokeo', text: SELF_PAGE_TEXT, scope_type: 'self', identity: {} }), [],
  );
});

t('phrasePresent respects word boundaries (no substring false positives)', () => {
  assert.ok(phrasePresent('jane q doe lives here', 'Jane Q Doe'));
  assert.ok(!phrasePresent('annual report for portlandia', 'ann')); // not inside another word
  assert.ok(!phrasePresent('the annual gathering', 'annual gathering meetup'));
});

t('buildProbes reduces sensitive fields to minimal discriminators', () => {
  const probes = buildProbes(SELF_IDENTITY);
  const byField = Object.fromEntries(probes.map((p) => [p.field, p.value]));
  assert.strictEqual(byField[FIELD.EMAIL_LOCAL], 'jqdoe', 'email reduced to local-part');
  assert.strictEqual(byField[FIELD.PHONE_LAST4], '4821', 'phone reduced to last 4');
  assert.ok(!Object.values(byField).includes('jqdoe@example.com'), 'full email must not be a probe');
});

t('integrates through the registry dispatcher under the BROKER_PAGE artifact kind', () => {
  const { events, by_module } = runDetectors([
    {
      kind: ARTIFACT_KINDS.BROKER_PAGE,
      broker_id: 'spokeo',
      text: SELF_PAGE_TEXT,
      url: 'https://www.spokeo.com/Jane-Doe/Oregon/Portland',
      scope_type: 'self',
      identity: SELF_IDENTITY,
    },
    // A prohibited-scope artifact in the SAME batch must contribute zero events.
    {
      kind: ARTIFACT_KINDS.BROKER_PAGE,
      broker_id: 'spokeo',
      text: SELF_PAGE_TEXT,
      scope_type: 'brand',
      identity: SELF_IDENTITY,
    },
  ]);
  const hits = events.filter((e) => e.event_type === EVENT_TYPES.BROKER_LISTING_HIT);
  assert.strictEqual(hits.length, 1, 'only the self-scoped artifact yields a hit');
  assert.strictEqual(by_module.broker_listing_detector, 1);
});

console.log(`\nbroker-listing-detector: ${pass} checks passed.`);
if (process.exitCode) {
  console.error('broker-listing-detector: FAILED');
} else {
  console.log('OK — corroborated self-match only; dual-use gated; no fabricated listings.');
}
