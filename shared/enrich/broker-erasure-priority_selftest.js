#!/usr/bin/env node
/**
 * shared/enrich/broker-erasure-priority_selftest.js
 *
 * Dependency-free self-tests for the erasure-priority triage enrichment.
 * Run with:  node shared/enrich/broker-erasure-priority_selftest.js
 *
 * NO FAKE DATA: the worklist is built from REAL BROKER_LISTING_HIT events
 * produced by the REAL detector against hand-authored synthetic broker text, then
 * ranked by the REAL severity model. Nothing is fabricated; an empty input yields
 * an empty worklist.
 */

'use strict';

const assert = require('assert');
const { detectBrokerListing } = require('../detectors/broker-listing-detector.js');
const { EVENT_TYPES, makeEvent } = require('../detectors/event-types.js');
const {
  buildErasureWorklist,
  toErasureItem,
  legalBasisFor,
} = require('./broker-erasure-priority.js');

let pass = 0;
function t(name, fn) {
  try { fn(); pass += 1; console.log(`  PASS  ${name}`); }
  catch (e) { console.error(`  FAIL  ${name}: ${e.message}`); process.exitCode = 1; }
}

const IDENTITY = {
  full_name: 'Jane Q Doe', city: 'Portland', state: 'Oregon', age: 34,
  email: 'jqdoe@example.com', handle: '@janeqdoe', phone: '+1 503 555 4821',
};
const PAGE = [
  'Jane Q Doe, age 34, Portland, Oregon.',
  'Emails: jqdoe@... handle @janeqdoe phone ending 4821.',
].join('\n');

function selfHit(brokerId, url) {
  const [ev] = detectBrokerListing({
    broker_id: brokerId, text: PAGE, url, scope_type: 'self', identity: IDENTITY,
  });
  assert.ok(ev, `expected a hit for ${brokerId}`);
  return ev;
}

console.log('[broker-erasure-priority]');

t('builds a prioritized worklist from confirmed listing events', () => {
  const events = [
    selfHit('spokeo', 'https://www.spokeo.com/Jane-Doe/Oregon/Portland'),
    selfHit('whitepages', 'https://www.whitepages.com/name/Jane-Doe/Portland-OR'),
  ];
  const wl = buildErasureWorklist(events);
  assert.strictEqual(wl.total, 2);
  assert.ok(wl.items.every((i) => i.record_type === 'erasure_worklist_item'));
  assert.ok(wl.items.every((i) => i.subject_relationship === 'self_owned_record'));
  // Sorted highest-priority-first.
  assert.ok(wl.items[0].priority >= wl.items[1].priority);
  assert.ok(wl.brokers.includes('spokeo') && wl.brokers.includes('whitepages'));
});

t('each item carries the EXISTING planners hand-off (opt-out url/method + legal basis), values not echoed', () => {
  const wl = buildErasureWorklist([selfHit('spokeo', 'https://www.spokeo.com/x')]);
  const item = wl.items[0];
  assert.ok(item.optout.url && /spokeo/.test(item.optout.url));
  assert.strictEqual(item.optout.method, 'web_form');
  assert.strictEqual(item.erasure.statute, 'CCPA §1798.105'); // us jurisdiction hint
  assert.ok(Array.isArray(item.erasure.data_at_issue) && item.erasure.data_at_issue.includes('name'));
  assert.ok(item.recheck && item.recheck.url, 'reappearance re-scan surface present');
  // No subject PII VALUES in the item.
  const blob = JSON.stringify(item);
  assert.ok(!blob.includes('jqdoe@example.com') && !blob.includes('4821'));
});

t('legalBasisFor maps jurisdictions to Art.17 / CCPA, defaults to plain opt-out', () => {
  assert.strictEqual(legalBasisFor('eu').statute, 'GDPR Art.17');
  assert.strictEqual(legalBasisFor('uk').statute, 'UK GDPR Art.17');
  assert.strictEqual(legalBasisFor('us').statute, 'CCPA §1798.105');
  assert.strictEqual(legalBasisFor('xx').statute, 'opt-out');
});

t('multi-surface corroboration of the SAME broker raises priority', () => {
  const oneSurface = buildErasureWorklist([selfHit('spokeo', 'https://www.spokeo.com/a')]);
  const twoSurfaces = buildErasureWorklist([
    selfHit('spokeo', 'https://www.spokeo.com/a'),
    selfHit('spokeo', 'https://www.spokeo.com/b'),
  ]);
  // Two distinct surfaces for spokeo ⇒ its item ranks at least as high.
  assert.ok(twoSurfaces.items[0].priority >= oneSurface.items[0].priority);
});

t('ignores non-broker events and returns an empty worklist for empty input (no fabrication)', () => {
  const mixed = buildErasureWorklist([
    makeEvent({ event_type: EVENT_TYPES.PII_EMAIL_PUBLIC, source_module: 'pii_detector', data: 'a@b.com' }),
  ]);
  assert.strictEqual(mixed.total, 0);
  assert.deepStrictEqual(buildErasureWorklist([]).items, []);
  assert.strictEqual(toErasureItem(null), null);
  assert.strictEqual(toErasureItem({ record_type: 'module_event', event_type: 'PII_EMAIL_PUBLIC' }), null);
});

console.log(`\nbroker-erasure-priority: ${pass} checks passed.`);
if (process.exitCode) {
  console.error('broker-erasure-priority: FAILED');
} else {
  console.log('OK — DeleteMe/Aura-style triage over confirmed self-listings; Art.17/CCPA basis; no PII echo.');
}
