#!/usr/bin/env node
/**
 * shared/enrich/remediation_selftest.js
 *
 * Dependency-free self-tests for the suggested-actions remediation enrichment.
 * Run with:  node shared/enrich/remediation_selftest.js
 *
 * NO FAKE DATA: actions are derived from REAL module_events (built via the real
 * makeEvent constructor / real detectors). The RECOMMENDATIONS map is a clearly-
 * labelled vetted rubric, not fabricated scrape output. An empty input yields an
 * empty worklist (honest empty state), asserted below.
 */

'use strict';

const assert = require('assert');
const { EVENT_TYPES, RISK, VISIBILITY, makeEvent } = require('../detectors/event-types.js');
const { detectBrokerListing } = require('../detectors/broker-listing-detector.js');
const {
  RECOMMENDATIONS,
  recommendationFor,
  toActionItem,
  buildSuggestedActions,
  EFFORT,
  IMPACT,
} = require('./remediation.js');

let pass = 0;
function t(name, fn) {
  try { fn(); pass += 1; console.log(`  PASS  ${name}`); }
  catch (e) { console.error(`  FAIL  ${name}: ${e.message}`); process.exitCode = 1; }
}

console.log('[remediation]');

t('RECOMMENDATIONS covers EVERY frozen EVENT_TYPE (no finding left without guidance)', () => {
  for (const et of Object.values(EVENT_TYPES)) {
    const rec = RECOMMENDATIONS[et];
    assert.ok(rec, `missing recommendation for event_type ${et}`);
    assert.ok(typeof rec.title === 'string' && rec.title.length > 0, `${et} needs a title`);
    assert.ok(typeof rec.why === 'string' && rec.why.length > 0, `${et} needs a why`);
    assert.ok(Array.isArray(rec.steps) && rec.steps.length > 0, `${et} needs steps`);
    assert.ok([EFFORT.LOW, EFFORT.MEDIUM, EFFORT.HIGH].includes(rec.effort), `${et} effort band`);
    assert.ok([IMPACT.LOW, IMPACT.MEDIUM, IMPACT.HIGH].includes(rec.impact), `${et} impact band`);
  }
});

t('recommendationFor returns a COPY (caller cannot mutate the frozen rubric)', () => {
  const a = recommendationFor(EVENT_TYPES.SECRET_LEAK_PUBLIC);
  a.title = 'mutated';
  a.steps.push('x');
  const b = recommendationFor(EVENT_TYPES.SECRET_LEAK_PUBLIC);
  assert.notStrictEqual(b.title, 'mutated');
  assert.ok(!b.steps.includes('x'));
  assert.strictEqual(recommendationFor('NOT_A_TYPE'), null);
});

t('empty / non-event input yields an empty worklist (honest empty state)', () => {
  for (const input of [[], undefined, [null, {}, { record_type: 'nope' }, 42]]) {
    const wl = buildSuggestedActions(input);
    assert.strictEqual(wl.total, 0);
    assert.deepStrictEqual(wl.items, []);
    assert.strictEqual(wl.quick_wins, 0);
  }
});

t('toActionItem maps a real finding to a plain-language action with canonical priority', () => {
  const ev = makeEvent({
    event_type: EVENT_TYPES.PII_POSTAL_PUBLIC,
    source_module: 'pii_detector',
    data: '500 Foo St',
    confidence: 0.5,
    visibility: VISIBILITY.INDEXED,
    risk: RISK.HIGH,
    source_url: 'https://self-demo.example/contact',
  });
  const item = toActionItem(ev);
  assert.strictEqual(item.record_type, 'suggested_action');
  assert.strictEqual(item.action_code, 'remove_public_address');
  assert.ok(typeof item.priority === 'number' && item.priority > 0, 'has canonical severity priority');
  assert.ok(item.quick_win === true, 'low effort + high impact = quick win');
  assert.strictEqual(item.subject_relationship, 'self_owned_exposure');
  // RED LINE: no third-party / romance / live-location concept anywhere in the
  // item. (We assert the SELF-only invariant via subject_relationship below and
  // scan for prohibited CONCEPT words — note we exclude the legitimate field name
  // "subject_relationship: self_owned_exposure", which is the self-only marker.)
  const blob = JSON.stringify(item).toLowerCase().replace(/subject_relationship/g, '');
  for (const bad of ['romance', 'intimacy', 'partner', 'romantic', 'gender', 'sexuality', 'live location', 'non-consenting private person']) {
    assert.ok(!blob.includes(bad), `action must not contain "${bad}"`);
  }
  assert.strictEqual(item.subject_relationship, 'self_owned_exposure', 'self-only invariant');
});

t('worklist is sorted highest-priority-first across mixed findings', () => {
  const events = [
    makeEvent({ event_type: EVENT_TYPES.PII_GEO_HINT_PUBLIC, source_module: 'pii_detector', data: 'Portland', confidence: 0.55, risk: RISK.LOW, visibility: VISIBILITY.LINKED, source_url: 'https://s/a' }),
    makeEvent({ event_type: EVENT_TYPES.SECRET_LEAK_PUBLIC, source_module: 'secret_leak_detector', data: 'AKIA…', confidence: 0.9, risk: RISK.HIGH, visibility: VISIBILITY.INDEXED, source_url: 'https://s/b' }),
    makeEvent({ event_type: EVENT_TYPES.COOKIE_THIRD_PARTY, source_module: 'tracker_detector', data: 'doubleclick.net', confidence: 0.8, risk: RISK.LOW, visibility: VISIBILITY.LINKED, source_url: 'https://s/c' }),
  ];
  const wl = buildSuggestedActions(events);
  assert.strictEqual(wl.total, 3);
  for (let i = 1; i < wl.items.length; i += 1) {
    assert.ok(wl.items[i - 1].priority >= wl.items[i].priority, 'descending priority');
  }
  // The high-risk indexed secret must outrank the low-risk geo hint.
  const secret = wl.items.find((x) => x.action_code === 'rotate_leaked_secret');
  const geo = wl.items.find((x) => x.action_code === 'review_location_text');
  assert.ok(wl.items.indexOf(secret) < wl.items.indexOf(geo));
  assert.ok(wl.quick_wins >= 0 && typeof wl.by_band === 'object');
});

t('identical (action_code, source_url) actions are de-duplicated', () => {
  const a = makeEvent({ event_type: EVENT_TYPES.PII_EMAIL_PUBLIC, source_module: 'pii_detector', data: 'me@self.example', confidence: 0.95, risk: RISK.MEDIUM, source_url: 'https://s/page' });
  const b = makeEvent({ event_type: EVENT_TYPES.PII_EMAIL_PUBLIC, source_module: 'pii_detector', data: 'me@self.example', confidence: 0.95, risk: RISK.MEDIUM, source_url: 'https://s/page' });
  const wl = buildSuggestedActions([a, b]);
  assert.strictEqual(wl.total, 1, 'same action+surface collapses to one');
});

t('BROKER findings are DELEGATED to the canonical erasure worklist and folded in as actions', () => {
  const IDENTITY = {
    full_name: 'Jane Q Doe', city: 'Portland', state: 'Oregon', age: 34,
    email: 'jqdoe@example.com', handle: '@janeqdoe', phone: '+1 503 555 4821',
  };
  const PAGE = 'Jane Q Doe, age 34, Portland, Oregon. handle @janeqdoe phone ending 4821.';
  const [hit] = detectBrokerListing({
    broker_id: 'spokeo', text: PAGE, url: 'https://www.spokeo.com/Jane-Doe/Oregon/Portland',
    scope_type: 'self', identity: IDENTITY,
  });
  assert.ok(hit, 'real broker detector produced a confirmed hit');

  const wl = buildSuggestedActions([hit]);
  assert.strictEqual(wl.total, 1);
  const action = wl.items[0];
  assert.strictEqual(action.action_code, 'request_broker_removal');
  assert.ok(/spokeo/i.test(action.title), 'broker name folded into title');
  // The executable opt-out / erasure hand-off is carried straight from the
  // canonical worklist (single-sourced — not re-derived here).
  assert.ok(action.erasure && action.erasure.optout && action.erasure.optout.url);
  assert.ok(/spokeo/.test(action.erasure.optout.url));
  assert.strictEqual(action.erasure.erasure.statute, 'CCPA §1798.105');
  // The delegated erasure worklist is also exposed for direct consumers.
  assert.strictEqual(wl.erasure.total, 1);
  // RED LINE: no subject PII VALUES leak into the action item.
  const blob = JSON.stringify(action);
  assert.ok(!blob.includes('jqdoe@example.com') && !blob.includes('4821'), 'no PII values echoed');
});

t('a mixed batch (PII + tracker + broker) produces one coherent prioritized list', () => {
  const IDENTITY = { full_name: 'Jane Q Doe', city: 'Portland', state: 'Oregon', age: 34, handle: '@janeqdoe' };
  const PAGE = 'Jane Q Doe, age 34, Portland, Oregon. handle @janeqdoe.';
  const [broker] = detectBrokerListing({ broker_id: 'spokeo', text: PAGE, url: 'https://www.spokeo.com/x', scope_type: 'self', identity: IDENTITY });
  const events = [
    broker,
    makeEvent({ event_type: EVENT_TYPES.TRACKER_SESSION_RECORDING, source_module: 'tracker_detector', data: 'fullstory.com', confidence: 0.85, risk: RISK.HIGH, visibility: VISIBILITY.INDEXED, source_url: 'https://s/about' }),
    makeEvent({ event_type: EVENT_TYPES.PII_PHONE_PUBLIC, source_module: 'pii_detector', data: '555 123 4567', confidence: 0.7, risk: RISK.MEDIUM, source_url: 'https://s/contact' }),
  ];
  const wl = buildSuggestedActions(events);
  assert.strictEqual(wl.total, 3);
  assert.ok(wl.items.every((i) => i.record_type === 'suggested_action'));
  assert.ok(wl.items.every((i) => i.subject_relationship === 'self_owned_exposure'));
  assert.ok(wl.items.every((i) => typeof i.priority === 'number'));
  // Every action carries actionable plain-language steps (Blacklight "what you can do").
  assert.ok(wl.items.every((i) => Array.isArray(i.steps) && i.steps.length > 0));
});

if (process.exitCode) {
  console.error(`\nremediation: FAILED (${pass} passed, see above)`);
} else {
  console.log(`\nOK — remediation suggested-actions enrichment: ${pass} checks passed, 0 failures.`);
}
