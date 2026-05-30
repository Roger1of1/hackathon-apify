/**
 * shared/aux/takedown-letter_selftest.js
 *
 * Zero-dependency self-test for the takedown-letter generator. Mirrors the style
 * of shared/detectors/_selftest.js and shared/aux/*_selftest.js. Run directly:
 *   node shared/aux/takedown-letter_selftest.js
 *
 * Proves the load-bearing guarantees: real clustering, correct legal-route
 * selection, owned-host vs third-party routing, NO FAKE DATA (empty in → empty
 * out; placeholders, not fabricated identity), and deterministic output.
 */

'use strict';

const assert = require('assert');
const { makeEvent, EVENT_TYPES, VISIBILITY, RISK } = require('../detectors/event-types.js');
const {
  buildTakedownPlan,
  requestKindsForGroup,
  groupEventsForTakedown,
  REQUEST_KINDS,
  PLACEHOLDER,
} = require('./takedown-letter.js');

let failures = 0;
function t(name, fn) {
  try {
    fn();
    console.log(`  PASS  ${name}`);
  } catch (e) {
    failures += 1;
    console.log(`  FAIL  ${name}\n        ${e.message}`);
  }
}

// NO FAKE DATA: nothing in → nothing out.
t('empty events → empty plan (no fabrication)', () => {
  const plan = buildTakedownPlan({ events: [] });
  assert.strictEqual(plan.packet_count, 0);
  assert.strictEqual(plan.letter_count, 0);
  assert.deepStrictEqual(plan.packets, []);
  assert.strictEqual(plan.is_template, true);
});

// EXPOSURE_SUMMARY / unknown-route events are never actionable.
t('meta EXPOSURE_SUMMARY yields no packet', () => {
  const ev = makeEvent({ event_type: EVENT_TYPES.EXPOSURE_SUMMARY, source_module: 'x' });
  const plan = buildTakedownPlan({ events: [ev] });
  assert.strictEqual(plan.packet_count, 0);
});

// Third-party PII host → GDPR + CCPA + de-index drafts.
t('third-party PII host → GDPR/CCPA/de-index letters', () => {
  const ev = makeEvent({
    event_type: EVENT_TYPES.PII_EMAIL_PUBLIC,
    source_module: 'pii_detector',
    data: { domain: 'example.com' },
    source_url: 'https://peoplefinder.example/profile/123',
    visibility: VISIBILITY.INDEXED,
    risk: RISK.HIGH,
  });
  const plan = buildTakedownPlan({ events: [ev], subjectName: 'Jane Doe' });
  assert.strictEqual(plan.packet_count, 1);
  const kinds = plan.packets[0].request_kinds;
  assert.ok(kinds.includes(REQUEST_KINDS.GDPR_ERASURE));
  assert.ok(kinds.includes(REQUEST_KINDS.CCPA_DELETE));
  assert.ok(kinds.includes(REQUEST_KINDS.SEARCH_DEINDEX));
  // Real subject name is used, not a placeholder.
  const gdpr = plan.packets[0].letters.find((l) => l.request_kind === REQUEST_KINDS.GDPR_ERASURE);
  assert.ok(gdpr.body_text.includes('Jane Doe'));
  assert.ok(gdpr.is_template === true && /DRAFT TEMPLATE/.test(gdpr.review_banner));
  assert.ok(gdpr.statute_refs.some((s) => /Article 17/.test(s)));
});

// Missing subject name → explicit placeholder, never fabricated.
t('missing subject name → [[ FILL IN ]] placeholder (no fabrication)', () => {
  const ev = makeEvent({
    event_type: EVENT_TYPES.PII_PHONE_PUBLIC,
    source_module: 'pii_detector',
    source_url: 'https://broker.example/p/9',
  });
  const plan = buildTakedownPlan({ events: [ev] });
  const body = plan.packets[0].letters[0].body_text;
  assert.ok(body.includes(PLACEHOLDER));
});

// Owned host → self-remediation, NOT a third-party data-subject request.
t('owned host → self-removal checklist (not GDPR)', () => {
  const ev = makeEvent({
    event_type: EVENT_TYPES.PII_EMAIL_PUBLIC,
    source_module: 'pii_detector',
    source_url: 'https://jane.example/contact',
  });
  const plan = buildTakedownPlan({ events: [ev], ownedHosts: ['jane.example'] });
  const kinds = plan.packets[0].request_kinds;
  assert.ok(kinds.includes(REQUEST_KINDS.SELF_REMOVAL));
  assert.ok(!kinds.includes(REQUEST_KINDS.GDPR_ERASURE));
});

// Breach/secret → credential rotation (no takedown target exists).
t('breach-range hit → credential-rotation guidance', () => {
  const ev = makeEvent({
    event_type: EVENT_TYPES.BREACH_RANGE_HIT,
    source_module: 'aux:breach-check',
    meta: { email_hash_prefix: 'ABCDE' },
  });
  const plan = buildTakedownPlan({ events: [ev] });
  assert.deepStrictEqual(plan.packets[0].request_kinds, [REQUEST_KINDS.CREDENTIAL_ROTATION]);
});

// SpiderFoot-style clustering: two leaks on one host collapse into one packet.
t('two events on one host cluster into a single packet', () => {
  const a = makeEvent({
    event_type: EVENT_TYPES.PII_EMAIL_PUBLIC,
    source_module: 'pii_detector',
    source_url: 'https://broker.example/a',
  });
  const b = makeEvent({
    event_type: EVENT_TYPES.PII_PHONE_PUBLIC,
    source_module: 'pii_detector',
    source_url: 'https://broker.example/b',
  });
  const groups = groupEventsForTakedown([a, b]);
  assert.strictEqual(groups.size, 1, 'same host → one group');
  const plan = buildTakedownPlan({ events: [a, b] });
  assert.strictEqual(plan.packet_count, 1);
  assert.strictEqual(plan.packets[0].finding_count, 2);
  // why_it_matters covers both exposures (Blacklight self-voice).
  assert.ok(/about you/.test(plan.packets[0].why_it_matters));
});

// Determinism: same input → byte-identical plan.
t('deterministic output (reproducible, no randomness)', () => {
  const ev = makeEvent({
    event_type: EVENT_TYPES.PII_EMAIL_PUBLIC,
    source_module: 'pii_detector',
    source_url: 'https://broker.example/x',
  });
  const p1 = buildTakedownPlan({ events: [ev], subjectName: 'A B' });
  const p2 = buildTakedownPlan({ events: [ev], subjectName: 'A B' });
  assert.strictEqual(JSON.stringify(p1.packets), JSON.stringify(p2.packets));
});

// requestKindsForGroup is stable-ordered.
t('requestKindsForGroup returns stable order', () => {
  const ev = makeEvent({
    event_type: EVENT_TYPES.PII_EMAIL_PUBLIC,
    source_module: 'pii_detector',
    source_url: 'https://broker.example/x',
  });
  const kinds = requestKindsForGroup([ev], new Set());
  assert.deepStrictEqual(kinds, [
    REQUEST_KINDS.GDPR_ERASURE,
    REQUEST_KINDS.CCPA_DELETE,
    REQUEST_KINDS.SEARCH_DEINDEX,
  ]);
});

console.log(`\ntakedown-letter self-test: ${failures === 0 ? 'OK' : failures + ' FAILURE(S)'}`);
process.exit(failures === 0 ? 0 : 1);
