#!/usr/bin/env node
/**
 * shared/detectors/_selftest.js
 *
 * Dependency-free self-tests for the detector modules. Run with:
 *   node shared/detectors/_selftest.js
 *
 * NO FAKE DATA: every assertion runs the REAL detector functions against
 * honestly-constructed inputs (text I wrote, not fabricated "scrape results").
 * Inputs are clearly synthetic test fixtures.
 */

'use strict';

const assert = require('assert');
const { EVENT_TYPES, VISIBILITY, RISK, makeEvent, isModuleEvent } = require('./event-types.js');
const { detectPii } = require('./pii-detector.js');
const { detectTrackers } = require('./tracker-detector.js');
const { toRange, parseRangeResponse, detectBreachInRange } = require('./breach-range-detector.js');
const { detectSecrets, shannonEntropyPerChar } = require('./secret-leak-detector.js');
const { detectUsernameAccounts } = require('./username-enum-detector.js');
const { emailHashKey } = require('../aux/kanon.js');
const { runDetectors, ARTIFACT_KINDS, summarizeForExposure, rankEvents } = require('./index.js');
const { exposureScore } = require('../scoring.js');

let pass = 0;
function t(name, fn) {
  try { fn(); pass += 1; console.log(`  PASS  ${name}`); }
  catch (e) { console.error(`  FAIL  ${name}: ${e.message}`); process.exitCode = 1; }
}

console.log('[event-types]');
t('makeEvent rejects unknown event_type', () => {
  assert.throws(() => makeEvent({ event_type: 'ROMANCE_INFERENCE', source_module: 'x' }));
});
t('makeEvent clamps confidence to [0,1]', () => {
  const e = makeEvent({ event_type: EVENT_TYPES.PII_EMAIL_PUBLIC, source_module: 'x', confidence: 9 });
  assert.strictEqual(e.confidence, 1);
  assert.ok(isModuleEvent(e));
});

console.log('[pii_detector]');
t('detects a public email with high confidence', () => {
  const ev = detectPii({ text: 'Contact me at jane.doe@example.com for work.', url: 'https://jane.example.com/contact' });
  const email = ev.find((e) => e.event_type === EVENT_TYPES.PII_EMAIL_PUBLIC);
  assert.ok(email, 'expected an email event');
  assert.strictEqual(email.data, 'jane.doe@example.com');
  assert.ok(email.confidence >= 0.9);
});
t('does not invent PII from empty text', () => {
  assert.deepStrictEqual(detectPii({ text: '' }), []);
});
t('detects self-stated city but labels it coarse, not live location', () => {
  const ev = detectPii({ text: 'I am based in Portland and love coffee.' });
  const geo = ev.find((e) => e.event_type === EVENT_TYPES.PII_GEO_HINT_PUBLIC);
  assert.ok(geo, 'expected a geo hint');
  assert.match(geo.meta.note, /not live location/);
});
t('phone-shaped IDs without separators are NOT matched (precision)', () => {
  const ev = detectPii({ text: 'order 1234567 shipped in 2024' });
  assert.ok(!ev.some((e) => e.event_type === EVENT_TYPES.PII_PHONE_PUBLIC));
});
t('email event carries the k-anonymity prefix as a correlation key (not plaintext join)', () => {
  const addr = 'jane.doe@example.com';
  const ev = detectPii({ text: `mail ${addr}`, url: 'https://jane.example.com/' });
  const email = ev.find((e) => e.event_type === EVENT_TYPES.PII_EMAIL_PUBLIC);
  assert.ok(email);
  const expected = emailHashKey(addr).email_hash_prefix;
  assert.strictEqual(email.meta.email_hash_prefix, expected);
  assert.strictEqual(email.meta.email_hash_prefix.length, 5); // 5-char HIBP prefix
});

console.log('[secret_leak_detector]');
t('detects an AWS access key, HIGH risk, and REDACTS the value', () => {
  const key = 'AKIAIOSFODNN7EXAMPLE';
  const ev = detectSecrets({ text: `export AWS_KEY=${key}`, url: 'https://me.example.com/config' });
  const hit = ev.find((e) => e.event_type === EVENT_TYPES.SECRET_LEAK_PUBLIC);
  assert.ok(hit, 'expected a secret leak event');
  assert.strictEqual(hit.risk, RISK.HIGH);
  // Never re-leaks the secret anywhere in the event.
  assert.ok(!JSON.stringify(hit).includes(key), 'secret must be redacted');
  assert.strictEqual(hit.data.vendor, 'AWS Access Key ID');
});
t('detects a GitHub token by its documented shape', () => {
  const tok = 'ghp_' + 'a'.repeat(36);
  const ev = detectSecrets({ text: `token: ${tok}` });
  assert.ok(ev.some((e) => e.data.vendor === 'GitHub Token'));
});
t('does NOT flag a low-entropy placeholder assignment (precision)', () => {
  const ev = detectSecrets({ text: 'api_secret = "changeme_changeme"' });
  assert.deepStrictEqual(ev, []);
});
t('flags a high-entropy generic secret assignment at lower confidence', () => {
  const ev = detectSecrets({ text: 'client_secret = "Xk9$qZ2vBpL7wRt3Hn6Yc1Md8Fa0Ue5"'.replace(/[$]/g, 'q') });
  const hit = ev.find((e) => e.event_type === EVENT_TYPES.SECRET_LEAK_PUBLIC);
  assert.ok(hit);
  assert.ok(hit.confidence < 0.7 && hit.confidence > 0);
});
t('clean text yields no secret events (no fabrication)', () => {
  assert.deepStrictEqual(detectSecrets({ text: 'just a normal paragraph about coffee.' }), []);
  assert.deepStrictEqual(detectSecrets({ text: '' }), []);
});
t('shannon entropy: random base64 >> english word', () => {
  assert.ok(shannonEntropyPerChar('Xk9qZ2vBpL7wRt3Hn6Yc1Md8Fa0Ue5') > shannonEntropyPerChar('passwordpassword'));
});

console.log('[tracker_detector]');
t('flags a session-recording vendor as HIGH risk', () => {
  const ev = detectTrackers({
    url: 'https://jane.example.com/',
    scripts: ['https://static.hotjar.com/c/hotjar-123.js'],
  });
  const sr = ev.find((e) => e.event_type === EVENT_TYPES.TRACKER_SESSION_RECORDING);
  assert.ok(sr, 'expected session recording event');
  assert.strictEqual(sr.risk, RISK.HIGH);
  assert.strictEqual(sr.data, 'Hotjar');
});
t('flags fingerprinting from observed JS API calls, scaling confidence', () => {
  const ev = detectTrackers({
    url: 'https://jane.example.com/',
    js_api_calls: ['canvas.toDataURL', 'WebGLRenderingContext.getParameter'],
  });
  const fp = ev.find((e) => e.event_type === EVENT_TYPES.TRACKER_FINGERPRINTING);
  assert.ok(fp);
  assert.ok(fp.confidence > 0.5);
});
t('identifies a third-party cookie by domain mismatch', () => {
  const ev = detectTrackers({
    url: 'https://jane.example.com/',
    cookies: [{ name: '_fbp', domain: '.facebook.com' }],
  });
  assert.ok(ev.some((e) => e.event_type === EVENT_TYPES.COOKIE_THIRD_PARTY));
});
t('clean page yields no tracker events', () => {
  assert.deepStrictEqual(detectTrackers({ url: 'https://jane.example.com/', scripts: ['/local.js'] }), []);
});

console.log('[breach_range_detector / k-anonymity]');
t('toRange exposes only a 5-char prefix; full hash stays local', () => {
  const r = toRange('correct horse battery staple');
  assert.strictEqual(r.prefix.length, 5);
  assert.strictEqual(r.prefix + r.suffix, r.full);
});
t('detects a breach hit when suffix is in the returned bucket', () => {
  const r = toRange('hunter2');
  // honest range response: the real suffix appears with a count.
  const body = `${r.suffix}:42\nFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF:1`;
  const map = parseRangeResponse(body);
  const ev = detectBreachInRange({ suffix: r.suffix, rangeMap: map, scope_type: 'self', label: 'test pw' });
  assert.strictEqual(ev.length, 1);
  assert.strictEqual(ev[0].meta.breach_count, 42);
  // never leaks the secret:
  assert.ok(!JSON.stringify(ev[0]).includes('hunter2'));
});
t('no hit when suffix absent (no fabrication)', () => {
  const r = toRange('a-unique-passphrase-not-in-bucket');
  const map = parseRangeResponse('00000000000000000000000000000000000:5');
  assert.deepStrictEqual(detectBreachInRange({ suffix: r.suffix, rangeMap: map, scope_type: 'self' }), []);
});
t('refuses to emit for non-self / non-public_figure scope (dual-use guard)', () => {
  const r = toRange('hunter2');
  const map = parseRangeResponse(`${r.suffix}:42`);
  assert.deepStrictEqual(detectBreachInRange({ suffix: r.suffix, rangeMap: map, scope_type: 'consented' }), []);
});

console.log('[username_enum_detector / dual-use guard]');
t('refuses to emit for a non-self / non-public_figure scope (dual-use chokepoint)', () => {
  const out = detectUsernameAccounts({
    handle: '@jane', scope_type: 'consented',
    probes: [{ platform: 'github', exists: true, method: 'status_and_content' }],
  });
  assert.deepStrictEqual(out, []);
});
t('also refuses for brand / safety_evidence / undefined scope', () => {
  for (const scope of ['brand', 'safety_evidence', undefined, 'private_person_tracking']) {
    assert.deepStrictEqual(
      detectUsernameAccounts({ handle: '@jane', scope_type: scope, probes: [{ platform: 'x', exists: true }] }),
      [],
      `scope ${scope} must yield no events`,
    );
  }
});
t('emits SELF_USERNAME (+ profile url) only for CONFIRMED hits under self scope', () => {
  const out = detectUsernameAccounts({
    handle: '@Jane', scope_type: 'self',
    probes: [
      { platform: 'GitHub', exists: true, method: 'status_and_content', profile_url: 'https://github.com/jane' },
      { platform: 'nowhere', exists: false }, // not-found => must NOT appear
      { platform: 'maybe', exists: 'unknown' }, // unknown => must NOT appear (no fabrication)
    ],
  });
  const usernames = out.filter((e) => e.event_type === EVENT_TYPES.SELF_USERNAME);
  const profiles = out.filter((e) => e.event_type === EVENT_TYPES.SELF_PROFILE_URL);
  assert.strictEqual(usernames.length, 1, 'one confirmed platform => one username event');
  assert.strictEqual(usernames[0].data, '@jane'); // normalized handle
  assert.strictEqual(usernames[0].meta.platform, 'github');
  assert.strictEqual(profiles.length, 1);
  assert.strictEqual(profiles[0].data, 'https://github.com/jane');
});
t('confidence reflects detection method, never fabricates a missing handle', () => {
  const strong = detectUsernameAccounts({ handle: '@jane', scope_type: 'public_figure', probes: [{ platform: 'a', exists: true, method: 'status_and_content' }] });
  const weak = detectUsernameAccounts({ handle: '@jane', scope_type: 'public_figure', probes: [{ platform: 'b', exists: true, method: 'status_only' }] });
  assert.ok(strong[0].confidence > weak[0].confidence);
  // no handle => nothing, even with confirmed probes
  assert.deepStrictEqual(detectUsernameAccounts({ scope_type: 'self', probes: [{ platform: 'a', exists: true }] }), []);
});

console.log('[registry / dispatch]');
t('registry routes USERNAME_PROBES through the scope-gated module', () => {
  const allowed = runDetectors([{
    kind: ARTIFACT_KINDS.USERNAME_PROBES, handle: '@jane', scope_type: 'self',
    probes: [{ platform: 'github', exists: true, method: 'canonical_profile', profile_url: 'https://github.com/jane' }],
  }]);
  assert.ok(allowed.events.some((e) => e.event_type === EVENT_TYPES.SELF_USERNAME));
  const refused = runDetectors([{
    kind: ARTIFACT_KINDS.USERNAME_PROBES, handle: '@jane', scope_type: 'brand',
    probes: [{ platform: 'github', exists: true }],
  }]);
  assert.deepStrictEqual(refused.events, []); // dual-use guard holds through dispatch
});
t('runDetectors dispatches artifacts by kind and feeds canonical exposureScore', () => {
  const artifacts = [
    { kind: ARTIFACT_KINDS.PAGE_TEXT, text: 'reach me jane@example.com', url: 'https://jane.example.com/c', visibility: VISIBILITY.INDEXED },
    { kind: ARTIFACT_KINDS.PAGE_RESOURCES, url: 'https://jane.example.com/', scripts: ['https://www.google-analytics.com/ga.js'] },
    { kind: 'unknown_kind', foo: 1 },
  ];
  const { events, skipped } = runDetectors(artifacts);
  assert.ok(events.length >= 2);
  assert.strictEqual(skipped, 1);
  const summary = summarizeForExposure(events);
  const score = exposureScore(summary); // reuse canonical scorer, do not reimplement
  assert.ok(score > 0 && score <= 100);
});
t('rankEvents sorts HIGH risk first', () => {
  const evs = [
    makeEvent({ event_type: EVENT_TYPES.PII_HANDLE_PUBLIC, source_module: 'pii_detector', risk: RISK.LOW }),
    makeEvent({ event_type: EVENT_TYPES.PII_POSTAL_PUBLIC, source_module: 'pii_detector', risk: RISK.HIGH }),
  ];
  assert.strictEqual(rankEvents(evs)[0].risk, RISK.HIGH);
});

console.log(`\nOK — detector self-tests, ${pass} passed.`);
