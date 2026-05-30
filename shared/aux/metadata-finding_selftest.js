/**
 * shared/aux/metadata-finding_selftest.js
 *
 * Self-test for the AUX metadata-exposure mapping layer. Lives under shared/aux
 * (NOT under test/, which Codex owns). Run directly:
 *
 *   node shared/aux/metadata-finding_selftest.js
 *
 * Asserts the compliance-critical invariants:
 *  - real GPS metadata → a coarsened PII_GEO_HINT_PUBLIC event (no pinpoint);
 *  - an embedded author EMAIL → a k-anonymity email_hash_prefix, never plaintext;
 *  - a clean file (no metadata) → ZERO events (NO FAKE DATA);
 *  - every emitted event is a valid frozen-vocabulary module_event (so an unknown
 *    /forbidden type could not have slipped through makeEvent);
 *  - the summary counts only real events.
 */

'use strict';

const assert = require('assert');
const {
  metadataEventsForAsset,
  metadataSummaryEvent,
  coarsenCoord,
  SOURCE_MODULE,
} = require('./metadata-finding.js');
const { isModuleEvent, EVENT_TYPES } = require('../detectors/event-types.js');
const { emailHashKey } = require('./kanon.js');

let passed = 0;
function ok(name, fn) {
  fn();
  passed += 1;
  // eslint-disable-next-line no-console
  console.log(`  ok - ${name}`);
}

// ── coarsenCoord reduces precision and rejects garbage ──
ok('coarsenCoord coarsens to 2 decimals and rejects non-numbers', () => {
  assert.strictEqual(coarsenCoord(51.523456), 51.52);
  assert.strictEqual(coarsenCoord('not-a-number'), null);
  assert.strictEqual(coarsenCoord(undefined), null);
});

// ── GPS → coarse geo-hint, never full precision ──
ok('GPS metadata emits a coarsened PII_GEO_HINT_PUBLIC event', () => {
  const events = metadataEventsForAsset({
    sourceUrl: 'https://self.example/photo.jpg',
    meta: { latitude: 51.523456, longitude: -0.158765 },
  });
  const geo = events.find((e) => e.event_type === EVENT_TYPES.PII_GEO_HINT_PUBLIC);
  assert.ok(geo, 'expected a geo-hint event');
  assert.strictEqual(geo.data.lat_coarse, 51.52);
  assert.strictEqual(geo.data.lon_coarse, -0.16);
  // The precise coordinate must NOT survive anywhere in the event.
  assert.ok(!JSON.stringify(geo).includes('51.523456'), 'precise lat leaked');
});

// ── Author email → k-anonymity prefix, plaintext never stored ──
ok('embedded author email emits a k-anonymity prefix, never plaintext', () => {
  const email = 'jane.doe@self.example';
  const events = metadataEventsForAsset({
    sourceUrl: 'https://self.example/doc.pdf',
    meta: { Artist: `Jane Doe <${email}>` },
  });
  const emailEvt = events.find((e) => e.event_type === EVENT_TYPES.PII_EMAIL_PUBLIC);
  assert.ok(emailEvt, 'expected a PII_EMAIL_PUBLIC event');
  const { email_hash_prefix } = emailHashKey(email);
  assert.strictEqual(emailEvt.meta.email_hash_prefix, email_hash_prefix);
  assert.strictEqual(email_hash_prefix.length, 5);
  const blob = JSON.stringify(emailEvt);
  assert.ok(!blob.includes('jane.doe'), 'plaintext local-part leaked');
  assert.ok(!blob.includes(email), 'plaintext email leaked');
});

// ── Author NAME (not email) → SELF_USERNAME ──
ok('plain author name emits SELF_USERNAME (no email machinery)', () => {
  const events = metadataEventsForAsset({
    sourceUrl: 'https://self.example/a.jpg',
    meta: { Artist: 'Jane Doe' },
  });
  const u = events.find((e) => e.event_type === EVENT_TYPES.SELF_USERNAME);
  assert.ok(u, 'expected SELF_USERNAME');
  assert.strictEqual(u.data, 'Jane Doe');
});

// ── Device serial → MEDIUM-risk handle event that flags but does not echo serial ──
ok('camera make/model/serial emits a device fingerprint without echoing the serial', () => {
  const events = metadataEventsForAsset({
    sourceUrl: 'https://self.example/a.jpg',
    meta: { Make: 'Canon', Model: 'EOS R5', SerialNumber: 'SECRET-SERIAL-123' },
  });
  const dev = events.find((e) => e.event_type === EVENT_TYPES.PII_HANDLE_PUBLIC);
  assert.ok(dev, 'expected a device event');
  assert.strictEqual(dev.data.has_serial, true);
  assert.strictEqual(dev.risk, 'medium');
  assert.ok(!JSON.stringify(dev).includes('SECRET-SERIAL-123'), 'serial leaked');
});

// ── Clean file → ZERO events (NO FAKE DATA) ──
ok('a file with no metadata yields zero events', () => {
  assert.deepStrictEqual(metadataEventsForAsset({ sourceUrl: 'https://x/y.jpg', meta: {} }), []);
  assert.deepStrictEqual(metadataEventsForAsset({ sourceUrl: 'https://x/y.jpg', meta: null }), []);
});

// ── Every emitted event is a valid frozen-vocabulary module_event ──
ok('all emitted events pass isModuleEvent (frozen vocabulary enforced)', () => {
  const events = metadataEventsForAsset({
    sourceUrl: 'https://self.example/a.jpg',
    meta: {
      latitude: 1.23456,
      longitude: 2.34567,
      Artist: 'someone@self.example',
      Make: 'Sony',
    },
  });
  assert.ok(events.length >= 3);
  for (const e of events) {
    assert.ok(isModuleEvent(e), `not a valid module_event: ${JSON.stringify(e)}`);
    assert.strictEqual(e.source_module, SOURCE_MODULE);
  }
});

// ── Summary counts only the real events handed to it ──
ok('summary event counts only real events and stays in-vocabulary', () => {
  const events = metadataEventsForAsset({
    sourceUrl: 'https://self.example/a.jpg',
    meta: { latitude: 1.23456, longitude: 2.34567 },
  });
  const summary = metadataSummaryEvent({
    assetsScanned: 3,
    assetsWithMetadata: 1,
    events,
    exposureScore: 42,
  });
  assert.ok(isModuleEvent(summary));
  assert.strictEqual(summary.event_type, EVENT_TYPES.EXPOSURE_SUMMARY);
  assert.strictEqual(summary.data.assets_scanned, 3);
  assert.strictEqual(summary.data.exposure_score, 42);
  assert.strictEqual(summary.data.event_type_counts[EVENT_TYPES.PII_GEO_HINT_PUBLIC], 1);
});

// eslint-disable-next-line no-console
console.log(`\nmetadata-finding selftest: ${passed} checks passed.`);
