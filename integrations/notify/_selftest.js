/**
 * integrations/notify/_selftest.js
 *
 * Zero-dependency self-test for the compliant notification dispatch policy.
 * Run directly:  node integrations/notify/_selftest.js
 * Discovered automatically by integrations/run-module-selftests.js.
 *
 * Proves the load-bearing guarantees of the Slack/Make/n8n/Zapier dispatch layer:
 *   - NO LEAK: an external channel can NEVER carry raw locators. TLP:RED to an
 *     external sink is REFUSED, and at TLP:GREEN the redacted rows physically
 *     drop url/html_key/screenshot_key/note (reuses redaction-policy.js).
 *   - SUCCESS != ANNOUNCEMENT: an EMPTY/MALFORMED/FAILED run yields NOT_READY and
 *     dispatch:false — we never announce "your audit is ready" for a bad run
 *     (reuses output-health.js). NO FAKE DATA.
 *   - ANTI-COMPULSION PACING: a second send inside the cadence floor is SUPPRESSED
 *     (dispatch:false, suppressed_until set), and a higher distress_risk_score
 *     SLOWS the floor, never speeds it (reuses cadence-policy.js).
 *   - NO CLICK BAIT: every dispatched payload asserts clickable_target:null and a
 *     reassurance-first voice (Closure Mode / GOV.UK banner pattern).
 *   - FAIL CLOSED: unknown channel and unknown marking are refused, not widened.
 */

'use strict';

const assert = require('assert');
const path = require('path');
const {
  decideNotification,
  suppressionGate,
  classifyKind,
  NOTIFY_KIND,
  CHANNELS,
} = require('./notify-policy.js');
const { HEALTH } = require(path.join(__dirname, '..', 'webhooks', 'output-health.js'));

let failures = 0;
function t(name, fn) {
  try {
    fn();
    process.stdout.write(`  ok  ${name}\n`);
  } catch (e) {
    failures += 1;
    process.stdout.write(`  FAIL  ${name}: ${e.message}\n`);
  }
}

// A REAL, healthy report run shape that output-health will judge HEALTHY: a
// well-formed report record carrying the required scoring fields.
function healthyRun() {
  return {
    status: 'SUCCEEDED',
    eventType: 'ACTOR.RUN.SUCCEEDED',
    datasetItems: [
      {
        record_type: 'report',
        exposure_score: 42,
        evidence_quality_score: 0.8,
        actionability_score: 0.5,
        distress_risk_score: 0.2,
        closure_mode_recommended: false,
      },
    ],
    output: {
      exposure_score: 42,
      evidence_quality_score: 0.8,
      actionability_score: 0.5,
      distress_risk_score: 0.2,
      closure_mode_recommended: false,
    },
  };
}

// A REAL change row of a known exportable record_type ('evidence_index') that,
// at TLP:RED, carries raw locators we must prove never leave.
function rawEvidenceRow() {
  return {
    record_type: 'evidence_index',
    case_id: 'self-abc12',
    url: 'https://example.com/me/profile', // RAW LOCATOR — must never leave RED
    timestamp: '2026-05-30T00:00:00Z',
    content_sha256: 'a'.repeat(64),
    html_sha256: 'b'.repeat(64),
    screenshot_key: 'KVS/shot-1.png', // RAW STORAGE KEY — must never leave RED
    html_key: 'KVS/page-1.html',
    change: 'modified',
    immutable: true,
  };
}

const T0 = new Date('2026-05-30T12:00:00Z');

// ── 1. Channel + marking fail-closed ─────────────────────────────────────────
t('unknown channel is refused (fail closed)', () => {
  const d = decideNotification({ channel: 'sms', run: healthyRun(), now: T0 });
  assert.strictEqual(d.dispatch, false);
  assert.match(d.reasons.join(' '), /Unknown or missing channel/);
});

t('all declared channels are real automation sinks (no sms/push)', () => {
  assert.deepStrictEqual([...CHANNELS].sort(), ['generic_webhook', 'make', 'n8n', 'slack', 'zapier']);
});

t('unknown marking is refused, not widened', () => {
  const d = decideNotification({ channel: 'slack', marking: 'TLP:PURPLE', run: healthyRun(), now: T0 });
  assert.strictEqual(d.dispatch, false);
  assert.match(d.reasons.join(' '), /Unknown distribution marking/);
});

// ── 2. NO LEAK: raw locators may never reach an external channel ─────────────
t('TLP:RED to an external channel is refused outright', () => {
  const d = decideNotification({
    channel: 'slack', marking: 'TLP:RED', run: healthyRun(),
    change_rows: [rawEvidenceRow()], scope_type: 'self', now: T0,
  });
  assert.strictEqual(d.dispatch, false);
  assert.match(d.reasons.join(' '), /Refusing TLP:RED to an external channel/);
});

t('default external marking is TLP:GREEN and drops url/keys/note', () => {
  const d = decideNotification({
    channel: 'slack', run: healthyRun(),
    change_rows: [rawEvidenceRow()], scope_type: 'self', now: T0,
  });
  assert.strictEqual(d.dispatch, true, `expected dispatch; reasons=${d.reasons.join('|')}`);
  assert.strictEqual(d.marking, 'TLP:GREEN');
  const row = d.payload.changes[0];
  // The thin shareable shape — proves the redaction reuse actually fired.
  assert.ok(!('url' in row), 'url must NOT leave TLP:GREEN');
  assert.ok(!('screenshot_key' in row), 'screenshot_key must NOT leave TLP:GREEN');
  assert.ok(!('html_key' in row), 'html_key must NOT leave TLP:GREEN');
  assert.ok(!('case_id' in row), 'case_id must NOT leave TLP:GREEN');
  // What it MAY carry: hash + change flag + timestamp (prove-it-changed, no where).
  assert.strictEqual(row.content_sha256, 'a'.repeat(64));
  assert.strictEqual(row.change, 'modified');
});

// ── 3. SUCCESS != ANNOUNCEMENT (NO FAKE DATA) ────────────────────────────────
t('an EMPTY run is NOT announced as ready', () => {
  const d = decideNotification({
    channel: 'slack',
    run: { status: 'SUCCEEDED', eventType: 'ACTOR.RUN.SUCCEEDED', datasetItems: [] },
    scope_type: 'self', now: T0,
  });
  assert.strictEqual(d.dispatch, false);
  assert.strictEqual(d.kind, NOTIFY_KIND.NOT_READY);
});

t('a FAILED run is NOT announced as ready', () => {
  const d = decideNotification({
    channel: 'slack',
    run: { status: 'FAILED', eventType: 'ACTOR.RUN.FAILED' },
    scope_type: 'self', now: T0,
  });
  assert.strictEqual(d.dispatch, false);
  assert.strictEqual(d.kind, NOTIFY_KIND.NOT_READY);
});

t('classifyKind: healthy + 0 changes => NO_CHANGE (the calm common case)', () => {
  assert.strictEqual(classifyKind({ health: HEALTH.HEALTHY }, 0), NOTIFY_KIND.NO_CHANGE);
  assert.strictEqual(classifyKind({ health: HEALTH.HEALTHY }, 3), NOTIFY_KIND.DIGEST);
  assert.strictEqual(classifyKind({ health: HEALTH.COMPLIANCE_STOP }, 0), NOTIFY_KIND.COMPLIANCE_STOP);
  assert.strictEqual(classifyKind(null, 1), NOTIFY_KIND.NOT_READY);
});

// ── 4. ANTI-COMPULSION PACING (reuses cadence floor) ─────────────────────────
t('first send allowed; second send inside the floor is suppressed', () => {
  const first = decideNotification({
    channel: 'slack', run: healthyRun(), scope_type: 'self', now: T0,
  });
  assert.strictEqual(first.dispatch, true);
  assert.ok(first.suppressed_until, 'first send must pin the next-allowed time');

  // One hour later is FAR inside the weekly 'closure' floor.
  const soon = new Date(T0.getTime() + 60 * 60 * 1000);
  const second = decideNotification({
    channel: 'slack', run: healthyRun(), scope_type: 'self',
    last_notified_at: T0.toISOString(), now: soon,
  });
  assert.strictEqual(second.dispatch, false);
  assert.match(second.reasons.join(' '), /anti-compulsion floor/);
  assert.ok(second.suppressed_until);
});

t('higher distress SLOWS the floor (never faster)', () => {
  const calm = suppressionGate({ scope_type: 'self', distress_risk_score: 0.0, now: T0 });
  const distressed = suppressionGate({ scope_type: 'self', distress_risk_score: 0.9, now: T0 });
  assert.ok(calm.allowed && distressed.allowed);
  assert.ok(
    distressed.floor_minutes >= calm.floor_minutes,
    `distressed floor (${distressed.floor_minutes}) must be >= calm floor (${calm.floor_minutes})`,
  );
});

t('non-schedulable scope fails closed (no floor => no dispatch)', () => {
  const d = decideNotification({
    channel: 'slack', run: healthyRun(), scope_type: 'safety_evidence', now: T0,
  });
  assert.strictEqual(d.dispatch, false);
  assert.match(d.reasons.join(' '), /cadence floor|may not be auto-scheduled/i);
});

// ── 5. NO CLICK BAIT + reassurance voice ─────────────────────────────────────
t('dispatched payload carries no clickable target and a what-next line', () => {
  const d = decideNotification({
    channel: 'n8n', run: healthyRun(), grade: 'C', scope_type: 'self', now: T0,
  });
  assert.strictEqual(d.dispatch, true);
  assert.strictEqual(d.payload.clickable_target, null, 'must NOT bait a click (Closure Mode)');
  assert.strictEqual(d.payload.kind, NOTIFY_KIND.NO_CHANGE);
  assert.match(d.payload.text, /nothing|same|no action/i);
  assert.ok(d.payload.what_next, 'must tell the user what happens next (GOV.UK pattern)');
  assert.match(d.payload.text, /grade: C/i, 'grade letter is the headline (Observatory)');
});

t('a digest states the count and stays calm (not an emergency)', () => {
  const d = decideNotification({
    channel: 'zapier', run: healthyRun(), grade: 'D', scope_type: 'self',
    change_rows: [rawEvidenceRow(), rawEvidenceRow()], now: T0,
  });
  assert.strictEqual(d.dispatch, true);
  assert.strictEqual(d.payload.kind, NOTIFY_KIND.DIGEST);
  assert.strictEqual(d.payload.change_count, 2);
  assert.match(d.payload.what_next, /No rush|not an emergency|review/i);
});

if (failures > 0) {
  process.stderr.write(`\nnotify-policy self-test FAILED: ${failures} failure(s)\n`);
  process.exit(1);
}
process.stdout.write('\nnotify-policy self-test: all assertions passed\n');
