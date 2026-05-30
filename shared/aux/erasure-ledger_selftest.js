/**
 * shared/aux/erasure-ledger_selftest.js
 *
 * Zero-dependency self-test for the erasure-request ledger. Run directly:
 *   node shared/aux/erasure-ledger_selftest.js
 *
 * Proves the load-bearing guarantees:
 *  - NO FAKE DATA: no findings → empty ledger; no removal outcome is ever invented.
 *  - REUSE: rows derive from buildTakedownPlan (the existing planner), not a
 *    re-implementation of letter/statute logic.
 *  - STATUTORY CLOCK (GDPR Art.17 ref): a real submitted_at yields the correct
 *    respond_by deadline (30 days GDPR / 45 days CCPA) and overdue detection.
 *  - CLOSURE MODE (DeleteMe ref): exactly one recheck_on date per row, and a
 *    single bounded next_recheck_on across the ledger.
 *  - HONEST PENDING: without a submitted_at the clock is NOT started (no invented
 *    deadline).
 *
 * REFERENCE PATTERNS UNDER TEST:
 *  - DeleteMe / Aura consolidated removal dashboard → status lifecycle + single
 *    scheduled recheck instead of compulsive manual checking.
 *  - GDPR Article 17 (RTBF) erasure-request automation → statutory respond-by
 *    deadline computed from the submission date (Art.12(3): one month, +2).
 */

'use strict';

const assert = require('assert');
const { makeEvent, EVENT_TYPES, VISIBILITY, RISK } = require('../detectors/event-types.js');
const { REQUEST_KINDS } = require('./takedown-letter.js');
const {
  buildErasureLedger,
  deadlineFor,
  addDays,
  validSubmittedAt,
  LEDGER_STATUS,
} = require('./erasure-ledger.js');

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

// A real third-party PII finding → produces GDPR/CCPA erasure requests.
function pubPiiEvent() {
  return makeEvent({
    event_type: EVENT_TYPES.PII_EMAIL_PUBLIC,
    source_module: 'pii_detector',
    data: { domain: 'example.com' },
    source_url: 'https://peoplefinder.example/profile/123',
    visibility: VISIBILITY.INDEXED,
    risk: RISK.HIGH,
  });
}

// ── NO FAKE DATA ────────────────────────────────────────────────────────────
t('no findings → empty ledger (no fabrication)', () => {
  const ledger = buildErasureLedger({ events: [] });
  assert.strictEqual(ledger.request_count, 0);
  assert.deepStrictEqual(ledger.rows, []);
  assert.strictEqual(ledger.next_recheck_on, null);
  assert.strictEqual(ledger.is_template, true);
});

t('never invents a "removed" outcome', () => {
  const ledger = buildErasureLedger({ events: [pubPiiEvent()] });
  for (const row of ledger.rows) {
    assert.notStrictEqual(row.status, LEDGER_STATUS.REMOVED);
    assert.notStrictEqual(row.status, LEDGER_STATUS.REAPPEARED);
  }
});

// ── REUSE (not re-implementation) ───────────────────────────────────────────
t('rows derive from the real takedown planner (GDPR + CCPA request kinds present)', () => {
  const ledger = buildErasureLedger({ events: [pubPiiEvent()] });
  const kinds = new Set(ledger.rows.map((r) => r.request_kind));
  assert.ok(kinds.has(REQUEST_KINDS.GDPR_ERASURE), 'expected a GDPR erasure row');
  assert.ok(kinds.has(REQUEST_KINDS.CCPA_DELETE), 'expected a CCPA delete row');
  // statute_refs carried straight through from the planner's letters.
  const gdpr = ledger.rows.find((r) => r.request_kind === REQUEST_KINDS.GDPR_ERASURE);
  assert.ok(gdpr.statute_refs.some((s) => /Article 17/.test(s)), 'expected GDPR Art.17 ref');
});

// ── HONEST PENDING (no invented deadline) ───────────────────────────────────
t('no submitted_at → clock not started, status drafted', () => {
  const ledger = buildErasureLedger({ events: [pubPiiEvent()], now: '2026-01-01T00:00:00.000Z' });
  const gdpr = ledger.rows.find((r) => r.request_kind === REQUEST_KINDS.GDPR_ERASURE);
  assert.strictEqual(gdpr.status, LEDGER_STATUS.DRAFTED);
  assert.strictEqual(gdpr.deadline.clock_started, false);
  assert.strictEqual(gdpr.deadline.respond_by, undefined);
  // but a single finite recheck date still exists (Closure Mode).
  assert.ok(typeof gdpr.recheck_on === 'string' && gdpr.recheck_on.length > 0);
});

// ── STATUTORY CLOCK (GDPR Art.17 = 30 days) ─────────────────────────────────
t('submitted_at → GDPR respond_by is exactly +30 days, awaiting within window', () => {
  const submitted = '2026-01-01T00:00:00.000Z';
  const ledger = buildErasureLedger({
    events: [pubPiiEvent()],
    submitted_at: { 'peoplefinder.example|gdpr_erasure': submitted },
    now: '2026-01-10T00:00:00.000Z', // 9 days in — within the month
  });
  const gdpr = ledger.rows.find((r) => r.request_kind === REQUEST_KINDS.GDPR_ERASURE);
  assert.strictEqual(gdpr.deadline.clock_started, true);
  assert.strictEqual(gdpr.deadline.respond_by, addDays(submitted, 30));
  assert.strictEqual(gdpr.deadline.is_overdue, false);
  assert.strictEqual(gdpr.status, LEDGER_STATUS.AWAITING);
  // recheck is the day AFTER the legal deadline (not constant checking).
  assert.strictEqual(gdpr.recheck_on, addDays(addDays(submitted, 30), 1));
});

t('past the deadline → overdue with statutory escalation', () => {
  const submitted = '2026-01-01T00:00:00.000Z';
  const ledger = buildErasureLedger({
    events: [pubPiiEvent()],
    submitted_at: { 'peoplefinder.example|gdpr_erasure': submitted },
    now: '2026-03-01T00:00:00.000Z', // ~59 days later — well past one month
  });
  const gdpr = ledger.rows.find((r) => r.request_kind === REQUEST_KINDS.GDPR_ERASURE);
  assert.strictEqual(gdpr.status, LEDGER_STATUS.OVERDUE);
  assert.strictEqual(gdpr.deadline.is_overdue, true);
  assert.ok(/Art. 77|supervisory authority/.test(gdpr.deadline.overdue_escalation));
  assert.strictEqual(ledger.overdue_count >= 1, true);
});

// CCPA window is the real 45 days.
t('CCPA respond_by is +45 days', () => {
  const submitted = '2026-01-01T00:00:00.000Z';
  const d = deadlineFor(REQUEST_KINDS.CCPA_DELETE, submitted, '2026-01-02T00:00:00.000Z');
  assert.strictEqual(d.respond_by, addDays(submitted, 45));
  assert.strictEqual(d.extended_max_by, addDays(submitted, 90));
});

// ── CLOSURE MODE (single bounded next check-back) ───────────────────────────
t('ledger exposes a single next_recheck_on across all rows', () => {
  const ledger = buildErasureLedger({ events: [pubPiiEvent()], now: '2026-01-01T00:00:00.000Z' });
  assert.ok(ledger.request_count > 0);
  assert.ok(typeof ledger.next_recheck_on === 'string');
  // it is the earliest recheck among pending rows.
  const earliest = ledger.rows
    .map((r) => r.recheck_on)
    .filter(Boolean)
    .sort()[0];
  assert.strictEqual(ledger.next_recheck_on, earliest);
});

// ── input hygiene ───────────────────────────────────────────────────────────
t('validSubmittedAt rejects garbage, accepts real ISO', () => {
  assert.strictEqual(validSubmittedAt('not-a-date'), null);
  assert.strictEqual(validSubmittedAt(''), null);
  assert.strictEqual(validSubmittedAt(42), null);
  assert.ok(validSubmittedAt('2026-01-01T00:00:00.000Z'));
});

t('determinism: same inputs → identical ledger', () => {
  const args = { events: [pubPiiEvent()], now: '2026-01-01T00:00:00.000Z' };
  assert.deepStrictEqual(buildErasureLedger(args), buildErasureLedger(args));
});

console.log(`\nerasure-ledger self-test: ${failures === 0 ? 'OK' : failures + ' FAILURE(S)'}`);
process.exit(failures === 0 ? 0 : 1);
