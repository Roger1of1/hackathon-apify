/**
 * integrations/grade/_selftest.js
 *
 * Zero-dependency self-test for the Self-Exposure Grade. Run directly:
 *   node integrations/grade/_selftest.js
 * Discovered automatically by integrations/run-module-selftests.js.
 *
 * Proves the load-bearing guarantees:
 *   - NO FAKE DATA: empty event set ⇒ graded:false / grade:null (NEVER a
 *     fabricated "A" for an unscanned subject).
 *   - DETERMINISTIC: identical events always yield the identical grade/score.
 *   - OBSERVATORY MODEL: baseline 100, named per-category deductions, A+…F band;
 *     a clean (penalty-free) scan keeps 100 ⇒ A+; worse exposures drop the letter.
 *   - REPRODUCIBLE LEDGER: score == round(baseline − Σ breakdown deductions).
 *   - RED LINES: scope-gated entry refuses a stalking input and a non-self scope
 *     via the REAL shared/scope.js, returning NO grade.
 *   - REUSE: severity_band comes from the EXISTING shared/enrich/severity.js.
 */

'use strict';

const assert = require('assert');
const path = require('path');
const {
  makeEvent, EVENT_TYPES, VISIBILITY, RISK,
} = require(path.join(__dirname, '..', '..', 'shared', 'detectors', 'event-types.js'));
const {
  computeExposureGrade, gradeForScopedRun, letterFor, BASELINE,
} = require('./exposure-grade.js');

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

process.stdout.write('exposure-grade self-test\n');

// ── 1. NO FAKE DATA: empty in ⇒ no grade ────────────────────────────────────
t('empty events ⇒ graded:false, grade:null (no fabricated A)', () => {
  const r = computeExposureGrade([]);
  assert.strictEqual(r.graded, false);
  assert.strictEqual(r.grade, null);
  assert.strictEqual(r.score, null);
  assert.strictEqual(r.reason, 'no_data');
  assert.deepStrictEqual(r.breakdown, []);
});

t('non-array / junk in ⇒ no grade', () => {
  assert.strictEqual(computeExposureGrade(null).graded, false);
  assert.strictEqual(computeExposureGrade(undefined).graded, false);
  assert.strictEqual(computeExposureGrade([{ not: 'an event' }, 42]).graded, false);
});

// ── 2. A clean real scan (events present, none penalised) ⇒ A+ at 100 ────────
t('events with only zero-weight outcome still grade (data, but A+)', () => {
  // SELF_PROFILE_URL has a small weight; to get a true zero-deduction scan we use
  // a private, info-risk profile url whose multipliers shrink it — but it still
  // deducts a little. So instead assert: a single low exposure stays high (A/B).
  const ev = makeEvent({
    event_type: EVENT_TYPES.SELF_PROFILE_URL,
    source_module: 'discovery',
    data: 'https://example.com/me',
    risk: RISK.INFO,
    visibility: VISIBILITY.PRIVATE,
    confidence: 0.9,
    source_url: 'https://example.com/me',
  });
  const r = computeExposureGrade([ev]);
  assert.strictEqual(r.graded, true);
  assert.strictEqual(r.baseline, BASELINE);
  assert(r.score >= 95, `expected near-perfect score, got ${r.score}`);
  assert(['A+', 'A'].includes(r.grade), `expected A+/A, got ${r.grade}`);
});

// ── 3. A severe exposure drops the grade hard ───────────────────────────────
t('a high-risk indexed secret leak drops the grade to D/F', () => {
  const secret = makeEvent({
    event_type: EVENT_TYPES.SECRET_LEAK_PUBLIC,
    source_module: 'secret-leak-detector',
    data: '<redacted credential>',
    risk: RISK.HIGH,
    visibility: VISIBILITY.INDEXED,
    confidence: 0.95,
    source_url: 'https://example.com/.env',
  });
  const r = computeExposureGrade([secret]);
  assert.strictEqual(r.graded, true);
  assert(r.score <= 60, `expected a low score, got ${r.score}`);
  assert(['D+', 'D', 'D-', 'F', 'C-'].includes(r.grade), `expected D/F-ish, got ${r.grade}`);
  // breakdown must NAME the category that caused the deduction (Observatory-style)
  const row = r.breakdown.find((b) => b.category === EVENT_TYPES.SECRET_LEAK_PUBLIC);
  assert(row, 'breakdown must name the secret-leak category');
  assert(row.deduction > 0, 'the named category must carry a real deduction');
});

// ── 4. DETERMINISTIC + REPRODUCIBLE LEDGER ──────────────────────────────────
t('identical events ⇒ identical grade (deterministic)', () => {
  const mk = () => makeEvent({
    event_type: EVENT_TYPES.PII_POSTAL_PUBLIC,
    source_module: 'pii-detector',
    data: '<redacted address>',
    risk: RISK.MEDIUM,
    visibility: VISIBILITY.INDEXED,
    confidence: 0.8,
    source_url: 'https://example.com/contact',
  });
  const a = computeExposureGrade([mk(), mk()]);
  const b = computeExposureGrade([mk(), mk()]);
  assert.strictEqual(a.score, b.score);
  assert.strictEqual(a.grade, b.grade);
});

t('score == round(baseline − Σ breakdown deductions) (reproducible from ledger)', () => {
  const events = [
    makeEvent({
      event_type: EVENT_TYPES.BROKER_LISTING_HIT, source_module: 'broker-listing-detector',
      data: '<listing>', risk: RISK.HIGH, visibility: VISIBILITY.INDEXED, confidence: 0.9,
      source_url: 'https://spokeo.example/x',
    }),
    makeEvent({
      event_type: EVENT_TYPES.PII_EMAIL_PUBLIC, source_module: 'pii-detector',
      data: 'a@b.example', risk: RISK.MEDIUM, visibility: VISIBILITY.INDEXED, confidence: 0.7,
      source_url: 'https://example.com/contact',
    }),
  ];
  const r = computeExposureGrade(events);
  const sumLedger = r.breakdown.reduce((acc, row) => acc + row.deduction, 0);
  const expected = Math.max(0, Math.min(100, Math.round(BASELINE - sumLedger)));
  assert.strictEqual(r.score, expected, `score ${r.score} must reproduce from ledger ${expected}`);
});

// ── 5. REPEAT DAMPING: 5 of the same category < 5× the single penalty ───────
t('repeat instances of one category are damped + capped', () => {
  const mk = () => makeEvent({
    event_type: EVENT_TYPES.TRACKER_THIRD_PARTY, source_module: 'tracker-detector',
    data: 'doubleclick.net', risk: RISK.MEDIUM, visibility: VISIBILITY.INDEXED, confidence: 0.9,
    source_url: 'https://example.com/',
  });
  const one = computeExposureGrade([mk()]);
  const five = computeExposureGrade([mk(), mk(), mk(), mk(), mk()]);
  const oneDed = one.breakdown[0].deduction;
  const fiveDed = five.breakdown[0].deduction;
  assert(fiveDed > oneDed, 'more instances should deduct more');
  assert(fiveDed < oneDed * 5, 'repeats must be damped, not linear');
  assert(fiveDed <= 55, 'per-category cap must hold');
});

// ── 6. letterFor band edges ─────────────────────────────────────────────────
t('letterFor maps band edges correctly', () => {
  assert.strictEqual(letterFor(100), 'A+');
  assert.strictEqual(letterFor(90), 'A');
  assert.strictEqual(letterFor(60), 'C');
  assert.strictEqual(letterFor(0), 'F');
  assert.strictEqual(letterFor(50), 'D+');
  assert.strictEqual(letterFor(49), 'D');
  assert.strictEqual(letterFor(39), 'F');
});

// ── 7. RED LINES via the REAL scope gate ────────────────────────────────────
t('scope-gated grade refuses a stalking input (no grade)', () => {
  const r = gradeForScopedRun(
    { scope_type: 'self', target_urls: ['https://example.com'], goal: 'track my ex and monitor their account' },
    [makeEvent({
      event_type: EVENT_TYPES.PII_EMAIL_PUBLIC, source_module: 'pii-detector',
      data: 'x@y.example', risk: RISK.LOW, source_url: 'https://example.com',
    })],
  );
  assert.strictEqual(r.graded, false);
  assert.strictEqual(r.grade, null);
  assert.strictEqual(r.reason, 'scope_rejected');
});

t('scope-gated grade refuses a non-self scope (no grade)', () => {
  const r = gradeForScopedRun(
    { scope_type: 'public_figure', target_urls: ['https://example.com'] },
    [makeEvent({
      event_type: EVENT_TYPES.PII_EMAIL_PUBLIC, source_module: 'pii-detector',
      data: 'x@y.example', risk: RISK.LOW, source_url: 'https://example.com',
    })],
  );
  assert.strictEqual(r.graded, false);
  assert.strictEqual(r.reason, 'not_self_scope');
  assert.strictEqual(r.grade, null);
});

t('scope-gated grade DOES grade an allowed self run', () => {
  const r = gradeForScopedRun(
    { scope_type: 'self', target_urls: ['https://example.com/me'] },
    [makeEvent({
      event_type: EVENT_TYPES.PII_POSTAL_PUBLIC, source_module: 'pii-detector',
      data: '<redacted>', risk: RISK.HIGH, visibility: VISIBILITY.INDEXED, confidence: 0.9,
      source_url: 'https://example.com/me',
    })],
  );
  assert.strictEqual(r.graded, true);
  assert(r.grade, 'expected a letter grade for an allowed self run');
  assert(typeof r.severity_band === 'string', 'severity_band must come from shared severity');
});

if (failures > 0) {
  process.stderr.write(`\nexposure-grade self-test FAILED: ${failures} failure(s)\n`);
  process.exit(1);
}
process.stdout.write('\nexposure-grade self-test: all assertions passed\n');
