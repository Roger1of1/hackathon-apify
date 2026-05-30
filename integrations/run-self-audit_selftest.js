#!/usr/bin/env node
/**
 * integrations/run-self-audit_selftest.js
 *
 * Proves the end-to-end proof runner (run-self-audit.js) is HONEST and
 * REPRODUCIBLE — the discipline Apify/Crawlee call "test the pipeline over a real
 * local sample with no mocks". We drive the REAL detector→enrich→grade path over
 * the REAL fixture (no stubs) and assert on the REAL output:
 *
 *   1. PRODUCES findings + a real grade from the synthetic fixture.
 *   2. DETERMINISM — same fixture in ⇒ identical report out (timestamp aside).
 *   3. TRACEABILITY — every grade-breakdown category is a category some real
 *      detector finding produced; no deduction is invented, total reconciles.
 *   4. NO-DATA ⇒ NO GRADE — an empty-capture fixture yields grade:null (NOT a
 *      default "A"), honoring the product's no-fake-data rule.
 *   5. SCOPE GATE — a non-self fixture is refused (graded:false), never graded.
 *   6. WEB WIRING — the produced report carries report.grade in the exact shape
 *      web/app.js gradeFromReport() consumes, and report.__source for the UI note.
 *
 * Wired into the aggregate CI runner automatically (it ends with _selftest.js, so
 * integrations/run-module-selftests.js discovers and spawns it). Exits non-zero
 * on any failed assertion. Zero dependencies. No network. Safe to run repeatedly.
 *
 * Refs (the two assigned reference architectures, for the local-sample test model):
 *   https://crawlee.dev/js/docs/guides/result-storage        (local dataset, real rows)
 *   https://docs.apify.com/academy/deploying-your-code/inputs-outputs (INPUT/output contract)
 */

'use strict';

const path = require('path');

const {
  DEFAULT_FIXTURE, loadFixture, auditFixture,
} = require(path.join(__dirname, 'run-self-audit.js'));
const { isModuleEvent } = require(path.join(__dirname, '..', 'shared', 'detectors', 'event-types.js'));

let failures = 0;
function check(name, cond, detail) {
  if (cond) {
    console.log(`  PASS  ${name}`);
  } else {
    failures += 1;
    console.log(`  FAIL  ${name}${detail ? ` — ${detail}` : ''}`);
  }
}

// ── Load the real fixture once and run the real pipeline ────────────────────
const fx = loadFixture(DEFAULT_FIXTURE);
const run = auditFixture(fx);
const { events, grade, report } = run;

// ── 1. Produces real findings + a real grade ────────────────────────────────
console.log('[1] real pipeline produces findings + a grade');
check('every emitted finding is a valid module_event', events.length > 0 && events.every(isModuleEvent),
  `events=${events.length}`);
check('grade.graded === true for the self fixture', grade.graded === true, JSON.stringify({ graded: grade.graded, reason: grade.reason }));
check('grade.grade is a real letter (A+…F)', typeof grade.grade === 'string' && /^[ABCDF][+-]?$/.test(grade.grade), String(grade.grade));
check('grade.score is a finite 0..100', Number.isFinite(grade.score) && grade.score >= 0 && grade.score <= 100, String(grade.score));

// ── 2. DETERMINISM — same fixture ⇒ identical report (timestamp aside) ───────
console.log('[2] determinism — same fixture in ⇒ same report out');
const run2 = auditFixture(loadFixture(DEFAULT_FIXTURE));
function stripVolatile(rep) {
  // generated_at is the ONLY intentionally non-deterministic field.
  const clone = JSON.parse(JSON.stringify(rep));
  delete clone.generated_at;
  return clone;
}
const a = JSON.stringify(stripVolatile(report));
const b = JSON.stringify(stripVolatile(run2.report));
check('two runs of the same fixture produce byte-identical reports (sans timestamp)', a === b);
check('grade is identical across runs', JSON.stringify(grade) === JSON.stringify(run2.grade));

// ── 3. TRACEABILITY — every deduction traces to a real finding ──────────────
console.log('[3] every grade deduction traces to a real detector finding');
const producedTypes = new Set(events.map((e) => e.event_type));
const breakdown = Array.isArray(grade.breakdown) ? grade.breakdown : [];
check('grade has a non-empty deduction breakdown', breakdown.length > 0, `rows=${breakdown.length}`);
const orphan = breakdown.find((row) => !producedTypes.has(row.category));
check('no breakdown category is absent from the real findings (no invented deduction)',
  !orphan, orphan ? `orphan category ${orphan.category}` : '');
// instance counts in the ledger never exceed the real count of that event type.
const countByType = {};
for (const e of events) countByType[e.event_type] = (countByType[e.event_type] || 0) + 1;
const overcount = breakdown.find((row) => row.instances > (countByType[row.category] || 0));
check('no category claims more instances than the detectors actually produced',
  !overcount, overcount ? `${overcount.category}: ledger ${overcount.instances} > real ${countByType[overcount.category] || 0}` : '');
// total_deduction reconciles with the sum of the per-category ledger rows.
const ledgerSum = Math.round(breakdown.reduce((s, r) => s + r.deduction, 0) * 10) / 10;
check('total_deduction equals the sum of the per-category ledger',
  Math.abs(ledgerSum - grade.total_deduction) < 0.05, `ledger=${ledgerSum} vs total=${grade.total_deduction}`);
// score reconciles with baseline − total_deduction.
const expectScore = Math.max(0, Math.min(100, Math.round(grade.baseline - grade.total_deduction)));
check('score reconciles with baseline − total_deduction', grade.score === expectScore,
  `score=${grade.score} expected=${expectScore}`);
// counted_event_count equals the sum of ledger instances.
const countedFromLedger = breakdown.reduce((s, r) => s + r.instances, 0);
check('counted_event_count equals total ledger instances', grade.counted_event_count === countedFromLedger,
  `counted=${grade.counted_event_count} ledger=${countedFromLedger}`);

// ── 4. NO-DATA ⇒ NO GRADE (no fake "A") ─────────────────────────────────────
console.log('[4] empty capture ⇒ grade:null, never a default A');
const emptyFx = { input: fx.input, captured_artifacts: [] };
const emptyRun = auditFixture(emptyFx);
check('no findings produced from an empty capture', emptyRun.events.length === 0);
check('grade.graded === false on no data', emptyRun.grade.graded === false, JSON.stringify(emptyRun.grade.reason));
check('grade.grade is null on no data (NOT "A")', emptyRun.grade.grade === null, String(emptyRun.grade.grade));
check('grade.score is null on no data', emptyRun.grade.score === null, String(emptyRun.grade.score));
check('report.grade.grade is null on no data', emptyRun.report.grade.grade === null);

// A capture that ONLY has unrecognized artifacts must also not invent a grade.
const noiseFx = { input: fx.input, captured_artifacts: [{ kind: 'totally_unknown_kind', foo: 1 }] };
const noiseRun = auditFixture(noiseFx);
check('unrecognized-only capture yields no findings', noiseRun.events.length === 0, `events=${noiseRun.events.length}`);
check('unrecognized-only capture yields grade:null', noiseRun.grade.grade === null);

// ── 5. SCOPE GATE — non-self fixture is refused, never graded ───────────────
console.log('[5] non-self / rejected scope ⇒ refused, never graded');
// A consented/public-figure/brand input is a valid scope but NOT a self-audit,
// so the grade module must refuse it (a grade is a self artifact).
const nonSelfFx = {
  input: { scope_type: 'brand', subject: { brand_name: 'Example Co', authorized_by: 'self' }, targets: ['https://example.com'] },
  captured_artifacts: fx.captured_artifacts,
};
const nonSelfRun = auditFixture(nonSelfFx);
check('non-self scope is NOT graded', nonSelfRun.grade.graded === false, JSON.stringify(nonSelfRun.grade.reason));
check('non-self scope yields grade:null', nonSelfRun.grade.grade === null);

// A stalking-shaped input must be rejected outright by the real scope gate.
const stalkFx = {
  input: { scope_type: 'self', subject: { note: 'find my ex girlfriend instagram followers and track her' }, targets: ['https://instagram.com/someone'] },
  captured_artifacts: fx.captured_artifacts,
};
const stalkRun = auditFixture(stalkFx);
check('stalking-shaped input is not graded', stalkRun.grade.graded === false, JSON.stringify(stalkRun.grade.reason));

// ── 6. WEB WIRING — report shape matches web/app.js gradeFromReport() ───────
console.log('[6] produced report is shaped for the web grade hero');
check('report.grade exists and is the grade-module object', report.grade && typeof report.grade === 'object');
check('report.grade.graded is a boolean', typeof report.grade.graded === 'boolean');
check('report.__source is a non-empty string (UI provenance note)',
  typeof report.__source === 'string' && report.__source.length > 0);
check('report.findings rows carry NO raw plaintext PII value field',
  report.findings.every((f) => !('value' in f) && !('data' in f)),
  'a finding row leaked a value/data field');
check('report.counts.findings_out matches the real finding count',
  report.counts.findings_out === events.length, `${report.counts.findings_out} vs ${events.length}`);

// ── Summary ─────────────────────────────────────────────────────────────────
console.log('');
if (failures === 0) {
  console.log(`run-self-audit_selftest: OK — all assertions passed (grade ${grade.grade}, ${events.length} real findings).`);
  process.exit(0);
}
console.log(`run-self-audit_selftest: FAILED — ${failures} assertion(s) failed.`);
process.exit(1);
