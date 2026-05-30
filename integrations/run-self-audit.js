#!/usr/bin/env node
/**
 * integrations/run-self-audit.js
 *
 * REAL END-TO-END PROOF RUNNER — the missing link between the existing detector
 * pipeline and the web dashboard's grade hero. It reads a SYNTHETIC/TEMPLATE
 * self-audit fixture, runs it through the REAL code path with NO mocks
 *
 *     captured artifacts  →  shared/detectors  (runDetectors)
 *                         →  shared/enrich     (severity / confidence)
 *                         →  integrations/grade/exposure-grade.js (read-only)
 *                         →  report shaping
 *
 * and writes the report the web app ALREADY tries to fetch
 * (web/app.js:loadExampleReport → web/data/example-report.json, plus a file://
 * fallback web/data/example-report.js). Before this runner existed those two
 * files were MISSING, so the grade hero always rendered its honest "no grade
 * yet" state. This makes the proof real: the letter the browser shows is the
 * exact output of the real grading code over real detector findings.
 *
 * ── NO FAKE DATA (the product's standing rule) ──────────────────────────────
 * The ONLY invented content is the *input* fixture (clearly labelled SYNTHETIC /
 * TEMPLATE — integrations/fixtures/self-audit-fixture.json). The runner never
 * fabricates a finding or a grade: it emits ONLY what the real detectors parse
 * out of that fixture and ONLY the grade exposure-grade.js computes from those
 * findings. Point the same runner at a real gate-approved capture and it would
 * produce a real report identically — the fixture is a stand-in for a capture,
 * not a stand-in for results. If the input yields zero scoreable findings, the
 * report honestly carries grade:null (no default "A").
 *
 * ── Reference architecture #1: Apify CLI local run (apify run) ──────────────
 * The Apify CLI's `apify run` executes an Actor on your machine against LOCAL
 * storage: the run's input is read from the default key-value store at
 *   storage/key_value_stores/default/INPUT.json
 * and its results are appended to the default dataset at
 *   storage/datasets/default/{INDEX}.json
 * (`--purge` clears those before a run; APIFY_LOCAL_STORAGE_DIR relocates them).
 * This runner mirrors that contract exactly so the proof is shaped like a real
 * local Actor run, not an ad-hoc script: it reads its INPUT from a default
 * key-value-store layout, writes each finding as a numbered dataset item, and
 * supports --purge. That means the same fixture can later be dropped into a real
 * Actor's INPUT.json with no reshaping.
 *   Refs (verified May 2026):
 *     https://docs.apify.com/cli/docs/reference                 (apify run, --purge)
 *     https://docs.apify.com/academy/deploying-your-code/inputs-outputs
 *     https://docs.apify.com/platform/storage/key-value-store   (INPUT.json, id "default")
 *
 * ── Reference architecture #2: Crawlee local Dataset + on-fixture testing ───
 * Crawlee's Dataset is the canonical "append-only table of result rows" store:
 * `Dataset.pushData(item)` writes each row as a separate JSON file under
 *   {CRAWLEE_STORAGE_DIR}/datasets/default/{INDEX}.json
 * and the default dataset is auto-created — no init needed. We borrow that exact
 * model for the findings ledger (one numbered JSON per finding under a default
 * dataset dir), so a third party can recompute the grade from the published
 * rows. And we borrow Crawlee/Apify's end-to-end testing discipline: drive the
 * pipeline over a REAL local sample with NO network and NO mocks, then assert on
 * the real output (see run-self-audit_selftest.js) rather than stubbing layers.
 *   Refs (verified May 2026):
 *     https://crawlee.dev/js/docs/introduction/saving-data      (Dataset.pushData)
 *     https://crawlee.dev/js/api/core/class/Dataset             (default dataset, local JSON)
 *     https://crawlee.dev/js/docs/guides/result-storage
 *
 * ── RED LINES (enforced by routing through the REAL gate) ───────────────────
 *  - The fixture is scope_type=self. The grade is produced via
 *    exposure-grade.gradeForScopedRun, which routes the input through the REAL
 *    shared/scope.js and refuses anything that is not an allowed self scope. A
 *    stalking/non-self fixture would yield graded:false, never a grade.
 *  - We do NOT touch shared/scope.js or rebuild exposure-grade.js — both are
 *    required READ-ONLY. All writes land in this agent's subtree (integrations/**)
 *    and the web/data/ report files the UI already references.
 *
 * Zero dependencies. Node >=18. Deterministic: same fixture → same report bytes
 * (modulo the generated_at timestamp, which is excluded from the determinism
 * assertion). Safe to run repeatedly.
 *
 * Usage:
 *   node integrations/run-self-audit.js            # write report + local stores
 *   node integrations/run-self-audit.js --purge    # clear local stores first
 *   node integrations/run-self-audit.js --quiet     # no stdout summary
 *   const { runSelfAudit } = require('./run-self-audit.js'); // programmatic
 */

'use strict';

const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');

// REAL pipeline modules (read-only require; we never write shared/** or rebuild grade).
const detectors = require(path.join(ROOT, 'shared', 'detectors', 'index.js'));
const { rankBySeverity, batchSeverity } = require(path.join(ROOT, 'shared', 'enrich', 'severity.js'));
const { gradeForScopedRun } = require(path.join(__dirname, 'grade', 'exposure-grade.js'));

const DEFAULT_FIXTURE = path.join(__dirname, 'fixtures', 'self-audit-fixture.json');

// Apify/Crawlee-style LOCAL storage layout, mirrored under integrations/ so the
// proof leaves the same on-disk artifacts a real `apify run` / Crawlee run would.
const STORAGE_DIR = path.join(__dirname, 'storage');
const KVS_DIR = path.join(STORAGE_DIR, 'key_value_stores', 'default'); // INPUT.json lives here
const DATASET_DIR = path.join(STORAGE_DIR, 'datasets', 'default');     // one JSON per finding

// Where the web app already looks for the produced report.
const WEB_DATA_DIR = path.join(ROOT, 'web', 'data');
const REPORT_JSON = path.join(WEB_DATA_DIR, 'example-report.json');
const REPORT_JS = path.join(WEB_DATA_DIR, 'example-report.js'); // file:// fallback wrapper

/** Load + lightly validate the synthetic fixture. */
function loadFixture(fixturePath = DEFAULT_FIXTURE) {
  const raw = fs.readFileSync(fixturePath, 'utf8');
  const fx = JSON.parse(raw);
  if (!fx || typeof fx !== 'object') throw new Error('fixture is not an object');
  if (!Array.isArray(fx.captured_artifacts)) throw new Error('fixture.captured_artifacts must be an array');
  if (!fx.input || typeof fx.input !== 'object') throw new Error('fixture.input (scoped input) is required');
  return fx;
}

/** Recreate a directory empty (Apify `--purge` semantics for local storage). */
function emptyDir(dir) {
  fs.rmSync(dir, { recursive: true, force: true });
  fs.mkdirSync(dir, { recursive: true });
}

function ensureDir(dir) {
  fs.mkdirSync(dir, { recursive: true });
}

/**
 * Write the run INPUT to the default key-value store as INPUT.json, exactly like
 * `apify run` reads it. This is the run's provenance: anyone can see the precise
 * scoped input the grade was computed for.
 */
function writeInput(fx, opts = {}) {
  if (opts.purge) emptyDir(KVS_DIR); else ensureDir(KVS_DIR);
  const input = {
    __label: 'SYNTHETIC / TEMPLATE INPUT — mirrors Apify default KVS INPUT.json',
    __ref: 'https://docs.apify.com/platform/storage/key-value-store',
    scope: fx.input,
    artifact_count: fx.captured_artifacts.length,
  };
  fs.writeFileSync(path.join(KVS_DIR, 'INPUT.json'), `${JSON.stringify(input, null, 2)}\n`, 'utf8');
  return input;
}

/**
 * Append findings to the default dataset as numbered JSON rows — the Crawlee
 * `Dataset.pushData` local layout ({INDEX}.json under datasets/default). Each row
 * is one real detector finding, so the grade is recomputable from the rows.
 */
function writeDataset(findings, opts = {}) {
  if (opts.purge) emptyDir(DATASET_DIR); else ensureDir(DATASET_DIR);
  findings.forEach((f, i) => {
    const name = `${String(i).padStart(9, '0')}.json`;
    fs.writeFileSync(path.join(DATASET_DIR, name), `${JSON.stringify(f, null, 2)}\n`, 'utf8');
  });
}

/**
 * Shape the produced report. Carries:
 *  - grade:        the EXACT exposure-grade.js result (the UI reads report.grade)
 *  - __source:     human label of where the grade came from (UI shows it, honestly)
 *  - findings:     a compact, non-PII-bearing summary of each counted finding
 *  - severity:     batch severity headline from the REAL shared/enrich/severity.js
 *  - provenance:   how to reproduce (fixture + stores + the two reference archs)
 *
 * NOTE: we deliberately keep raw PII values OUT of the published report — each
 * finding row exposes only event_type / risk / visibility / confidence / source,
 * matching how the grade module itself never reads raw values.
 */
function shapeReport(fx, events, grade) {
  const generatedAt = new Date().toISOString();

  const crawlSummary = detectors.summarizeForExposure(events);
  const severity = batchSeverity(events, crawlSummary);
  const ranked = rankBySeverity(events);

  const findings = ranked.map((ev) => ({
    event_type: ev.event_type,
    source_module: ev.source_module,
    risk: ev.risk,
    visibility: ev.visibility,
    confidence: ev.confidence,
    source_url: ev.source_url || null,
    severity_band: ev._severity ? ev._severity.band : null,
  }));

  return {
    __label: 'SYNTHETIC / TEMPLATE-DERIVED REPORT — produced by integrations/run-self-audit.js',
    __notice:
      'Findings below are the REAL output of shared/detectors over a clearly-labelled SYNTHETIC fixture '
      + '(integrations/fixtures/self-audit-fixture.json). Nothing is fabricated: the grade is computed by '
      + 'integrations/grade/exposure-grade.js from exactly these findings. Point the runner at a real '
      + 'gate-approved capture for a real report.',
    __source: 'synthetic self-audit fixture (template) · real detector→grade pipeline',
    generated_at: generatedAt,
    scope: fx.input,
    grade,                  // ← the web grade hero reads report.grade (graded:true|false)
    severity,               // batch severity headline (shared/enrich/severity.js)
    crawl_summary: crawlSummary,
    findings,               // compact, value-free finding rows (mirrors dataset)
    counts: {
      artifacts_in: fx.captured_artifacts.length,
      findings_out: events.length,
      counted_in_grade: grade.counted_event_count != null ? grade.counted_event_count : 0,
    },
    provenance: {
      runner: 'integrations/run-self-audit.js',
      fixture: 'integrations/fixtures/self-audit-fixture.json',
      input_store: 'integrations/storage/key_value_stores/default/INPUT.json',
      findings_dataset: 'integrations/storage/datasets/default/',
      pipeline: ['shared/detectors/index.js', 'shared/enrich/severity.js', 'integrations/grade/exposure-grade.js'],
      grade_module: 'integrations/grade/exposure-grade.js (read-only)',
      reference_architectures: {
        apify_cli_local_run: 'https://docs.apify.com/cli/docs/reference',
        apify_kvs_input: 'https://docs.apify.com/platform/storage/key-value-store',
        crawlee_dataset: 'https://crawlee.dev/js/docs/introduction/saving-data',
      },
    },
  };
}

/**
 * Run the full pipeline over a fixture object and return { events, grade, report }.
 * Pure compute (no file I/O) so the self-test can assert determinism cheaply.
 */
function auditFixture(fx) {
  // 1) REAL detector dispatch over the captured artifacts.
  const { events, by_module, skipped } = detectors.runDetectors(fx.captured_artifacts);

  // 2) REAL scope-gated grade. gradeForScopedRun routes fx.input through the real
  //    shared/scope.js and only grades an allowed self scope; otherwise graded:false.
  const grade = gradeForScopedRun(fx.input, events);

  // 3) Shape the web-facing report from the real findings + real grade.
  const report = shapeReport(fx, events, grade);

  return { events, grade, report, by_module, skipped };
}

/**
 * Full side-effecting run: read fixture, write the Apify/Crawlee-style local
 * stores, write the web report (+ file:// JS wrapper). Returns the run result.
 */
function runSelfAudit(opts = {}) {
  const fixturePath = opts.fixture || DEFAULT_FIXTURE;
  const fx = loadFixture(fixturePath);

  const { events, grade, report, by_module, skipped } = auditFixture(fx);

  // Apify-style: INPUT.json into the default KVS; findings into the default dataset.
  writeInput(fx, opts);
  writeDataset(report.findings, opts);

  // The two files the web app already references.
  ensureDir(WEB_DATA_DIR);
  fs.writeFileSync(REPORT_JSON, `${JSON.stringify(report, null, 2)}\n`, 'utf8');
  // file:// fallback: fetch() is blocked from file://, so the app also tries a
  // <script> that sets window.__EX_REPORT__ (mirrors web/data/plan.js).
  const jsWrapper =
    '/* AUTO-GENERATED by integrations/run-self-audit.js — file:// fallback for'
    + ' web/data/example-report.json. SYNTHETIC/TEMPLATE-derived; do not edit by hand. */\n'
    + `window.__EX_REPORT__ = ${JSON.stringify(report, null, 2)};\n`;
  fs.writeFileSync(REPORT_JS, jsWrapper, 'utf8');

  if (!opts.quiet) {
    const g = grade.graded ? `${grade.grade} (score ${grade.score}/100, −${grade.total_deduction})` : `none (${grade.reason})`;
    process.stdout.write(
      `\nrun-self-audit — REAL pipeline over SYNTHETIC fixture\n`
      + `  fixture     : ${path.relative(ROOT, fixturePath)}\n`
      + `  by module   : ${JSON.stringify(by_module)} (skipped ${skipped})\n`
      + `  findings    : ${events.length}\n`
      + `  grade       : ${g}\n`
      + `  wrote       : ${path.relative(ROOT, REPORT_JSON)}\n`
      + `              : ${path.relative(ROOT, REPORT_JS)}\n`
      + `  local stores: ${path.relative(ROOT, KVS_DIR)}/INPUT.json + ${path.relative(ROOT, DATASET_DIR)}/*.json\n\n`,
    );
  }

  return { fx, events, grade, report };
}

// CLI entry.
if (require.main === module) {
  const args = new Set(process.argv.slice(2));
  try {
    runSelfAudit({ purge: args.has('--purge'), quiet: args.has('--quiet') });
  } catch (err) {
    process.stderr.write(`run-self-audit: FAILED — ${err && err.message}\n`);
    process.exit(1);
  }
}

module.exports = {
  DEFAULT_FIXTURE,
  REPORT_JSON,
  REPORT_JS,
  loadFixture,
  auditFixture,
  shapeReport,
  runSelfAudit,
};
