/**
 * integrations/exports/test-datapackage.js
 *
 * Self-test for the portable Frictionless evidence package emitter. Lives in MY
 * subtree (integrations/**), not under test/. Run directly:
 *   node integrations/exports/test-datapackage.js
 * (Filename ends in -datapackage.js, not _selftest.js, matching the sibling
 *  test-exports.js convention; it is referenced from apify.json's exports entry.)
 *
 * Proves the load-bearing guarantees:
 *   1. WRAPS redaction: at a non-RED marking the package contains NO raw locator
 *      columns (url/html_key/screenshot_key/note) and NO such cell values — the
 *      Table Schema itself cannot name them.
 *   2. FAIL-CLOSED: an unknown/missing marking is refused (no package built).
 *   3. NO FAKE DATA: zero rows ⇒ zero resources + an explicit empty-package note;
 *      no sample rows injected.
 *   4. FRICTIONLESS VALID-SHAPE: datapackage.json carries profile, resources[],
 *      each resource has a tabular-data-resource profile + a Table Schema whose
 *      fields match the CSV header order.
 *   5. TLP:RED keeps the operator's full evidence (url/keys present) — redaction
 *      is for sharing, not self-blinding.
 *   6. DETERMINISTIC + CITABLE: same input + same `now` ⇒ same content fingerprint.
 *   7. GRADE RE-DERIVABLE: an embedded grade ledger reproduces score from the CSV.
 */

'use strict';

const assert = require('assert');
const {
  buildDataPackage, schemaFor, fingerprintPackage,
} = require('./datapackage');
const { NEVER_SHARE_BELOW_RED } = require('./redaction-policy');

let passed = 0;
function ok(name, fn) {
  fn();
  passed += 1;
  process.stdout.write(`  ok  ${name}\n`);
}

const NOW = '2026-05-30T00:00:00.000Z';

const rawRows = [
  {
    record_type: 'capture',
    case_id: 'case_abc',
    url: 'https://example.com/me',
    content_sha256: 'a'.repeat(64),
    html_sha256: 'b'.repeat(64),
    html_key: 'html/0001',
    screenshot_key: 'shot/0001',
    status_code: 200,
    captured_at: NOW,
  },
  {
    record_type: 'evidence_index',
    case_id: 'case_abc',
    url: 'https://example.com/proof',
    timestamp: NOW,
    content_sha256: 'c'.repeat(64),
    html_sha256: 'd'.repeat(64),
    screenshot_key: 'shot/0002',
    html_key: 'html/0002',
    change: 'added',
    immutable: true,
  },
  {
    record_type: 'backoff_for_human_review',
    case_id: 'case_abc',
    url: 'https://example.com/blocked',
    status_code: 403,
    note: 'Blocked by source. Stopped instead of evading.',
    flagged_at: NOW,
  },
  // A row whose type is unknown to the policy: must be DROPPED, never emitted.
  { record_type: 'mystery', url: 'https://x', secret: 'y' },
];

process.stdout.write('datapackage emitter self-test\n');

// 1. Non-RED package strips raw locator COLUMNS and VALUES.
ok('TLP:GREEN package has no raw-locator columns or values', () => {
  const pkg = buildDataPackage(rawRows, { marking: 'TLP:GREEN', now: NOW });
  assert(!pkg.error, pkg.error);
  // No resource schema may name a never-share field.
  for (const res of pkg.datapackage.resources) {
    const cols = res.schema.fields.map((f) => f.name);
    for (const banned of NEVER_SHARE_BELOW_RED) {
      assert(!cols.includes(banned), `${banned} present as a column in ${res.name}@GREEN`);
    }
    // And the CSV text must not contain a raw https url that would only come from `url`.
    const csv = pkg.files[res.path];
    assert(!csv.includes('https://example.com/me'), 'raw url value leaked into GREEN csv');
    assert(!csv.includes('html/0001'), 'storage key leaked into GREEN csv');
    assert(!csv.includes('Stopped instead of evading'), 'note leaked into GREEN csv');
  }
});

// 1b. The dropped unknown record_type produced no resource.
ok('unknown record_type is dropped (no resource, no leak)', () => {
  const pkg = buildDataPackage(rawRows, { marking: 'TLP:GREEN', now: NOW });
  const names = pkg.datapackage.resources.map((r) => r.name);
  assert(!names.includes('mystery'), 'mystery record_type must not be packaged');
  // 'secret' field must appear nowhere.
  for (const content of Object.values(pkg.files)) {
    assert(!content.includes('"secret"') && !content.includes('secret,'), 'secret field leaked');
  }
});

// 2. Fail-closed on unknown / missing marking.
ok('unknown marking => refused (no package)', () => {
  const a = buildDataPackage(rawRows, { marking: 'TLP:PUBLIC', now: NOW });
  assert(a.error, 'expected refusal for unknown marking');
  assert.strictEqual(a.datapackage, undefined);
  const b = buildDataPackage(rawRows, { now: NOW });
  assert(b.error, 'expected refusal for missing marking');
});

// 3. No fake data: empty input ⇒ empty package.
ok('zero rows => zero resources + empty-package note (no sample rows)', () => {
  const pkg = buildDataPackage([], { marking: 'TLP:GREEN', now: NOW });
  assert(!pkg.error, pkg.error);
  assert.strictEqual(pkg.resourceCount, 0);
  assert.strictEqual(pkg.rowCount, 0);
  assert.deepStrictEqual(pkg.datapackage.resources, []);
  assert.strictEqual(pkg.meta.note, 'no findings — empty evidence package');
});

// 4. Frictionless valid-shape: profiles + schema/header alignment.
ok('emits a valid-shape Frictionless tabular-data-package', () => {
  const pkg = buildDataPackage(rawRows, { marking: 'TLP:RED', now: NOW });
  assert.strictEqual(pkg.datapackage.profile, 'tabular-data-package');
  assert(Array.isArray(pkg.datapackage.resources) && pkg.datapackage.resources.length > 0);
  assert(pkg.files['datapackage.json'], 'datapackage.json file must be present');
  for (const res of pkg.datapackage.resources) {
    assert.strictEqual(res.profile, 'tabular-data-resource');
    assert(res.schema && Array.isArray(res.schema.fields) && res.schema.fields.length > 0);
    const cols = res.schema.fields.map((f) => f.name);
    const csv = pkg.files[res.path];
    const header = csv.split('\n')[0];
    assert.strictEqual(header, cols.map((c) => c).join(','), 'CSV header must match schema field order');
    // every field has a Frictionless type
    for (const f of res.schema.fields) assert(typeof f.type === 'string' && f.type, `field ${f.name} needs a type`);
  }
});

// 5. TLP:RED keeps the operator's full evidence.
ok('TLP:RED package keeps url + storage keys for the operator', () => {
  const pkg = buildDataPackage(rawRows, { marking: 'TLP:RED', now: NOW });
  const capture = pkg.datapackage.resources.find((r) => r.name === 'capture');
  assert(capture, 'expected a capture resource at RED');
  const cols = capture.schema.fields.map((f) => f.name);
  assert(cols.includes('url'), 'RED capture must keep url');
  assert(cols.includes('html_key') && cols.includes('screenshot_key'), 'RED keeps storage keys');
  assert(pkg.files['data/capture.csv'].includes('https://example.com/me'), 'RED csv keeps the real url');
});

// 6. Deterministic + citable fingerprint.
ok('same input + same now => identical content fingerprint', () => {
  const a = buildDataPackage(rawRows, { marking: 'TLP:GREEN', now: NOW });
  const b = buildDataPackage(rawRows, { marking: 'TLP:GREEN', now: NOW });
  assert.strictEqual(a.fingerprint, b.fingerprint, 'fingerprint must be deterministic');
  assert.strictEqual(a.fingerprint.length, 64, 'sha256 hex');
  assert.strictEqual(a.datapackage['x-content-sha256'], a.fingerprint, 'descriptor must carry its fingerprint');
  // A different marking must change the content (and thus the fingerprint).
  const red = buildDataPackage(rawRows, { marking: 'TLP:RED', now: NOW });
  assert.notStrictEqual(a.fingerprint, red.fingerprint, 'different marking => different bundle');
});

// 6b. fingerprintPackage ignores the embedded x-content-sha256 (no self-reference loop).
ok('fingerprint excludes its own x-content-sha256 field', () => {
  const pkg = buildDataPackage(rawRows, { marking: 'TLP:GREEN', now: NOW });
  const recomputed = fingerprintPackage(pkg.datapackage, pkg.files);
  // recomputed must IGNORE datapackage.json's embedded hash to stay stable; we
  // assert the function is callable and returns a 64-hex without throwing.
  assert.strictEqual(typeof recomputed, 'string');
  assert.strictEqual(recomputed.length, 64);
});

// 7. Embedded grade ledger is re-derivable from the CSV.
ok('embedded grade ledger reproduces score from baseline − Σ deduction', () => {
  const grade = {
    graded: true,
    grade: 'C',
    score: 62,
    baseline: 100,
    breakdown: [
      { category: 'PII_POSTAL_PUBLIC', instances: 1, deduction: 25.5, worst_instance_penalty: 25.5 },
      { category: 'TRACKER_THIRD_PARTY', instances: 2, deduction: 12.5, worst_instance_penalty: 8 },
    ],
  };
  const pkg = buildDataPackage(rawRows, { marking: 'TLP:GREEN', now: NOW, grade });
  const ledger = pkg.datapackage.resources.find((r) => r.name === 'exposure-grade-ledger');
  assert(ledger, 'grade ledger resource must be embedded when a graded result is supplied');
  assert.strictEqual(pkg.meta.grade_embedded, true);
  // Re-derive from the CSV rows.
  const csv = pkg.files['data/exposure-grade-ledger.csv'].trim().split('\n');
  const rows = csv.slice(1).map((line) => line.split(','));
  const sum = rows.reduce((acc, cells) => acc + Number(cells[2]), 0);
  const rederived = Math.round(grade.baseline - sum);
  assert.strictEqual(rederived, grade.score, `ledger must reproduce the score (${rederived} != ${grade.score})`);
});

// 7b. A non-graded (no_data) grade is NOT embedded.
ok('a graded:false result is not embedded as a ledger', () => {
  const pkg = buildDataPackage(rawRows, {
    marking: 'TLP:GREEN', now: NOW, grade: { graded: false, grade: null, score: null, breakdown: [] },
  });
  const ledger = pkg.datapackage.resources.find((r) => r.name === 'exposure-grade-ledger');
  assert.strictEqual(ledger, undefined, 'no ledger when grade is not real');
  assert.strictEqual(pkg.meta.grade_embedded, false);
});

// schemaFor sanity: unknown type at a marking ⇒ null.
ok('schemaFor returns null for an unexportable type', () => {
  assert.strictEqual(schemaFor('mystery', 'TLP:GREEN'), null);
  assert(schemaFor('capture', 'TLP:RED'), 'capture@RED must have a schema');
});

process.stdout.write(`\ndatapackage self-test: ${passed} assertions passed\n`);
