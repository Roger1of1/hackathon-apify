/**
 * integrations/exports/test-exports.js
 *
 * Self-test for the Dataset Views + Exports capability. Lives in MY subtree
 * (integrations/**), not under test/ (Codex owns test/). Run directly:
 *   node integrations/exports/test-exports.js
 *
 * Asserts the compliance invariants of the redaction policy + export client:
 *   1. Raw locators (url/html_key/screenshot_key/note) NEVER survive a non-RED
 *      redaction or a non-RED export query.
 *   2. An unknown marking is REFUSED (fail-closed), never widened to "all".
 *   3. The export client DRY-RUNS without a token and fabricates NO rows.
 *   4. The TLP:RED operator view keeps the full evidence (so the audit subject
 *      still gets their real data — redaction is for sharing, not self-blinding).
 *   5. redactRecord drops a record whose type is not exportable at the marking
 *      (no half-redacted leak).
 */

'use strict';

const assert = require('assert');
const {
  MARKINGS, NEVER_SHARE_BELOW_RED, allowedFields, redactRecord, exportQueryFor, isMarking,
} = require('./redaction-policy');
const { buildExportRequest, exportDataset } = require('./export-client');

let passed = 0;
function ok(name, fn) {
  fn();
  passed += 1;
  process.stdout.write(`  ok  ${name}\n`);
}
async function okAsync(name, fn) {
  await fn();
  passed += 1;
  process.stdout.write(`  ok  ${name}\n`);
}

const captureRow = {
  record_type: 'capture',
  case_id: 'case_abc',
  url: 'https://example.com/me',
  content_sha256: 'a'.repeat(64),
  html_sha256: 'b'.repeat(64),
  html_key: 'html/0001',
  screenshot_key: 'shot/0001',
  status_code: 200,
  captured_at: '2026-05-30T00:00:00.000Z',
};
const backoffRow = {
  record_type: 'backoff_for_human_review',
  case_id: 'case_abc',
  url: 'https://example.com/blocked',
  status_code: 403,
  note: 'Blocked by source. Stopped instead of evading.',
  flagged_at: '2026-05-30T00:00:00.000Z',
};

process.stdout.write('exports redaction self-test\n');

// 1. Non-RED redaction strips raw locators.
ok('TLP:GREEN capture drops url/html_key/screenshot_key', () => {
  const r = redactRecord(captureRow, 'TLP:GREEN');
  assert(r, 'expected a redacted row');
  for (const banned of ['url', 'html_key', 'screenshot_key']) {
    assert.strictEqual(r[banned], undefined, `${banned} leaked into TLP:GREEN`);
  }
  assert.strictEqual(r.content_sha256, captureRow.content_sha256, 'hash should survive');
});

ok('TLP:AMBER backoff drops url + note', () => {
  const r = redactRecord(backoffRow, 'TLP:AMBER');
  assert(r);
  assert.strictEqual(r.url, undefined, 'url leaked into AMBER backoff');
  assert.strictEqual(r.note, undefined, 'note leaked into AMBER backoff');
  assert.strictEqual(r.status_code, 403, 'status should survive as the compliance signal');
});

// 1b. The never-share tripwire holds for every marking below RED and record type.
ok('no NEVER_SHARE field appears in any non-RED allow-list', () => {
  for (const marking of MARKINGS) {
    if (marking === 'TLP:RED') continue;
    for (const rt of ['capture', 'evidence_index', 'backoff_for_human_review', 'decision_log']) {
      const fields = allowedFields(rt, marking);
      for (const banned of NEVER_SHARE_BELOW_RED) {
        assert(!fields.includes(banned), `${banned} present in ${rt}@${marking}`);
      }
    }
  }
});

// 2. Unknown marking is refused (fail-closed), not widened.
ok('unknown marking => allowedFields []', () => {
  assert.deepStrictEqual(allowedFields('capture', 'TLP:PUBLIC'), []);
  assert.strictEqual(isMarking('TLP:PUBLIC'), false);
});

ok('exportQueryFor unknown marking => error, no params', () => {
  const q = exportQueryFor('PUBLIC');
  assert(q.error, 'expected refusal');
  assert.strictEqual(q.params, undefined);
});

ok('buildExportRequest unknown marking => error (no url built)', () => {
  const req = buildExportRequest('ds123', 'WIDE-OPEN');
  assert(req.error, 'expected refusal');
  assert.strictEqual(req.url, undefined);
});

// 2b. Export query for a shareable marking carries omit tripwire + clean.
ok('TLP:GREEN export query sets clean=1 and omits raw locators', () => {
  const q = exportQueryFor('TLP:GREEN', { format: 'csv' });
  assert(!q.error, q.error);
  assert.strictEqual(q.params.clean, '1');
  assert(q.params.omit.includes('url'), 'omit must include url below RED');
  assert(!q.params.fields.includes('html_key'), 'fields must not name html_key at GREEN');
});

// 2c. Bad format refused.
ok('exportQueryFor rejects unsupported format', () => {
  const q = exportQueryFor('TLP:GREEN', { format: 'pdf' });
  assert(q.error, 'expected format refusal');
});

// 4. TLP:RED keeps the operator's full evidence.
ok('TLP:RED capture keeps url + storage keys (operator gets real data)', () => {
  const r = redactRecord(captureRow, 'TLP:RED');
  assert.strictEqual(r.url, captureRow.url);
  assert.strictEqual(r.html_key, captureRow.html_key);
  assert.strictEqual(r.screenshot_key, captureRow.screenshot_key);
});

// 5. Non-exportable record type at a marking is dropped, not half-emitted.
ok('redactRecord drops unknown record_type (no half-redacted leak)', () => {
  const r = redactRecord({ record_type: 'mystery', url: 'x', secret: 'y' }, 'TLP:GREEN');
  assert.strictEqual(r, null);
});

ok('redactRecord returns null for non-object input', () => {
  assert.strictEqual(redactRecord(null, 'TLP:RED'), null);
  assert.strictEqual(redactRecord('nope', 'TLP:RED'), null);
});

// 3. Export client dry-runs without a token and fabricates no rows (async).
(async () => {
  await okAsync('exportDataset DRY RUNs without APIFY_TOKEN and returns no rows', async () => {
    assert(!process.env.APIFY_TOKEN, 'this test must run without APIFY_TOKEN set');
    const r = await exportDataset('ds123', 'TLP:GREEN', { format: 'json' });
    assert.strictEqual(r.ok, true);
    assert.strictEqual(r.dryRun, true);
    assert.strictEqual(r.rows, undefined, 'dry run must not fabricate rows');
    assert(r.url.includes('/v2/datasets/ds123/items'), 'should expose the real endpoint it would call');
  });
  process.stdout.write(`\nexports self-test: ${passed} assertions passed\n`);
})().catch((e) => {
  process.stderr.write(`exports self-test FAILED: ${e.message}\n`);
  process.exit(1);
});
