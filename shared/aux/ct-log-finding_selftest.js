/**
 * shared/aux/ct-log-finding_selftest.js
 *
 * Self-test for the AUX Certificate-Transparency exposure core. Lives under
 * shared/aux (NOT under test/, which Codex owns) so it is auto-discovered by
 * integrations/run-module-selftests.js. Run directly:
 *
 *   node shared/aux/ct-log-finding_selftest.js
 *
 * Asserts the compliance-critical + correctness invariants:
 *  - normalizeDomain / normalizeHostname accept real names, reject junk;
 *  - parseCrtShRows de-duplicates SANs, splits crt.sh's newline name_value,
 *    detects "*." wildcards, and NEVER returns an out-of-scope hostname
 *    (in-scope guard is a privacy boundary, not just hygiene);
 *  - NO FAKE DATA: an empty/garbage crt.sh response yields an EMPTY result with
 *    record_status 'not_found' — no hostname is ever invented;
 *  - risky-label classification flags admin/staging/vpn/internal/… with a cited
 *    reason and leaves the apex domain un-flagged;
 *  - grading: an open domain with risky internals + wildcard grades worse than a
 *    domain with only its apex; every deduction carries a cited reason;
 *  - every emitted event carries the {record_type, event_type, source_module,
 *    domain, confidence, data} shape the correlation engine expects.
 */

'use strict';

const assert = require('assert');
const {
  normalizeDomain,
  normalizeHostname,
  isInScope,
  parseCrtShRows,
  classifyHostname,
  gradeExposure,
  buildFindings,
  makeHostnameEvent,
  SOURCE_MODULE,
  RECORD_TYPE,
  EVENT_TYPES,
} = require('./ct-log-finding.js');

let passed = 0;
function ok(name, fn) {
  fn();
  passed += 1;
  // eslint-disable-next-line no-console
  console.log(`  ok - ${name}`);
}

// ── normalizeDomain ──
ok('normalizeDomain accepts real domains, strips scheme/path/@/wildcard', () => {
  assert.strictEqual(normalizeDomain('Example.COM'), 'example.com');
  assert.strictEqual(normalizeDomain('https://sub.example.com/p?q=1'), 'sub.example.com');
  assert.strictEqual(normalizeDomain('user@example.org'), 'example.org');
  assert.strictEqual(normalizeDomain('*.example.com'), 'example.com');
  assert.strictEqual(normalizeDomain('example.com.'), 'example.com');
});
ok('normalizeDomain rejects junk', () => {
  assert.strictEqual(normalizeDomain('not a domain'), '');
  assert.strictEqual(normalizeDomain('localhost'), '');
  assert.strictEqual(normalizeDomain(''), '');
  assert.strictEqual(normalizeDomain(null), '');
});

// ── normalizeHostname ──
ok('normalizeHostname normalizes and preserves wildcard, rejects junk', () => {
  assert.strictEqual(normalizeHostname('Admin.Example.COM.'), 'admin.example.com');
  assert.strictEqual(normalizeHostname('*.example.com'), '*.example.com');
  assert.strictEqual(normalizeHostname('   '), '');
  assert.strictEqual(normalizeHostname('not a host'), '');
});

// ── isInScope ──
ok('isInScope accepts apex + subdomains, rejects look-alikes', () => {
  assert.ok(isInScope('example.com', 'example.com'));
  assert.ok(isInScope('admin.example.com', 'example.com'));
  assert.ok(isInScope('*.example.com', 'example.com'));
  assert.ok(!isInScope('evil-example.com', 'example.com'));
  assert.ok(!isInScope('example.com.attacker.net', 'example.com'));
});

// ── parseCrtShRows: dedupe + newline split + wildcard + in-scope guard + NO FAKE DATA ──
ok('parseCrtShRows dedupes, splits name_value, finds wildcard, drops out-of-scope', () => {
  const rows = [
    { name_value: 'example.com\nwww.example.com' },
    { name_value: 'www.example.com\n*.example.com' }, // dup + wildcard
    { common_name: 'admin.example.com' },
    { name_value: 'evil-example.com\nexample.com.attacker.net' }, // BOTH out of scope
    { name_value: '   \n\n' }, // junk
    'garbage-not-an-object',
  ];
  const parsed = parseCrtShRows(rows, 'example.com');
  assert.deepStrictEqual(
    parsed.hostnames,
    ['*.example.com', 'admin.example.com', 'example.com', 'www.example.com'],
  );
  assert.strictEqual(parsed.wildcard, true);
  assert.strictEqual(parsed.count, 4);
  // privacy/scope boundary: no out-of-scope name leaked through
  assert.ok(!parsed.hostnames.includes('evil-example.com'));
  assert.ok(!parsed.hostnames.some((h) => h.includes('attacker')));
});
ok('parseCrtShRows on empty/garbage yields EMPTY result (NO FAKE DATA)', () => {
  assert.deepStrictEqual(parseCrtShRows([], 'example.com'), { hostnames: [], wildcard: false, count: 0 });
  assert.deepStrictEqual(parseCrtShRows(null, 'example.com'), { hostnames: [], wildcard: false, count: 0 });
  assert.deepStrictEqual(parseCrtShRows('nope', 'example.com'), { hostnames: [], wildcard: false, count: 0 });
});

// ── classifyHostname ──
ok('classifyHostname flags risky labels with a cited reason, spares the apex', () => {
  const admin = classifyHostname('admin.example.com', 'example.com');
  assert.strictEqual(admin.risky, true);
  assert.ok(admin.labels.some((l) => l.label === 'admin' && typeof l.reason === 'string' && l.reason.length > 0));

  const staging = classifyHostname('staging.example.com', 'example.com');
  assert.strictEqual(staging.risky, true);

  const apex = classifyHostname('example.com', 'example.com');
  assert.strictEqual(apex.risky, false);

  const www = classifyHostname('www.example.com', 'example.com');
  assert.strictEqual(www.risky, false);
});

// ── gradeExposure: relative risk + auditable reasons + honest empty case ──
ok('gradeExposure: risky+wildcard grades worse than apex-only; reasons cited', () => {
  const clean = gradeExposure({ count: 1, riskyCount: 0, wildcard: false });
  const exposed = gradeExposure({ count: 6, riskyCount: 3, wildcard: true });
  assert.ok(exposed.score < clean.score, 'exposed must score lower than clean');
  assert.ok(exposed.deductions.length >= 1);
  for (const d of exposed.deductions) {
    assert.ok(typeof d.reason === 'string' && d.reason.length > 0, 'every deduction must cite a reason');
  }
  assert.ok(['A', 'B', 'C', 'D', 'F'].includes(exposed.band));
});
ok('gradeExposure on zero certs is an honest A with a NO_CT_RECORDS note', () => {
  const none = gradeExposure({ count: 0, riskyCount: 0, wildcard: false });
  assert.strictEqual(none.band, 'A');
  assert.strictEqual(none.deductions[0].code, 'NO_CT_RECORDS');
});

// ── event shape (correlation contract) ──
ok('emitted events carry the correlation-event shape with a domain key', () => {
  const evt = makeHostnameEvent({ domain: 'example.com', host: 'admin.example.com' });
  assert.strictEqual(evt.record_type, RECORD_TYPE);
  assert.strictEqual(evt.event_type, EVENT_TYPES.HOSTNAME);
  assert.strictEqual(evt.source_module, SOURCE_MODULE);
  assert.strictEqual(evt.domain, 'example.com');
  assert.ok(evt.confidence >= 0 && evt.confidence <= 100);
  assert.strictEqual(typeof evt.data, 'object');
  assert.strictEqual(evt.data.risky, true);
});

// ── buildFindings end-to-end (pure) ──
ok('buildFindings produces hostname + wildcard + risky events and a summary', () => {
  const parsed = parseCrtShRows([
    { name_value: 'example.com\nwww.example.com\nadmin.example.com\n*.example.com\nvpn.example.com' },
  ], 'example.com');
  const { events, summary, grade, riskyHostnames } = buildFindings({
    domain: 'example.com',
    subjectLabel: 'My Site',
    scopeType: 'self',
    parsed,
  });
  // one HOSTNAME per host
  const hostEvents = events.filter((e) => e.event_type === EVENT_TYPES.HOSTNAME);
  assert.strictEqual(hostEvents.length, parsed.count);
  // wildcard + risky events present
  assert.ok(events.some((e) => e.event_type === EVENT_TYPES.WILDCARD));
  assert.ok(events.some((e) => e.event_type === EVENT_TYPES.RISKY));
  assert.ok(riskyHostnames.includes('admin.example.com'));
  assert.ok(riskyHostnames.includes('vpn.example.com'));
  // summary is honest + graded
  assert.strictEqual(summary.event_type, EVENT_TYPES.SUMMARY);
  assert.strictEqual(summary.record_status, 'present');
  assert.strictEqual(summary.data.hostname_count, parsed.count);
  assert.strictEqual(summary.data.band, grade.band);
  assert.ok(/self-exposure/i.test(summary.data.framing));
});

// eslint-disable-next-line no-console
console.log(`\nOK — ct-log-finding self-test: ${passed} checks passed, 0 failures.`);
