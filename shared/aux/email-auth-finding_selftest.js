/**
 * shared/aux/email-auth-finding_selftest.js
 *
 * Self-test for the AUX email-auth posture core. Lives under shared/aux (NOT
 * under test/, which Codex owns) so it is auto-discovered by
 * integrations/run-module-selftests.js. Run directly:
 *
 *   node shared/aux/email-auth-finding_selftest.js
 *
 * Asserts the compliance-critical + correctness invariants:
 *  - normalizeDomain accepts real domains and rejects junk / URLs / emails;
 *  - cleanTxt re-joins chunked, quoted DoH TXT strings (RFC 1035);
 *  - SPF "+all" is graded WORSE than a missing SPF (worst-case anti-spoofing);
 *  - a missing SPF/DMARC yields record_status:'not_found' — never a fake "pass";
 *  - DKIM with NO supplied selectors is 'unknown', NOT a fabricated failure
 *    (NO FAKE DATA);
 *  - a fully-hardened domain grades band 'A'; an open domain grades 'F';
 *  - every deduction carries a cited reason (auditable, not opaque);
 *  - every emitted event carries the {record_type, event_type, source_module,
 *    domain, confidence, data} shape the correlation engine expects.
 */

'use strict';

const assert = require('assert');
const {
  normalizeDomain,
  cleanTxt,
  parseSpf,
  parseDmarc,
  parseTagValue,
  summarizeDkim,
  gradePosture,
  makeSpfEvent,
  makeDmarcEvent,
  makeDkimEvent,
  makeSummaryEvent,
  SOURCE_MODULE,
  EVENT_TYPES,
} = require('./email-auth-finding.js');

let passed = 0;
function ok(name, fn) {
  fn();
  passed += 1;
  // eslint-disable-next-line no-console
  console.log(`  ok - ${name}`);
}

// ── normalizeDomain ──
ok('normalizeDomain accepts real domains and strips scheme/path/@', () => {
  assert.strictEqual(normalizeDomain('Example.COM'), 'example.com');
  assert.strictEqual(normalizeDomain('https://sub.example.com/path?q=1'), 'sub.example.com');
  assert.strictEqual(normalizeDomain('user@example.org'), 'example.org');
  assert.strictEqual(normalizeDomain('example.com.'), 'example.com');
});
ok('normalizeDomain rejects junk', () => {
  assert.strictEqual(normalizeDomain('not a domain'), '');
  assert.strictEqual(normalizeDomain('localhost'), '');
  assert.strictEqual(normalizeDomain(''), '');
  assert.strictEqual(normalizeDomain(null), '');
});

// ── cleanTxt re-joins chunked quoted DoH TXT ──
ok('cleanTxt concatenates multiple quoted chunks (RFC 1035 long TXT)', () => {
  assert.strictEqual(cleanTxt('"v=spf1 include:_spf." "example.com -all"'), 'v=spf1 include:_spf.example.com -all');
  assert.strictEqual(cleanTxt('"single chunk"'), 'single chunk');
});

// ── SPF parsing + grading ──
ok('parseSpf reads the all-qualifier', () => {
  assert.strictEqual(parseSpf(['"v=spf1 -all"'])[ 'all_qualifier' ], '-all');
  assert.strictEqual(parseSpf(['"v=spf1 +all"']).all_qualifier, '+all');
  assert.strictEqual(parseSpf(['"v=spf1 mx ~all"']).all_qualifier, '~all');
  assert.strictEqual(parseSpf([]).present, false);
});

ok('SPF "+all" grades WORSE than a missing SPF record', () => {
  const open = gradePosture({
    spf: parseSpf(['"v=spf1 +all"']),
    dmarc: parseDmarc([]),
    dkim: summarizeDkim([]),
  });
  const missing = gradePosture({
    spf: parseSpf([]),
    dmarc: parseDmarc([]),
    dkim: summarizeDkim([]),
  });
  // "+all" authorizes anyone => must score lower (worse) than simply absent SPF.
  assert.ok(open.score < missing.score, `+all (${open.score}) should be worse than absent (${missing.score})`);
});

// ── NO FAKE DATA: absence is reported as not_found, never a fake pass ──
ok('missing SPF/DMARC produce record_status:"not_found", not a fabricated pass', () => {
  const spfEvt = makeSpfEvent({ domain: 'example.com', spf: parseSpf([]) });
  const dmarcEvt = makeDmarcEvent({ domain: 'example.com', dmarc: parseDmarc([]) });
  assert.strictEqual(spfEvt.record_status, 'not_found');
  assert.strictEqual(dmarcEvt.record_status, 'not_found');
  assert.ok(/Publish an SPF/i.test(spfEvt.data.advice));
});

// ── DKIM with no selectors is UNKNOWN, not a fake failure ──
ok('DKIM with no supplied selectors is "unknown", never a fabricated failure', () => {
  const dkim = summarizeDkim([]);
  assert.strictEqual(dkim.status, 'unknown_no_selectors');
  const evt = makeDkimEvent({ domain: 'example.com', dkim });
  assert.strictEqual(evt.record_status, 'unknown');
  // And it must NOT contribute a deduction to the grade.
  const g = gradePosture({ spf: parseSpf(['"v=spf1 -all"']), dmarc: parseDmarc(['"v=DMARC1; p=reject; rua=mailto:r@example.com"']), dkim });
  assert.ok(!g.deductions.some((d) => d.code === 'dkim_absent'), 'unknown DKIM must not be penalized');
});

// ── A fully-hardened domain grades A; an open one grades F ──
ok('hardened domain grades A; open domain grades F', () => {
  const hardened = gradePosture({
    spf: parseSpf(['"v=spf1 include:_spf.google.com -all"']),
    dmarc: parseDmarc(['"v=DMARC1; p=reject; rua=mailto:dmarc@example.com; pct=100"']),
    dkim: summarizeDkim([{ selector: 'google', present: true }]),
    mtaSts: { present: true },
    mx: { present: true, hosts: ['aspmx.l.google.com'] },
  });
  assert.strictEqual(hardened.band, 'A', `expected A, got ${hardened.band} (${hardened.score})`);

  const open = gradePosture({
    spf: parseSpf(['"v=spf1 +all"']),
    dmarc: parseDmarc([]),
    dkim: summarizeDkim([{ selector: 'default', present: false }]),
    mtaSts: { present: false },
    mx: { present: true, hosts: ['mail.example.com'] },
  });
  assert.strictEqual(open.band, 'F', `expected F, got ${open.band} (${open.score})`);
});

// ── Every deduction is cited/auditable ──
ok('every deduction carries a non-empty cited reason', () => {
  const g = gradePosture({ spf: parseSpf([]), dmarc: parseDmarc([]), dkim: summarizeDkim([]) });
  assert.ok(g.deductions.length > 0);
  for (const d of g.deductions) {
    assert.ok(typeof d.code === 'string' && d.code.length > 0, 'deduction missing code');
    assert.ok(typeof d.reason === 'string' && d.reason.length > 10, 'deduction missing reason');
    assert.ok(/RFC/.test(d.reason), `deduction "${d.code}" should cite an RFC`);
  }
});

// ── parseDmarc tag parsing ──
ok('parseDmarc extracts policy/pct/rua', () => {
  const d = parseDmarc(['"v=DMARC1; p=quarantine; pct=50; rua=mailto:agg@example.com"']);
  assert.strictEqual(d.policy, 'quarantine');
  assert.strictEqual(d.pct, 50);
  assert.strictEqual(d.rua, 'mailto:agg@example.com');
  assert.ok(d.issues.includes('dmarc_pct_below_100'));
});

ok('parseTagValue handles whitespace and missing values', () => {
  const t = parseTagValue('v=DMARC1; p=reject ; rua = mailto:x ');
  assert.strictEqual(t.p, 'reject');
  assert.strictEqual(t.v, 'DMARC1');
});

// ── event shape for the correlation engine ──
ok('events carry the correlation-ready typed shape', () => {
  const evt = makeSpfEvent({ domain: 'example.com', spf: parseSpf(['"v=spf1 -all"']) });
  assert.strictEqual(evt.record_type, 'email_auth_finding');
  assert.strictEqual(evt.source_module, SOURCE_MODULE);
  assert.strictEqual(evt.event_type, EVENT_TYPES.SPF);
  assert.strictEqual(evt.domain, 'example.com'); // co-occurrence key
  assert.ok(Number.isInteger(evt.confidence) && evt.confidence >= 0 && evt.confidence <= 100);
  assert.ok(evt.data && typeof evt.data === 'object');
});

ok('summary event reflects the grade and is self-framed (no surveillance)', () => {
  const grade = gradePosture({ spf: parseSpf(['"v=spf1 +all"']), dmarc: parseDmarc([]), dkim: summarizeDkim([]) });
  const s = makeSummaryEvent({ domain: 'example.com', subjectLabel: 'My Domain', scopeType: 'self', grade, parts: {} });
  assert.strictEqual(s.data.band, grade.band);
  assert.strictEqual(s.data.spoofable, true);
  assert.ok(/self|your/i.test(s.data.framing));
});

// eslint-disable-next-line no-console
console.log(`\nemail-auth-finding_selftest: OK — ${passed} checks passed, 0 failures.`);
