#!/usr/bin/env node
/**
 * shared/detectors/finding-validator_selftest.js
 *
 * Dependency-free self-tests for the false-positive / low-value suppression pass.
 * Run: node shared/detectors/finding-validator_selftest.js
 *
 * NO FAKE DATA: every verdict is derived from a REAL documented rule (RFC
 * 2606/6761 reserved DNS, RFC 5321 role mailbox, NANP fictional 555-01xx). A
 * "suppress" verdict means "matched a documented reserved/test pattern", never
 * "we decided this is fake". Suppressed findings are kept + labelled, not dropped.
 */

'use strict';

const assert = require('assert');
const { EVENT_TYPES, VISIBILITY, RISK, makeEvent } = require('./event-types.js');
const {
  VERDICT, classifyFinding, validateFindings, partitionByValidation, registrableSuffix,
} = require('./finding-validator.js');

let pass = 0;
function t(name, fn) {
  try { fn(); pass += 1; console.log(`  PASS  ${name}`); }
  catch (e) { console.error(`  FAIL  ${name}: ${e.message}`); process.exitCode = 1; }
}

function email(value, url = 'https://me.example/contact') {
  return makeEvent({
    event_type: EVENT_TYPES.PII_EMAIL_PUBLIC, source_module: 'pii_detector',
    data: value, confidence: 0.95, visibility: VISIBILITY.INDEXED, risk: RISK.MEDIUM, source_url: url,
  });
}
function phone(value) {
  return makeEvent({
    event_type: EVENT_TYPES.PII_PHONE_PUBLIC, source_module: 'pii_detector',
    data: value, confidence: 0.7, visibility: VISIBILITY.LINKED, risk: RISK.MEDIUM, source_url: 'https://me.example',
  });
}
function handle(h) {
  return makeEvent({
    event_type: EVENT_TYPES.PII_HANDLE_PUBLIC, source_module: 'pii_detector',
    data: `@${h}`, confidence: 0.6, visibility: VISIBILITY.LINKED, risk: RISK.LOW,
    source_url: 'https://me.example', meta: { handle: h },
  });
}

console.log('[validator / RFC 2606+6761 reserved DNS — suppress documentation emails]');
t('example.com email is suppressed and cites the RFC', () => {
  const v = classifyFinding(email('jane@example.com'));
  assert.strictEqual(v.verdict, VERDICT.SUPPRESS);
  assert.strictEqual(v.rule, 'rfc2606_reserved_dns');
  assert.ok(/RFC 2606/.test(v.reason));
});
t('*.test and *.invalid TLDs are suppressed', () => {
  assert.strictEqual(classifyFinding(email('a@foo.test')).verdict, VERDICT.SUPPRESS);
  assert.strictEqual(classifyFinding(email('a@bar.invalid')).verdict, VERDICT.SUPPRESS);
  assert.strictEqual(classifyFinding(email('a@host.localhost')).verdict, VERDICT.SUPPRESS);
});
t('a REAL address on a real domain stays VALID (no over-suppression)', () => {
  assert.strictEqual(classifyFinding(email('jane.doe@gmail.com')).verdict, VERDICT.VALID);
  assert.strictEqual(classifyFinding(email('me@my-startup.io')).verdict, VERDICT.VALID);
});
t('subdomain of example.com still resolves to reserved suffix', () => {
  assert.strictEqual(registrableSuffix('mail.example.com'), 'example.com');
  assert.strictEqual(classifyFinding(email('x@mail.example.com')).verdict, VERDICT.SUPPRESS);
});

console.log('[validator / role & disposable mailboxes]');
t('no-reply family is LOW_VALUE (real-shaped but not actionable)', () => {
  assert.strictEqual(classifyFinding(email('noreply@my-startup.io')).verdict, VERDICT.LOW_VALUE);
  assert.strictEqual(classifyFinding(email('postmaster@my-startup.io')).verdict, VERDICT.LOW_VALUE);
});
t('disposable domain is suppressed', () => {
  assert.strictEqual(classifyFinding(email('throwaway@mailinator.com')).verdict, VERDICT.SUPPRESS);
});

console.log('[validator / placeholder phones]');
t('NANP 555-01xx fictional number is suppressed', () => {
  assert.strictEqual(classifyFinding(phone('(555) 555-0123')).verdict, VERDICT.SUPPRESS);
});
t('dummy repeated/sequential digit run is suppressed', () => {
  assert.strictEqual(classifyFinding(phone('000-000-0000')).verdict, VERDICT.SUPPRESS);
});
t('a plausible real phone stays VALID', () => {
  assert.strictEqual(classifyFinding(phone('+1 415 729 4471')).verdict, VERDICT.VALID);
});

console.log('[validator / CSS asset tokens masquerading as handles]');
t('@2x retina token is suppressed, not treated as a social handle', () => {
  assert.strictEqual(classifyFinding(handle('2x')).verdict, VERDICT.SUPPRESS);
  assert.strictEqual(classifyFinding(handle('media')).verdict, VERDICT.SUPPRESS);
});
t('a real handle stays VALID', () => {
  assert.strictEqual(classifyFinding(handle('jane_doe')).verdict, VERDICT.VALID);
});

console.log('[validator / batch + partition — keeps everything, labels noise]');
t('validateFindings annotates without dropping; non-events pass through', () => {
  const out = validateFindings([email('jane@example.com'), { not: 'an event' }, email('real@gmail.com')]);
  assert.strictEqual(out.length, 3, 'nothing dropped');
  assert.strictEqual(out[0]._validation.verdict, VERDICT.SUPPRESS);
  assert.strictEqual(out[1].not, 'an event'); // passthrough untouched
  assert.strictEqual(out[2]._validation.verdict, VERDICT.VALID);
});
t('partitionByValidation splits trusted / suppressed / low_value honestly', () => {
  const p = partitionByValidation([
    email('real@gmail.com'),       // trusted
    email('jane@example.com'),     // suppressed
    email('noreply@gmail.com'),    // low_value
  ]);
  assert.strictEqual(p.trusted.length, 1);
  assert.strictEqual(p.suppressed.length, 1);
  assert.strictEqual(p.low_value.length, 1);
});
t('invalid input never throws', () => {
  assert.doesNotThrow(() => classifyFinding(null));
  assert.doesNotThrow(() => classifyFinding({ record_type: 'nope' }));
});

console.log(`\nOK — finding-validator self-test: ${pass} checks passed, ${process.exitCode ? 'with failures' : '0 failures'}.`);
if (process.exitCode) process.exit(process.exitCode);
