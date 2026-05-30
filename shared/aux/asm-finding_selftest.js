/**
 * shared/aux/asm-finding_selftest.js
 *
 * Self-test for the AUX attack-surface (CT + WHOIS self-exposure) mapping layer.
 * Lives under shared/aux (NOT under test/, which Codex owns). Run directly:
 *
 *   node shared/aux/asm-finding_selftest.js
 *
 * Asserts the compliance-critical invariants:
 *  - a real CT host that BELONGS to the subject's apex => a valid SELF_PROFILE_URL
 *    module_event from the frozen vocabulary (no forbidden type can slip through);
 *  - an off-domain SAN (someone else's host sharing a cert) => NO event (never
 *    leak a third party's surface into the self inventory);
 *  - a wildcard `*.example.com` normalizes to the apex it covers;
 *  - a "dev/admin" subdomain is flagged sensitive and risk-raised;
 *  - a public WHOIS registrant email => PII_EMAIL_PUBLIC carrying a k-anonymity
 *    PREFIX and a MASKED address, never the plaintext email;
 *  - an empty scan (no hosts, no whois) => the summary reports ZERO surfaces
 *    (NO FAKE DATA);
 *  - every emitted event passes isModuleEvent (valid frozen-vocabulary event).
 */

'use strict';

const assert = require('assert');
const {
  normalizeHost,
  belongsToDomain,
  looksSensitive,
  makeSubdomainEvent,
  makeWhoisEmailEvent,
  makeSummaryEvent,
  sha1Hex,
} = require('./asm-finding.js');
const { isModuleEvent, EVENT_TYPES, RISK } = require('../detectors/event-types.js');

let passed = 0;
function ok(name, fn) {
  fn();
  passed += 1;
  // eslint-disable-next-line no-console
  console.log(`  ok - ${name}`);
}

// ── normalizeHost: lowercases, strips wildcard + trailing dot, rejects junk ──
ok('normalizeHost strips wildcard and trailing dot, rejects non-hosts', () => {
  assert.strictEqual(normalizeHost('*.Example.COM.'), 'example.com');
  assert.strictEqual(normalizeHost('  API.example.com '), 'api.example.com');
  assert.strictEqual(normalizeHost('localhost'), ''); // no dot => not a host
  assert.strictEqual(normalizeHost('two words.com'), ''); // whitespace => junk
  assert.strictEqual(normalizeHost(42), '');
});

// ── belongsToDomain gates off-domain hosts out of the inventory ──
ok('belongsToDomain accepts apex + subdomains, rejects off-domain', () => {
  assert.strictEqual(belongsToDomain('example.com', 'example.com'), true);
  assert.strictEqual(belongsToDomain('api.example.com', 'example.com'), true);
  assert.strictEqual(belongsToDomain('evil.com', 'example.com'), false);
  // classic suffix-confusion attempt: notexample.com must NOT match example.com
  assert.strictEqual(belongsToDomain('notexample.com', 'example.com'), false);
});

// ── a real on-domain CT host => a valid SELF_PROFILE_URL event ──
ok('on-domain CT host => valid SELF_PROFILE_URL module_event', () => {
  const evt = makeSubdomainEvent({ host: 'API.example.com', apex: 'example.com', firstSeen: '2024-01-01' });
  assert.ok(evt, 'expected an event');
  assert.ok(isModuleEvent(evt), 'must be a valid frozen-vocabulary module_event');
  assert.strictEqual(evt.event_type, EVENT_TYPES.SELF_PROFILE_URL);
  assert.strictEqual(evt.data, 'api.example.com');
  assert.strictEqual(evt.meta.discovered_via, 'certificate_transparency');
  assert.strictEqual(evt.meta.sensitive_surface, false);
});

// ── off-domain SAN must NOT produce an event (no third-party surface leak) ──
ok('off-domain SAN => null (never leak a third party into the self inventory)', () => {
  const evt = makeSubdomainEvent({ host: 'cdn.someoneelse.net', apex: 'example.com' });
  assert.strictEqual(evt, null);
});

// ── wildcard SAN normalizes to the apex it covers ──
ok('wildcard *.example.com => apex event', () => {
  const evt = makeSubdomainEvent({ host: '*.example.com', apex: 'example.com' });
  assert.ok(evt);
  assert.strictEqual(evt.data, 'example.com');
});

// ── sensitive label raises risk + flags advice ──
ok('dev/admin subdomain flagged sensitive and risk-raised', () => {
  assert.strictEqual(looksSensitive('staging.example.com', 'example.com'), true);
  assert.strictEqual(looksSensitive('www.example.com', 'example.com'), false);
  const evt = makeSubdomainEvent({ host: 'admin.example.com', apex: 'example.com' });
  assert.strictEqual(evt.meta.sensitive_surface, true);
  assert.strictEqual(evt.risk, RISK.MEDIUM);
});

// ── WHOIS registrant email => PII_EMAIL_PUBLIC, k-anon prefix + masked, no plaintext ──
ok('WHOIS email => PII_EMAIL_PUBLIC with k-anon prefix and masked address', () => {
  const full = 'JaneDoe@registrant.example';
  const evt = makeWhoisEmailEvent({ apex: 'example.com', registrantEmail: full });
  assert.ok(evt);
  assert.ok(isModuleEvent(evt));
  assert.strictEqual(evt.event_type, EVENT_TYPES.PII_EMAIL_PUBLIC);
  // The full plaintext address must NOT appear anywhere in the serialized event.
  const serialized = JSON.stringify(evt);
  assert.ok(!serialized.includes('janedoe@registrant.example'), 'plaintext email must never be present');
  assert.ok(!serialized.includes(full), 'original-case plaintext email must never be present');
  // Correlation key is the real 5-char SHA-1 prefix of the normalized address.
  const expectedPrefix = sha1Hex('janedoe@registrant.example').slice(0, 5);
  assert.strictEqual(evt.meta.email_hash_prefix, expectedPrefix);
  // Masked display keeps the domain but hides the local-part.
  assert.ok(evt.data.endsWith('@registrant.example'));
  assert.ok(evt.data.includes('*'));
});

// ── garbage WHOIS email => null, never a fabricated PII event ──
ok('invalid registrant email => null (NO FAKE DATA)', () => {
  assert.strictEqual(makeWhoisEmailEvent({ apex: 'example.com', registrantEmail: 'not-an-email' }), null);
  assert.strictEqual(makeWhoisEmailEvent({ apex: 'example.com', registrantEmail: '' }), null);
  assert.strictEqual(makeWhoisEmailEvent({ apex: '', registrantEmail: 'a@b.com' }), null);
});

// ── empty scan => summary reports ZERO surfaces (NO FAKE DATA) ──
ok('empty scan => summary with zero surfaces', () => {
  const summary = makeSummaryEvent({ apex: 'example.com', events: [], scopeType: 'self' });
  assert.ok(isModuleEvent(summary));
  assert.strictEqual(summary.event_type, EVENT_TYPES.EXPOSURE_SUMMARY);
  assert.strictEqual(summary.data.subdomains_found, 0);
  assert.strictEqual(summary.data.sensitive_surfaces, 0);
  assert.strictEqual(summary.data.whois_email_exposed, false);
  assert.strictEqual(summary.risk, RISK.INFO);
});

// ── summary counts only the REAL events it is given ──
ok('summary counts real events only', () => {
  const events = [
    makeSubdomainEvent({ host: 'www.example.com', apex: 'example.com' }),
    makeSubdomainEvent({ host: 'admin.example.com', apex: 'example.com' }),
    makeWhoisEmailEvent({ apex: 'example.com', registrantEmail: 'jane@registrant.example' }),
  ].filter(Boolean);
  const summary = makeSummaryEvent({ apex: 'example.com', events, scopeType: 'self' });
  assert.strictEqual(summary.data.subdomains_found, 2);
  assert.strictEqual(summary.data.sensitive_surfaces, 1);
  assert.strictEqual(summary.data.whois_email_exposed, true);
  assert.strictEqual(summary.risk, RISK.MEDIUM);
});

// eslint-disable-next-line no-console
console.log(`\nasm-finding_selftest: OK — ${passed} checks passed`);
