/**
 * shared/aux/paste-exposure-finding_selftest.js
 *
 * Standalone, offline self-test for the AUX paste-exposure finding shapers.
 * Lives in shared/aux (NOT under test/, owned by another track). It never
 * touches the network — it only asserts that the shapers:
 *   - classify self-identifiers (email / domain / handle) correctly,
 *   - emit valid, frozen-vocabulary module_events with provenance,
 *   - carry the correlation keys the engine needs (email_hash_prefix, handle),
 *   - NEVER place a plaintext email in the event,
 *   - NEVER fabricate a hit for missing/invalid input.
 *
 * Run: node shared/aux/paste-exposure-finding_selftest.js
 */

'use strict';

const assert = require('assert');
const {
  classifyIdentifier,
  maskEmail,
  normalizeDomain,
  normalizeHandle,
  makePasteHitEvent,
  makePasteSummaryEvent,
  SOURCE_MODULE,
} = require('./paste-exposure-finding.js');
const { isModuleEvent, EVENT_TYPES, RISK, VISIBILITY } = require('../detectors/event-types.js');
const { clusterKeysFor } = require('../enrich/cluster-keys.js');
const { emailHashKey } = require('./kanon.js');

let pass = 0;
const ok = (name) => { pass += 1; console.log(`  PASS  ${name}`); };

// 1) classifyIdentifier sorts each kind and normalizes it.
{
  const e = classifyIdentifier('  Jane.Doe@Example.COM ');
  assert(e && e.kind === 'email' && e.value === 'jane.doe@example.com', 'email classified+normalized');

  const d = classifyIdentifier('https://WWW.Example.com/contact');
  assert(d && d.kind === 'domain' && d.value === 'example.com', 'domain classified from URL, www stripped');

  const h = classifyIdentifier('@Jane_99');
  assert(h && h.kind === 'handle' && h.value === 'jane_99', 'handle classified, @ stripped, lowercased');

  assert.strictEqual(classifyIdentifier('   '), null, 'blank -> null');
  assert.strictEqual(classifyIdentifier('!!!'), null, 'punctuation-only -> null');
  assert.strictEqual(classifyIdentifier(42), null, 'non-string -> null');
  ok('classifyIdentifier sorts email/domain/handle and rejects junk');
}

// 2) maskEmail is a non-reversible display hint, never the address.
{
  assert.strictEqual(maskEmail('jane.doe@example.com'), 'j***@e***.com', 'masked hint shape');
  assert.strictEqual(maskEmail('not-an-email'), '', 'non-email -> empty hint');
  const m = maskEmail('a@b.co');
  assert(!m.includes('jane') && m.includes('***'), 'mask hides the local-part');
  ok('maskEmail produces a non-reversible hint and never leaks the address');
}

// 3) An EMAIL paste hit is a valid PII_EMAIL_PUBLIC event that carries the
//    k-anonymity prefix + masked hint and NO plaintext email anywhere.
{
  const id = classifyIdentifier('jane.doe@example.com');
  const ev = makePasteHitEvent({
    identifier: id,
    pasteUrl: 'https://pastebin.com/abc123',
    pasteId: 'abc123',
    source: 'pastebin',
    lineCount: 40,
  });
  assert(isModuleEvent(ev), 'email hit must be a valid module_event');
  assert.strictEqual(ev.event_type, EVENT_TYPES.PII_EMAIL_PUBLIC);
  assert.strictEqual(ev.source_module, SOURCE_MODULE);
  assert.strictEqual(ev.visibility, VISIBILITY.INDEXED);
  assert.strictEqual(ev.risk, RISK.MEDIUM, 'email hit defaults to MEDIUM risk');
  assert.strictEqual(ev.source_url, 'https://pastebin.com/abc123');

  const expectedPrefix = emailHashKey('jane.doe@example.com').email_hash_prefix;
  assert.strictEqual(ev.meta.email_hash_prefix, expectedPrefix, 'carries the kanon prefix');

  // The plaintext address must appear NOWHERE in the serialized event.
  const serialized = JSON.stringify(ev);
  assert(!/jane\.doe@example\.com/i.test(serialized), 'NO plaintext email anywhere in the event');

  // cluster-keys can link it via the email prefix.
  const keys = clusterKeysFor(ev);
  assert(keys.includes(`email_prefix:${expectedPrefix}`), 'yields an email_prefix cluster key');
  assert(keys.includes('host:pastebin.com'), 'yields a host cluster key');
  ok('email paste hit: valid event, kanon prefix, no plaintext, clusterable');
}

// 4) A credential-dump-flagged email hit escalates to HIGH risk.
{
  const id = classifyIdentifier('jane@example.com');
  const ev = makePasteHitEvent({
    identifier: id,
    pasteUrl: 'https://pastebin.com/dump42',
    source: 'pastebin',
    looksLikeCredentialDump: true,
  });
  assert.strictEqual(ev.risk, RISK.HIGH, 'credential-dump flag raises risk to HIGH');
  assert.strictEqual(ev.meta.looks_like_credential_dump, true);
  ok('credential-dump email hit escalates risk to HIGH');
}

// 5) A HANDLE hit is a valid PII_HANDLE_PUBLIC event clusterable by handle.
{
  const id = classifyIdentifier('@jane_99');
  const ev = makePasteHitEvent({
    identifier: id,
    pasteUrl: 'https://controlc.com/xyz',
    source: 'controlc',
  });
  assert(isModuleEvent(ev));
  assert.strictEqual(ev.event_type, EVENT_TYPES.PII_HANDLE_PUBLIC);
  assert.strictEqual(ev.data, 'jane_99');
  assert.strictEqual(ev.risk, RISK.LOW, 'handle alone is LOW risk');
  const keys = clusterKeysFor(ev);
  assert(keys.includes('handle:jane_99'), 'yields a handle cluster key');
  ok('handle paste hit: valid event, LOW risk, clusterable by handle');
}

// 6) A DOMAIN hit is a valid SELF_PROFILE_URL event carrying the domain.
{
  const id = classifyIdentifier('example.com');
  const ev = makePasteHitEvent({
    identifier: id,
    pasteUrl: 'https://pastebin.com/dom1',
    source: 'pastebin',
  });
  assert(isModuleEvent(ev));
  assert.strictEqual(ev.event_type, EVENT_TYPES.SELF_PROFILE_URL);
  assert.strictEqual(ev.data, 'example.com');
  ok('domain paste hit: valid SELF_PROFILE_URL event');
}

// 7) NO FAKE DATA: a hit without a real paste URL (or with junk input) yields null.
{
  const id = classifyIdentifier('jane@example.com');
  assert.strictEqual(makePasteHitEvent({ identifier: id }), null, 'no pasteUrl -> null');
  assert.strictEqual(makePasteHitEvent({ identifier: id, pasteUrl: 'not-a-url' }), null, 'invalid pasteUrl -> null');
  assert.strictEqual(makePasteHitEvent({ identifier: null, pasteUrl: 'https://pastebin.com/x' }), null, 'no identifier -> null');
  assert.strictEqual(makePasteHitEvent({}), null, 'empty input -> null');
  ok('makePasteHitEvent never fabricates a hit for missing/invalid input');
}

// 8) Summary event honestly reports zero when nothing matched.
{
  const empty = makePasteSummaryEvent({ counts: { identifiers_scanned: 3, pastes_matched: 0 }, sources: ['pastebin'] });
  assert(isModuleEvent(empty));
  assert.strictEqual(empty.event_type, EVENT_TYPES.EXPOSURE_SUMMARY);
  assert.strictEqual(empty.data.pastes_matched, 0);
  assert.strictEqual(empty.risk, RISK.INFO, 'zero matches -> INFO risk, not a scare');

  const hot = makePasteSummaryEvent({ counts: { identifiers_scanned: 3, pastes_matched: 2, emails: 2 }, sources: ['pastebin'] });
  assert.strictEqual(hot.data.pastes_matched, 2);
  assert.strictEqual(hot.data.by_kind.email, 2);
  assert.strictEqual(hot.risk, RISK.MEDIUM, 'matches -> MEDIUM risk');
  ok('summary event reports real tallies and an honest risk band');
}

// 9) normalizeDomain / normalizeHandle edge cases.
{
  assert.strictEqual(normalizeDomain('http://Sub.Example.co.uk/path'), 'sub.example.co.uk');
  assert.strictEqual(normalizeDomain('not a domain'), '');
  assert.strictEqual(normalizeHandle('@@Foo'), 'foo');
  ok('normalizeDomain/normalizeHandle handle URLs, junk, and @ prefixes');
}

console.log(`\npaste-exposure-finding_selftest: OK — ${pass} checks passed, 0 failures.`);
