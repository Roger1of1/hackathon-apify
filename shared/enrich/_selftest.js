#!/usr/bin/env node
/**
 * shared/enrich/_selftest.js
 *
 * Dependency-free self-tests for the enrichment modules. Run with:
 *   node shared/enrich/_selftest.js
 *
 * NO FAKE DATA: real functions, honest synthetic inputs.
 */

'use strict';

const assert = require('assert');
const { EVENT_TYPES, makeEvent } = require('../detectors/event-types.js');
const { toObservedData, toBundle } = require('./stix-evidence.js');
const { rangeOf, isAnonymousBucket, suffixInBucket, DEFAULT_K } = require('./k-anonymity.js');
const { eventEvidenceQuality, enrichEvents } = require('./evidence-quality.js');
const { clusterKeysFor, buildKeyIndex, hostOf, normalizeHandle } = require('./cluster-keys.js');
const { eventSeverity, rankBySeverity, batchSeverity, bandFor } = require('./severity.js');
const { RISK, VISIBILITY } = require('../detectors/event-types.js');
const { emailHashKey } = require('../aux/kanon.js');
const { CATEGORIES, categoryOf, buildReport, toCard } = require('./report-groups.js');
const { buildClusters, correlatedClusters } = require('./clusters.js');
const { VALID_EVENT_TYPES } = require('../detectors/event-types.js');

let pass = 0;
function t(name, fn) {
  try { fn(); pass += 1; console.log(`  PASS  ${name}`); }
  catch (e) { console.error(`  FAIL  ${name}: ${e.message}`); process.exitCode = 1; }
}

console.log('[stix-evidence]');
t('wraps an event as a STIX observed-data object with provenance', () => {
  const ev = makeEvent({
    event_type: EVENT_TYPES.PII_EMAIL_PUBLIC,
    source_module: 'pii_detector',
    data: 'jane@example.com',
    source_url: 'https://jane.example.com/contact',
  });
  const od = toObservedData(ev, { now: '2026-05-30T00:00:00.000Z' });
  assert.strictEqual(od.type, 'observed-data');
  assert.strictEqual(od.spec_version, '2.1');
  assert.strictEqual(od.x_source_module, 'pii_detector');
  assert.strictEqual(od.objects[0].type, 'email-addr');
  assert.match(od.x_scope_note, /No third-party-private inference/);
});
t('observed-data id is deterministic for same input', () => {
  const ev = makeEvent({ event_type: EVENT_TYPES.PII_EMAIL_PUBLIC, source_module: 'pii_detector', data: 'a@b.com', source_url: 'https://x/' });
  const a = toObservedData(ev, { now: '2026-05-30T00:00:00.000Z' });
  const b = toObservedData(ev, { now: '2026-05-30T00:00:00.000Z' });
  assert.strictEqual(a.id, b.id);
});
t('toBundle attaches integrity handles by url', () => {
  const ev = makeEvent({ event_type: EVENT_TYPES.PII_EMAIL_PUBLIC, source_module: 'pii_detector', data: 'a@b.com', source_url: 'https://x/' });
  const bundle = toBundle([ev], {
    now: '2026-05-30T00:00:00.000Z',
    integrityByUrl: { 'https://x/': { content_sha256: 'abc', html_sha256: 'def', html_key: 'k', screenshot_key: 's' } },
  });
  assert.strictEqual(bundle.type, 'bundle');
  assert.strictEqual(bundle.objects[0].x_integrity.content_sha256, 'abc');
});
t('non-event input yields null', () => {
  assert.strictEqual(toObservedData({ foo: 1 }), null);
});

console.log('[k-anonymity]');
t('rangeOf returns a 5-char prefix by default', () => {
  const r = rangeOf('secret');
  assert.strictEqual(r.prefix.length, 5);
  assert.strictEqual(r.prefix + r.suffix, r.full);
});
t('isAnonymousBucket requires k candidates', () => {
  assert.strictEqual(isAnonymousBucket(DEFAULT_K).anonymous, true);
  assert.strictEqual(isAnonymousBucket(DEFAULT_K - 1).anonymous, false);
});
t('suffixInBucket does local membership check', () => {
  const r = rangeOf('secret');
  assert.strictEqual(suffixInBucket(r.suffix, [r.suffix]), true);
  assert.strictEqual(suffixInBucket(r.suffix, ['DEADBEEF']), false);
});

console.log('[evidence-quality]');
t('blends canonical integrity score, confidence, and corroboration', () => {
  const ev = makeEvent({
    event_type: EVENT_TYPES.PII_EMAIL_PUBLIC, source_module: 'pii_detector',
    data: 'a@b.com', confidence: 0.95, source_url: 'https://x/',
  });
  const { quality, components } = eventEvidenceQuality(ev, {
    integrity: { content_sha256: 'c', html_sha256: 'h', html_key: 'k', screenshot_key: 's' },
    corroborations: 2,
  });
  assert.ok(quality > 0 && quality <= 100);
  assert.strictEqual(components.integrity_score, 100); // full preservation handles
  assert.ok(components.confidence_score >= 90);
});
t('enrichEvents counts distinct-surface corroboration honestly', () => {
  const a = makeEvent({ event_type: EVENT_TYPES.PII_EMAIL_PUBLIC, source_module: 'pii_detector', data: 'a@b.com', source_url: 'https://x/1' });
  const b = makeEvent({ event_type: EVENT_TYPES.PII_EMAIL_PUBLIC, source_module: 'pii_detector', data: 'a@b.com', source_url: 'https://x/2' });
  const out = enrichEvents([a, b]);
  assert.strictEqual(out[0]._evidence_quality.components.corroborations, 2);
});
t('no events -> empty enrichment', () => {
  assert.deepStrictEqual(enrichEvents([]), []);
});

console.log('[cluster-keys]');
t('extracts host + email_prefix keys from a PII email event', () => {
  const ev = makeEvent({
    event_type: EVENT_TYPES.PII_EMAIL_PUBLIC, source_module: 'pii_detector',
    data: 'jane@example.com', source_url: 'https://jane.example.com/contact',
    meta: { email_hash_prefix: emailHashKey('jane@example.com').email_hash_prefix },
  });
  const keys = clusterKeysFor(ev);
  assert.ok(keys.includes('host:jane.example.com'));
  assert.ok(keys.some((k) => k.startsWith('email_prefix:')));
});
t('two events for the SAME email co-occur on email_prefix even across hosts', () => {
  const prefix = emailHashKey('jane@example.com').email_hash_prefix;
  const a = makeEvent({ event_type: EVENT_TYPES.PII_EMAIL_PUBLIC, source_module: 'pii_detector', data: 'jane@example.com', source_url: 'https://a.example/', meta: { email_hash_prefix: prefix } });
  // a breach-style event that only carries the prefix (no plaintext) still joins.
  const b = makeEvent({ event_type: EVENT_TYPES.BREACH_RANGE_HIT, source_module: 'breach_range_detector', data: { label: 'pw' }, source_url: 'https://b.example/', meta: { email_hash_prefix: prefix } });
  const { index } = buildKeyIndex([a, b]);
  const bucket = index.get(`email_prefix:${prefix}`);
  assert.deepStrictEqual(bucket, [0, 1]); // both events share the prefix key
});
t('secret leak events co-occur by one-way fingerprint, never the secret', () => {
  const fp = 'deadbeef0001';
  const a = makeEvent({ event_type: EVENT_TYPES.SECRET_LEAK_PUBLIC, source_module: 'secret_leak_detector', data: { vendor: 'X', fingerprint: fp }, source_url: 'https://a/' });
  const b = makeEvent({ event_type: EVENT_TYPES.SECRET_LEAK_PUBLIC, source_module: 'secret_leak_detector', data: { vendor: 'X', fingerprint: fp }, source_url: 'https://b/' });
  const { index } = buildKeyIndex([a, b]);
  assert.deepStrictEqual(index.get(`secret_fp:${fp}`), [0, 1]);
});
t('no person/identity key is ever produced; handle normalizes', () => {
  assert.strictEqual(normalizeHandle('@Jane'), 'jane');
  assert.strictEqual(hostOf('not a url'), null);
  const ev = makeEvent({ event_type: EVENT_TYPES.PII_HANDLE_PUBLIC, source_module: 'pii_detector', data: '@Jane', meta: { handle: 'Jane' } });
  const keys = clusterKeysFor(ev);
  assert.ok(keys.includes('handle:jane'));
  assert.ok(keys.every((k) => /^(host|handle|email_prefix|secret_fp):/.test(k)));
});
t('non-event yields no keys', () => {
  assert.deepStrictEqual(clusterKeysFor({ foo: 1 }), []);
  assert.deepStrictEqual(buildKeyIndex([]).keysByEvent, []);
});

console.log('[severity]');
t('a HIGH-risk, indexed, confident finding outranks an INFO/low-confidence one', () => {
  const high = makeEvent({ event_type: EVENT_TYPES.PII_POSTAL_PUBLIC, source_module: 'pii_detector', data: '1 Main St', risk: RISK.HIGH, visibility: VISIBILITY.INDEXED, confidence: 0.95, source_url: 'https://x/' });
  const info = makeEvent({ event_type: EVENT_TYPES.PII_HANDLE_PUBLIC, source_module: 'pii_detector', data: '@x', risk: RISK.INFO, visibility: VISIBILITY.PRIVATE, confidence: 0.2 });
  assert.ok(eventSeverity(high).severity > eventSeverity(info).severity);
  assert.strictEqual(eventSeverity(high).band, 'critical');
});
t('low confidence GATES a high-risk signal so it cannot dominate certainty', () => {
  const riskyButUnsure = makeEvent({ event_type: EVENT_TYPES.PII_POSTAL_PUBLIC, source_module: 'm', risk: RISK.HIGH, visibility: VISIBILITY.INDEXED, confidence: 0.2 });
  const midButSure = makeEvent({ event_type: EVENT_TYPES.PII_EMAIL_PUBLIC, source_module: 'm', risk: RISK.MEDIUM, visibility: VISIBILITY.INDEXED, confidence: 1 });
  assert.ok(eventSeverity(midButSure).severity > eventSeverity(riskyButUnsure).severity);
});
t('rankBySeverity returns events sorted highest-first and is non-destructive', () => {
  const a = makeEvent({ event_type: EVENT_TYPES.PII_HANDLE_PUBLIC, source_module: 'm', risk: RISK.LOW, confidence: 0.6 });
  const b = makeEvent({ event_type: EVENT_TYPES.SECRET_LEAK_PUBLIC, source_module: 'm', data: { vendor: 'X', fingerprint: 'f' }, risk: RISK.HIGH, visibility: VISIBILITY.INDEXED, confidence: 0.95 });
  const ranked = rankBySeverity([a, b]);
  assert.strictEqual(ranked[0].event_type, EVENT_TYPES.SECRET_LEAK_PUBLIC);
  assert.ok(ranked.every((e) => typeof e._severity.severity === 'number'));
  assert.ok(!('_severity' in a) && !('_severity' in b)); // inputs not mutated
});
t('batchSeverity reuses canonical exposureScore and never fabricates from nothing', () => {
  const empty = batchSeverity([], {});
  assert.strictEqual(empty.event_count, 0);
  assert.strictEqual(empty.max_event_severity, 0);
  assert.strictEqual(empty.exposure_score, 0);
  const some = batchSeverity(
    [makeEvent({ event_type: EVENT_TYPES.PII_POSTAL_PUBLIC, source_module: 'm', risk: RISK.HIGH, visibility: VISIBILITY.INDEXED, confidence: 0.95, source_url: 'https://x/' })],
    { reachablePages: 1, distinctHosts: 1, indexablePages: 1 },
  );
  assert.ok(some.severity > 0 && some.severity <= 100);
  assert.ok(some.exposure_score > 0);
});
t('bandFor thresholds are monotonic; non-events score 0', () => {
  assert.strictEqual(bandFor(0), 'info');
  assert.strictEqual(bandFor(100), 'critical');
  assert.deepStrictEqual(eventSeverity({ foo: 1 }), { severity: 0, band: 'info', components: {} });
});

console.log('[report-groups]');
t('every frozen EVENT_TYPE maps to exactly one category (exhaustive, no orphans)', () => {
  // Blacklight framing: nothing may silently fall outside the report buckets.
  const covered = new Map();
  for (const cat of CATEGORIES) {
    for (const et of cat.event_types) {
      assert.ok(!covered.has(et), `${et} bucketed twice (${covered.get(et)} & ${cat.id})`);
      covered.set(et, cat.id);
    }
  }
  for (const et of VALID_EVENT_TYPES) {
    assert.ok(covered.has(et), `EVENT_TYPE ${et} has no report category`);
  }
});
t('categoryOf routes events to plain-language buckets; non-event -> null', () => {
  const sec = makeEvent({ event_type: EVENT_TYPES.SECRET_LEAK_PUBLIC, source_module: 'm', data: { vendor: 'X', fingerprint: 'f' } });
  const email = makeEvent({ event_type: EVENT_TYPES.PII_EMAIL_PUBLIC, source_module: 'm', data: 'a@b.com' });
  const trk = makeEvent({ event_type: EVENT_TYPES.TRACKER_FINGERPRINTING, source_module: 'm', data: ['canvas.toDataURL'] });
  assert.strictEqual(categoryOf(sec), 'secret_leaks');
  assert.strictEqual(categoryOf(email), 'pii');
  assert.strictEqual(categoryOf(trk), 'trackers');
  assert.strictEqual(categoryOf({ foo: 1 }), null);
});
t('buildReport groups, ranks, and carries why_it_matters + severity badges', () => {
  const events = [
    makeEvent({ event_type: EVENT_TYPES.PII_EMAIL_PUBLIC, source_module: 'pii_detector', data: 'a@b.com', risk: RISK.MEDIUM, visibility: VISIBILITY.INDEXED, confidence: 0.95, source_url: 'https://x/' }),
    makeEvent({ event_type: EVENT_TYPES.SECRET_LEAK_PUBLIC, source_module: 'secret_leak_detector', data: { vendor: 'AWS', fingerprint: 'abc123def456' }, risk: RISK.HIGH, visibility: VISIBILITY.INDEXED, confidence: 0.95, source_url: 'https://x/' }),
    makeEvent({ event_type: EVENT_TYPES.PII_HANDLE_PUBLIC, source_module: 'pii_detector', data: '@jane', risk: RISK.LOW, confidence: 0.6, source_url: 'https://x/' }),
  ];
  const report = buildReport(events, { crawlSummary: { reachablePages: 1, distinctHosts: 1, indexablePages: 2 } });
  assert.strictEqual(report.total_findings, 3);
  // highest-stakes category (secret leak) present with a populated explainer
  const secretCat = report.categories.find((c) => c.id === 'secret_leaks');
  assert.ok(secretCat && secretCat.count === 1);
  assert.match(secretCat.why_it_matters, /Rotate it/);
  assert.ok(['critical', 'high'].includes(secretCat.band));
  // empty categories are dropped by default
  assert.ok(!report.categories.some((c) => c.count === 0));
  // headline reuses canonical batchSeverity
  assert.ok(report.headline.severity > 0 && report.headline.exposure_score > 0);
});
t('buildReport can include empty categories when asked', () => {
  const report = buildReport([], { includeEmpty: true });
  assert.strictEqual(report.total_findings, 0);
  assert.strictEqual(report.categories.length, CATEGORIES.length);
  assert.ok(report.categories.every((c) => c.count === 0 && c.band === 'info'));
});
t('toCard projects only UI fields incl. severity + evidence-quality note', () => {
  const events = [makeEvent({ event_type: EVENT_TYPES.PII_EMAIL_PUBLIC, source_module: 'pii_detector', data: 'a@b.com', risk: RISK.MEDIUM, visibility: VISIBILITY.INDEXED, confidence: 0.9, source_url: 'https://x/' })];
  const report = buildReport(events);
  const finding = report.categories[0].findings[0];
  const card = toCard(finding);
  assert.strictEqual(card.event_type, EVENT_TYPES.PII_EMAIL_PUBLIC);
  assert.strictEqual(card.category, 'pii');
  assert.strictEqual(card.category_label, 'Personal info you published');
  assert.ok(typeof card.severity === 'number' && card.severity_band);
  assert.ok(typeof card.evidence_quality === 'number');
  assert.strictEqual(card.corroborations, 1);
  assert.strictEqual(toCard({ foo: 1 }), null);
});

console.log('[clusters]');
t('correlates events sharing an email_prefix across DIFFERENT hosts (SpiderFoot link)', () => {
  const prefix = emailHashKey('jane@example.com').email_hash_prefix;
  const a = makeEvent({ event_type: EVENT_TYPES.PII_EMAIL_PUBLIC, source_module: 'pii_detector', data: 'jane@example.com', source_url: 'https://a.example/', confidence: 0.95, meta: { email_hash_prefix: prefix } });
  const b = makeEvent({ event_type: EVENT_TYPES.BREACH_RANGE_HIT, source_module: 'breach_range_detector', data: { label: 'pw' }, source_url: 'https://b.example/', risk: RISK.HIGH, confidence: 0.9, meta: { email_hash_prefix: prefix } });
  const correlated = correlatedClusters([a, b]);
  assert.strictEqual(correlated.length, 1);
  const c = correlated[0];
  assert.strictEqual(c.size, 2);
  assert.ok(c.keys.includes(`email_prefix:${prefix}`));
  assert.ok(c.email_prefixes.includes(prefix));
  // both surfaces represented
  assert.deepStrictEqual(c.hosts, ['a.example', 'b.example']);
  // cluster severity is the worst of its members (breach HIGH)
  assert.ok(c.top_severity > 0);
});
t('the same leaked secret on two pages clusters by one-way fingerprint, never the secret', () => {
  const fp = 'cafebabe1234';
  const a = makeEvent({ event_type: EVENT_TYPES.SECRET_LEAK_PUBLIC, source_module: 'secret_leak_detector', data: { vendor: 'X', fingerprint: fp }, source_url: 'https://a/', risk: RISK.HIGH, confidence: 0.95 });
  const b = makeEvent({ event_type: EVENT_TYPES.SECRET_LEAK_PUBLIC, source_module: 'secret_leak_detector', data: { vendor: 'X', fingerprint: fp }, source_url: 'https://b/', risk: RISK.HIGH, confidence: 0.95 });
  const correlated = correlatedClusters([a, b]);
  assert.strictEqual(correlated.length, 1);
  assert.ok(correlated[0].secret_fingerprints.includes(fp));
  // the binding key carries only the fingerprint, never a plaintext secret
  assert.ok(correlated[0].keys.every((k) => /^(host|handle|email_prefix|secret_fp):/.test(k)));
});
t('unrelated events do NOT merge (no false correlation / no fabrication)', () => {
  const a = makeEvent({ event_type: EVENT_TYPES.PII_EMAIL_PUBLIC, source_module: 'pii_detector', data: 'a@b.com', source_url: 'https://one.example/', meta: { email_hash_prefix: emailHashKey('a@b.com').email_hash_prefix } });
  const b = makeEvent({ event_type: EVENT_TYPES.PII_EMAIL_PUBLIC, source_module: 'pii_detector', data: 'z@y.com', source_url: 'https://two.example/', meta: { email_hash_prefix: emailHashKey('z@y.com').email_hash_prefix } });
  const { clusters, linked_count } = buildClusters([a, b]);
  assert.strictEqual(linked_count, 0);            // nothing shared a key
  assert.strictEqual(clusters.length, 2);          // two singletons
  assert.ok(clusters.every((c) => c.size === 1));
  assert.strictEqual(correlatedClusters([a, b]).length, 0);
});
t('events on the SAME host cluster together (shared public surface)', () => {
  const a = makeEvent({ event_type: EVENT_TYPES.PII_EMAIL_PUBLIC, source_module: 'pii_detector', data: 'a@b.com', source_url: 'https://site.example/contact', meta: { email_hash_prefix: emailHashKey('a@b.com').email_hash_prefix } });
  const b = makeEvent({ event_type: EVENT_TYPES.TRACKER_THIRD_PARTY, source_module: 'tracker_detector', data: 'Google Analytics', source_url: 'https://site.example/home' });
  const correlated = correlatedClusters([a, b]);
  assert.strictEqual(correlated.length, 1);
  assert.deepStrictEqual(correlated[0].hosts, ['site.example']);
  assert.strictEqual(correlated[0].size, 2);
});
t('empty input -> empty clusters, non-destructive ranking', () => {
  const out = buildClusters([]);
  assert.deepStrictEqual(out.clusters, []);
  assert.strictEqual(out.linked_count, 0);
  assert.deepStrictEqual(out.ranked, []);
});

console.log(`\nOK — enrich self-tests, ${pass} passed.`);
