/**
 * shared/aux/archive-finding_selftest.js
 *
 * Standalone self-test for the AUX Public-Archive Self-Exposure feature. Lives
 * in shared/aux (NOT under test/, which another track owns). Pure + offline: it
 * never touches the network. It asserts that:
 *   (A) the shapers emit valid, frozen-vocabulary module_events carrying the
 *       REAL Wayback timestamp + digest, and that those events round-trip into a
 *       STIX 2.1 Observed Data object whose first_observed/last_observed are the
 *       TRUE archive capture time (not "now") — the OpenCTI/MISP-interop shape;
 *   (B) the SCOPE GATE the actor applies is FAIL-CLOSED: a private-individual /
 *       stalking query is dropped BEFORE any fetch, and only self/public_figure
 *       are allowed (consented/brand/safety_evidence cannot run this dual-use
 *       archive enumeration);
 *   (C) NO FAKE DATA: an unparseable CDX row produces NO event.
 *
 * Run: node shared/aux/archive-finding_selftest.js
 *
 * Refs cited in the module under test: OASIS STIX 2.1 Observed Data SDO
 * (OpenCTI/MISP interop); Internet Archive Wayback CDX Server API; Apify
 * apify/website-content-crawler + apify/rag-web-browser ingestion pattern.
 */

'use strict';

const assert = require('assert');

const {
  MODULE,
  waybackTimestampToISO,
  waybackReplayUrl,
  makeArchivedUrlEvent,
  makeArchivedPiiEvent,
  makeSummaryEvent,
} = require('./archive-finding.js');
const { isModuleEvent, EVENT_TYPES } = require('../detectors/event-types.js');
const { toObservedData } = require('../enrich/stix-evidence.js');
const { validateScope, ALLOWED_SCOPES } = require('../scope.js');

// Mirror of the actor's dual-use restriction (kept in sync with src/main.js).
const ARCHIVE_SCOPES = new Set(['self', 'public_figure']);

/**
 * The EXACT decision the actor makes before any network call: it builds an
 * input from a scope + subject URL and runs the real scope gate, then applies
 * the dual-use restriction. This is the fail-closed pre-fetch filter.
 * Returns { willFetch, reason }.
 */
function archivePreFetchDecision({ scope_type, subject_url, subject_label }) {
  const gate = validateScope({
    scope_type,
    target_urls: subject_url ? [subject_url] : [],
    subject_label,
    description: subject_label,
  });
  if (!gate.allowed) return { willFetch: false, reason: 'scope_gate_rejected', gate };
  if (!ALLOWED_SCOPES.includes(scope_type) || !ARCHIVE_SCOPES.has(scope_type)) {
    return { willFetch: false, reason: 'dual_use_restricted', gate };
  }
  if (!subject_url) return { willFetch: false, reason: 'no_subject_url', gate };
  return { willFetch: true, reason: 'allowed', gate };
}

let pass = 0;
const ok = (name) => { pass += 1; console.log(`  PASS  ${name}`); };

console.log('AUX archive-exposure self-test\n');

// ── (A) Shapers + STIX round-trip ──────────────────────────────────────────

// 1) A real CDX row → SELF_PROFILE_URL event carrying true capture time + digest.
{
  const ev = makeArchivedUrlEvent({
    original: 'https://example.com/old-contact-page',
    timestamp: '20190731164102',
    digest: 'AB23CXYZ7QWE9LMNOP4567RSTUV890123',
    mimetype: 'text/html',
    statuscode: '200',
    subjectUrlPrefix: 'https://example.com',
  });
  assert(isModuleEvent(ev), 'archived url must be a valid module_event');
  assert.strictEqual(ev.event_type, EVENT_TYPES.SELF_PROFILE_URL);
  assert.strictEqual(ev.source_module, MODULE);
  assert.strictEqual(ev.meta.observed_at, '2019-07-31T16:41:02.000Z', 'observed_at must be the parsed Wayback time');
  assert.strictEqual(ev.meta.content_digest, 'AB23CXYZ7QWE9LMNOP4567RSTUV890123');
  assert.strictEqual(ev.source_url, 'https://web.archive.org/web/20190731164102/https://example.com/old-contact-page');
  ok('CDX row → SELF_PROFILE_URL event with true capture time + digest + replay url');
}

// 2) STIX round-trip: first_observed/last_observed must be the ARCHIVE time, not now.
{
  const ev = makeArchivedUrlEvent({
    original: 'https://example.com/old-contact-page',
    timestamp: '20190731164102',
    digest: 'AB23CXYZ7QWE9LMNOP4567RSTUV890123',
  });
  const observed = ev.meta.observed_at;
  const od = toObservedData(ev, {
    now: observed, // actor passes the snapshot time as the STIX timestamp
    integrity: { content_sha256: null, html_sha256: ev.meta.content_digest },
  });
  assert(od, 'must produce a STIX observed-data object');
  assert.strictEqual(od.type, 'observed-data');
  assert.strictEqual(od.spec_version, '2.1');
  assert.strictEqual(od.first_observed, '2019-07-31T16:41:02.000Z', 'first_observed = true archive time');
  assert.strictEqual(od.last_observed, '2019-07-31T16:41:02.000Z', 'last_observed = true archive time');
  assert.strictEqual(od.objects[0].type, 'url', 'SELF_PROFILE_URL maps to a url observable');
  assert.strictEqual(od.x_integrity.html_sha256, 'AB23CXYZ7QWE9LMNOP4567RSTUV890123', 'content digest carried into STIX integrity');
  ok('STIX 2.1 Observed Data dates the finding to the TRUE archive capture time (OpenCTI/MISP interop shape)');
}

// 3) PII found inside an archived snapshot → PII_EMAIL_PUBLIC event, archive-dated.
{
  const pii = makeArchivedPiiEvent({
    event_type: EVENT_TYPES.PII_EMAIL_PUBLIC,
    data: 'me@example.com',
    replayUrl: 'https://web.archive.org/web/20190731164102/https://example.com/old',
    observedISO: '2019-07-31T16:41:02.000Z',
    original: 'https://example.com/old',
    confidence: 0.95,
  });
  assert(isModuleEvent(pii));
  assert.strictEqual(pii.event_type, EVENT_TYPES.PII_EMAIL_PUBLIC);
  assert.strictEqual(pii.meta.observed_at, '2019-07-31T16:41:02.000Z');
  // A non-PII event type must be rejected by the PII shaper (defensive).
  assert.strictEqual(
    makeArchivedPiiEvent({ event_type: EVENT_TYPES.TRACKER_THIRD_PARTY, data: 'x', replayUrl: 'u', observedISO: 't' }),
    null,
    'non-PII event type must not be shaped as archived PII',
  );
  ok('archived-PII shaper emits a valid PII event and refuses non-PII types');
}

// 4) Summary event is a real aggregate (zero counts are honest, not fabricated).
{
  const sum = makeSummaryEvent({
    subjectUrlPrefix: 'https://example.com',
    counts: { snapshots: 3, unique_urls: 2, pii_in_archive: 1 },
    earliestISO: '2017-01-01T00:00:00.000Z',
    latestISO: '2019-07-31T16:41:02.000Z',
  });
  assert(isModuleEvent(sum));
  assert.strictEqual(sum.event_type, EVENT_TYPES.EXPOSURE_SUMMARY);
  assert.strictEqual(sum.data.snapshots, 3);
  const empty = makeSummaryEvent({ subjectUrlPrefix: 'https://example.com', counts: {} });
  assert.strictEqual(empty.data.snapshots, 0, 'empty archive => zero, not invented');
  ok('summary event aggregates real counts and stays honest on empty input');
}

// ── (C) NO FAKE DATA: unparseable inputs produce NO event ───────────────────
{
  assert.strictEqual(waybackTimestampToISO('not-a-timestamp'), null);
  assert.strictEqual(waybackTimestampToISO('2019'), null);
  assert.strictEqual(waybackReplayUrl('20190731164102', ''), null);
  assert.strictEqual(
    makeArchivedUrlEvent({ original: 'https://example.com/x', timestamp: 'bad' }),
    null,
    'unparseable CDX row must yield NO event (no fabrication)',
  );
  ok('unparseable timestamp / empty row produce NO event (no fake data)');
}

// ── (B) FAIL-CLOSED scope gate: drop stalking/private-individual BEFORE fetch ─

// 5) self + own URL is allowed (the happy path that reaches a real fetch).
{
  const d = archivePreFetchDecision({ scope_type: 'self', subject_url: 'https://example.com', subject_label: 'My own site' });
  assert.strictEqual(d.willFetch, true, 'self + own URL must be allowed to fetch');
  ok('self scope with own URL is allowed to fetch');
}

// 6) public_figure + official site is allowed.
{
  const d = archivePreFetchDecision({ scope_type: 'public_figure', subject_url: 'https://official.example.gov', subject_label: 'Mayor official site' });
  assert.strictEqual(d.willFetch, true, 'public_figure + official site must be allowed');
  ok('public_figure scope with official site is allowed to fetch');
}

// 7) consented/brand/safety_evidence — legal elsewhere but NOT for this dual-use
//    archive enumeration — must be dropped before fetch.
for (const s of ['consented', 'brand', 'safety_evidence']) {
  const d = archivePreFetchDecision({ scope_type: s, subject_url: 'https://example.com', subject_label: 'x' });
  assert.strictEqual(d.willFetch, false, `${s} must NOT reach a fetch`);
  ok(`dual-use restriction drops scope_type=${s} before any fetch`);
}

// 8) An outright invalid / private-person scope is rejected by the gate, no fetch.
{
  const d = archivePreFetchDecision({ scope_type: 'private_person_tracking', subject_url: 'https://example.com', subject_label: 'find a private person' });
  assert.strictEqual(d.willFetch, false, 'private_person_tracking must be rejected');
  assert.strictEqual(d.reason, 'scope_gate_rejected', 'rejection must come from the canonical scope gate');
  ok('private_person_tracking scope is rejected by the gate before any fetch');
}

// 9) PROMPT LAUNDERING: a legal-looking self scope whose free text encodes a
//    stalking intent must be dropped by the gate's free-text scan before fetch.
{
  const d = archivePreFetchDecision({
    scope_type: 'self',
    subject_url: 'https://example.com',
    subject_label: 'track a private person girlfriend and find who she is dating',
  });
  assert.strictEqual(d.willFetch, false, 'laundered stalking intent under self must be dropped');
  assert.strictEqual(d.reason, 'scope_gate_rejected', 'must be the gate, not a downstream check, that drops it');
  ok('laundered stalking intent under a self scope is dropped before any fetch');
}

console.log(`\nOK — ${pass} archive-exposure checks, 0 failures.`);
