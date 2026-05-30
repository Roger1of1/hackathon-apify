/**
 * integrations/optout/_selftest.js
 *
 * Zero-dependency self-test for the data-broker opt-out workflow. Mirrors the
 * style of shared/aux/*_selftest.js and integrations/* tests. Run directly:
 *   node integrations/optout/_selftest.js
 *
 * Proves the load-bearing guarantees:
 *   - SCOPE-GATE-FIRST: a stalking/private-person input is refused by the REAL
 *     shared/scope.js before any registry/listing logic runs.
 *   - SELF-ONLY: even an accepted scope is refused unless it is self|consented —
 *     you only ever remove YOUR OWN listing, never a third party's.
 *   - TEMPLATE-HONESTY / NO FAKE DATA: the registry is a template of opt-out
 *     ROUTES, not listings; an empty/non-broker event set yields an empty plan;
 *     a listing exists only from a REAL module_event on a broker host.
 *   - REUSE: the emitted evidence comes from shared/enrich/stix-evidence.js
 *     (STIX 2.1 Observed Data) and shared/aux/takedown-letter.js (GDPR erasure),
 *     not a duplicated encoder.
 *   - RE-CHECK: a paced Apify Schedule (cron via cadence-policy) + Webhook is
 *     proposed for scope=self; scope=consented is not schedulable (manual).
 */

'use strict';

const assert = require('assert');
const { makeEvent, EVENT_TYPES, VISIBILITY, RISK } = require('../../shared/detectors/event-types.js');
const { toObservedData } = require('../../shared/enrich/stix-evidence.js');
const {
  buildOptOutPlan,
  loadBrokerRegistry,
  confirmSelfListings,
  indexRegistryByHost,
  REFUSAL,
  SELF_REMOVAL_SCOPES,
} = require('./optout-policy.js');

let failures = 0;
function t(name, fn) {
  try {
    fn();
    console.log(`  PASS  ${name}`);
  } catch (e) {
    failures += 1;
    console.log(`  FAIL  ${name}\n        ${e.message}`);
  }
}

const NOW = '2026-05-30T09:00:00.000Z';

// A REAL listing event: PII observed on a known broker host (spokeo.com).
function spokeoListing() {
  return makeEvent({
    event_type: EVENT_TYPES.PII_PHONE_PUBLIC,
    source_module: 'pii_detector',
    data: { kind: 'phone' },
    source_url: 'https://www.spokeo.com/Jane-Doe/profile/12345',
    visibility: VISIBILITY.INDEXED,
    risk: RISK.HIGH,
  });
}

// ── Registry is a labelled TEMPLATE of opt-out routes (not listings) ──────────
t('registry loads and is a labelled template of opt-out ROUTES', () => {
  const reg = loadBrokerRegistry();
  assert.strictEqual(reg.is_template, true, 'registry must be is_template:true');
  assert.ok(Array.isArray(reg.brokers) && reg.brokers.length > 0);
  for (const b of reg.brokers) {
    assert.ok(b.host && b.optout_url && b.optout_method, 'each entry is a route');
    assert.strictEqual(b.is_template, true, 'each broker entry is template-flagged');
    // Template-honesty: a route entry must NOT carry a person/listing field.
    assert.ok(!('listing_url' in b) && !('person' in b) && !('found' in b),
      'registry must NOT contain any listing/person data');
  }
});

// ── SCOPE-GATE-FIRST: a stalking input is refused before any registry logic ──
t('scope-gate-first: private-person stalking input is refused (SCOPE_REJECTED)', () => {
  const res = buildOptOutPlan({
    scope_type: 'self',
    target_urls: ['https://www.spokeo.com/me'],
    events: [spokeoListing()],
    // laundering attempt: legal scope + valid broker URL, but stalking free-text
    freeText: 'track my ex and watch their account',
  }, { now: NOW });
  assert.strictEqual(res.allowed, false);
  assert.strictEqual(res.refusal, REFUSAL.SCOPE_REJECTED);
  // It must carry the gate's own reasons + alternatives (real gate, read-only).
  assert.ok(Array.isArray(res.alternatives) && res.alternatives.length > 0);
});

t('scope-gate-first: disallowed scope_type is refused by the gate', () => {
  const res = buildOptOutPlan({
    scope_type: 'ex_partner',
    target_urls: ['https://www.spokeo.com/them'],
    events: [spokeoListing()],
  }, { now: NOW });
  assert.strictEqual(res.allowed, false);
  assert.strictEqual(res.refusal, REFUSAL.SCOPE_REJECTED);
});

// ── SELF-ONLY: accepted-but-not-self scopes are refused (you remove YOURSELF) ─
t('self-only: public_figure is refused (NOT_SELF_REMOVAL_SCOPE)', () => {
  const res = buildOptOutPlan({
    scope_type: 'public_figure',
    target_urls: ['https://www.spokeo.com/official'],
    events: [spokeoListing()],
  }, { now: NOW });
  assert.strictEqual(res.allowed, false);
  assert.strictEqual(res.refusal, REFUSAL.NOT_SELF_REMOVAL_SCOPE);
});

t('self-only: brand is refused (you cannot delete a third party from a broker)', () => {
  const res = buildOptOutPlan({
    scope_type: 'brand',
    target_urls: ['https://www.spokeo.com/acme'],
    events: [spokeoListing()],
  }, { now: NOW });
  assert.strictEqual(res.allowed, false);
  assert.strictEqual(res.refusal, REFUSAL.NOT_SELF_REMOVAL_SCOPE);
});

t('self-only: SELF_REMOVAL_SCOPES is exactly {self, consented}', () => {
  assert.deepStrictEqual([...SELF_REMOVAL_SCOPES].sort(), ['consented', 'self']);
});

// ── NO FAKE DATA: empty / non-broker events yield an empty plan ──────────────
t('no fake data: empty events → NO_LISTINGS refusal (never invents a listing)', () => {
  const res = buildOptOutPlan({
    scope_type: 'self',
    target_urls: ['https://example.com/me'],
    events: [],
  }, { now: NOW });
  assert.strictEqual(res.allowed, false);
  assert.strictEqual(res.refusal, REFUSAL.NO_LISTINGS);
  assert.strictEqual(res.registry_is_template, true);
});

t('no fake data: a non-broker-host event is NOT a confirmed listing', () => {
  const ev = makeEvent({
    event_type: EVENT_TYPES.PII_EMAIL_PUBLIC,
    source_module: 'pii_detector',
    source_url: 'https://example.com/contact', // not a broker host
  });
  const reg = loadBrokerRegistry();
  const confirmed = confirmSelfListings([ev], indexRegistryByHost(reg));
  assert.strictEqual(confirmed.length, 0);
  const res = buildOptOutPlan({
    scope_type: 'self', target_urls: ['https://example.com/me'], events: [ev],
  }, { now: NOW });
  assert.strictEqual(res.allowed, false);
  assert.strictEqual(res.refusal, REFUSAL.NO_LISTINGS);
});

// ── HAPPY PATH (self): real broker listing → STIX + erasure + paced re-check ─
t('self + real broker listing → accepted plan with one confirmed listing', () => {
  const res = buildOptOutPlan({
    scope_type: 'self',
    target_urls: ['https://www.spokeo.com/Jane-Doe/profile/12345'],
    events: [spokeoListing()],
    subjectName: 'Jane Doe',
  }, { now: NOW });
  assert.strictEqual(res.allowed, true);
  assert.strictEqual(res.deployed, false, 'never claims deployment');
  assert.strictEqual(res.listing_count, 1);
  const L = res.listings[0];
  assert.strictEqual(L.broker.id, 'spokeo');
  assert.strictEqual(L.broker.host, 'spokeo.com', 'www-stripped host match');
  assert.ok(L.broker.optout_url && L.broker.route_is_template === true,
    'opt-out route present and flagged as template to re-verify');
  assert.strictEqual(L.listing_url, 'https://www.spokeo.com/Jane-Doe/profile/12345');
});

// ── REUSE: STIX Observed Data is the SAME object stix-evidence.js produces ───
t('reuse: per-listing observed_data byte-matches shared/enrich/stix-evidence', () => {
  const ev = spokeoListing();
  const res = buildOptOutPlan({
    scope_type: 'self', target_urls: [ev.source_url], events: [ev], subjectName: 'Jane Doe',
  }, { now: NOW });
  const direct = toObservedData(ev, { now: NOW });
  assert.strictEqual(
    JSON.stringify(res.listings[0].observed_data),
    JSON.stringify(direct),
    'opt-out reuses the canonical STIX encoder, not a duplicate',
  );
  // Bundle is STIX 2.1 and carries exactly the listing events.
  assert.strictEqual(res.stix_bundle.type, 'bundle');
  assert.strictEqual(res.stix_bundle.spec_version, '2.1');
  assert.strictEqual(res.stix_bundle.objects.length, 1);
});

// ── REUSE: erasure request comes from takedown-letter (GDPR Art.17) ──────────
t('reuse: erasure_plan is a takedown-letter GDPR erasure draft (template)', () => {
  const ev = spokeoListing();
  const res = buildOptOutPlan({
    scope_type: 'self', target_urls: [ev.source_url], events: [ev], subjectName: 'Jane Doe',
  }, { now: NOW });
  assert.strictEqual(res.erasure_plan.record_type, 'takedown_plan');
  assert.strictEqual(res.erasure_plan.is_template, true);
  assert.ok(res.erasure_plan.packet_count >= 1);
  const packet = res.erasure_plan.packets[0];
  // A broker host is third-party → must include a GDPR erasure letter.
  const kinds = packet.request_kinds;
  assert.ok(kinds.includes('gdpr_erasure'), 'broker = third-party → GDPR erasure');
  const gdpr = packet.letters.find((l) => l.request_kind === 'gdpr_erasure');
  assert.ok(/Article 17/.test(gdpr.body_text) || gdpr.statute_refs.some((s) => /Article 17/.test(s)));
  // Real subject name flows through; draft is template-flagged for review.
  assert.ok(gdpr.body_text.includes('Jane Doe'));
  assert.strictEqual(gdpr.is_template, true);
});

// ── RE-CHECK: self gets a paced cron + reappearance webhook (not deployed) ───
t('re-check: scope=self proposes a policy-derived cron + reappearance webhook', () => {
  const ev = spokeoListing();
  const res = buildOptOutPlan({
    scope_type: 'self', target_urls: [ev.source_url], events: [ev], cadence: 'closure',
  }, { now: NOW });
  assert.strictEqual(res.recheck.schedule.schedulable, true);
  assert.ok(/^\S+ \S+ \S+ \S+ \S+$/.test(res.recheck.schedule.cron), '5-field cron from cadence-policy');
  assert.strictEqual(res.recheck.schedule.deployed, false);
  assert.ok(res.recheck.webhook.eventTypes.includes('ACTOR.RUN.SUCCEEDED'));
  assert.strictEqual(res.recheck.webhook.deployed, false);
  // Cites the existing WCC ingest path (Reference Architecture #2).
  assert.strictEqual(res.recheck.ingests_via.actor, 'apify/website-content-crawler');
});

t('re-check: high distress slows the cron (anti-compulsion floor)', () => {
  const ev = spokeoListing();
  const calm = buildOptOutPlan({
    scope_type: 'self', target_urls: [ev.source_url], events: [ev], cadence: 'daily',
    distress_risk_score: 0.0,
  }, { now: NOW });
  const distressed = buildOptOutPlan({
    scope_type: 'self', target_urls: [ev.source_url], events: [ev], cadence: 'daily',
    distress_risk_score: 0.9,
  }, { now: NOW });
  assert.ok(
    distressed.recheck.schedule.effective_floor_minutes > calm.recheck.schedule.effective_floor_minutes,
    'higher distress → slower re-check, never faster',
  );
});

// ── RE-CHECK: consented is not auto-schedulable → manual recommendation ──────
t('re-check: scope=consented is not schedulable → manual re-check (fail-closed)', () => {
  const ev = makeEvent({
    event_type: EVENT_TYPES.PII_EMAIL_PUBLIC,
    source_module: 'pii_detector',
    source_url: 'https://www.whitepages.com/name/Friend-Name',
  });
  const res = buildOptOutPlan({
    scope_type: 'consented',
    target_urls: [ev.source_url],
    authorization_evidence_url: 'https://example.com/signed-consent.pdf',
    events: [ev],
  }, { now: NOW });
  assert.strictEqual(res.allowed, true, 'consented is a valid self-removal scope');
  assert.strictEqual(res.scope, 'consented');
  assert.strictEqual(res.recheck.schedule.schedulable, false);
  assert.ok(/manual/i.test(res.recheck.schedule.recommendation));
});

console.log(`\noptout self-test: ${failures === 0 ? 'OK' : failures + ' FAILURE(S)'}`);
process.exit(failures === 0 ? 0 : 1);
