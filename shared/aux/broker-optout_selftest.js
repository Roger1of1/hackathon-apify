/**
 * shared/aux/broker-optout_selftest.js
 *
 * Zero-dependency self-test for the scope-gated data-broker opt-out workflow.
 * Mirrors the style of shared/aux/takedown-letter_selftest.js. Run directly:
 *   node shared/aux/broker-optout_selftest.js
 *
 * Proves the load-bearing guarantees the round directive requires:
 *   (1) SCOPE-GATE-FIRST  — every target routes through the REAL shared/scope.js.
 *   (2) SELF-ONLY refusal — a broker opt-out for any non-self/non-consented
 *       subject (public_figure / brand / another person) is refused.
 *   (3) TEMPLATE HONESTY  — no fabricated listings; empty in → empty out; the
 *       registry is flagged is_template with contains_listings:false.
 *   (4) REUSE             — emits STIX 2.1 Observed Data via stix-evidence.js and
 *       a ready-to-send erasure request via takedown-letter.js (not duplicated).
 *   (+) Apify re-check proposal cites the WCC/RAG ingest + schedule/webhook path.
 */

'use strict';

const assert = require('assert');

const {
  buildBrokerOptOutPlan,
  listingToEvent,
  recheckProposalFor,
  REFUSAL,
  SELF_OPTOUT_SCOPES,
} = require('./broker-optout.js');
const { getBroker, REGISTRY_STATUS, BROKER_REGISTRY } = require('./broker-registry.js');
const { toObservedData } = require('../enrich/stix-evidence.js');
const { isModuleEvent } = require('../detectors/event-types.js');

const NOW = '2026-01-01T00:00:00.000Z';

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

// ───────────────────────────── (1) SCOPE-GATE-FIRST ─────────────────────────────

// A stalking-flavoured scope is rejected by the REAL gate, not silently allowed.
t('scope-gate-first: prohibited scope is refused by the real scope gate', () => {
  const r = buildBrokerOptOutPlan({
    scope_type: 'private_person_tracking',
    confirmed_listings: [{ broker_id: 'spokeo', confirmed_self: true }],
  });
  assert.strictEqual(r.allowed, false);
  assert.strictEqual(r.refusal, REFUSAL.SCOPE_GATE);
  assert.ok(r.violated_red_lines.length > 0, 'gate must report a violated red line');
});

// Free-text laundering under a legal-looking scope is still caught by the gate.
t('scope-gate-first: laundering free-text under self is refused', () => {
  const r = buildBrokerOptOutPlan({
    scope_type: 'self',
    subject_label: 'find whether this person is active on Tinder',
    confirmed_listings: [],
  });
  assert.strictEqual(r.allowed, false);
  assert.strictEqual(r.refusal, REFUSAL.SCOPE_GATE);
});

// A private-social host smuggled in as a "listing" is blocked by the gate.
t('scope-gate-first: private-social host listing is blocked by the gate', () => {
  const r = buildBrokerOptOutPlan({
    scope_type: 'self',
    confirmed_listings: [
      { broker_id: 'spokeo', listing_url: 'https://instagram.com/someone', confirmed_self: true },
    ],
  });
  assert.strictEqual(r.allowed, false);
  assert.strictEqual(r.refusal, REFUSAL.SCOPE_GATE);
});

// ───────────────────────────── (2) SELF-ONLY refusal ─────────────────────────────

t('self-only: public_figure broker opt-out is refused (cannot opt others out)', () => {
  const r = buildBrokerOptOutPlan({
    scope_type: 'public_figure',
    confirmed_listings: [{ broker_id: 'spokeo', confirmed_self: true }],
  });
  assert.strictEqual(r.allowed, false);
  assert.strictEqual(r.refusal, REFUSAL.NOT_SELF);
  assert.ok(r.violated_red_lines.includes('broker_optout_requires_self'));
});

t('self-only: brand broker opt-out is refused', () => {
  const r = buildBrokerOptOutPlan({
    scope_type: 'brand',
    confirmed_listings: [{ broker_id: 'spokeo', confirmed_self: true }],
  });
  assert.strictEqual(r.allowed, false);
  assert.strictEqual(r.refusal, REFUSAL.NOT_SELF);
});

t('self-only: safety_evidence broker opt-out is refused', () => {
  const r = buildBrokerOptOutPlan({
    scope_type: 'safety_evidence',
    confirmed_listings: [{ broker_id: 'spokeo', confirmed_self: true }],
  });
  assert.strictEqual(r.allowed, false);
  assert.strictEqual(r.refusal, REFUSAL.NOT_SELF);
});

t('self-only: the only allowed opt-out scopes are self + consented', () => {
  assert.deepStrictEqual([...SELF_OPTOUT_SCOPES].sort(), ['consented', 'self']);
});

// consented passes ONLY because the gate forces authorization_evidence_url.
t('consented broker opt-out allowed only with authorization (gate enforced)', () => {
  const noAuth = buildBrokerOptOutPlan({
    scope_type: 'consented',
    confirmed_listings: [{ broker_id: 'spokeo', listing_url: 'https://www.spokeo.com/x', confirmed_self: true }],
  });
  assert.strictEqual(noAuth.allowed, false, 'consented w/o auth must fail at the gate');
  const withAuth = buildBrokerOptOutPlan({
    scope_type: 'consented',
    authorization_evidence_url: 'https://example.com/written-consent',
    confirmed_listings: [{ broker_id: 'spokeo', listing_url: 'https://www.spokeo.com/x', confirmed_self: true }],
  }, { now: NOW });
  assert.strictEqual(withAuth.allowed, true, 'consented WITH auth proceeds');
});

// ───────────────────────────── (3) TEMPLATE HONESTY ─────────────────────────────

t('template honesty: registry holds NO listings and is flagged is_template', () => {
  assert.strictEqual(REGISTRY_STATUS.is_template, true);
  assert.strictEqual(REGISTRY_STATUS.contains_listings, false);
  // No registry entry carries a "found you here" / match field.
  for (const b of BROKER_REGISTRY) {
    assert.ok(!('listing' in b) && !('match' in b) && !('found' in b),
      `broker ${b.id} must not carry a fabricated listing/match`);
    assert.ok(typeof b.optout_url === 'string' && /^https:\/\//.test(b.optout_url),
      `broker ${b.id} must expose a real https opt-out URL`);
  }
});

t('template honesty: empty confirmed listings → empty plan (no fabrication)', () => {
  const p = buildBrokerOptOutPlan({ scope_type: 'self', confirmed_listings: [] }, { now: NOW });
  assert.strictEqual(p.allowed, true);
  assert.strictEqual(p.confirmed_listing_count, 0);
  assert.deepStrictEqual(p.optouts, []);
  assert.deepStrictEqual(p.observed_data, []);
  assert.strictEqual(p.erasure_plan.letter_count, 0);
  assert.deepStrictEqual(p.recheck_proposals, []);
  assert.strictEqual(p.is_template, true);
});

t('template honesty: unconfirmed listing is skipped, never actioned', () => {
  const p = buildBrokerOptOutPlan({
    scope_type: 'self',
    confirmed_listings: [{ broker_id: 'spokeo', listing_url: 'https://www.spokeo.com/x' }], // confirmed_self omitted
  }, { now: NOW });
  assert.strictEqual(p.confirmed_listing_count, 0);
  assert.ok(p.skipped.some((s) => s.reason === 'not_confirmed_self'));
});

t('template honesty: unknown broker id is skipped, never invented', () => {
  const p = buildBrokerOptOutPlan({
    scope_type: 'self',
    confirmed_listings: [{ broker_id: 'totally-made-up', confirmed_self: true }],
  }, { now: NOW });
  assert.strictEqual(p.confirmed_listing_count, 0);
  assert.ok(p.skipped.some((s) => s.reason === REFUSAL.NO_BROKER));
});

t('template honesty: plan carries the registry_status banner', () => {
  const p = buildBrokerOptOutPlan({ scope_type: 'self', confirmed_listings: [] }, { now: NOW });
  assert.strictEqual(p.registry_status.is_template, true);
  assert.strictEqual(p.registry_status.contains_listings, false);
});

// ───────────────────────────── (4) REUSE proofs ─────────────────────────────

t('reuse: confirmed listing emits a STIX 2.1 Observed Data object (stix-evidence)', () => {
  const broker = getBroker('spokeo');
  const ev = listingToEvent({
    broker,
    listing_url: 'https://www.spokeo.com/Jane-Doe/123',
    host: 'www.spokeo.com',
    confirmed_self: true,
  });
  assert.ok(isModuleEvent(ev), 'listingToEvent must produce a real module_event');
  // The plan's observed_data must be byte-identical to a direct stix-evidence call
  // (proving REUSE, not a re-implementation).
  const direct = toObservedData(ev, { now: NOW });
  const p = buildBrokerOptOutPlan({
    scope_type: 'self',
    subject_label: 'Jane Doe',
    confirmed_listings: [{ broker_id: 'spokeo', listing_url: 'https://www.spokeo.com/Jane-Doe/123', confirmed_self: true }],
  }, { now: NOW });
  assert.strictEqual(p.observed_data.length, 1);
  const od = p.observed_data[0];
  assert.strictEqual(od.type, 'observed-data');
  assert.strictEqual(od.spec_version, '2.1');
  assert.strictEqual(JSON.stringify(od), JSON.stringify(direct), 'must reuse stix-evidence output verbatim');
  // STIX bundle + OpenCTI/MISP interop bundle are both present.
  assert.strictEqual(p.stix_bundle.type, 'bundle');
  assert.strictEqual(p.stix_interop_bundle.type, 'bundle');
});

t('reuse: confirmed listing yields a GDPR Art.17 + CCPA erasure request (takedown-letter)', () => {
  const p = buildBrokerOptOutPlan({
    scope_type: 'self',
    subject_label: 'Jane Doe',
    confirmed_listings: [{ broker_id: 'whitepages', listing_url: 'https://www.whitepages.com/name/Jane-Doe', confirmed_self: true }],
  }, { now: NOW });
  assert.strictEqual(p.erasure_plan.record_type, 'takedown_plan');
  const kinds = p.erasure_plan.packets[0].request_kinds;
  assert.ok(kinds.includes('gdpr_erasure'), 'broker is a third party → GDPR erasure');
  assert.ok(kinds.includes('ccpa_delete'), 'broker is a third party → CCPA delete');
  const gdpr = p.erasure_plan.packets[0].letters.find((l) => l.request_kind === 'gdpr_erasure');
  assert.ok(gdpr.body_text.includes('Jane Doe'), 'real subject name used, not placeholder');
  assert.ok(gdpr.statute_refs.some((s) => /Article 17/.test(s)));
  assert.strictEqual(gdpr.is_template, true);
});

t('reuse: broker host is NEVER treated as a user-owned surface (no self-removal shortcut)', () => {
  const p = buildBrokerOptOutPlan({
    scope_type: 'self',
    subject_label: 'Jane Doe',
    confirmed_listings: [{ broker_id: 'spokeo', listing_url: 'https://www.spokeo.com/Jane-Doe/123', confirmed_self: true }],
  }, { now: NOW });
  const kinds = p.erasure_plan.packets[0].request_kinds;
  assert.ok(!kinds.includes('self_removal'),
    'a data broker is a third party; erasure must be a data-subject request, not self-removal');
});

// ───────────────────────────── (+) Apify re-check ─────────────────────────────

t('re-check proposal cites WCC/RAG ingest + schedule + webhook (reappearance guard)', () => {
  const prop = recheckProposalFor(getBroker('spokeo'));
  assert.strictEqual(prop.purpose, 'reappearance_guard');
  assert.ok(/website_content_crawler|rag_web_browser/.test(prop.ingest_via));
  assert.ok(/integrations\/ingest/.test(prop.ingest_path));
  assert.strictEqual(prop.cadence, 'closure');
  assert.ok(/cadence-policy/.test(prop.schedule_ref));
  assert.ok(/webhook/i.test(prop.webhook_ref));
  // RAG-based broker (Acxiom) routes via rag_web_browser.
  const acx = recheckProposalFor(getBroker('acxiom'));
  assert.strictEqual(acx.ingest_via, 'rag_web_browser');
});

t('re-check: one proposal per DISTINCT broker even with multiple listings', () => {
  const p = buildBrokerOptOutPlan({
    scope_type: 'self',
    confirmed_listings: [
      { broker_id: 'spokeo', listing_url: 'https://www.spokeo.com/a', confirmed_self: true },
      { broker_id: 'spokeo', listing_url: 'https://www.spokeo.com/b', confirmed_self: true },
      { broker_id: 'radaris', listing_url: 'https://radaris.com/p/x', confirmed_self: true },
    ],
  }, { now: NOW });
  assert.strictEqual(p.confirmed_listing_count, 3);
  assert.strictEqual(p.recheck_proposals.length, 2, 'spokeo dedupes to one proposal; radaris is the second');
});

// Determinism (NO FAKE DATA → reproducible).
t('deterministic output: same input → byte-identical plan', () => {
  const input = {
    scope_type: 'self',
    subject_label: 'A B',
    confirmed_listings: [{ broker_id: 'spokeo', listing_url: 'https://www.spokeo.com/x', confirmed_self: true }],
  };
  const a = buildBrokerOptOutPlan(input, { now: NOW });
  const b = buildBrokerOptOutPlan(input, { now: NOW });
  assert.strictEqual(JSON.stringify(a), JSON.stringify(b));
});

console.log(`\nbroker-optout self-test: ${failures === 0 ? 'OK' : failures + ' FAILURE(S)'}`);
process.exit(failures === 0 ? 0 : 1);
