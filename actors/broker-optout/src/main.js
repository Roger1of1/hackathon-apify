/**
 * AUX — Data-Broker Opt-Out (self-only)
 *
 * An auxiliary actor that orbits the core MirrorTrace pipeline. It answers ONE
 * compliant, action-oriented question for the SELF subject: "I found MY OWN
 * listing on a people-search / data-broker site — how do I get it removed, and
 * how do I make sure it stays gone?" This is the genuinely-unbuilt, market-proven
 * self-protection pattern (cf. DeleteMe / Privacy Bee style services), rebuilt
 * compliantly: it never acts on anyone but the requester, and it never scrapes.
 *
 * ───────────────────────────── COMPLIANCE BOUNDARY ─────────────────────────────
 * 1. SCOPE-GATE-FIRST. The pure planner (shared/aux/broker-optout.js) routes the
 *    request through the canonical shared/scope.js validateScope() BEFORE doing
 *    anything, and additionally hard-restricts to scope_type ∈ {self, consented}.
 *    A broker opt-out is a first-person erasure; you cannot opt a public figure,
 *    a brand, or another person out of a broker. Those scopes are refused here
 *    AND are absent from the input_schema enum (two doors).
 * 2. NO SCRAPING, NO FAKE DATA. This actor performs NO network fetch. A "listing"
 *    only becomes actionable when the USER confirms (confirmed_self:true) it is
 *    about them. The broker registry is a clearly-labeled TEMPLATE of public
 *    opt-out contact points — zero scraped listings, zero "you were found here".
 *    Nothing is sent and nothing is removed; we emit a reviewable PLAN.
 * 3. No identity/romance/gender/intimacy/live-location pathway anywhere.
 * ───────────────────────────────────────────────────────────────────────────────
 *
 * REFERENCE ARCHITECTURES APPLIED (both required this round):
 *  - OASIS STIX 2.1 Observed Data + OpenCTI/MISP interop: per confirmed listing
 *    we emit a STIX 2.1 Observed Data object by REUSING shared/enrich/stix-
 *    evidence.js (and an Indicator via shared/enrich/stix-indicator.js) so the
 *    evidence is portable into a CTI platform / SIEM and into the erasure letter.
 *    A "this listing about ME is public at URL U, observed at T" finding is
 *    literally an Observed Data object.
 *  - Apify Website Content Crawler + RAG Web Browser ingestion: the re-check
 *    PROPOSAL re-reads the broker's OWN public surface through the existing,
 *    gated, capped ingest path (integrations/ingest/*: apify/website-content-
 *    crawler for a known opt-out URL, apify/rag-web-browser for a public name
 *    search), paced by integrations/schedules (cadence=closure) and alerted by
 *    integrations/webhooks — so a REMOVED listing that REAPPEARS is re-flagged
 *    (Closure-Mode-friendly). This actor only PROPOSES it; it deploys nothing.
 *
 * The GDPR Art.17 / CCPA erasure requests are produced by REUSING
 * shared/aux/takedown-letter.js (a data broker is a third-party host holding the
 * subject's PII → data-subject-request channel, not self-removal).
 */

'use strict';

const { Actor, log } = require('apify');

const { buildBrokerOptOutPlan } = require('../../../shared/aux/broker-optout.js');

Actor.main(async () => {
  const input = (await Actor.getInput()) || {};

  // Resolve a case id from the shared KV store if a pipeline created one.
  const caseStoreName = input.case_store_name || 'mirrortrace-case';
  let caseId = input.case_id || null;
  try {
    const caseStore = await Actor.openKeyValueStore(caseStoreName);
    const caseRecord = await caseStore.getValue('CASE');
    if (caseRecord && caseRecord.case_id) caseId = caseRecord.case_id;
  } catch (err) {
    log.debug(`No case store available (${err.message}); running standalone.`);
  }
  if (!caseId) caseId = 'standalone_broker_optout';

  // ── Build the plan. The planner runs the REAL scope gate first and refuses any
  // non-self/non-consented subject. We do NOT pre-empt it — single chokepoint. ──
  const plan = buildBrokerOptOutPlan({
    scope_type: input.scope_type,
    subject_label: input.subject_label,
    authorization_evidence_url: input.authorization_evidence_url,
    confirmed_listings: Array.isArray(input.confirmed_listings) ? input.confirmed_listings : [],
  });

  if (!plan.allowed) {
    // Fail-closed: surface the refusal as a dataset record, then fail the run.
    log.error('Broker opt-out refused.', {
      refusal: plan.refusal,
      reasons: plan.reasons,
      violated: plan.violated_red_lines,
    });
    await Actor.pushData({
      record_type: 'broker_optout_refusal',
      source_module: 'aux:broker-optout',
      case_id: caseId,
      refusal: plan.refusal,
      reasons: plan.reasons,
      violated_red_lines: plan.violated_red_lines,
      alternatives: plan.alternatives,
    });
    await Actor.setValue('BROKER_OPTOUT_REFUSAL', {
      ...plan,
      case_id: caseId,
      generated_at: new Date().toISOString(),
    });
    await Actor.fail(
      `Broker opt-out rejected (${plan.refusal}). A broker opt-out is allowed only for your own ` +
      'listings (scope_type=self), or consented with written authorization.',
    );
    return;
  }

  // ── Allowed. Emit one dataset record per confirmed listing's action bundle, so
  // the report-builder / UI can render each opt-out + its STIX evidence + its
  // erasure letter together. NO row is emitted if there is nothing confirmed. ──
  const optouts = plan.optouts;
  const observed = plan.observed_data;
  const erasurePackets = plan.erasure_plan.packets;

  for (let i = 0; i < optouts.length; i += 1) {
    await Actor.pushData({
      record_type: 'broker_optout_action',
      source_module: 'aux:broker-optout',
      case_id: caseId,
      scope_type: plan.scope_type,
      broker_id: optouts[i].broker_id,
      broker_name: optouts[i].broker_name,
      listing_url: optouts[i].listing_url,
      optout_url: optouts[i].optout_url,
      optout_method: optouts[i].optout_method,
      jurisdiction_hint: optouts[i].jurisdiction_hint,
      // STIX 2.1 Observed Data for THIS listing (reused, not duplicated).
      stix_observed_data: observed[i] || null,
      is_template: true,
      note: optouts[i].note,
    });
  }

  // The erasure letters (clustered per broker host by takedown-letter.js).
  for (const packet of erasurePackets) {
    await Actor.pushData({
      record_type: 'broker_erasure_request',
      source_module: 'aux:broker-optout',
      case_id: caseId,
      ...packet,
    });
  }

  // The Apify re-check PROPOSALS (reappearance guard) — one per distinct broker.
  for (const proposal of plan.recheck_proposals) {
    await Actor.pushData({
      record_type: 'broker_recheck_proposal',
      source_module: 'aux:broker-optout',
      case_id: caseId,
      ...proposal,
    });
  }

  // Blacklight-style self-exposure summary: what to DO, in the subject's voice.
  await Actor.setValue('BROKER_OPTOUT_SUMMARY', {
    record_type: 'broker_optout_summary',
    source_module: 'aux:broker-optout',
    case_id: caseId,
    scope_type: plan.scope_type,
    subject_label: typeof input.subject_label === 'string' ? input.subject_label : '',
    confirmed_listing_count: plan.confirmed_listing_count,
    erasure_letter_count: plan.erasure_plan.letter_count,
    recheck_proposal_count: plan.recheck_proposals.length,
    skipped: plan.skipped,
    registry_status: plan.registry_status, // honest TEMPLATE banner
    stix_bundle: plan.stix_bundle,           // STIX 2.1 bundle (Observed Data)
    stix_interop_bundle: plan.stix_interop_bundle, // OpenCTI/MISP interop bundle
    generated_at: plan.generated_at,
    disclaimer: plan.disclaimer,
  });

  log.info('Broker opt-out plan built.', {
    confirmed_listings: plan.confirmed_listing_count,
    erasure_letters: plan.erasure_plan.letter_count,
    recheck_proposals: plan.recheck_proposals.length,
    note: 'Nothing scraped, sent, or removed. Plan is a reviewable template.',
  });
});
