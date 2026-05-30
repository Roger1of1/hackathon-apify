/**
 * integrations/optout/optout-policy.js
 *
 * The DATA-BROKER OPT-OUT workflow: a scope-gated, Apify-driven, pure input-
 * builder that turns the subject's OWN confirmed broker listings into (1) a
 * STIX 2.1 Observed Data record of the exposure, (2) a ready-to-send erasure
 * request, and (3) a proposed Apify Schedule/Webhook RE-CHECK cadence so a
 * listing that REAPPEARS after removal is automatically re-flagged.
 *
 * WHY THIS IS THE COMPLIANT, MARKET-PROVEN PATTERN
 * ─────────────────────────────────────────────────────────────────────────────
 * Removing yourself from people-search / data-broker sites (Spokeo, Whitepages,
 * BeenVerified, …) is the single most-recommended concrete self-protection step
 * in consumer-privacy guidance (EFF, Privacy Rights Clearinghouse, the California
 * Delete Act / DROP registry). It is the LITERAL OPPOSITE of stalking: a broker
 * opt-out is a first-person assertion — "remove the listing about ME" — and is
 * ONLY ever valid for the subject's OWN listing. This module encodes that as a
 * hard refusal: any target that is not the subject's own (scope self, or a
 * consented subject who authorized the removal on their behalf) is dropped before
 * a single request is built.
 *
 * COMPLIANT-BY-CONSTRUCTION
 *  - Door 1: the REAL shared/scope.js gate (Codex owns it; we only READ it).
 *    buildOptOutPlan() calls validateScope() FIRST and refuses for any rejected
 *    subject. A private-individual "remove THEM" / stalking input never reaches
 *    the registry.
 *  - Door 2: SELF-ONLY narrowing. Even an ACCEPTED scope is narrowed here: a
 *    broker opt-out is permitted only for scope=self or scope=consented (a real,
 *    authorized data-subject acting/being acted-for). public_figure / brand /
 *    safety_evidence are refused — you do not "delete" a third party from a
 *    broker, and a public figure's public role is not a self-removal target.
 *  - No fabricated listings: the broker REGISTRY is a clearly-labelled TEMPLATE
 *    of each broker's PUBLIC opt-out URL + method (broker-registry.template.json,
 *    is_template:true). A "listing" only exists when REAL crawler output — a
 *    shared/detectors module_event whose source_url host matches a broker.host —
 *    is passed in. Empty findings in → empty plan out; we never invent a listing.
 *
 * REUSE, DO NOT DUPLICATE
 *  - STIX 2.1 Observed Data: reuses shared/enrich/stix-evidence.js verbatim
 *    (toObservedData/toBundle). We add NO new STIX encoder.
 *  - Erasure request: reuses shared/aux/takedown-letter.js verbatim
 *    (buildTakedownPlan → GDPR Art.17 erasure draft). A broker host is NEVER an
 *    owned host, so takedown-letter routes it to GDPR_ERASURE + CCPA_DELETE +
 *    SEARCH_DEINDEX — exactly the data-subject request a broker opt-out needs.
 *
 * RE-CHECK CADENCE (Closure-Mode-friendly)
 *  - A removed broker listing frequently REAPPEARS (brokers re-acquire data). The
 *    healthy answer is not to refresh the page daily — it is a PACED, automated
 *    re-check. We PROPOSE (never auto-deploy) an Apify Schedule via the existing
 *    integrations/schedules cadence-policy (cron, anti-compulsion floor) plus an
 *    Apify Webhook on the re-check run (integrations/webhooks) that re-flags a
 *    REAPPEARED listing. cron is derived by the real cadence-policy, not hand-typed.
 *
 * REFERENCE ARCHITECTURE #1 — OASIS STIX 2.1 Observed Data + OpenCTI/MISP interop.
 *  A confirmed broker listing is precisely a STIX 2.1 *Observed Data* SDO: "the
 *  raw data was observed at a particular time" — here, the subject's PII observed
 *  public on broker.host at time T, with first_observed/last_observed and a
 *  content hash for tamper-evidence (OASIS STIX 2.1, §Observed Data). Emitting it
 *  as the standard SDO makes the exposure portable into OpenCTI/MISP exactly as
 *  those platforms round-trip bundles (MISP-STIX exports an Observed Data linked
 *  by a Relationship; OpenCTI workers ingest STIX 2.1 bundles —
 *  docs.opencti.io, github.com/OpenCTI-Platform/connectors). The RE-CHECK is the
 *  OpenCTI "last_observed bump": a reappeared listing increments number_observed /
 *  moves last_observed rather than minting a brand-new identity — the same way a
 *  re-sighted observable is updated, not duplicated.
 *
 * REFERENCE ARCHITECTURE #2 — Apify Website Content Crawler + RAG Web Browser.
 *  Detecting and RE-checking a broker listing ingests through the EXISTING
 *  WCC/RAG path (integrations/ingest): apify/website-content-crawler crawls the
 *  subject's OWN broker listing URL → clean text + htmlUrl/screenshotUrl evidence
 *  handles + `error` on a failed page; apify/rag-web-browser can do the dual-use
 *  name-search discovery step (allowed only for scope=self|public_figure). This
 *  module does NOT re-implement crawling — it consumes the module_events that
 *  ingest-policy.js already produces from REAL WCC rows, and proposes the actor +
 *  schedule that re-runs that same WCC ingest on a paced cadence. robots stays
 *  forced ON and pages/depth clamped upstream (anti-evasion / anti-dragnet).
 *
 * Pure + dependency-light at the decision boundary: only fs to load the registry
 * TEMPLATE (injectable for tests). No network. NO claim of being deployed.
 */

'use strict';

const fs = require('fs');
const path = require('path');

// Door 1: the REAL scope gate (read-only use of Coda private person's module).
const { validateScope } = require('../../shared/scope.js');
// Reuse — do NOT duplicate — the STIX encoder and the erasure-letter builder.
const { toObservedData, toBundle } = require('../../shared/enrich/stix-evidence.js');
const { buildTakedownPlan } = require('../../shared/aux/takedown-letter.js');
// Read the typed event vocabulary so we only act on real module_events.
const { isModuleEvent, EVENT_TYPES } = require('../../shared/detectors/event-types.js');
// Re-check cadence is derived by the real Schedules policy (no hand-typed cron).
const { evaluateCadence } = require('../schedules/cadence-policy.js');

const REGISTRY_PATH = path.join(__dirname, 'broker-registry.template.json');

/**
 * The ONLY scopes for which a broker self-removal is valid. A broker opt-out is a
 * first-person "remove the listing about ME" assertion, so it is narrowed BELOW
 * the full ALLOWED_SCOPES set even after the real gate accepts the subject:
 *  - self      : your own listing — the canonical case.
 *  - consented : a real, authorized data subject (the gate already demanded an
 *                authorization_evidence_url), e.g. removing on behalf of a family
 *                member who signed authorization.
 * public_figure / brand / safety_evidence are deliberately EXCLUDED: you cannot
 * "delete" a third party from a broker, and that is the exact line this product
 * refuses to cross.
 */
const SELF_REMOVAL_SCOPES = Object.freeze(['self', 'consented']);

/** Refusal codes so callers/tests can assert the EXACT reason (fail-closed). */
const REFUSAL = Object.freeze({
  SCOPE_REJECTED: 'scope_rejected',
  NOT_SELF_REMOVAL_SCOPE: 'not_a_self_removal_scope',
  NO_LISTINGS: 'no_confirmed_self_listings',
});

/** Event types that can represent a PII exposure ON a broker host. */
const BROKER_LISTING_EVENT_TYPES = Object.freeze(new Set([
  EVENT_TYPES.PII_EMAIL_PUBLIC,
  EVENT_TYPES.PII_PHONE_PUBLIC,
  EVENT_TYPES.PII_POSTAL_PUBLIC,
  EVENT_TYPES.PII_HANDLE_PUBLIC,
]));

/** Load the broker REGISTRY TEMPLATE (only fs touch; injectable for tests). */
function loadBrokerRegistry(registryPath = REGISTRY_PATH) {
  const reg = JSON.parse(fs.readFileSync(registryPath, 'utf8'));
  if (reg && reg.is_template !== true) {
    // Fail closed: the registry MUST be a labelled template, never live data.
    throw new Error('broker registry is not marked is_template:true — refusing to treat it as real listings.');
  }
  return reg;
}

/** Lowercase hostname of a URL, or null. (Local copy; no scope.js write.) */
function hostOf(urlString) {
  try {
    return new URL(urlString).hostname.toLowerCase();
  } catch {
    return null;
  }
}

/** Strip a leading "www." so "www.spokeo.com" matches registry host "spokeo.com". */
function bareHost(host) {
  return typeof host === 'string' ? host.replace(/^www\./, '').toLowerCase() : '';
}

/**
 * Build a host -> broker-template lookup from the registry. Matches on the bare
 * (www-stripped) host so a listing on www.spokeo.com maps to the spokeo entry.
 */
function indexRegistryByHost(registry) {
  const idx = new Map();
  for (const b of (registry && registry.brokers) || []) {
    if (b && typeof b.host === 'string') idx.set(bareHost(b.host), b);
  }
  return idx;
}

/**
 * Confirm which REAL module_events are broker listings. A listing is confirmed
 * ONLY when: it is a valid PII module_event AND its source_url host matches a
 * broker in the TEMPLATE registry. Nothing is invented; a non-broker host or a
 * non-PII event yields no listing.
 *
 * @returns {Array<{ event, broker, host, source_url }>}
 */
function confirmSelfListings(events, registryIndex) {
  const out = [];
  for (const ev of Array.isArray(events) ? events : []) {
    if (!isModuleEvent(ev)) continue;
    if (!BROKER_LISTING_EVENT_TYPES.has(ev.event_type)) continue;
    const host = bareHost(hostOf(ev.source_url));
    if (!host) continue;
    const broker = registryIndex.get(host);
    if (!broker) continue; // not a known broker host → not a confirmed listing
    out.push({ event: ev, broker, host, source_url: ev.source_url });
  }
  return out;
}

/**
 * buildOptOutPlan(input, opts) -> plan | refusal
 *
 * Ordered guard pipeline (Scrapy-style; first objection DROPS and builds nothing):
 *   1. scope gate      — real shared/scope.js must accept the subject (fail-closed)
 *   2. self-removal gate — scope must be self|consented (you only remove YOURSELF)
 *   3. confirm listings — keep only REAL events on a TEMPLATE-registry broker host
 *   4. build           — per confirmed listing emit STIX Observed Data + erasure
 *                        request (REUSED modules) + a per-broker opt-out route, and
 *                        propose a paced Apify re-check Schedule + Webhook.
 *
 * @param {object} input
 *   - scope_type, target_urls/…    (as the rest of the product; gated for real)
 *   - events: module_event[]        REAL detector output (e.g. from ingest-policy)
 *   - subjectName?                  optional, for the erasure letter (never faked)
 *   - cadence?                      re-check cadence (default "closure"); routed
 *                                   through the real cadence-policy floor
 *   - distress_risk_score?          slows the re-check cadence (anti-compulsion)
 *   - subject_token?                short non-identifying token for schedule name
 * @param {object} [opts] { registry, registryPath, now }
 * @returns {object} accepted plan or { allowed:false, refusal, ... }
 */
function buildOptOutPlan(input, opts = {}) {
  const safe = input && typeof input === 'object' ? input : {};
  const now = typeof opts.now === 'string' ? opts.now : new Date().toISOString();

  // ---- Guard 1: the REAL scope gate (read-only) -----------------------------
  const scopeResult = validateScope(safe);
  if (!scopeResult.allowed) {
    return drop(REFUSAL.SCOPE_REJECTED, {
      detail: 'The subject was refused by the scope gate; no opt-out request is built.',
      scope_reasons: scopeResult.reasons,
      violated_red_lines: scopeResult.violated_red_lines,
      alternatives: scopeResult.alternatives,
      scope: safe.scope_type || null,
    });
  }
  const scope = scopeResult.scope_type;

  // ---- Guard 2: SELF-REMOVAL narrowing — you only ever remove YOURSELF -------
  if (!SELF_REMOVAL_SCOPES.includes(scope)) {
    return drop(REFUSAL.NOT_SELF_REMOVAL_SCOPE, {
      detail:
        `A data-broker opt-out is a first-person "remove the listing about ME" ` +
        `request, valid only for scope=${SELF_REMOVAL_SCOPES.join('|')}. ` +
        `scope=${scope} cannot request removal of a listing about someone else.`,
      scope,
    });
  }

  // ---- Guard 3: confirm REAL listings against the TEMPLATE registry ----------
  const registry = opts.registry || loadBrokerRegistry(opts.registryPath);
  const registryIndex = indexRegistryByHost(registry);
  const confirmed = confirmSelfListings(safe.events, registryIndex);

  if (confirmed.length === 0) {
    // NO FAKE DATA: nothing real in → empty plan out. We never invent a listing
    // just to have something to remove.
    return drop(REFUSAL.NO_LISTINGS, {
      detail:
        'No confirmed self-listing: no REAL module_event was found whose host ' +
        'matches a broker in the template registry. (The registry is a list of ' +
        'opt-out ROUTES, not a list of your listings — a listing must come from ' +
        'real crawler output.)',
      scope,
      registry_is_template: true,
    });
  }

  // ---- Guard 4: build (only reached when everything above passed) ------------
  // (a) STIX 2.1 Observed Data per confirmed listing — REUSE stix-evidence.js.
  const listingEvents = confirmed.map((c) => c.event);
  const stixBundle = toBundle(listingEvents, { now });

  // (b) Ready-to-send erasure request — REUSE takedown-letter.js. A broker host
  //     is NEVER passed as an owned host, so the builder routes it to GDPR
  //     erasure + CCPA delete + de-index — exactly a broker opt-out.
  const erasurePlan = buildTakedownPlan({
    events: listingEvents,
    ownedHosts: [], // brokers are third parties by definition — never "owned"
    subjectName: typeof safe.subjectName === 'string' ? safe.subjectName : undefined,
  });

  // (c) Per-listing opt-out record: pair the confirmed listing with the broker's
  //     PUBLIC opt-out route (from the TEMPLATE) and its STIX Observed Data.
  const listings = confirmed.map((c) => ({
    record_type: 'broker_optout_listing',
    is_template: false, // the LISTING is real (from a real event)…
    broker: {
      id: c.broker.id,
      name: c.broker.name,
      host: c.broker.host,
      category: c.broker.category || null,
      // …but the opt-out ROUTE is template data the operator must re-verify.
      optout_url: c.broker.optout_url,
      optout_method: c.broker.optout_method,
      requires: Array.isArray(c.broker.requires) ? c.broker.requires.slice() : [],
      route_is_template: true,
    },
    listing_url: c.source_url,
    event_type: c.event.event_type,
    risk: c.event.risk,
    visibility: c.event.visibility,
    observed_data: toObservedData(c.event, { now }),
  }));

  // (d) PROPOSE (never deploy) a paced Apify re-check Schedule + a Webhook that
  //     re-flags a REAPPEARED listing. cron is derived by the REAL cadence-policy
  //     (anti-compulsion floor); consented is not schedulable, so a re-check
  //     schedule is proposed only for scope=self (others get a manual re-check).
  const recheck = proposeRecheck({ scope, safe, brokers: confirmed });

  return {
    allowed: true,
    record_type: 'broker_optout_plan',
    source_module: 'integrations:optout',
    scope,
    deployed: false,
    generated_at: now,
    listing_count: listings.length,
    listings,
    // The reused artifacts, surfaced at the top level for the report builder.
    stix_bundle: stixBundle,
    erasure_plan: erasurePlan,
    recheck,
    registry_is_template: true,
    note:
      'Opt-out plan built from REAL listings only. STIX Observed Data reused from ' +
      'shared/enrich/stix-evidence.js; erasure request reused from ' +
      'shared/aux/takedown-letter.js. Opt-out routes are TEMPLATE data — re-verify ' +
      'each before sending. NOT deployed; nothing was submitted or removed.',
  };
}

/**
 * Propose the paced Apify re-check: an Apify Schedule (cron from cadence-policy)
 * that re-runs the SAME WCC ingest over the confirmed broker listing URLs, plus a
 * Webhook that re-flags a REAPPEARED listing (last_observed bump, STIX-style). We
 * never auto-deploy — this is the body an operator WOULD submit.
 *
 * scope=consented is NOT schedulable (cadence-policy restricts auto re-audit to
 * self|public_figure), so consented opt-outs get a MANUAL re-check recommendation
 * instead of a cron — fail-closed, never silently widened.
 */
function proposeRecheck({ scope, safe, brokers }) {
  const listingUrls = Array.from(new Set(brokers.map((b) => b.source_url).filter(Boolean))).sort();
  const cadence = typeof safe.cadence === 'string' && safe.cadence ? safe.cadence : 'closure';

  const cadenceDecision = evaluateCadence({
    scope_type: scope,
    cadence,
    distress_risk_score: safe.distress_risk_score,
    anchor: safe.anchor || {},
  });

  const base = {
    purpose:
      'Re-check the SAME broker listing URLs on a paced cadence so a listing that ' +
      'REAPPEARS after removal is automatically re-flagged (last_observed bump). ' +
      'Closure-Mode-friendly: one paced sweep replaces compulsive manual checking.',
    ingests_via: {
      // Cite Reference Architecture #2: re-check ingests through the existing path.
      actor: 'apify/website-content-crawler',
      path: 'integrations/ingest (buildIngestPlan → WCC; robots forced on, pages/depth clamped)',
      rag_discovery: 'apify/rag-web-browser (name-search discovery, self|public_figure only)',
    },
    listing_urls: listingUrls,
    webhook: {
      // Cite the existing webhooks integration for the reappearance alert.
      path: 'integrations/webhooks (register-webhooks.js + output-health receiver)',
      eventTypes: ['ACTOR.RUN.SUCCEEDED'],
      on_success:
        'Compare new STIX Observed Data for each listing_url against the prior run. ' +
        'A listing whose host reappears → re-flag (number_observed++ / last_observed ' +
        'bump), surfaced to the user as "this listing came back".',
      deployed: false,
    },
    deployed: false,
  };

  if (!cadenceDecision.allowed) {
    // scope=consented (or an unknown cadence) → no cron; recommend manual re-check.
    return Object.assign(base, {
      schedule: {
        schedulable: false,
        reasons: cadenceDecision.reasons,
        recommendation:
          'This scope is not auto-schedulable (anti-compulsion / dual-use floor). ' +
          'Re-run the opt-out re-check MANUALLY (e.g. monthly) and re-confirm removal.',
      },
    });
  }

  return Object.assign(base, {
    schedule: {
      // Cite the schedules integration; cron is policy-derived, not hand-typed.
      schedulable: true,
      path: 'integrations/schedules (cadence-policy.evaluateCadence → cron)',
      cadence,
      cron: cadenceDecision.cron,
      effective_floor_minutes: cadenceDecision.effectiveFloorMinutes,
      reasons: cadenceDecision.reasons,
      action: { type: 'RUN_ACTOR_TASK', actorTaskId: '<MIRRORTRACE_OPTOUT_RECHECK_TASK_ID>' },
      deployed: false,
    },
  });
}

/** Internal: shape a refusal value (never throws on a bad request). */
function drop(refusal, extra) {
  return Object.assign({ allowed: false, refusal }, extra);
}

module.exports = {
  SELF_REMOVAL_SCOPES,
  REFUSAL,
  BROKER_LISTING_EVENT_TYPES,
  loadBrokerRegistry,
  indexRegistryByHost,
  confirmSelfListings,
  buildOptOutPlan,
  proposeRecheck,
  bareHost,
  hostOf,
};
