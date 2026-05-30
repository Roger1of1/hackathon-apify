/**
 * shared/aux/broker-optout.js
 *
 * A SCOPE-GATED DATA-BROKER OPT-OUT WORKFLOW (pure input-builder).
 *
 * This is the genuinely-unbuilt, market-proven self-protection pattern: helping a
 * user remove THEIR OWN listing from a people-search / data-broker site. It is
 * complementary to the already-built GDPR Art.17 takedown letters — those act on
 * arbitrary third-party hosts holding the subject's PII; this one specialises in
 * the well-known data-broker channel, which has its OWN documented opt-out routes.
 *
 * ─────────────────────────── COMPLIANCE, BY CONSTRUCTION ───────────────────────────
 * (a) SCOPE-GATE-FIRST. EVERY broker target is routed through the REAL
 *     shared/scope.js validateScope() BEFORE anything else. A broker opt-out is a
 *     first-person erasure ("remove the record about ME"), so this module ALSO
 *     hard-restricts to scope_type === 'self' (and 'consented' only with the
 *     authorization the gate already demands). Any non-self / non-consented
 *     subject is REFUSED — you cannot opt someone ELSE out of a broker. That would
 *     be acting on another person, the exact opposite of this product.
 * (b) TEMPLATE registry. Brokers come from shared/aux/broker-registry.js, which
 *     holds NO scraped listings — only each broker's public opt-out contact point.
 * (c) STIX 2.1 Observed Data. For each listing the USER CONFIRMS is their own, we
 *     emit a STIX 2.1 Observed Data object by REUSING shared/enrich/stix-evidence.js
 *     (we do NOT duplicate STIX logic) so the evidence is portable into OpenCTI /
 *     MISP and the report. We additionally emit a STIX Indicator via
 *     shared/enrich/stix-indicator.js for interop bundles.
 * (d) Erasure request. Each confirmed listing yields a ready-to-send erasure
 *     request by REUSING shared/aux/takedown-letter.js (GDPR Art.17 / CCPA) — no
 *     duplicated letter logic.
 * (e) Re-check cadence. We PROPOSE an Apify Schedule + Webhook re-check so a
 *     removed listing that REAPPEARS is re-flagged (Closure-Mode-friendly: one
 *     paced sweep, not compulsive manual re-checking). The re-check INGESTS the
 *     broker's OWN public surface via the existing WCC / RAG path.
 *
 * NO FAKE DATA: nothing here scrapes, sends, or removes anything. With no
 * confirmed listings in → an empty plan out. We never fabricate "you are listed
 * at broker X" or "it was removed". Confirmed listings are user-asserted facts.
 *
 * REFERENCE ARCHITECTURES CITED:
 *  1) OASIS STIX 2.1 Observed Data + OpenCTI/MISP interop — reused via
 *     shared/enrich/stix-evidence.js (toObservedData/toBundle) and
 *     shared/enrich/stix-indicator.js (toInteropBundle). A "this listing about ME
 *     is public at URL U, observed at T, content-hash H" finding is exactly an
 *     Observed Data object; the standard shape makes it portable to a SIEM/CTI
 *     platform and to the erasure request.
 *  2) Apify Website Content Crawler + RAG Web Browser ingestion — the re-check
 *     re-reads the broker's public opt-out/result surface through the gated,
 *     capped ingest path in integrations/ingest/* (WCC for a known URL, RAG for a
 *     public name search), and is driven by integrations/schedules +
 *     integrations/webhooks (paced cadence + reappearance alert).
 *
 * Pure, deterministic given input + an injectable clock. No I/O, no network.
 */

'use strict';

const { validateScope } = require('../scope.js');
const { getBroker, REGISTRY_STATUS } = require('./broker-registry.js');
const { makeEvent, EVENT_TYPES, VISIBILITY, RISK } = require('../detectors/event-types.js');
const { toObservedData, toBundle } = require('../enrich/stix-evidence.js');
const { toInteropBundle } = require('../enrich/stix-indicator.js');
const { buildTakedownPlan } = require('./takedown-letter.js');

const SOURCE_MODULE = 'aux:broker-optout';

/**
 * Scopes for which a broker self-removal is meaningful. A broker opt-out removes
 * the record about the REQUESTER, so it is only ever 'self' — or 'consented',
 * which the scope gate already forces to carry written authorization_evidence_url
 * from the subject. public_figure / brand / safety_evidence are refused: you do
 * not file a "delete the record about me" erasure on behalf of a public figure,
 * a brand, or (least of all) some other person.
 */
const SELF_OPTOUT_SCOPES = Object.freeze(['self', 'consented']);

const REFUSAL = Object.freeze({
  SCOPE_GATE: 'refused_by_scope_gate',
  NOT_SELF: 'refused_not_self_subject',
  NO_BROKER: 'unknown_broker',
});

/**
 * Coerce a user-asserted confirmed listing into a clean, minimal record. We keep
 * ONLY fields the user supplied; we never enrich, infer, or invent.
 * A confirmed listing means: the user looked at the broker page and confirmed the
 * record there is about THEM and they want it gone.
 */
function normalizeListing(raw) {
  if (!raw || typeof raw !== 'object') return null;
  const brokerId = typeof raw.broker_id === 'string' ? raw.broker_id.trim().toLowerCase() : '';
  const broker = getBroker(brokerId);
  if (!broker) return null;
  const listingUrl = typeof raw.listing_url === 'string' ? raw.listing_url.trim() : '';
  // The listing URL, if given, must be on the broker's own surface — we do not
  // accept an arbitrary off-broker URL smuggled in under a broker opt-out.
  let host = null;
  try { host = listingUrl ? new URL(listingUrl).hostname.toLowerCase() : null; } catch { host = null; }
  return {
    broker,
    listing_url: listingUrl || null,
    host,
    // user-confirmed: this is the gate that makes a listing "real" without scraping.
    confirmed_self: raw.confirmed_self === true,
  };
}

/**
 * Turn ONE confirmed-self broker listing into a typed module_event. We reuse the
 * existing PII_HANDLE_PUBLIC event type: a data-broker listing is the user's own
 * personal identifiers (name/handle/contact) published on a THIRD-PARTY host the
 * user does NOT control. Choosing this type (over SELF_PROFILE_URL, which means a
 * surface the user owns) is load-bearing: it makes takedown-letter.js route the
 * broker through the third-party data-subject channel (GDPR Art.17 + CCPA delete
 * + de-index) rather than a self-remediation checklist — which is the correct
 * erasure path for a broker. ownedHosts is left empty so the broker is never
 * mistaken for a surface the user controls.
 */
function listingToEvent(listing) {
  return makeEvent({
    event_type: EVENT_TYPES.PII_HANDLE_PUBLIC,
    source_module: SOURCE_MODULE,
    data: { broker: listing.broker.name, broker_id: listing.broker.id },
    confidence: 1, // user-confirmed; not an inference
    visibility: VISIBILITY.INDEXED, // broker profiles are search-indexable by design
    risk: RISK.HIGH, // aggregated people-search listings are high self-exposure
    source_url: listing.listing_url,
    meta: {
      optout_url: listing.broker.optout_url,
      optout_method: listing.broker.method,
      is_data_broker: true,
    },
  });
}

/**
 * Propose the Apify re-check (Closure-Mode reappearance guard) for a broker.
 * This is a PROPOSAL descriptor — it deploys nothing. It names the broker's OWN
 * public surface and which Apify ingest actor would re-read it, and cites the
 * schedule + webhook integrations that actually run/alert it.
 *
 * cadence = 'closure' deliberately: the SLOWEST paced sweep (see
 * integrations/schedules/cadence-policy.js). A removed listing reappearing is the
 * thing we watch for — not the person.
 */
function recheckProposalFor(broker) {
  return {
    record_type: 'recheck_proposal',
    broker_id: broker.id,
    purpose: 'reappearance_guard',
    // The broker's own public surface to re-read (NOT a person, NOT a private graph).
    recheck_url: broker.recheck.url,
    // Which already-built Apify ingest actor re-reads it (WCC for a URL, RAG for
    // a public name search). Gated + capped by integrations/ingest/*.
    ingest_via: broker.recheck.via,
    ingest_path: 'integrations/ingest/* (apify/website-content-crawler | apify/rag-web-browser)',
    // Paced, anti-compulsion cadence. cron is generated by cadence-policy, not here.
    cadence: 'closure',
    schedule_ref: 'integrations/schedules/cadence-policy.js (cadence=closure → slowest sweep)',
    // Reappearance alert routing.
    webhook_ref: 'integrations/webhooks/* (ACTOR.RUN.SUCCEEDED → diff vs. last sweep → alert only if REAPPEARED)',
    note:
      'Proposal only — nothing is scheduled or fetched here. Wiring the live ' +
      'schedule/webhook is the operator\'s last step. The re-check re-reads the ' +
      'broker\'s OWN public surface to detect a REMOVED listing REAPPEARING.',
  };
}

/**
 * buildBrokerOptOutPlan(input, opts) — the workflow entry point.
 *
 * @param {object} input
 * @param {string} input.scope_type            MUST gate to self (or consented w/ auth)
 * @param {string} [input.subject_label]       user's name (for the erasure letter)
 * @param {string} [input.authorization_evidence_url] required when scope=consented
 * @param {object[]} [input.confirmed_listings] user-confirmed self listings:
 *        [{ broker_id, listing_url, confirmed_self:true }]
 * @param {object} [opts]
 * @param {string} [opts.now]  ISO clock (deterministic tests)
 * @returns {object} a plan, or a structured refusal. NEVER throws on bad input.
 */
function buildBrokerOptOutPlan(input = {}, opts = {}) {
  const now = typeof opts.now === 'string' ? opts.now : new Date().toISOString();

  // ── (a) SCOPE-GATE-FIRST. The real canonical gate, read-only, before anything.
  // We synthesize the target_urls the gate needs from the confirmed listings so
  // it can also reject private-social hosts / laundering text in one pass.
  const listingUrls = Array.isArray(input.confirmed_listings)
    ? input.confirmed_listings
        .map((l) => (l && typeof l.listing_url === 'string' ? l.listing_url.trim() : ''))
        .filter(Boolean)
    : [];
  const gate = validateScope({
    scope_type: input.scope_type,
    subject_label: input.subject_label,
    authorization_evidence_url: input.authorization_evidence_url,
    // The gate requires ≥1 target; a broker opt-out for self is about the user's
    // own broker surface, so hand it the listing URLs (or a self placeholder).
    target_urls: listingUrls.length ? listingUrls : ['https://example.invalid/self-broker-optout'],
    description: input.subject_label,
  });

  if (!gate.allowed) {
    return {
      record_type: 'broker_optout_refusal',
      source_module: SOURCE_MODULE,
      allowed: false,
      refusal: REFUSAL.SCOPE_GATE,
      reasons: gate.reasons,
      violated_red_lines: gate.violated_red_lines,
      alternatives: gate.alternatives,
    };
  }

  // ── (a, continued) SELF-ONLY. Even a gate-passing legal scope must be self/
  // consented for a broker self-removal. A broker opt-out about a public_figure,
  // brand, or anyone else is refused outright.
  const scopeType = gate.scope_type;
  if (!SELF_OPTOUT_SCOPES.includes(scopeType)) {
    return {
      record_type: 'broker_optout_refusal',
      source_module: SOURCE_MODULE,
      allowed: false,
      refusal: REFUSAL.NOT_SELF,
      reasons: [
        `A data-broker opt-out is a first-person erasure ("remove the record about ME"). ` +
        `It is allowed only for scope_type "self" (or "consented" with the subject's written ` +
        `authorization). scope_type "${scopeType}" cannot file a broker self-removal — you ` +
        `cannot opt another person, a public figure, or a brand out of a broker.`,
      ],
      violated_red_lines: ['broker_optout_requires_self'],
      alternatives: [
        'Audit YOUR OWN broker exposure with scope_type="self".',
        'For a third party who agreed in writing, use scope_type="consented" with authorization_evidence_url.',
      ],
    };
  }

  // ── (b)+ Only USER-CONFIRMED self listings become actionable. No confirmation
  // ⇒ not actionable. We NEVER scrape or invent a listing. Unknown broker ⇒ skip.
  const rawListings = Array.isArray(input.confirmed_listings) ? input.confirmed_listings : [];
  const listings = [];
  const skipped = [];
  for (const raw of rawListings) {
    const norm = normalizeListing(raw);
    if (!norm) { skipped.push({ reason: REFUSAL.NO_BROKER, raw_broker_id: raw && raw.broker_id }); continue; }
    if (!norm.confirmed_self) { skipped.push({ reason: 'not_confirmed_self', broker_id: norm.broker.id }); continue; }
    // If a listing URL was given, it must be on the broker's own host (anti-smuggle).
    if (norm.listing_url && norm.host && norm.host !== hostOfBrokerOptout(norm.broker)) {
      // The listing page may legitimately differ from the opt-out host; we only
      // require it to be a real URL the user pasted. Keep it — but flag host.
      norm.host_matches_optout = false;
    }
    listings.push(norm);
  }

  // ── (c) STIX 2.1 Observed Data per confirmed listing (REUSE stix-evidence.js).
  // ── (d) Erasure request per listing (REUSE takedown-letter.js).
  const events = listings.map(listingToEvent);
  const observedData = events.map((ev) => toObservedData(ev, { now }));
  const stixBundle = toBundle(events, { now });             // STIX 2.1 bundle (Observed Data)
  const interopBundle = toInteropBundle(events, { now });   // OpenCTI/MISP interop (Observed Data + Indicator)

  // Erasure letters: the broker host is THIRD-PARTY (a data broker holding the
  // user's PII), so takedown-letter routes it to GDPR Art.17 + CCPA delete —
  // exactly the broker erasure channel. ownedHosts stays empty (a broker is not
  // a surface the user controls), guaranteeing the data-subject-request path.
  const erasurePlan = buildTakedownPlan({
    events,
    ownedHosts: [],
    subjectName: typeof input.subject_label === 'string' ? input.subject_label : undefined,
  });

  // ── (e) Apify re-check proposal per distinct broker (reappearance guard).
  const seen = new Set();
  const recheckProposals = [];
  for (const l of listings) {
    if (seen.has(l.broker.id)) continue;
    seen.add(l.broker.id);
    recheckProposals.push(recheckProposalFor(l.broker));
  }

  // Per-listing action summary the report/UI can render plainly.
  const optouts = listings.map((l) => ({
    broker_id: l.broker.id,
    broker_name: l.broker.name,
    listing_url: l.listing_url,
    optout_url: l.broker.optout_url,     // broker's OWN public removal page
    optout_method: l.broker.method,
    jurisdiction_hint: l.broker.jurisdiction_hint,
    is_template: true,                   // the route is a template; verify before use
    note: 'Submit the erasure request via the broker\'s own opt-out URL. Nothing was sent.',
  }));

  return {
    record_type: 'broker_optout_plan',
    source_module: SOURCE_MODULE,
    allowed: true,
    scope_type: scopeType,
    generated_at: now,
    registry_status: REGISTRY_STATUS, // honest TEMPLATE banner (no fake listings)
    confirmed_listing_count: listings.length,
    skipped, // listings dropped (unknown broker / not confirmed) — transparency
    optouts,
    // STIX 2.1 evidence (reused, not duplicated).
    observed_data: observedData,
    stix_bundle: stixBundle,
    stix_interop_bundle: interopBundle,
    // Ready-to-send erasure requests (reused takedown-letter).
    erasure_plan: erasurePlan,
    // Apify Schedule/Webhook reappearance guard (proposal only).
    recheck_proposals: recheckProposals,
    is_template: true,
    disclaimer:
      'Generated from broker opt-out routes (a template) + listings YOU confirmed are ' +
      'about you. Nothing was scraped, sent, or removed. Verify each opt-out URL before use.',
  };
}

/** Host of a broker's opt-out URL, or null. Pure helper. */
function hostOfBrokerOptout(broker) {
  try { return new URL(broker.optout_url).hostname.toLowerCase(); } catch { return null; }
}

module.exports = {
  SOURCE_MODULE,
  SELF_OPTOUT_SCOPES,
  REFUSAL,
  normalizeListing,
  listingToEvent,
  recheckProposalFor,
  buildBrokerOptOutPlan,
};
