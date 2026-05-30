/**
 * shared/aux/broker-registry.js
 *
 * A KNOWN-BROKER REGISTRY, shipped as a clearly-labeled TEMPLATE.
 *
 * ─────────────────────────── WHAT THIS IS (AND IS NOT) ───────────────────────────
 * People-search / data-broker sites (Spokeo, Whitepages, BeenVerified, …) publish
 * aggregated profiles of individuals. A compliant self-protection workflow lets a
 * user remove THEIR OWN listing from such a broker. To do that we need to know,
 * per broker, the PUBLIC opt-out URL + the method the broker documents (web form,
 * email, etc.). That public metadata is what this registry holds.
 *
 * NO FAKE DATA — THE HARD RULE:
 *  - This file contains ZERO scraped listings, ZERO "we found YOU at broker X"
 *    claims, and ZERO fabricated match results. It is a static directory of each
 *    broker's own publicly-documented opt-out CONTACT POINT — the same thing a
 *    privacy guide or the broker's footer links to.
 *  - Every entry is flagged `is_template: true`. The opt-out URLs are the brokers'
 *    real, publicly-advertised removal pages, but operators MUST verify each one
 *    is current before relying on it (brokers move these). `registry_status`
 *    documents this honestly. A real "you are listed here" finding only ever comes
 *    from the user CONFIRMING their own listing (the actor never invents one).
 *
 * RED LINE: a broker opt-out is, by definition, a FIRST-PERSON request ("remove
 * the record about ME"). There is no field, code path, or registry entry that
 * targets another person. The opt-out builder (broker-optout.js) routes every
 * subject through shared/scope.js FIRST and refuses anything that is not the
 * user's own (self) — see that module. This registry is inert data.
 *
 * REFERENCE ARCHITECTURE — Apify Website Content Crawler + RAG Web Browser:
 *  The `recheck` field on each broker tells the re-check pass which PUBLIC URL the
 *  apify/website-content-crawler (page -> clean text) or apify/rag-web-browser
 *  (name -> public search) would re-read to see whether a REMOVED listing has
 *  REAPPEARED. We only ever name the broker's OWN public search/result surface;
 *  ingestion is gated + capped by integrations/ingest/* (two doors).
 *
 * Pure data + tiny pure lookups. No I/O, no network. Safe to require at load.
 */

'use strict';

/**
 * Methods a broker documents for self-removal. Stable strings the opt-out
 * builder switches on. NOTE: "captcha-gated form" is intentionally NOT a method
 * we automate — see broker-optout.js (we draft the request for the human to
 * submit; we never solve a CAPTCHA or bypass a control).
 */
const OPTOUT_METHOD = Object.freeze({
  WEB_FORM: 'web_form',       // a self-service removal web form the user submits
  EMAIL: 'email',             // email a privacy/removal address
  DSAR_PORTAL: 'dsar_portal', // a formal data-subject-access-request portal
});

/**
 * The TEMPLATE registry. Each entry is a broker's publicly-documented opt-out
 * contact point. Fields:
 *  - id           stable slug
 *  - name         broker display name
 *  - optout_url   the broker's OWN public opt-out / removal page (verify before use)
 *  - method       one of OPTOUT_METHOD
 *  - email        removal email IF the documented method is EMAIL (else null)
 *  - jurisdiction_hint  which erasure statute usually applies (drives the letter)
 *  - recheck      { url, via } — the broker's OWN public surface a re-check would
 *                 read to detect REAPPEARANCE; `via` = which Apify ingest actor.
 *  - notes        honest caveats.
 *
 * THESE ARE TEMPLATE ENTRIES. The opt-out URLs are the brokers' real, publicly
 * advertised removal pages as of authoring, but they change; verify each.
 */
const BROKER_REGISTRY = Object.freeze([
  Object.freeze({
    id: 'spokeo',
    name: 'Spokeo',
    optout_url: 'https://www.spokeo.com/optout',
    method: OPTOUT_METHOD.WEB_FORM,
    email: null,
    jurisdiction_hint: 'us',
    recheck: Object.freeze({
      url: 'https://www.spokeo.com/optout',
      via: 'website_content_crawler',
    }),
    notes: 'Self-service removal form; requires confirming the specific listing URL you own.',
  }),
  Object.freeze({
    id: 'whitepages',
    name: 'Whitepages',
    optout_url: 'https://www.whitepages.com/suppression-requests',
    method: OPTOUT_METHOD.WEB_FORM,
    email: null,
    jurisdiction_hint: 'us',
    recheck: Object.freeze({
      url: 'https://www.whitepages.com/suppression-requests',
      via: 'website_content_crawler',
    }),
    notes: 'Suppression-request flow; verify it is still the live path before use.',
  }),
  Object.freeze({
    id: 'beenverified',
    name: 'BeenVerified',
    optout_url: 'https://www.beenverified.com/app/optout/search',
    method: OPTOUT_METHOD.WEB_FORM,
    email: null,
    jurisdiction_hint: 'us',
    recheck: Object.freeze({
      url: 'https://www.beenverified.com/app/optout/search',
      via: 'website_content_crawler',
    }),
    notes: 'You search for your OWN record then request its removal.',
  }),
  Object.freeze({
    id: 'radaris',
    name: 'Radaris',
    optout_url: 'https://radaris.com/control/privacy',
    method: OPTOUT_METHOD.WEB_FORM,
    email: null,
    jurisdiction_hint: 'us',
    recheck: Object.freeze({
      url: 'https://radaris.com/control/privacy',
      via: 'website_content_crawler',
    }),
    notes: 'Privacy-control page; confirm the listing is yours before submitting.',
  }),
  Object.freeze({
    id: 'acxiom',
    name: 'Acxiom (LiveRamp)',
    optout_url: 'https://isapps.acxiom.com/optout/optout.aspx',
    method: OPTOUT_METHOD.DSAR_PORTAL,
    email: null,
    jurisdiction_hint: 'us',
    recheck: Object.freeze({
      url: 'https://isapps.acxiom.com/optout/optout.aspx',
      via: 'rag_web_browser',
    }),
    notes: 'Marketing-data broker; opt-out portal, not a per-listing page.',
  }),
]);

const BY_ID = Object.freeze(
  BROKER_REGISTRY.reduce((acc, b) => {
    acc[b.id] = b;
    return acc;
  }, {}),
);

/** Honest status of this registry — surfaced everywhere it is used. */
const REGISTRY_STATUS = Object.freeze({
  is_template: true,
  contains_listings: false,
  note:
    'TEMPLATE: a directory of brokers\' own public opt-out contact points. It holds ' +
    'NO scraped listings and NO "you were found here" data. Verify each opt-out URL ' +
    'is current before relying on it. A real listing is only ever one the USER confirms.',
});

/** Look up a broker by id, or null. Pure. */
function getBroker(id) {
  if (typeof id !== 'string') return null;
  return BY_ID[id.trim().toLowerCase()] || null;
}

/** All known broker ids (stable order). Pure. */
function knownBrokerIds() {
  return BROKER_REGISTRY.map((b) => b.id);
}

module.exports = {
  OPTOUT_METHOD,
  BROKER_REGISTRY,
  REGISTRY_STATUS,
  getBroker,
  knownBrokerIds,
};
