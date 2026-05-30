/**
 * shared/detectors/broker-listing-detector.js
 *
 * SpiderFoot-style detector MODULE: confirm whether the SELF (or public_figure)
 * subject's OWN aggregated record actually appears on a known data-broker /
 * people-search listing page — the exact "is my profile on Spokeo/Whitepages?"
 * signal a DeleteMe / Aura privacy service scans for, and the precondition for a
 * GDPR Article 17 (Right to Erasure) / CCPA deletion request.
 *
 * ───────────────────────── WHY THIS IS INSIDE THE RED LINES ─────────────────────────
 *  - It NEVER scrapes and NEVER fabricates a listing. It runs ONLY on the PUBLIC
 *    text of a broker page the OPERATOR captured (via the gated ingest doors) and
 *    on identity tokens the SUBJECT supplied about THEMSELVES. If the subject's
 *    tokens are not actually present in that text, it emits NOTHING — there is no
 *    code path that invents a "you were found here" claim. (NO FAKE DATA.)
 *  - It confirms ONLY the subject's own record. The artifact carries the
 *    subject's self-asserted tokens; there is no field, and no code path, that
 *    matches or profiles a third private party. A non-self / non-public_figure
 *    scope short-circuits to zero events, mirroring the dual-use refusal in
 *    username-enum-detector.js — the technique is reachable only through the gate.
 *  - It asserts a security/privacy-hygiene FACT ("your aggregated record is
 *    publicly visible here"), never an inference about gender/romance/intimacy.
 *    The frozen EVENT_TYPES enum has no slot for any of that.
 *
 * REFERENCE ARCHITECTURE #1 — DeleteMe / Aura data-broker opt-out workflow:
 *   Those services run a recurring SCAN across a fixed registry of people-search
 *   brokers, CONFIRM which ones list the subscriber, then file removals and
 *   RE-SCAN for reappearance. This module is the "confirm a listing exists" stage
 *   of that loop. It reuses the EXISTING shared/aux/broker-registry.js (so the
 *   broker's documented opt-out contact point + recheck surface come for free) and
 *   produces an event the EXISTING shared/aux/broker-optout.js planner can turn
 *   into a (self-only, scope-gated) opt-out request. We do NOT re-implement the
 *   planner or the registry — we feed them.
 *
 * REFERENCE ARCHITECTURE #2 — GDPR Article 17 RTBF erasure-request automation:
 *   An Art.17 erasure request must identify the specific controller and the
 *   specific record being erased. This module emits exactly the structured
 *   "matched fields + broker id + jurisdiction hint" payload a downstream
 *   erasure-letter builder (shared/aux/takedown-letter.js) needs to name the
 *   controller and the data at issue — i.e. it produces the *evidence of
 *   processing* that legitimises the request, without storing anything more than
 *   the subject already published or supplied.
 *
 * MATCHING MODEL (honest, precision-first):
 *   A people-search result page for a person typically co-locates several of the
 *   subject's identifiers (name, city, an age band, a partial email/handle). A
 *   single common token (e.g. just a first name, or just a city) is NOT a
 *   confident match and must not trigger an erasure request on its own. So we
 *   require token CORROBORATION: a full-name phrase match plus at least one other
 *   independent identifier, OR a strong combination — and we report the matched
 *   fields and a confidence derived from how many independent identifiers aligned.
 *   This mirrors HIBP/SpiderFoot "more independent sightings ⇒ higher confidence"
 *   and keeps false positives (which would mis-target an erasure request) low.
 *
 * Pure function, no network, no state. Safe to require at load.
 */

'use strict';

const { EVENT_TYPES, VISIBILITY, RISK, makeEvent } = require('./event-types.js');
const { getBroker } = require('../aux/broker-registry.js');

const MODULE = 'broker_listing_detector';

// Scopes under which confirming the subject's OWN broker listing is permitted.
// Same dual-use gate posture as username-enum-detector.js: anything else ⇒ [].
const ALLOWED_SCOPES = Object.freeze(new Set(['self', 'public_figure']));

// Independent identifier kinds we look for. "name" is necessary-but-not-
// sufficient; corroboration from >=1 of the others is what makes a confident hit.
const FIELD = Object.freeze({
  NAME: 'name',
  CITY: 'city',
  STATE: 'state',
  AGE: 'age',
  EMAIL_LOCAL: 'email_local', // local-part of a self-published email (never the full addr stored here)
  HANDLE: 'handle',
  PHONE_LAST4: 'phone_last4', // only last 4 digits — we never store/seek the full number on a broker page
});

/** Normalize page text for tolerant, case-insensitive token search. */
function normalizeText(text) {
  return String(text || '')
    .toLowerCase()
    .replace(/\s+/g, ' ')
    .trim();
}

/** Word-boundary presence test for a phrase, tolerant of internal whitespace. */
function phrasePresent(haystack, phrase) {
  const p = String(phrase || '').toLowerCase().trim();
  if (p.length < 2) return false;
  // Build a regex that allows variable whitespace between words and requires
  // boundaries at the ends so "ann" doesn't match inside "annual".
  const parts = p.split(/\s+/).map((w) => w.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'));
  const re = new RegExp(`(?:^|[^a-z0-9])${parts.join('\\s+')}(?:[^a-z0-9]|$)`, 'i');
  return re.test(haystack);
}

/**
 * Build the set of identity probes from the subject's self-asserted identity.
 * We deliberately accept ALREADY-PUBLIC / subject-supplied fields only. Sensitive
 * full values (full email, full phone) are reduced to a minimal discriminator
 * (local-part, last-4) so we never seek or store more than necessary.
 *
 * @param {object} identity
 * @returns {Array<{field:string, value:string, weight:number}>}
 */
function buildProbes(identity = {}) {
  const probes = [];
  const push = (field, value, weight) => {
    const v = String(value || '').trim();
    if (v) probes.push({ field, value: v, weight });
  };

  // Full name is the anchor (high weight) but never sufficient alone.
  if (identity.full_name) push(FIELD.NAME, identity.full_name, 0.5);
  if (identity.city) push(FIELD.CITY, identity.city, 0.25);
  if (identity.state) push(FIELD.STATE, identity.state, 0.15);
  if (identity.age !== undefined && identity.age !== null && `${identity.age}`.trim()) {
    push(FIELD.AGE, String(identity.age).trim(), 0.15);
  }
  if (identity.email) {
    const local = String(identity.email).split('@')[0] || '';
    if (local.length >= 3) push(FIELD.EMAIL_LOCAL, local, 0.3);
  }
  if (identity.handle) push(FIELD.HANDLE, String(identity.handle).replace(/^@/, ''), 0.3);
  if (identity.phone) {
    const digits = String(identity.phone).replace(/\D/g, '');
    if (digits.length >= 4) push(FIELD.PHONE_LAST4, digits.slice(-4), 0.2);
  }
  return probes;
}

/**
 * Detect the subject's OWN listing on one captured broker page.
 *
 * @param {object} page
 * @param {string} page.broker_id    a known broker id from broker-registry.js
 * @param {string} page.text         PUBLIC text of the broker result page (operator-captured)
 * @param {string} [page.url]        the public broker URL it came from
 * @param {string} page.scope_type   gate-approved scope; only self|public_figure run
 * @param {object} page.identity     subject's self-asserted identity tokens (see buildProbes)
 * @param {string} [page.visibility] VISIBILITY for this surface (default indexed — broker pages
 *                                    are search-indexable by design)
 * @returns {object[]} module_event[]  (empty unless a CORROBORATED self-match is confirmed)
 */
function detectBrokerListing(page = {}) {
  // Dual-use gate: refuse anything that is not the subject's own (or a
  // public_figure's public) record. Zero events, never a exception — same shape
  // as the other gated detectors so the registry can dispatch it uniformly.
  if (!ALLOWED_SCOPES.has(page.scope_type)) return [];

  const broker = getBroker(page.broker_id);
  if (!broker) return []; // unknown broker ⇒ we have no documented opt-out surface; do not guess.

  const text = normalizeText(page.text);
  if (!text) return [];

  const identity = page.identity && typeof page.identity === 'object' ? page.identity : {};
  const probes = buildProbes(identity);
  if (!probes.length) return [];

  // Which probes actually appear in THIS page's public text?
  const matched = [];
  let nameMatched = false;
  let weightSum = 0;
  for (const probe of probes) {
    if (phrasePresent(text, probe.value)) {
      matched.push(probe.field);
      weightSum += probe.weight;
      if (probe.field === FIELD.NAME) nameMatched = true;
    }
  }

  // CORROBORATION RULE (precision-first, to never mis-target an erasure request):
  //  - require the full name to be present (the anchor), AND
  //  - require at least ONE independent corroborating identifier.
  // A lone name, or corroborators without a name, is NOT a confident self-listing.
  const independentCorroborators = matched.filter((f) => f !== FIELD.NAME).length;
  const confirmed = nameMatched && independentCorroborators >= 1;
  if (!confirmed) return [];

  // Confidence from how many independent identifiers aligned (honest: more
  // distinct fields ⇒ higher confidence), capped, never a fabricated certainty.
  const confidence = Math.max(0.55, Math.min(0.97, 0.45 + weightSum));

  return [makeEvent({
    event_type: EVENT_TYPES.BROKER_LISTING_HIT,
    source_module: MODULE,
    // `data` is the broker the record sits on (a public controller), NOT the
    // subject's PII — the matched-field NAMES (not values) go in meta so the
    // erasure builder knows what is exposed without us re-storing the values.
    data: { broker_id: broker.id, broker_name: broker.name },
    confidence,
    // Broker result pages are search-indexable by design ⇒ the most findable band.
    visibility: page.visibility || VISIBILITY.INDEXED,
    // A publicly-aggregated dossier (name + location + more) is a high-value,
    // high-effort-to-clean exposure ⇒ HIGH risk to the subject.
    risk: RISK.HIGH,
    source_url: typeof page.url === 'string' ? page.url : (broker.recheck && broker.recheck.url) || null,
    meta: {
      broker_id: broker.id,
      // Field NAMES only — the discriminator values are NOT echoed back, so the
      // event carries no more PII than necessary to drive an opt-out/erasure.
      matched_fields: matched,
      corroborators: independentCorroborators,
      // Hand-off hooks for the EXISTING planners (we feed, never re-implement):
      //  - broker-optout.js     uses optout_url + method (self-only, scope-gated)
      //  - takedown-letter.js   uses jurisdiction_hint to pick Art.17 vs CCPA text
      optout_url: broker.optout_url,
      optout_method: broker.method,
      jurisdiction_hint: broker.jurisdiction_hint,
      recheck: broker.recheck,
      note:
        'Confirmed against operator-captured PUBLIC broker text + subject-supplied ' +
        'identity tokens. No listing is fabricated; absence of a corroborated match ' +
        'yields no event.',
    },
  })];
}

module.exports = {
  MODULE,
  ALLOWED_SCOPES,
  FIELD,
  buildProbes,
  phrasePresent,
  detectBrokerListing,
};
