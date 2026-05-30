/**
 * shared/detectors/event-types.js
 *
 * The typed vocabulary every detector module emits, modelled directly on
 * SpiderFoot's event-driven OSINT-module architecture: in SpiderFoot each
 * module receives and produces typed *events* (an event has a type, the module
 * that produced it, the data, and provenance), and the correlation engine later
 * links those events. We mirror that here so that detectors are composable and
 * a downstream correlation pass (shared/correlation.js, owned by another track)
 * can link our events into self-exposure clusters.
 *
 * Ref: SpiderFoot modular, event-driven architecture — "modules only receive
 * events they're interested in" — and the SpiderFoot 4.0 correlation engine.
 * https://github.com/smicallef/spiderfoot  https://deepwiki.com/smicallef/spiderfoot
 *
 * RED LINES baked in here: there is deliberately NO event type for romance,
 * intimacy, gender/sexuality inference, follower/like scraping, or live
 * location. The enum below is the *only* set of things a detector may assert,
 * and it is frozen. Adding such a type would be the violation, so it is absent
 * by construction. Detectors describe what a SELF subject (or a public_figure)
 * is publicly exposing about THEMSELVES — never an inference about a third
 * private party.
 *
 * Pure data + tiny constructors. No I/O, no network, no imports with side
 * effects. Safe to require at module load.
 */

'use strict';

/**
 * Event types a detector may emit. Each maps to a concrete, observable public
 * exposure of the subject's OWN footprint. Names are stable strings so the
 * correlation engine and report builder can switch on them.
 */
const EVENT_TYPES = Object.freeze({
  // PII the subject themselves has published publicly (e.g. an email on their
  // own "contact" page). Detected, never inferred or de-anonymized.
  PII_EMAIL_PUBLIC: 'PII_EMAIL_PUBLIC',
  PII_PHONE_PUBLIC: 'PII_PHONE_PUBLIC',
  PII_POSTAL_PUBLIC: 'PII_POSTAL_PUBLIC',
  PII_HANDLE_PUBLIC: 'PII_HANDLE_PUBLIC',
  PII_GEO_HINT_PUBLIC: 'PII_GEO_HINT_PUBLIC', // self-published coarse location text, NOT live tracking

  // A SECRET the subject accidentally published on a page/repo they control —
  // an API key, access token, private key header, or .env-style assignment. This
  // is a security-hygiene leak about the SELF subject's OWN credential (the
  // subject should rotate it), modelled on secret-scanning tools (TruffleHog /
  // GitHub secret scanning) reframed as a self-audit. NOT a third-party secret.
  SECRET_LEAK_PUBLIC: 'SECRET_LEAK_PUBLIC',

  // Surfaces / accounts the subject controls and exposes.
  SELF_PROFILE_URL: 'SELF_PROFILE_URL',
  SELF_USERNAME: 'SELF_USERNAME',

  // Third-party tracking / leak surfaces present on a page the subject controls
  // (Blacklight-style). These describe what trackers can learn about *visitors
  // to the subject's own site* — a privacy exposure the subject can fix.
  TRACKER_THIRD_PARTY: 'TRACKER_THIRD_PARTY',
  TRACKER_FINGERPRINTING: 'TRACKER_FINGERPRINTING',
  TRACKER_SESSION_RECORDING: 'TRACKER_SESSION_RECORDING',
  TRACKER_KEYLOGGING: 'TRACKER_KEYLOGGING',
  COOKIE_THIRD_PARTY: 'COOKIE_THIRD_PARTY',
  LEAK_REFERRER: 'LEAK_REFERRER', // URL/referrer that leaks subject identity to third parties

  // Breach exposure of a self-owned credential, checked via k-anonymity range
  // (HIBP-style) — we never transmit or store the full secret.
  BREACH_RANGE_HIT: 'BREACH_RANGE_HIT',

  // Aggregate / meta events.
  EXPOSURE_SUMMARY: 'EXPOSURE_SUMMARY',
});

/**
 * Coarse visibility of an exposure — how easily a *third party* could find it.
 * Mirrors Blacklight's framing of "what a site/visitor can trivially observe".
 * Ordered low→high so the inspector panel can sort.
 */
const VISIBILITY = Object.freeze({
  PRIVATE: 'private',         // behind something; shouldn't normally surface
  LINKED: 'linked',           // reachable by following links
  INDEXED: 'indexed',         // search-engine indexable / trivially discoverable
});

const VISIBILITY_RANK = Object.freeze({ private: 1, linked: 2, indexed: 3 });

/**
 * Risk band of an exposure to the SELF subject. This is about the subject's
 * own privacy hygiene, NOT a threat score about another person.
 */
const RISK = Object.freeze({
  INFO: 'info',
  LOW: 'low',
  MEDIUM: 'medium',
  HIGH: 'high',
});

const RISK_RANK = Object.freeze({ info: 0, low: 1, medium: 2, high: 3 });

const VALID_EVENT_TYPES = Object.freeze(new Set(Object.values(EVENT_TYPES)));

/**
 * Construct a typed module event. This is the single shape every detector
 * returns, so the correlation engine downstream can rely on it.
 *
 * @param {object} p
 * @param {string} p.event_type   one of EVENT_TYPES
 * @param {string} p.source_module the detector module name that produced it
 * @param {*}      p.data          the observed value (string/object), as-found
 * @param {number} [p.confidence] 0..1 honesty signal (regex match strength etc.)
 * @param {string} [p.visibility] one of VISIBILITY
 * @param {string} [p.risk]       one of RISK
 * @param {string} [p.source_url] the page/surface the event was observed on
 * @param {object} [p.meta]       extra non-PII context (counts, vendor names…)
 * @returns {object} a frozen-ish module_event record
 */
function makeEvent({
  event_type,
  source_module,
  data,
  confidence = 0.5,
  visibility = VISIBILITY.LINKED,
  risk = RISK.LOW,
  source_url = null,
  meta = {},
}) {
  if (!VALID_EVENT_TYPES.has(event_type)) {
    throw new Error(`Unknown event_type "${event_type}" — not in the frozen EVENT_TYPES enum.`);
  }
  if (typeof source_module !== 'string' || !source_module) {
    throw new Error('makeEvent requires a non-empty source_module.');
  }
  const c = Number(confidence);
  return {
    record_type: 'module_event',
    event_type,
    source_module,
    data: data === undefined ? null : data,
    confidence: Number.isFinite(c) ? Math.max(0, Math.min(1, c)) : 0.5,
    visibility: VISIBILITY_RANK[visibility] ? visibility : VISIBILITY.LINKED,
    risk: RISK_RANK[risk] !== undefined ? risk : RISK.LOW,
    source_url: typeof source_url === 'string' ? source_url : null,
    meta: meta && typeof meta === 'object' ? meta : {},
  };
}

function isModuleEvent(x) {
  return !!x
    && typeof x === 'object'
    && x.record_type === 'module_event'
    && VALID_EVENT_TYPES.has(x.event_type);
}

module.exports = {
  EVENT_TYPES,
  VISIBILITY,
  VISIBILITY_RANK,
  RISK,
  RISK_RANK,
  VALID_EVENT_TYPES,
  makeEvent,
  isModuleEvent,
};
