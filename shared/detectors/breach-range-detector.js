/**
 * shared/detectors/breach-range-detector.js
 *
 * SpiderFoot-style detector MODULE for breach exposure of a SELF-owned
 * credential, using the k-ANONYMITY RANGE model that Have I Been Pwned's
 * Pwned Passwords API popularised (and that SpiderFoot's HIBP modules use):
 *
 *   1. The caller hashes the subject's OWN secret locally (e.g. SHA-1 of a
 *      password the subject is auditing for themselves).
 *   2. Only the FIRST 5 HEX CHARS of the hash (the "range prefix") would ever
 *      leave the machine, returning a bucket of ~hundreds of hash *suffixes*.
 *   3. This module receives that prefix + the returned suffix list and checks,
 *      OFFLINE, whether the remaining suffix is in the bucket.
 *
 * Crucially, the full secret and full hash NEVER leave the process, and THIS
 * module never sees the secret at all — only hashes. That is the whole point of
 * k-anonymity: confirm a breach hit without disclosing the credential. We also
 * gate to self-owned credentials only; there is no path to check someone else's.
 *
 * Refs:
 *   k-anonymity range model — Have I Been Pwned "Pwned Passwords" API.
 *   SpiderFoot HIBP modules + correlation engine — github.com/smicallef/spiderfoot
 *
 * Pure function, NO network. The HTTP fetch of the range bucket is the caller's
 * job (an actor), kept out of here so this stays unit-testable and side-effect
 * free. Safe to require at load.
 */

'use strict';

const crypto = require('crypto');
const { EVENT_TYPES, VISIBILITY, RISK, makeEvent } = require('./event-types.js');

const MODULE = 'breach_range_detector';
const PREFIX_LEN = 5; // HIBP range prefix length

/**
 * Compute the SHA-1 (uppercase hex) of a secret and split it into the
 * k-anonymity {prefix, suffix}. This is the ONLY function that touches the raw
 * secret; the prefix is all a caller may transmit. Returned object lets a caller
 * build the range request WITHOUT ever sending the suffix.
 *
 * @param {string} secret  the subject's OWN credential being audited
 * @returns {{prefix:string, suffix:string, full:string}}
 */
function toRange(secret) {
  if (typeof secret !== 'string' || secret.length === 0) {
    throw new Error('toRange requires a non-empty secret string.');
  }
  const full = crypto.createHash('sha1').update(secret, 'utf8').digest('hex').toUpperCase();
  return {
    prefix: full.slice(0, PREFIX_LEN),
    suffix: full.slice(PREFIX_LEN),
    full, // stays in-process; callers MUST NOT transmit this
  };
}

/**
 * Parse an HIBP-style range response body: lines of "SUFFIX:count".
 * @param {string} body
 * @returns {Map<string, number>} suffix(uppercase) -> breach count
 */
function parseRangeResponse(body) {
  const map = new Map();
  if (typeof body !== 'string') return map;
  for (const line of body.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    const [suffix, countStr] = trimmed.split(':');
    if (!suffix) continue;
    const count = Number.parseInt(countStr, 10);
    map.set(suffix.toUpperCase(), Number.isFinite(count) ? count : 0);
  }
  return map;
}

/**
 * The detector: given a precomputed range {prefix, suffix} for a SELF-owned
 * credential and the suffix→count map returned for that prefix, emit a
 * BREACH_RANGE_HIT event IFF the suffix is present. No secret, no network.
 *
 * @param {object} p
 * @param {string} p.suffix          the hash suffix (uppercase hex)
 * @param {Map|object} p.rangeMap    suffix->count (from parseRangeResponse)
 * @param {string} [p.scope_type]    must be self|public_figure to proceed
 * @param {string} [p.label]         non-secret label for the credential (e.g. "main email pw")
 * @returns {object[]} module_event[] (0 or 1 event)
 */
function detectBreachInRange({ suffix, rangeMap, scope_type = 'self', label = 'self_credential' } = {}) {
  // Dual-use enumeration guard: this capability only makes sense for one's own
  // (or a public figure's publicly-acknowledged) credential audit. Anything else
  // returns nothing here; the canonical gate (shared/scope.js) is the real
  // authority — we simply refuse to emit for non-self/public_figure scopes.
  if (scope_type !== 'self' && scope_type !== 'public_figure') return [];
  if (typeof suffix !== 'string' || !suffix) return [];

  const lookup = rangeMap instanceof Map
    ? rangeMap
    : new Map(Object.entries(rangeMap || {}).map(([k, v]) => [String(k).toUpperCase(), v]));

  const count = lookup.get(suffix.toUpperCase());
  if (count === undefined) return []; // honest: not in the breached set we were given

  // Risk scales with how many times the credential appears in breaches.
  let risk = RISK.MEDIUM;
  if (count >= 100000) risk = RISK.HIGH;
  else if (count < 10) risk = RISK.LOW;

  return [makeEvent({
    event_type: EVENT_TYPES.BREACH_RANGE_HIT,
    source_module: MODULE,
    // We surface the count and a non-secret label only — never the credential.
    data: { label, breach_count: count },
    confidence: 0.99, // exact suffix match in a k-anon bucket is high-confidence
    visibility: VISIBILITY.PRIVATE, // a breached secret isn't "indexed", but it is exposed
    risk,
    source_url: null,
    meta: { method: 'k_anonymity_range', prefix_len: PREFIX_LEN, breach_count: count },
  })];
}

module.exports = { MODULE, PREFIX_LEN, toRange, parseRangeResponse, detectBreachInRange };
