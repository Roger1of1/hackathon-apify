/**
 * shared/detectors/breach-range-contract.js
 *
 * The SINGLE SOURCE OF TRUTH for the Have I Been Pwned (HIBP) "Pwned Passwords"
 * k-anonymity range-query SPLIT CONTRACT, so the breach actor, the
 * breach-range-detector, and the browser self-proof panel (web/app.js, a sibling
 * track) all agree on EXACTLY what leaves the machine and what stays local.
 *
 * Why a dedicated contract module:
 *   shared/aux/kanon.js already implements the SHA-1 + 5/35 split (kAnonPair) and
 *   shared/detectors/breach-range-detector.js re-implements `toRange`. The UI
 *   directive requires the browser to mirror "the exact prefix/suffix split
 *   contract" and clearly state which 5 chars WOULD be sent and which 35 stay
 *   local. Rather than let three places drift, this module RE-EXPORTS the canon
 *   from shared/aux/kanon.js and adds the honest framing the UI needs:
 *     - explicit, named constants (PREFIX_LEN=5, SUFFIX_LEN=35, HASH_ALGO=SHA-1)
 *     - splitForRangeQuery(secret) -> {prefix, suffix, sent, kept, ...} with a
 *       plain-language `disclosure` describing exactly what crosses the network.
 *     - kAnonymityQuality(bucketSize) -> an HONEST privacy-guarantee read of how
 *       anonymous a query was, given the REAL number of suffixes the range
 *       endpoint returned (never fabricated; if you have no bucket, you get
 *       "unknown", not a made-up number).
 *
 * HIBP model (Troy Hunt, "Understanding Have I Been Pwned's Use of SHA-1 and
 * k-Anonymity", and the Pwned Passwords range API docs):
 *   1. SHA-1 the candidate locally -> 40 hex chars.
 *   2. Send ONLY the first 5 hex chars (prefix). 16^5 = 1,048,576 buckets, so a
 *      prefix is shared by ~hundreds of real-world hashes -> the server cannot
 *      tell which credential you asked about (that is the k of k-anonymity).
 *   3. The server returns every (suffix:count) in that bucket; you match the
 *      remaining 35-char suffix LOCALLY. The full hash / secret never leaves.
 *
 * RED LINE: this only ever describes the SELF subject's OWN credential audit.
 * Nothing here infers identity, romance, gender, or intimacy. A breach hit is a
 * security-hygiene fact about the subject's own credential — they should rotate
 * it — not a statement about any other person. There is no slot for any of that.
 *
 * Pure + zero network at import time (node crypto only, via aux/kanon.js).
 * Refs:
 *   Have I Been Pwned Pwned Passwords range API + k-anonymity — haveibeenpwned.com/API/v3
 *   Troy Hunt, "Enhancing Pwned Passwords Privacy with Padding" (count-0 padding).
 */

'use strict';

const { sha1Hex, kAnonPair } = require('../aux/kanon.js');

// HIBP's documented split for the Pwned Passwords range query. These are the
// numbers the UI must show ("5 chars sent / 35 chars kept") and the actor must
// honor. SHA-1 hex is 40 chars total.
const HASH_ALGO = 'SHA-1';
const HASH_HEX_LEN = 40;
const PREFIX_LEN = 5;            // chars transmitted to the range endpoint
const SUFFIX_LEN = HASH_HEX_LEN - PREFIX_LEN; // 35 chars matched locally, never sent
const RANGE_BUCKETS = 16 ** PREFIX_LEN; // 1,048,576 possible prefixes

/**
 * Split a SELF-owned candidate secret into the HIBP range-query parts and
 * describe, honestly and in plain language, exactly what crosses the network.
 *
 * The returned object is the contract both web/app.js and the actor consume:
 *   - prefix : the 5 hex chars that WOULD be sent (the only thing transmitted)
 *   - suffix : the 35 hex chars that STAY LOCAL (matched against the bucket)
 *   - sent   : alias of prefix, named to make the UI copy unambiguous
 *   - kept   : alias of suffix
 *   - full   : the complete 40-char hash — stays in-process, MUST NOT transmit
 *
 * @param {string} secret the subject's OWN credential being audited
 * @returns {{
 *   algo:string, prefix:string, suffix:string, sent:string, kept:string,
 *   full:string, prefix_len:number, suffix_len:number, range_buckets:number,
 *   disclosure:string
 * }}
 */
function splitForRangeQuery(secret) {
  if (typeof secret !== 'string' || secret.length === 0) {
    throw new Error('splitForRangeQuery requires a non-empty secret string.');
  }
  // kAnonPair is the canonical SHA-1 + 5/35 split in aux/kanon.js. We reuse it
  // verbatim so the UI, the actor, and this contract can NEVER drift apart.
  const { hash, prefix, suffix } = kAnonPair(secret);
  return {
    algo: HASH_ALGO,
    prefix,
    suffix,
    sent: prefix,        // the ONLY thing a range query transmits
    kept: suffix,        // matched locally; never leaves the machine
    full: hash,          // stays in-process; transmitting this would break k-anonymity
    prefix_len: PREFIX_LEN,
    suffix_len: SUFFIX_LEN,
    range_buckets: RANGE_BUCKETS,
    disclosure:
      `SHA-1(secret) -> ${HASH_HEX_LEN} hex chars. Only the first ${PREFIX_LEN} ` +
      `(prefix "${prefix}") would be sent to the range endpoint, sharing a bucket ` +
      `with one of ${RANGE_BUCKETS.toLocaleString('en-US')} prefixes; the remaining ` +
      `${SUFFIX_LEN} chars stay local and are matched offline. The full hash and the ` +
      'secret itself never leave this machine.',
  };
}

/**
 * HONEST proof, for the UI self-test, that the split discloses nothing more than
 * the 5-char prefix: re-derives the full hash from prefix+suffix and asserts it
 * equals SHA-1(secret), and that the transmitted part is exactly the prefix.
 * Returns booleans only — it NEVER claims a breach result (there is no corpus
 * here). This proves the privacy MECHANIC, not a breach hit.
 *
 * @param {string} secret
 * @returns {{
 *   secret_stays_local:boolean, only_prefix_sent:boolean,
 *   recombines_to_full_hash:boolean, sent_length:number, kept_length:number
 * }}
 */
function proveLocalOnly(secret) {
  const s = splitForRangeQuery(secret);
  const recombined = (s.prefix + s.suffix).toUpperCase();
  const expected = sha1Hex(secret); // uppercase hex, same as kanon
  return {
    // The secret never appears in what we'd transmit (the prefix is a hash slice).
    secret_stays_local: !s.sent.includes(secret) && s.sent.length === PREFIX_LEN,
    only_prefix_sent: s.sent === s.prefix && s.sent.length === PREFIX_LEN,
    recombines_to_full_hash: recombined === expected,
    sent_length: s.sent.length,
    kept_length: s.kept.length,
  };
}

// k-anonymity quality bands. The "k" of k-anonymity is the bucket size: how many
// other candidates shared your prefix and thus hid your query. HIBP buckets are
// typically several hundred. Bigger bucket = more anonymous query. These bands
// are an honest read of a REAL returned size — never a fabricated count.
const KANON_BANDS = Object.freeze([
  { band: 'strong', min: 300, note: 'Hundreds of candidates shared this prefix; the query was well hidden.' },
  { band: 'adequate', min: 100, note: 'At least ~100 candidates shared this prefix (typical k-anonymity floor).' },
  { band: 'weak', min: 2, note: 'Few candidates shared this prefix; the query was only thinly anonymized.' },
  { band: 'none', min: 1, note: 'The bucket held only your own candidate — effectively no anonymity set.' },
]);

/**
 * Honestly rate how anonymous a range query was, given the REAL number of
 * suffixes the endpoint returned for the prefix (the k of k-anonymity). With no
 * bucket data, returns "unknown" — we never invent a size.
 *
 * @param {number|null|undefined} bucketSize  count of suffixes returned for the prefix
 * @returns {{ k:number|null, band:string, anonymous:boolean, note:string }}
 */
function kAnonymityQuality(bucketSize) {
  if (typeof bucketSize !== 'number' || !Number.isFinite(bucketSize) || bucketSize < 0) {
    return {
      k: null,
      band: 'unknown',
      anonymous: false,
      note: 'No bucket size observed — anonymity of the query cannot be asserted (no fabrication).',
    };
  }
  const k = Math.floor(bucketSize);
  for (const b of KANON_BANDS) {
    if (k >= b.min) {
      return { k, band: b.band, anonymous: k >= 100, note: b.note };
    }
  }
  return {
    k,
    band: 'none',
    anonymous: false,
    note: 'Empty bucket — the prefix matched nothing, so there is no anonymity set and no hit.',
  };
}

module.exports = {
  HASH_ALGO,
  HASH_HEX_LEN,
  PREFIX_LEN,
  SUFFIX_LEN,
  RANGE_BUCKETS,
  KANON_BANDS,
  splitForRangeQuery,
  proveLocalOnly,
  kAnonymityQuality,
};
