/**
 * shared/aux/kanon.js
 *
 * k-anonymity primitives for the breach-check auxiliary actor.
 *
 * This is the privacy chokepoint for the breach feature. The product audits
 * the SELF subject's own exposure; to do that compliantly we must NEVER send a
 * full secret (password or email) to a third party. We use the same
 * k-anonymity model Have I Been Pwned's "Pwned Passwords" range API uses
 * (Troy Hunt, "Understanding Have I Been Pwned's Use of SHA-1 and k-Anonymity"):
 *
 *   1. Hash the secret locally with SHA-1.
 *   2. Send ONLY the first 5 hex chars (the "prefix") to the range endpoint.
 *      16^5 = 1,048,576 buckets, so a prefix is shared by thousands of hashes
 *      and the server cannot tell which one you asked about.
 *   3. The server returns every suffix (chars 6..40) in that bucket, with a
 *      breach count. We match the SUFFIX locally — the secret never leaves.
 *
 * Pure + dependency-light (node crypto only) so it is trivially unit-tested and
 * reused by the actor and by the SpiderFoot-style correlation engine (it
 * clusters on the email_hash_prefix as a co-occurrence key).
 *
 * RED LINE: nothing here infers identity, romance, gender, or intimacy. A breach
 * hit is a security-hygiene fact about the SELF subject's OWN credentials, not a
 * statement about any other person.
 */

'use strict';

const crypto = require('crypto');

/** Uppercase hex SHA-1 of a UTF-8 string (HIBP corpus is uppercase hex). */
function sha1Hex(input) {
  const s = typeof input === 'string' ? input : String(input ?? '');
  return crypto.createHash('sha1').update(s, 'utf8').digest('hex').toUpperCase();
}

/**
 * Split a secret into the k-anonymity {prefix, suffix} pair.
 * Only `prefix` is ever transmitted; `suffix` is matched locally.
 * @param {string} secret
 * @returns {{ hash: string, prefix: string, suffix: string }}
 */
function kAnonPair(secret) {
  const hash = sha1Hex(secret);
  return { hash, prefix: hash.slice(0, 5), suffix: hash.slice(5) };
}

/**
 * Normalize an email for hashing: trim + lowercase. (Local-part case can matter
 * on some servers, but breach corpora and HIBP normalize to lowercase, so we
 * match that to avoid false negatives.) Returns '' for non-strings.
 */
function normalizeEmail(email) {
  if (typeof email !== 'string') return '';
  return email.trim().toLowerCase();
}

/**
 * A correlation-ready, privacy-preserving fingerprint of an email. We emit the
 * 5-char SHA-1 prefix as a co-occurrence key the correlation engine can cluster
 * on WITHOUT ever storing the plaintext email. This is the email analogue of
 * the HIBP password range model.
 * @param {string} email
 * @returns {{ email_hash_prefix: string|null, email_hash_suffix: string|null }}
 */
function emailHashKey(email) {
  const norm = normalizeEmail(email);
  if (!norm || !norm.includes('@')) {
    return { email_hash_prefix: null, email_hash_suffix: null };
  }
  const { prefix, suffix } = kAnonPair(norm);
  return { email_hash_prefix: prefix, email_hash_suffix: suffix };
}

/**
 * Parse the text body returned by the HIBP Pwned Passwords range endpoint and
 * find the breach count for our suffix. Body lines look like:
 *   "0018A45C4D1DEF81644B54AB7F969B88D65:1"  (suffix:count)
 *
 * Per HIBP's padding guidance ("Enhancing Pwned Passwords Privacy with
 * Padding"), suffixes with count 0 are PADDING and MUST be excluded — we treat
 * a 0 as "not breached" so injected padding can never become a fake hit.
 *
 * @param {string} body  raw range response text
 * @param {string} suffix  uppercase 35-char suffix we are looking for
 * @returns {{ found: boolean, count: number }}
 */
function parseRangeResponse(body, suffix) {
  if (typeof body !== 'string' || typeof suffix !== 'string') {
    return { found: false, count: 0 };
  }
  const want = suffix.toUpperCase();
  const lines = body.split(/\r?\n/);
  for (const line of lines) {
    const idx = line.indexOf(':');
    if (idx === -1) continue;
    const sfx = line.slice(0, idx).trim().toUpperCase();
    if (sfx !== want) continue;
    const count = parseInt(line.slice(idx + 1).trim(), 10);
    if (!Number.isFinite(count) || count <= 0) {
      // count 0 (or unparseable) == padding / not a real hit. NEVER fabricate.
      return { found: false, count: 0 };
    }
    return { found: true, count };
  }
  return { found: false, count: 0 };
}

module.exports = {
  sha1Hex,
  kAnonPair,
  normalizeEmail,
  emailHashKey,
  parseRangeResponse,
};
