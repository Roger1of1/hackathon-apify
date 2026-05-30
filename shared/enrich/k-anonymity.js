/**
 * shared/enrich/k-anonymity.js
 *
 * A tiny, general k-anonymity helper used to keep any "is my X exposed?" lookup
 * privacy-preserving — the same model HIBP's range API uses and SpiderFoot's
 * breach modules rely on. The idea: to check whether a sensitive value is in
 * some set, you reveal only a short PREFIX of its hash, receive a bucket of
 * candidates sharing that prefix, and finish the comparison locally. The bucket
 * must contain at least `k` candidates, or the query was too identifying.
 *
 * This module never performs the network fetch and never stores secrets — it
 * only computes prefixes and evaluates locally returned buckets. Pure + testable.
 *
 * Ref: k-anonymity range query — Have I Been Pwned Pwned Passwords API.
 */

'use strict';

const crypto = require('crypto');

const DEFAULT_PREFIX_LEN = 5;
const DEFAULT_K = 100; // require buckets of at least this many to consider the query anonymous

/**
 * Split a value's hash into {prefix, suffix} for a range query.
 * @param {string} value
 * @param {object} [opts] {algo='sha1', prefixLen=5, upper=true}
 */
function rangeOf(value, opts = {}) {
  if (typeof value !== 'string' || value.length === 0) {
    throw new Error('rangeOf requires a non-empty string.');
  }
  const algo = opts.algo || 'sha1';
  const prefixLen = Number.isInteger(opts.prefixLen) ? opts.prefixLen : DEFAULT_PREFIX_LEN;
  let digest = crypto.createHash(algo).update(value, 'utf8').digest('hex');
  if (opts.upper !== false) digest = digest.toUpperCase();
  return { prefix: digest.slice(0, prefixLen), suffix: digest.slice(prefixLen), full: digest };
}

/**
 * Decide whether a returned bucket is large enough to have protected the query.
 * @param {Iterable|number} bucket  the returned candidates (or its size)
 * @param {number} [k]
 * @returns {{ anonymous: boolean, size: number, k: number }}
 */
function isAnonymousBucket(bucket, k = DEFAULT_K) {
  let size = 0;
  if (typeof bucket === 'number') size = bucket;
  else if (bucket instanceof Map || bucket instanceof Set) size = bucket.size;
  else if (Array.isArray(bucket)) size = bucket.length;
  else if (bucket && typeof bucket === 'object') size = Object.keys(bucket).length;
  return { anonymous: size >= k, size, k };
}

/**
 * Local membership check: is `suffix` present in the returned bucket? The bucket
 * is the only thing that crossed the network; the suffix stayed local.
 * @param {string} suffix
 * @param {Map|Set|object|string[]} bucket
 * @returns {boolean}
 */
function suffixInBucket(suffix, bucket) {
  if (typeof suffix !== 'string') return false;
  const s = suffix.toUpperCase();
  if (bucket instanceof Map) return bucket.has(s);
  if (bucket instanceof Set) return bucket.has(s);
  if (Array.isArray(bucket)) return bucket.some((x) => String(x).toUpperCase() === s);
  if (bucket && typeof bucket === 'object') {
    return Object.keys(bucket).some((x) => x.toUpperCase() === s);
  }
  return false;
}

module.exports = {
  DEFAULT_PREFIX_LEN,
  DEFAULT_K,
  rangeOf,
  isAnonymousBucket,
  suffixInBucket,
};
