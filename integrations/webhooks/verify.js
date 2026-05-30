/**
 * integrations/webhooks/verify.js
 *
 * Authenticate that an incoming webhook request really came from Apify, before
 * we act on it. Two independent, additive checks (use either or both):
 *
 *  1) Secret token in the URL path — Apify's documented, simplest method:
 *     register the webhook target as
 *       https://your-host/apify-webhook/<SECRET>
 *     and only accept requests whose <SECRET> matches. (Per Apify docs:
 *     "include a secret token in the webhook URL to ensure that only Apify can
 *     invoke it." — https://docs.apify.com/platform/integrations/webhooks/actions)
 *
 *  2) HMAC of the raw body — defense in depth. We compute
 *     HMAC-SHA256(rawBody, sharedSecret) and compare, in constant time, against
 *     a signature header we ask Apify to send via the webhook "headers" template
 *     (e.g. `X-MirrorTrace-Signature: {{ ... }}` is not natively HMAC'd by Apify,
 *     so this path is for proxies/relays that DO add an HMAC, or for a future
 *     signing relay). The verifier is written so it works the moment such a
 *     header is present and is simply skipped when it is not configured.
 *
 * IMPORTANT (and a documented footgun): the HMAC MUST be computed over the RAW
 * request body bytes, before any JSON parse/re-serialize. Middleware that mutates
 * the body silently breaks signatures. The receiver in receiver.js therefore
 * captures the raw body and passes it here untouched.
 *
 * Pure + only Node built-ins (crypto). No network, no external deps.
 */

'use strict';

const crypto = require('crypto');

/**
 * Constant-time string compare that never throws on length mismatch.
 * @param {string} a
 * @param {string} b
 * @returns {boolean}
 */
function safeEqual(a, b) {
  const ba = Buffer.from(String(a == null ? '' : a), 'utf8');
  const bb = Buffer.from(String(b == null ? '' : b), 'utf8');
  if (ba.length !== bb.length) {
    // Still run a comparison to avoid leaking length via early-return timing.
    crypto.timingSafeEqual(ba, ba);
    return false;
  }
  return crypto.timingSafeEqual(ba, bb);
}

/**
 * Verify the URL secret token.
 * @param {string} provided - token taken from the request path/query.
 * @param {string} expected - the configured secret (from env).
 * @returns {boolean} true if a non-empty expected secret matches provided.
 */
function verifyUrlSecret(provided, expected) {
  if (!expected) return false; // not configured → cannot pass on this method
  return safeEqual(provided, expected);
}

/**
 * Verify an HMAC-SHA256 signature over the raw body.
 * @param {Buffer|string} rawBody - the EXACT bytes received.
 * @param {string} signatureHeader - hex (optionally `sha256=`-prefixed) signature.
 * @param {string} secret - shared HMAC secret (from env).
 * @returns {boolean} true if configured and the signature matches.
 */
function verifyHmac(rawBody, signatureHeader, secret) {
  if (!secret || !signatureHeader) return false;
  const provided = String(signatureHeader).replace(/^sha256=/i, '').trim();
  const expected = crypto
    .createHmac('sha256', secret)
    .update(rawBody == null ? Buffer.alloc(0) : rawBody)
    .digest('hex');
  return safeEqual(provided, expected);
}

/**
 * High-level decision used by the receiver. A request is authentic if EITHER
 * configured method passes. If NEITHER method is configured (no secrets in env),
 * we fail closed and say so — we never accept an unauthenticated webhook by
 * default.
 *
 * @param {object} p
 * @param {string} [p.urlSecretProvided]
 * @param {string} [p.urlSecretExpected]
 * @param {Buffer|string} [p.rawBody]
 * @param {string} [p.signatureHeader]
 * @param {string} [p.hmacSecret]
 * @returns {{ authentic:boolean, method:string|null, reason:string }}
 */
function authenticate(p = {}) {
  const hasUrlMethod = Boolean(p.urlSecretExpected);
  const hasHmacMethod = Boolean(p.hmacSecret);

  if (!hasUrlMethod && !hasHmacMethod) {
    return {
      authentic: false,
      method: null,
      reason:
        'No webhook secret configured (set APIFY_WEBHOOK_SECRET and/or APIFY_WEBHOOK_HMAC_SECRET). Failing closed.',
    };
  }

  if (hasUrlMethod && verifyUrlSecret(p.urlSecretProvided, p.urlSecretExpected)) {
    return { authentic: true, method: 'url_secret', reason: 'URL secret token matched.' };
  }
  if (hasHmacMethod && verifyHmac(p.rawBody, p.signatureHeader, p.hmacSecret)) {
    return { authentic: true, method: 'hmac', reason: 'HMAC-SHA256 of raw body matched.' };
  }

  return {
    authentic: false,
    method: null,
    reason: 'Provided secret/signature did not match any configured method.',
  };
}

module.exports = { safeEqual, verifyUrlSecret, verifyHmac, authenticate };
