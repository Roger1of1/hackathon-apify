/**
 * shared/detectors/secret-leak-detector.js
 *
 * SpiderFoot-style detector MODULE for SECRETS the SELF (or public_figure)
 * subject has *accidentally published* on a page / repo / paste they control:
 * cloud access keys, OAuth / bot tokens, private-key PEM blocks, and .env-style
 * credential assignments. The whole point is "did I leak my own key somewhere
 * public so I can rotate it" — a self-audit, not third-party surveillance.
 *
 * Patterns + the verify/precision philosophy are borrowed from secret-scanning
 * tools (TruffleHog, GitHub secret scanning, gitleaks): a curated set of
 * high-signal "detectors", each keyed to a vendor's documented credential shape,
 * preferring precision over recall so a false leak claim is rare. We additionally
 * apply a Shannon-entropy gate to generic assignments so ordinary config words
 * ("password=changeme") don't masquerade as real secrets.
 *
 * SpiderFoot patterns borrowed:
 *  - A named module (`MODULE`) consuming one captured artifact (page text) and
 *    producing typed module_events with provenance + honest confidence.
 *  - Confidence reflects pattern specificity + entropy, not certainty about a
 *    human. A vendor-shaped key is high confidence; a generic assignment is only
 *    flagged when its value is high-entropy, and at lower confidence.
 *
 * RED-LINE NOTE: this emits SECRET_LEAK_PUBLIC, a security-hygiene exposure of
 * the subject's OWN credential. It never infers identity, romance, gender, or
 * intimacy, and it REDACTS the secret in `data` (keeps only a short fingerprint
 * + vendor) so the finding itself never re-leaks the credential.
 *
 * Pure function, no network, no state. Safe to require at load.
 * Refs:
 *   TruffleHog detectors — github.com/trufflesecurity/trufflehog
 *   GitHub secret scanning patterns — docs.github.com (secret-scanning)
 *   SpiderFoot module/event pattern — github.com/smicallef/spiderfoot
 */

'use strict';

const crypto = require('crypto');
const { EVENT_TYPES, VISIBILITY, RISK, makeEvent } = require('./event-types.js');

const MODULE = 'secret_leak_detector';

/**
 * Curated vendor secret shapes (a small honest seed, clearly NON-exhaustive —
 * NOT fabricated results). Each entry is a real, documented credential format.
 * `re` must be global so we can collect every distinct occurrence.
 */
const VENDOR_SECRETS = Object.freeze([
  {
    vendor: 'AWS Access Key ID',
    kind: 'cloud_key',
    re: /\b(?:AKIA|ASIA|AROA|AIDA)[0-9A-Z]{16}\b/g,
    confidence: 0.95,
    risk: RISK.HIGH,
  },
  {
    vendor: 'GitHub Token',
    kind: 'vcs_token',
    // ghp_/gho_/ghu_/ghs_/ghr_ + 36 base62 chars (GitHub's documented shape).
    re: /\bgh[posur]_[A-Za-z0-9]{36}\b/g,
    confidence: 0.95,
    risk: RISK.HIGH,
  },
  {
    vendor: 'Slack Token',
    kind: 'chat_token',
    re: /\bxox[baprs]-[A-Za-z0-9-]{10,72}\b/g,
    confidence: 0.9,
    risk: RISK.HIGH,
  },
  {
    vendor: 'Google API Key',
    kind: 'api_key',
    re: /\bAIza[0-9A-Za-z_-]{35}\b/g,
    confidence: 0.85,
    risk: RISK.HIGH,
  },
  {
    vendor: 'Stripe Live Secret Key',
    kind: 'payment_key',
    re: /\bsk_live_[0-9A-Za-z]{24,}\b/g,
    confidence: 0.95,
    risk: RISK.HIGH,
  },
  {
    vendor: 'JSON Web Token',
    kind: 'jwt',
    re: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g,
    confidence: 0.6,
    risk: RISK.MEDIUM,
  },
  {
    vendor: 'Private Key Block',
    kind: 'private_key',
    re: /-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----/g,
    confidence: 0.97,
    risk: RISK.HIGH,
  },
]);

// Generic ".env-style" assignment: KEY = "value". We only flag these when the
// value clears the entropy gate, so config noise isn't mistaken for a secret.
const ASSIGNMENT_RE = /\b([A-Za-z][A-Za-z0-9_]{2,40})\s*[:=]\s*["']?([A-Za-z0-9+/_=.-]{16,100})["']?/g;
// The key name must look credential-ish to even consider it.
const SECRETISH_KEY = /(secret|token|api[_-]?key|access[_-]?key|password|passwd|client[_-]?secret|private[_-]?key|auth)/i;
// Common non-secret values to never flag even if they're long.
const ASSIGNMENT_DENYLIST = /^(changeme|password|example|placeholder|your[_-]?(secret|key|token)|xxx+|todo|none|null|true|false|undefined)$/i;

const MIN_ENTROPY_BITS_PER_CHAR = 3.0; // Shannon bits/char; random base64 ~6, words ~3-4

/** Shannon entropy in bits per character of a string. Pure, deterministic. */
function shannonEntropyPerChar(s) {
  if (typeof s !== 'string' || s.length === 0) return 0;
  const counts = Object.create(null);
  for (const ch of s) counts[ch] = (counts[ch] || 0) + 1;
  let bits = 0;
  const n = s.length;
  for (const ch in counts) {
    const p = counts[ch] / n;
    bits -= p * Math.log2(p);
  }
  return bits;
}

/**
 * A short, NON-reversible fingerprint of a secret so a finding can be tracked /
 * de-duplicated without ever echoing the credential. SHA-256, first 12 hex.
 */
function fingerprint(secret) {
  return crypto.createHash('sha256').update(String(secret), 'utf8').digest('hex').slice(0, 12);
}

/** Keep only the first/last 2 chars so a report can point at it, e.g. "AK…7Q". */
function maskedHint(secret) {
  const s = String(secret);
  if (s.length <= 6) return '…';
  return `${s.slice(0, 2)}…${s.slice(-2)}`;
}

function pushSecretEvent(events, { vendor, kind, secret, confidence, risk, url, visibility, via }) {
  events.push(makeEvent({
    event_type: EVENT_TYPES.SECRET_LEAK_PUBLIC,
    source_module: MODULE,
    // REDACTED by construction: never the raw secret, only a fingerprint + hint.
    data: { vendor, kind, fingerprint: fingerprint(secret), hint: maskedHint(secret) },
    confidence,
    visibility,
    risk,
    source_url: url,
    meta: {
      vendor,
      kind,
      via, // 'vendor_pattern' | 'entropy_assignment'
      length: String(secret).length,
      note: 'Self-published credential leak; rotate this secret. Value redacted.',
    },
  }));
}

/**
 * Run the secret-leak module on one captured page artifact.
 *
 * @param {object} page
 * @param {string} page.text   normalized visible/source text already captured
 * @param {string} [page.url]  the public URL it came from
 * @param {string} [page.visibility] VISIBILITY for this surface (default linked)
 * @returns {object[]} module_event[]
 */
function detectSecrets(page = {}) {
  const text = typeof page.text === 'string' ? page.text : '';
  if (!text) return [];

  const url = typeof page.url === 'string' ? page.url : null;
  const visibility = page.visibility || VISIBILITY.LINKED;
  const events = [];
  const seen = new Set(); // dedupe by fingerprint so one secret => one event

  // 1) Vendor-shaped secrets (high precision).
  for (const v of VENDOR_SECRETS) {
    v.re.lastIndex = 0;
    let m;
    while ((m = v.re.exec(text)) !== null) {
      const secret = m[0];
      const fp = fingerprint(secret);
      if (seen.has(fp)) continue;
      seen.add(fp);
      pushSecretEvent(events, {
        vendor: v.vendor, kind: v.kind, secret,
        confidence: v.confidence, risk: v.risk, url, visibility, via: 'vendor_pattern',
      });
    }
  }

  // 2) Generic high-entropy credential assignments (precision via entropy gate).
  ASSIGNMENT_RE.lastIndex = 0;
  let a;
  while ((a = ASSIGNMENT_RE.exec(text)) !== null) {
    const key = a[1];
    const value = a[2];
    if (!SECRETISH_KEY.test(key)) continue;
    if (ASSIGNMENT_DENYLIST.test(value)) continue;
    if (shannonEntropyPerChar(value) < MIN_ENTROPY_BITS_PER_CHAR) continue; // not random enough
    const fp = fingerprint(value);
    if (seen.has(fp)) continue;
    seen.add(fp);
    pushSecretEvent(events, {
      vendor: `generic:${key}`, kind: 'generic_secret', secret: value,
      // lower confidence than a vendor-shaped key; entropy-gated but heuristic.
      confidence: 0.55, risk: RISK.MEDIUM, url, visibility, via: 'entropy_assignment',
    });
  }

  return events;
}

module.exports = {
  MODULE,
  detectSecrets,
  shannonEntropyPerChar,
  fingerprint,
  VENDOR_SECRETS,
  MIN_ENTROPY_BITS_PER_CHAR,
};
