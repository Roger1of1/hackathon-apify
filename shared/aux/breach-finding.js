/**
 * shared/aux/breach-finding.js
 *
 * Shapes breach-check results as TYPED MODULE-EVENTS so they slot directly into
 * the Track-A correlation engine (shared/correlation.js, SpiderFoot-inspired).
 *
 * SpiderFoot models every finding as an event with a TYPE that flows between
 * OSINT modules; its correlation engine then links events that share an entity
 * (host / handle / email). We mirror that: each breach event carries
 *   { event_type, source_module, data, confidence }
 * and exposes an `email_hash_prefix` so the correlation pass can cluster a
 * credential exposure with other self-exposure events for the same address —
 * using only the k-anonymity prefix, never the plaintext email.
 *
 * event_type vocabulary (security-hygiene only; NO identity/romance/intimacy):
 *   - PASSWORD_EXPOSED   : a candidate password appears in the Pwned Passwords
 *                          corpus (k-anonymity password range check).
 *   - EMAIL_HASH_PROBE   : a privacy-preserving email fingerprint emitted for
 *                          correlation (no breach claim by itself).
 *   - ACCOUNT_BREACHED   : the SELF subject's own email appears in a named
 *                          breach (only when an authenticated key is configured
 *                          and scope=self; never fabricated).
 */

'use strict';

const SOURCE_MODULE = 'aux:breach-check';

/** Confidence is a coarse 0..100 reliability of the SIGNAL, not of any person. */
function clampConfidence(n) {
  if (!Number.isFinite(n)) return 0;
  return Math.max(0, Math.min(100, Math.round(n)));
}

/**
 * PASSWORD_EXPOSED event. `count` is the real breach occurrence count returned
 * by HIBP; confidence scales with it (a password seen in many breaches is a
 * stronger hygiene signal). The plaintext password is NEVER included.
 */
function makePasswordExposedEvent({ caseId, label, count, prefix }) {
  const c = Number.isFinite(count) ? count : 0;
  return {
    record_type: 'breach_event',
    event_type: 'PASSWORD_EXPOSED',
    source_module: SOURCE_MODULE,
    case_id: caseId || null,
    confidence: clampConfidence(c > 0 ? 70 + Math.min(30, Math.log10(c + 1) * 10) : 0),
    data: {
      // A user-facing label only ("password #2"), so reports can point at it
      // without ever echoing the secret.
      credential_label: label || 'password',
      breach_count: c,
      sha1_prefix: prefix || null,
      advice: 'Stop using this password anywhere; it is in public breach corpora.',
    },
  };
}

/**
 * EMAIL_HASH_PROBE event — a correlation key, not a breach claim. Emits the
 * k-anonymity prefix so the correlation engine can co-occur this with other
 * self-exposure events for the same email without storing the address.
 */
function makeEmailProbeEvent({ caseId, emailHashPrefix }) {
  return {
    record_type: 'breach_event',
    event_type: 'EMAIL_HASH_PROBE',
    source_module: SOURCE_MODULE,
    case_id: caseId || null,
    confidence: 100, // the probe itself is a certain fact; it asserts no breach
    data: {
      email_hash_prefix: emailHashPrefix || null,
      note: 'Privacy-preserving email fingerprint for cross-source correlation.',
    },
    // hoisted so correlation.js can read it as a cluster key without digging.
    email_hash_prefix: emailHashPrefix || null,
  };
}

/**
 * ACCOUNT_BREACHED event for the SELF subject's own email in a named breach.
 * `breachName` and `breachDate` come straight from the authenticated HIBP
 * response — we pass them through, never invent them.
 */
function makeAccountBreachedEvent({ caseId, breachName, breachDate, emailHashPrefix, dataClasses }) {
  return {
    record_type: 'breach_event',
    event_type: 'ACCOUNT_BREACHED',
    source_module: SOURCE_MODULE,
    case_id: caseId || null,
    confidence: 95,
    data: {
      breach_name: breachName || null,
      breach_date: breachDate || null,
      // What kinds of data leaked (e.g. "Email addresses", "Passwords").
      data_classes: Array.isArray(dataClasses) ? dataClasses : [],
      advice: 'Rotate the password and enable MFA on this account.',
    },
    email_hash_prefix: emailHashPrefix || null,
  };
}

module.exports = {
  SOURCE_MODULE,
  clampConfidence,
  makePasswordExposedEvent,
  makeEmailProbeEvent,
  makeAccountBreachedEvent,
};
