/**
 * shared/detectors/finding-validator.js
 *
 * FALSE-POSITIVE SUPPRESSION for detector module_events. The raw detectors
 * (pii-detector, secret-leak-detector, …) deliberately favour RECALL and emit
 * every regex hit; this module is the PRECISION pass that runs AFTER them and
 * marks honest false positives so the report does not waste the user's attention
 * on noise. Clarity is the product's #1 deliverable, and a contact page full of
 * "noreply@example.com (MEDIUM RISK)" rows actively destroys it.
 *
 * WHY THIS IS A SEPARATE MODULE (consolidate, don't sprawl):
 *  - It adds NO new event type and NO new actor. It only ANNOTATES existing
 *    module_events with a `_validation` verdict and an honest reason. The
 *    downstream confidence/severity/grade layers read that verdict; nothing here
 *    is fabricated and nothing is silently deleted (suppressed findings are
 *    *kept and labelled*, never invented or hidden — the user can still inspect
 *    them). NO FAKE DATA: a verdict is only ever "this matched a documented
 *    reserved/example/test pattern", never "we decided this is fake".
 *
 * REFERENCE PATTERNS APPLIED
 * ─────────────────────────────────────────────────────────────────────────────
 *  1) IANA / IETF reserved-namespace allowlists, the same way secret scanners
 *     (TruffleHog "DetectorVerificationOverlap", gitleaks allowlists) and email
 *     validators suppress documentation artifacts:
 *       - RFC 2606 / RFC 6761 reserved DNS names: example.com/.net/.org,
 *         *.example, *.test, *.invalid, *.localhost  → never a real address.
 *       - RFC 5321 §4.5.1 mandated mailbox "postmaster", plus the de-facto
 *         no-reply family (noreply@, no-reply@, donotreply@, mailer-daemon@).
 *       - well-known disposable / sink domains (mailinator, example, test).
 *     These are the SAME suppression lists real OSINT/secret tools ship; we cite
 *     the RFCs rather than inventing our own notion of "fake".
 *  2) Mozilla Observatory / SecurityHeaders "scored rubric of weighted modifiers"
 *     mechanic (baseline → deductions per failed/suspicious check, banded
 *     output). Observatory starts every site at 100 and subtracts a documented,
 *     severity-weighted penalty for each problem; we mirror that at the
 *     PER-FINDING TRUST layer (finding-confidence.js) — this validator produces
 *     the typed "demerits" that confidence engine consumes.
 *     Ref: github.com/mozilla/http-observatory  (scanner/grader/grade.py)
 *
 * Pure functions, no network, no mutation of inputs, no state. Safe to require.
 * Refs: RFC 2606, RFC 6761, RFC 5321; mozilla/http-observatory.
 */

'use strict';

const { isModuleEvent, EVENT_TYPES } = require('./event-types.js');

/**
 * RFC 2606 + RFC 6761 reserved domains / TLDs. An address or URL on any of these
 * is documentation/example/test by definition and cannot be a live exposure.
 * Stored lower-case; matched against the registrable suffix of the host.
 */
const RESERVED_DNS = Object.freeze({
  // RFC 6761 special-use TLDs that resolve to nothing routable.
  tlds: Object.freeze(['test', 'example', 'invalid', 'localhost']),
  // RFC 2606 second-level example domains.
  domains: Object.freeze(['example.com', 'example.net', 'example.org', 'example.edu']),
});

/**
 * Local-parts that are role/automation mailboxes, not a person's exposed address.
 * "postmaster" is RFC 5321 §4.5.1 mandated; the no-reply family is universal.
 * These are LOW-VALUE for a self-footprint audit: finding "noreply@mysite.com"
 * tells the user nothing actionable about THEIR personal exposure.
 */
const ROLE_LOCALPARTS = Object.freeze(new Set([
  'noreply', 'no-reply', 'donotreply', 'do-not-reply', 'mailer-daemon',
  'postmaster', 'bounce', 'bounces', 'notifications', 'notification',
  'automated', 'auto', 'system', 'daemon',
]));

/**
 * Well-known disposable / sink mail domains. NON-exhaustive honest seed (clearly
 * a small curated list, NOT fabricated coverage), the same shape secret/PII
 * tools ship. A hit means "this is a throwaway, not the subject's real inbox".
 */
const DISPOSABLE_DOMAINS = Object.freeze(new Set([
  'mailinator.com', 'guerrillamail.com', '10minutemail.com', 'trashmail.com',
  'yopmail.com', 'tempmail.com', 'temp-mail.org', 'sharklasers.com',
]));

/** Obvious placeholder phone numbers. Two checks: (a) the NANP fictional range
 *  555-0100..555-0199 (reserved for fiction) matched against the raw string with
 *  optional separators; (b) dummy digit runs (all-repeat or sequential) matched
 *  against the SEPARATOR-STRIPPED digits, since "000-000-0000" only reads as a
 *  dummy once the dashes are removed. Suppress, don't trust as a real exposure. */
const PLACEHOLDER_PHONE_RAW = [
  /\b555[\s.-]?01\d{2}\b/,          // NANP fictional 555-0100..0199
];
const PLACEHOLDER_PHONE_DIGITS = [
  /^0{7,}$/,                        // all zeros
  /^(\d)\1{6,}$/,                   // any single digit repeated 7+ times
  /^0?1234567\d*$/,                 // sequential dummy (optionally leading 0)
];

const VERDICT = Object.freeze({
  VALID: 'valid',            // no suppression signal — trust as-found
  SUPPRESS: 'suppress',      // matched a documented reserved/test/role pattern
  LOW_VALUE: 'low_value',    // real-shaped but not personally actionable (role mailbox)
});

function registrableSuffix(host) {
  const h = String(host || '').toLowerCase().replace(/\.$/, '');
  const parts = h.split('.').filter(Boolean);
  if (parts.length === 0) return '';
  const tld = parts[parts.length - 1];
  if (RESERVED_DNS.tlds.includes(tld)) return tld; // *.test/*.example/...
  return parts.slice(-2).join('.'); // best-effort eTLD+1 (no PSL dep on purpose)
}

function emailParts(value) {
  const s = String(value || '').trim().toLowerCase();
  const at = s.lastIndexOf('@');
  if (at <= 0 || at === s.length - 1) return null;
  return { local: s.slice(0, at), domain: s.slice(at + 1) };
}

/**
 * Classify ONE detector event for false-positive / low-value suppression.
 * Returns a verdict + a human-readable, citation-bearing reason. Never throws.
 *
 * @param {object} event a module_event
 * @returns {{ verdict: string, reason: string|null, rule: string|null }}
 */
function classifyFinding(event) {
  if (!isModuleEvent(event)) {
    return { verdict: VERDICT.VALID, reason: null, rule: null };
  }

  // EMAIL --------------------------------------------------------------------
  if (event.event_type === EVENT_TYPES.PII_EMAIL_PUBLIC) {
    const parts = emailParts(event.data);
    if (!parts) return { verdict: VERDICT.VALID, reason: null, rule: null };
    const suffix = registrableSuffix(parts.domain);

    if (RESERVED_DNS.tlds.includes(suffix) || RESERVED_DNS.domains.includes(suffix)) {
      return {
        verdict: VERDICT.SUPPRESS,
        reason: `Reserved documentation domain (${suffix}) per RFC 2606/6761 — cannot be a real address.`,
        rule: 'rfc2606_reserved_dns',
      };
    }
    if (DISPOSABLE_DOMAINS.has(parts.domain)) {
      return {
        verdict: VERDICT.SUPPRESS,
        reason: `Disposable/sink mail domain (${parts.domain}) — throwaway, not the subject's real inbox.`,
        rule: 'disposable_domain',
      };
    }
    if (ROLE_LOCALPARTS.has(parts.local)) {
      return {
        verdict: VERDICT.LOW_VALUE,
        reason: `Role/automation mailbox ("${parts.local}@", RFC 5321 §4.5.1 / no-reply family) — not a personally-actionable exposure.`,
        rule: 'role_localpart',
      };
    }
    return { verdict: VERDICT.VALID, reason: null, rule: null };
  }

  // PHONE --------------------------------------------------------------------
  if (event.event_type === EVENT_TYPES.PII_PHONE_PUBLIC) {
    const raw = String(event.data || '');
    const digits = raw.replace(/\D/g, '');
    const isPlaceholder = PLACEHOLDER_PHONE_RAW.some((re) => re.test(raw))
      || PLACEHOLDER_PHONE_DIGITS.some((re) => re.test(digits));
    if (isPlaceholder) {
      return {
        verdict: VERDICT.SUPPRESS,
        reason: 'Placeholder/fictional phone (NANP 555-01xx reserved-for-fiction or dummy digit run).',
        rule: 'placeholder_phone',
      };
    }
    return { verdict: VERDICT.VALID, reason: null, rule: null };
  }

  // HANDLE -------------------------------------------------------------------
  // Common false positive: an image/asset token ("@2x", "@media") or a bare
  // email-ish fragment the handle regex grabbed. Suppress non-handle shapes.
  if (event.event_type === EVENT_TYPES.PII_HANDLE_PUBLIC) {
    const h = String((event.meta && event.meta.handle) || event.data || '').replace(/^@/, '');
    if (/^\d+x$/i.test(h) || /^(media|import|charset|font-face|2x|3x)$/i.test(h)) {
      return {
        verdict: VERDICT.SUPPRESS,
        reason: `CSS/asset token "@${h}" — not a social handle.`,
        rule: 'css_asset_token',
      };
    }
    return { verdict: VERDICT.VALID, reason: null, rule: null };
  }

  // Everything else (secrets, trackers, broker hits, breach ranges) is left to
  // its own detector's precision logic — this validator only owns the noisy
  // free-text PII surfaces. Default: trust as-found.
  return { verdict: VERDICT.VALID, reason: null, rule: null };
}

/**
 * Annotate a whole batch with `_validation`. PURE: returns new objects, keeps
 * every event (suppressed ones are LABELLED, not dropped — the inspector can
 * still show them under a "filtered noise" disclosure). Order is preserved.
 *
 * @param {object[]} events
 * @returns {object[]} events with `_validation` added to valid module_events
 */
function validateFindings(events = []) {
  return (events || []).map((ev) => {
    if (!isModuleEvent(ev)) return ev;
    return { ...ev, _validation: classifyFinding(ev) };
  });
}

/**
 * Convenience splitter for the report builder: the trustworthy findings vs. the
 * suppressed/low-value noise, computed honestly from the verdicts above.
 *
 * @param {object[]} events  (may or may not already carry `_validation`)
 * @returns {{ trusted: object[], suppressed: object[], low_value: object[] }}
 */
function partitionByValidation(events = []) {
  const annotated = validateFindings(events);
  const out = { trusted: [], suppressed: [], low_value: [] };
  for (const ev of annotated) {
    const v = ev && ev._validation ? ev._validation.verdict : VERDICT.VALID;
    if (v === VERDICT.SUPPRESS) out.suppressed.push(ev);
    else if (v === VERDICT.LOW_VALUE) out.low_value.push(ev);
    else out.trusted.push(ev);
  }
  return out;
}

module.exports = {
  VERDICT,
  RESERVED_DNS,
  ROLE_LOCALPARTS,
  DISPOSABLE_DOMAINS,
  PLACEHOLDER_PHONE_RAW,
  PLACEHOLDER_PHONE_DIGITS,
  registrableSuffix,
  classifyFinding,
  validateFindings,
  partitionByValidation,
};
