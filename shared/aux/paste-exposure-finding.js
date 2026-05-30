/**
 * shared/aux/paste-exposure-finding.js
 *
 * Finding-shapers for the AUX Public-Paste Self-Exposure scan. They turn a real
 * hit from a PUBLIC paste-aggregator search ("does my OWN email / domain /
 * handle appear in a public paste dump?") into the SAME typed module_events the
 * rest of MirrorTrace emits, so the SpiderFoot-style correlation engine
 * (shared/correlation.js) and the report builder consume them with no special
 * casing.
 *
 * WHY PASTES — and why it is NOT redundant with breach-check / gh-leak-scan:
 *   - breach-check (HIBP) answers "is my credential in a *named breach corpus*?"
 *   - gh-leak-scan answers "did I commit a secret to my *own* GitHub?"
 *   - paste-exposure answers "is my identifier sitting in a *public paste*
 *     (Pastebin & friends) right now?" — a distinct, well-known self-audit
 *     surface. HIBP itself ingests pastes as a separate source ("Pastes")
 *     precisely because they are a different exposure channel from breaches.
 *     (Troy Hunt, "Pwned websites... and pastes": haveibeenpwned.com/Pastes)
 *
 * PRIVACY MODEL (matches the rest of the toolkit):
 *   - For an EMAIL hit we NEVER place the plaintext address in `data`. We carry
 *     only the HIBP k-anonymity SHA-1 prefix (meta.email_hash_prefix) plus a
 *     masked hint ("j***@e***.com"), exactly like breach-check / kanon.js. The
 *     prefix is the correlation key cluster-keys.js reads.
 *   - For a DOMAIN/HANDLE hit the token is the subject's own public identifier,
 *     which is non-secret by nature, so it is carried as a normalized handle.
 *   - The paste BODY is never stored or echoed — only its public URL, a coarse
 *     line-count, and which identifier matched. We do not exfiltrate paste text.
 *
 * RED LINES: no person/romance/gender/intimacy inference, no third-party
 * tracking. A paste hit is a security-hygiene fact about the SELF (or
 * public_figure) subject's OWN published identifier. The actor that feeds this
 * module is scope-gated to self/public_figure only.
 *
 * REFERENCE PATTERNS APPLIED:
 *   - SpiderFoot event model: every finding is a typed makeEvent() module_event
 *     with provenance (source_url) and correlation keys, so it links by shared
 *     surface/identifier — never by person. (github.com/smicallef/spiderfoot)
 *   - HIBP "Pastes" data source + k-anonymity email handling
 *     (haveibeenpwned.com/Pastes; Troy Hunt, SHA-1 + k-Anonymity).
 *
 * Pure + offline. No network, no I/O. Safe to require at load and trivially
 * unit-tested by paste-exposure-finding_selftest.js.
 */

'use strict';

const {
  makeEvent,
  EVENT_TYPES,
  VISIBILITY,
  RISK,
} = require('../detectors/event-types.js');
const { emailHashKey, normalizeEmail } = require('./kanon.js');

const SOURCE_MODULE = 'aux:paste-exposure';

/** The identifier kinds this scan accepts. Each is one the subject OWNS. */
const IDENTIFIER_KINDS = Object.freeze(['email', 'domain', 'handle']);

/** Lower-cased hostname of a URL, or null. Never throws. */
function hostOf(url) {
  if (typeof url !== 'string' || !url) return null;
  try { return new URL(url).hostname.toLowerCase() || null; } catch { return null; }
}

/**
 * Mask an email to a non-reversible HINT for human-facing reports. Keeps the
 * first char of the local-part and of each domain label, e.g.
 *   "jane.doe@example.com" -> "j***@e***.com"
 * Returns '' for anything that is not an email. This is a display hint only; the
 * correlation key is the hash prefix, never this string.
 */
function maskEmail(email) {
  const norm = normalizeEmail(email);
  const at = norm.indexOf('@');
  if (at <= 0 || at === norm.length - 1) return '';
  const local = norm.slice(0, at);
  const domain = norm.slice(at + 1);
  const maskLabel = (s) => (s.length ? `${s[0]}***` : '***');
  const maskedLocal = maskLabel(local);
  const labels = domain.split('.');
  if (labels.length < 2) return `${maskedLocal}@***`;
  const tld = labels[labels.length - 1];
  const head = labels.slice(0, -1).map(maskLabel).join('.');
  return `${maskedLocal}@${head}.${tld}`;
}

/** Normalize a bare handle/username token to a stable comparable form. */
function normalizeHandle(h) {
  if (typeof h !== 'string') return '';
  return h.trim().replace(/^@+/, '').toLowerCase();
}

/** Normalize a domain token: strip scheme/path, lowercase, drop a leading "www.". */
function normalizeDomain(d) {
  if (typeof d !== 'string') return '';
  let v = d.trim().toLowerCase();
  if (!v) return '';
  // Allow callers to pass a full URL or a bare domain.
  if (/^[a-z][a-z0-9+.-]*:\/\//.test(v)) {
    const h = hostOf(v);
    v = h || '';
  }
  v = v.replace(/^www\./, '').replace(/\/.*$/, '');
  return /\.[a-z]{2,}$/.test(v) ? v : '';
}

/**
 * Classify + normalize a single self-identifier the user wants to scan for.
 * Returns { kind, value, query } or null if it is not a usable identifier.
 *  - email  -> never queried in plaintext beyond what the paste index requires;
 *              the finding carries only the hash prefix + masked hint.
 *  - domain -> the apex/registrable domain string.
 *  - handle -> a bare username.
 * `query` is the literal string the actor will look up in the paste index. For
 * an email this is intentionally the full address (paste search engines index
 * full strings); the PRIVACY guarantee is about what we STORE/EMIT, matching how
 * HIBP itself searches pastes by address but returns only metadata.
 */
function classifyIdentifier(raw) {
  if (typeof raw !== 'string') return null;
  const s = raw.trim();
  if (!s) return null;

  if (s.includes('@') && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(s)) {
    const value = normalizeEmail(s);
    return { kind: 'email', value, query: value };
  }
  const dom = normalizeDomain(s);
  if (dom) return { kind: 'domain', value: dom, query: dom };

  const handle = normalizeHandle(s);
  // A handle must look like a username, not random punctuation.
  if (handle && /^[a-z0-9._-]{2,64}$/.test(handle)) {
    return { kind: 'handle', value: handle, query: handle };
  }
  return null;
}

/**
 * Risk band for a paste hit. A leaked email/domain in a public paste is a
 * meaningful self-exposure (often part of a credential dump), so emails are
 * MEDIUM by default; a hit flagged by the caller as appearing alongside
 * password-like lines is HIGH. Handles/domains alone are LOW (they are
 * non-secret public identifiers). This is about the SUBJECT's own hygiene only.
 */
function riskFor(kind, { looksLikeCredentialDump = false } = {}) {
  if (looksLikeCredentialDump) return RISK.HIGH;
  if (kind === 'email') return RISK.MEDIUM;
  return RISK.LOW;
}

function eventTypeFor(kind) {
  if (kind === 'email') return EVENT_TYPES.PII_EMAIL_PUBLIC;
  if (kind === 'handle') return EVENT_TYPES.PII_HANDLE_PUBLIC;
  // a domain hit is a self-owned surface identifier
  return EVENT_TYPES.SELF_PROFILE_URL;
}

/**
 * Build the typed module_event for one REAL paste hit. The caller passes the
 * concrete paste it actually fetched from a public index; this shaper never
 * fabricates a hit and refuses to emit one without a real paste URL.
 *
 * @param {object} p
 * @param {{kind:string,value:string}} p.identifier  classified self-identifier
 * @param {string} p.pasteUrl       PUBLIC url of the paste the match was found in
 * @param {string} [p.pasteId]      source-specific paste id (provenance only)
 * @param {string} [p.source]       paste source name (e.g. "pastebin")
 * @param {number} [p.lineCount]    coarse size signal (NOT the body)
 * @param {string} [p.observedAt]   ISO timestamp the index reported, if any
 * @param {boolean} [p.looksLikeCredentialDump] caller's real signal that the
 *                  paste matched a credential-dump shape (raises risk to HIGH)
 * @returns {object|null} a valid module_event, or null if input is unusable
 */
function makePasteHitEvent({
  identifier,
  pasteUrl,
  pasteId = null,
  source = null,
  lineCount = null,
  observedAt = null,
  looksLikeCredentialDump = false,
} = {}) {
  if (!identifier || typeof identifier !== 'object') return null;
  const { kind, value } = identifier;
  if (!IDENTIFIER_KINDS.includes(kind) || typeof value !== 'string' || !value) return null;
  // NO FAKE DATA: a hit is only real if it points at a real public paste URL.
  if (typeof pasteUrl !== 'string' || !hostOf(pasteUrl)) return null;

  const meta = {
    identifier_kind: kind,
    paste_source: typeof source === 'string' ? source : null,
    paste_id: typeof pasteId === 'string' ? pasteId : null,
    line_count: Number.isFinite(lineCount) ? lineCount : null,
    observed_at: typeof observedAt === 'string' ? observedAt : null,
    looks_like_credential_dump: !!looksLikeCredentialDump,
    advice: kind === 'email'
      ? 'Your email appears in a public paste. Treat any password used with it as compromised: rotate it and enable MFA.'
      : 'Your public identifier appears in a paste. Review the paste and request removal if it contains data you did not intend to publish.',
  };

  // `data` carries NO plaintext email. For email hits we hoist the k-anonymity
  // prefix + a masked hint so cluster-keys.js links it without the address.
  let data;
  if (kind === 'email') {
    const { email_hash_prefix } = emailHashKey(value);
    meta.email_hash_prefix = email_hash_prefix; // correlation key (not the address)
    meta.masked_hint = maskEmail(value);
    data = { kind: 'email', masked_hint: meta.masked_hint, email_hash_prefix };
  } else {
    // domain / handle are non-secret public identifiers; carry the value + handle
    // hoisted into meta so the correlation engine can cluster on it.
    meta.handle = value;
    data = value;
  }

  return makeEvent({
    event_type: eventTypeFor(kind),
    source_module: SOURCE_MODULE,
    data,
    // Confidence is the strength of the MATCH signal, not a claim about a person.
    // An exact identifier match in a public index is high-confidence.
    confidence: 0.9,
    // Pastes are search-engine indexable / trivially discoverable.
    visibility: VISIBILITY.INDEXED,
    risk: riskFor(kind, { looksLikeCredentialDump }),
    source_url: pasteUrl,
    meta,
  });
}

/**
 * Aggregate EXPOSURE_SUMMARY event for the whole paste scan. Counts are REAL
 * tallies the actor accumulated; if nothing was found the summary honestly says
 * zero rather than implying a hit.
 *
 * @param {object} p
 * @param {object} p.counts { identifiers_scanned, pastes_matched, emails, domains, handles }
 * @param {string[]} [p.sources] which public paste sources were queried
 * @returns {object} a valid EXPOSURE_SUMMARY module_event
 */
function makePasteSummaryEvent({ counts = {}, sources = [] } = {}) {
  const safe = (n) => (Number.isFinite(n) ? n : 0);
  const matched = safe(counts.pastes_matched);
  return makeEvent({
    event_type: EVENT_TYPES.EXPOSURE_SUMMARY,
    source_module: SOURCE_MODULE,
    data: {
      identifiers_scanned: safe(counts.identifiers_scanned),
      pastes_matched: matched,
      by_kind: {
        email: safe(counts.emails),
        domain: safe(counts.domains),
        handle: safe(counts.handles),
      },
    },
    confidence: 1, // the tally itself is a certain fact
    visibility: VISIBILITY.INDEXED,
    risk: matched > 0 ? RISK.MEDIUM : RISK.INFO,
    meta: {
      sources: Array.isArray(sources) ? sources.filter((s) => typeof s === 'string') : [],
      note: 'Counts reflect REAL matches from public paste indexes only. No paste body is stored; emails are carried as k-anonymity prefixes, never plaintext.',
    },
  });
}

module.exports = {
  SOURCE_MODULE,
  IDENTIFIER_KINDS,
  hostOf,
  maskEmail,
  normalizeHandle,
  normalizeDomain,
  classifyIdentifier,
  riskFor,
  eventTypeFor,
  makePasteHitEvent,
  makePasteSummaryEvent,
};
