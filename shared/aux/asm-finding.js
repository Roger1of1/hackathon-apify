/**
 * shared/aux/asm-finding.js
 *
 * Mapping layer for the AUX "Attack-Surface / Public-Domain Self-Exposure"
 * actor. It turns PUBLIC certificate-transparency and WHOIS facts about a domain
 * the SELF subject OWNS into TYPED module-events from the frozen vocabulary in
 * shared/detectors/event-types.js, so they slot straight into the SpiderFoot-
 * style correlation engine and the report builder alongside every other module.
 *
 * WHY THIS IS COMPLIANT (and what it deliberately is NOT)
 * ─────────────────────────────────────────────────────────────────────────────
 *  - Certificate Transparency (RFC 6962) logs are PUBLIC, append-only, and
 *    deliberately published so anyone can audit certs issued for a domain. A
 *    self-audit over crt.sh is exactly the intended use: "which subdomains of
 *    MY OWN domain are publicly discoverable and might be forgotten staging /
 *    admin / dev hosts I should lock down?" This mirrors the subdomain-discovery
 *    step of attack-surface-management tools (Amass / OWASP, Subfinder), but
 *    reframed as a SELF inventory, not reconnaissance against a third party.
 *  - Public WHOIS / RDAP for a domain the subject registered can leak the
 *    registrant's OWN email / name into the public record (a classic "I forgot
 *    to enable WHOIS privacy" exposure). We surface that as the subject's own
 *    PII_EMAIL_PUBLIC so they can enable privacy protection — we never resolve a
 *    third party's identity, and we apply the same k-anonymity prefixing used
 *    elsewhere so the full registrant email is a CORRELATION KEY, not a stored
 *    value.
 *
 * RED LINES (absent by construction, same as every module here):
 *  - No romance / gender / sexuality / intimacy / relationship inference.
 *  - No live-location. CT/WHOIS carry none; we assert none.
 *  - No third-party identity resolution. The actor is scope-gated to
 *    self / public_figure and the operator must assert ownership of the domain.
 *  - NO FAKE DATA: a host or registrant field is emitted ONLY when it really
 *    appears in the CT / WHOIS response. An empty response => zero events.
 *
 * Pure data + tiny constructors. No I/O, no network. Safe to require at load.
 */

'use strict';

const crypto = require('crypto');
const { makeEvent, EVENT_TYPES, VISIBILITY, RISK } = require('../detectors/event-types.js');

const SOURCE_MODULE = 'aux:attack-surface-scan';

/**
 * Subdomain labels that strongly suggest a non-production / sensitive surface
 * the subject probably did NOT mean to expose. Used ONLY to RAISE the risk band
 * and add advice — never to infer anything about a person. Kept small + literal.
 */
const SENSITIVE_LABELS = Object.freeze([
  'admin', 'dev', 'test', 'staging', 'stage', 'qa', 'uat', 'beta',
  'internal', 'intranet', 'vpn', 'jenkins', 'gitlab', 'jira', 'grafana',
  'kibana', 'phpmyadmin', 'db', 'database', 'backup', 'old', 'legacy',
  'mail', 'webmail', 'smtp', 'ftp', 'ssh', 'remote', 'portal',
]);

/** Uppercase hex SHA-1 — same primitive kanon.js uses, kept local to stay pure. */
function sha1Hex(input) {
  const s = typeof input === 'string' ? input : String(input ?? '');
  return crypto.createHash('sha1').update(s, 'utf8').digest('hex').toUpperCase();
}

/**
 * Normalize a hostname found in a CT entry: trim, lowercase, strip a leading
 * wildcard label and any trailing dot. Returns '' for junk so callers can skip.
 */
function normalizeHost(host) {
  if (typeof host !== 'string') return '';
  let h = host.trim().toLowerCase();
  if (h.startsWith('*.')) h = h.slice(2); // wildcard cert -> the apex it covers
  if (h.endsWith('.')) h = h.slice(0, -1);
  // Reject obviously non-host strings (spaces, no dot, control chars).
  if (!h || /\s/.test(h) || !h.includes('.')) return '';
  return h;
}

/**
 * Is `host` the apex domain itself or a subdomain of it? We only ever emit hosts
 * that belong to the domain the operator asserted ownership of, so a CT log
 * sharing a SAN with someone else's domain can never leak into the inventory.
 */
function belongsToDomain(host, apex) {
  const h = normalizeHost(host);
  const a = normalizeHost(apex);
  if (!h || !a) return false;
  return h === a || h.endsWith(`.${a}`);
}

/** The left-most labels of `host` relative to `apex` (the subdomain part). */
function subdomainLabelsOf(host, apex) {
  const h = normalizeHost(host);
  const a = normalizeHost(apex);
  if (!h || !a || h === a || !h.endsWith(`.${a}`)) return [];
  return h.slice(0, h.length - a.length - 1).split('.');
}

/** True if any label of the subdomain looks like a sensitive/non-prod surface. */
function looksSensitive(host, apex) {
  const labels = subdomainLabelsOf(host, apex);
  return labels.some((l) => SENSITIVE_LABELS.includes(l));
}

/**
 * Build a SELF_PROFILE_URL event for a discovered subdomain of the subject's
 * OWN domain. (SELF_PROFILE_URL = "a surface the subject controls and exposes",
 * which is exactly what a CT-discovered host is.) Risk is raised when the label
 * looks like a forgotten dev/admin surface.
 *
 * @returns {object|null} a module_event, or null if the host is junk / off-domain
 */
function makeSubdomainEvent({ host, apex, firstSeen }) {
  const normalized = normalizeHost(host);
  if (!normalized || !belongsToDomain(normalized, apex)) return null;
  const sensitive = looksSensitive(normalized, apex);
  return makeEvent({
    event_type: EVENT_TYPES.SELF_PROFILE_URL,
    source_module: SOURCE_MODULE,
    data: normalized,
    // CT-derived hosts are high-confidence facts (a cert really was issued).
    confidence: 0.95,
    // Anything in a public CT log is trivially discoverable by anyone.
    visibility: VISIBILITY.INDEXED,
    risk: sensitive ? RISK.MEDIUM : RISK.LOW,
    source_url: `https://${normalized}`,
    meta: {
      apex_domain: normalizeHost(apex),
      discovered_via: 'certificate_transparency',
      sensitive_surface: sensitive,
      first_seen: typeof firstSeen === 'string' ? firstSeen : null,
      advice: sensitive
        ? 'This looks like a non-production surface exposed in public CT logs. Confirm it should be internet-reachable; restrict or decommission if not.'
        : 'Publicly discoverable via certificate-transparency logs. Confirm it is meant to be public.',
    },
  });
}

/**
 * Build a PII_EMAIL_PUBLIC event when the SELF subject's OWN registrant email is
 * exposed in public WHOIS/RDAP for a domain they registered. We emit the
 * k-anonymity SHA-1 PREFIX of the email as a correlation key and a masked
 * display form — never the full plaintext address.
 *
 * @returns {object|null}
 */
function makeWhoisEmailEvent({ apex, registrantEmail }) {
  const a = normalizeHost(apex);
  const email = typeof registrantEmail === 'string' ? registrantEmail.trim().toLowerCase() : '';
  if (!a || !email || !email.includes('@')) return null;
  const prefix = sha1Hex(email).slice(0, 5);
  const at = email.indexOf('@');
  const local = email.slice(0, at);
  const domain = email.slice(at + 1);
  const maskedLocal = local.length <= 2 ? `${local[0] || ''}*` : `${local[0]}***${local[local.length - 1]}`;
  return makeEvent({
    event_type: EVENT_TYPES.PII_EMAIL_PUBLIC,
    source_module: SOURCE_MODULE,
    // Masked display only — full address never stored.
    data: `${maskedLocal}@${domain}`,
    confidence: 0.9,
    visibility: VISIBILITY.INDEXED,
    risk: RISK.MEDIUM,
    source_url: `https://rdap.org/domain/${a}`,
    meta: {
      apex_domain: a,
      discovered_via: 'public_whois_rdap',
      email_hash_prefix: prefix, // correlation key, NOT the address
      advice: 'Your registrant email is public in WHOIS. Enable WHOIS/registrant privacy protection at your registrar.',
    },
    // hoisted so the correlation engine can read the cluster key directly.
  });
}

/**
 * Aggregate EXPOSURE_SUMMARY for the run. Counts are derived ONLY from the real
 * events passed in; an all-clean scan yields zeroes, never an invented surface.
 */
function makeSummaryEvent({ apex, events, scopeType }) {
  const list = Array.isArray(events) ? events : [];
  const subdomains = list.filter((e) => e && e.event_type === EVENT_TYPES.SELF_PROFILE_URL);
  const sensitive = subdomains.filter((e) => e.meta && e.meta.sensitive_surface);
  const whois = list.filter((e) => e && e.event_type === EVENT_TYPES.PII_EMAIL_PUBLIC);
  return makeEvent({
    event_type: EVENT_TYPES.EXPOSURE_SUMMARY,
    source_module: SOURCE_MODULE,
    data: {
      apex_domain: normalizeHost(apex),
      scope_type: typeof scopeType === 'string' ? scopeType : null,
      subdomains_found: subdomains.length,
      sensitive_surfaces: sensitive.length,
      whois_email_exposed: whois.length > 0,
    },
    confidence: 1,
    visibility: VISIBILITY.INDEXED,
    risk: sensitive.length > 0 || whois.length > 0 ? RISK.MEDIUM : RISK.INFO,
    meta: {
      note: 'Self-attack-surface inventory from PUBLIC certificate-transparency + WHOIS only. No third-party identity resolution; no scraping behind logins.',
    },
  });
}

module.exports = {
  SOURCE_MODULE,
  SENSITIVE_LABELS,
  sha1Hex,
  normalizeHost,
  belongsToDomain,
  subdomainLabelsOf,
  looksSensitive,
  makeSubdomainEvent,
  makeWhoisEmailEvent,
  makeSummaryEvent,
};
