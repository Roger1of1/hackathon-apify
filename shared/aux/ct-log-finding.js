/**
 * shared/aux/ct-log-finding.js
 *
 * PURE parsing + grading core for the Certificate-Transparency (CT) Exposure
 * auxiliary actor.
 *
 * WHY THIS EXISTS
 * ─────────────────────────────────────────────────────────────────────────────
 * Every TLS certificate issued for a domain is, by design, published to PUBLIC,
 * append-only Certificate Transparency logs (RFC 6962). Anyone can read them via
 * a public index such as crt.sh. For the SELF subject this is a large, usually
 * IGNORED part of their own public footprint: forgotten staging/dev/admin/VPN
 * hostnames (e.g. `staging.example.com`, `vpn.example.com`, `internal-admin…`)
 * and even wildcard certs leak the existence of internal services to the whole
 * internet, simply because a cert was once issued. That is exactly the Blacklight
 * framing — "what a third party can trivially learn about you from what's already
 * public" — and it is a self-exposure fact the subject can ACT on (decommission
 * the host, rotate/scope the cert, put it behind auth).
 *
 * None of the existing MirrorTrace actors enumerate a subject's OWN published
 * hostnames from CT logs, so this is a genuinely-missing, high-leverage self-audit
 * capability rather than churn. It also feeds the SAME `domain` correlation key as
 * the attack-surface and email-auth actors, so a leaked `admin.example.com` here
 * can cluster with that host's exposure elsewhere.
 *
 * SCOPE / RED LINES (enforced upstream by the actor + shared/scope.js):
 *  - Reads ONLY PUBLIC CT-log data for a registrable domain the SELF subject OWNS,
 *    or a genuine public_figure's public domain. CT logs are public by design
 *    (RFC 6962); there is NO login wall, NO captcha bypass, NO private social
 *    graph, NO person-tracking, NO romance/gender/sexuality/intimacy inference.
 *  - Subdomain ENUMERATION is a dual-use technique, so it is restricted upstream
 *    to scope_type ∈ {self, public_figure} and routed through validateScope; this
 *    PURE file performs no I/O and so cannot, by construction, be pointed at a
 *    private person.
 *  - NO FAKE DATA: this file only ever shapes hostnames that the CT index actually
 *    returned. If the index returns nothing it yields an EMPTY result with an
 *    honest `not_found` status — it never invents a hostname.
 *
 * REFERENCE PATTERNS APPLIED (cited):
 *  - RFC 6962 Certificate Transparency + crt.sh public index: the canonical way
 *    to read a domain's own issued certs. We parse crt.sh's JSON `name_value`
 *    field (newline-separated SANs, may include a leading "*." wildcard).
 *  - SpiderFoot's `sfp_crt` / sfp_sublist3r CT-enumeration model: every result is
 *    a TYPED module-event { record_type, event_type, source_module, domain,
 *    confidence, data } carrying the parent `domain` co-occurrence key, mirroring
 *    shared/aux/email-auth-finding.js so the correlation engine can cluster a
 *    leaked hostname with other self-exposure events for the same domain.
 *  - The Markup "Blacklight" self-exposure inspector framing: output is phrased as
 *    "hostnames YOU have made public + what to do about the risky ones", never as
 *    reconnaissance of a third party.
 *  - OWASP "sensitive subdomain" heuristics + GOV.UK plain-language advice: risky
 *    host labels (staging/dev/admin/vpn/internal/test/git/jenkins/…) are flagged
 *    with a cited, plain-English remediation, not opaque jargon.
 */

'use strict';

const SOURCE_MODULE = 'aux:ct-log-exposure';

/** A finding is a typed module-event. record_type groups them in the dataset. */
const RECORD_TYPE = 'ct_log_finding';

/**
 * Frozen event_type vocabulary for THIS aux module (self-contained, like
 * email-auth-finding.js — we deliberately do NOT mutate the core frozen detector
 * enum, which is another agent's subtree). Exposure-surface only; there is no
 * identity/romance/gender/intimacy event type and there never will be.
 */
const EVENT_TYPES = Object.freeze({
  HOSTNAME: 'CT_HOSTNAME_EXPOSED',   // one published hostname from CT logs
  WILDCARD: 'CT_WILDCARD_EXPOSED',   // a "*." wildcard cert was issued
  RISKY: 'CT_RISKY_HOSTNAME',        // a hostname whose label suggests a sensitive service
  SUMMARY: 'CT_EXPOSURE_SUMMARY',    // roll-up + A–F grade
});

/**
 * Risky subdomain-label heuristics (OWASP "sensitive subdomain" surface). Each
 * key maps to a plain-English reason so the finding is auditable, not opaque.
 * These are LABEL substrings checked against each left-most labels of a host.
 */
const RISKY_LABELS = Object.freeze({
  staging: 'A staging environment is often a near-copy of production with weaker auth.',
  stage: 'A staging environment is often a near-copy of production with weaker auth.',
  dev: 'A dev environment may run debug endpoints or unpatched builds.',
  develop: 'A dev environment may run debug endpoints or unpatched builds.',
  test: 'A test host may expose unhardened or sample data.',
  qa: 'A QA host may expose unhardened or sample data.',
  uat: 'A UAT host may expose pre-release, less-hardened functionality.',
  admin: 'An admin panel is a high-value login target; it should not be publicly discoverable.',
  internal: 'A host labelled "internal" likely was not meant to be reachable from the public internet.',
  intranet: 'An intranet host likely was not meant to be reachable from the public internet.',
  corp: 'A corporate-internal host likely was not meant to be public.',
  vpn: 'A VPN endpoint reveals a remote-access surface worth attacking.',
  git: 'A git host can leak source code and credentials if misconfigured.',
  gitlab: 'A self-hosted GitLab can leak source code and credentials if misconfigured.',
  jenkins: 'A CI server (Jenkins) is a frequent target for code-execution.',
  ci: 'A CI host is a frequent target for code-execution and secret theft.',
  jira: 'An issue tracker can leak internal project and personnel detail.',
  confluence: 'A wiki can leak internal documentation.',
  grafana: 'A monitoring dashboard can leak infrastructure topology.',
  kibana: 'A log dashboard can leak logs and infrastructure topology.',
  phpmyadmin: 'A database admin UI is a high-value login target.',
  db: 'A host labelled "db" may front a database that should be private.',
  database: 'A host labelled "database" may front a database that should be private.',
  backup: 'A backup host may expose archived data.',
  old: 'A host labelled "old" is likely deprecated and unpatched.',
  legacy: 'A legacy host is likely deprecated and unpatched.',
  mail: 'A mail host reveals email infrastructure (pair with the email-auth audit).',
  smtp: 'An SMTP host reveals mail-relay infrastructure.',
  ftp: 'An FTP host often runs a plaintext, frequently-misconfigured protocol.',
  api: 'An API host may expose machine endpoints worth probing for authz gaps.',
});

/** Coarse 0..100 confidence in the SIGNAL (a hostname's publication), never a person. */
function clampConfidence(n) {
  if (!Number.isFinite(n)) return 0;
  return Math.max(0, Math.min(100, Math.round(n)));
}

/**
 * Normalize a registrable domain: trim, lowercase, strip a trailing dot, strip
 * scheme/path/"user@". Returns '' for junk (no dot, bad chars). Mirrors the
 * email-auth normalizer so both actors accept the same pasted forms.
 */
function normalizeDomain(input) {
  if (typeof input !== 'string') return '';
  let d = input.trim().toLowerCase();
  if (!d) return '';
  if (d.includes('@')) d = d.slice(d.lastIndexOf('@') + 1);
  d = d.replace(/^[a-z]+:\/\//, '');
  d = d.split('/')[0].split('?')[0];
  d = d.replace(/^\*\./, ''); // a pasted wildcard collapses to its base
  d = d.replace(/\.$/, '');
  if (!/^[a-z0-9.-]+\.[a-z]{2,}$/.test(d)) return '';
  return d;
}

/**
 * Normalize a single hostname found in a CT entry. Lowercases, trims, strips a
 * trailing dot. Preserves a leading "*." so the caller can detect a wildcard.
 * Returns '' for junk (whitespace, bare labels, illegal chars).
 */
function normalizeHostname(input) {
  if (typeof input !== 'string') return '';
  let h = input.trim().toLowerCase().replace(/\.$/, '');
  if (!h) return '';
  const bare = h.replace(/^\*\./, '');
  // require at least one dot and DNS-legal characters (allow leading * already stripped)
  if (!/^[a-z0-9.-]+\.[a-z0-9-]+$/.test(bare)) return '';
  if (bare.length > 253) return '';
  return h;
}

/** True if `host` (already normalized, may be "*.x") is `domain` or a subdomain of it. */
function isInScope(host, domain) {
  if (!host || !domain) return false;
  const bare = host.replace(/^\*\./, '');
  return bare === domain || bare.endsWith(`.${domain}`);
}

/**
 * Parse the raw array crt.sh returns (each row has a `name_value` field that is a
 * newline-separated list of SANs, possibly with duplicates across rows). Returns
 * a de-duplicated, in-scope, sorted set of hostnames plus a wildcard flag.
 *
 * PURE: it only ever returns hostnames that were actually present in `rows`.
 * Tolerant of crt.sh shape drift: also reads `common_name` when present.
 */
function parseCrtShRows(rows, domain) {
  const set = new Set();
  let sawWildcard = false;
  const safeRows = Array.isArray(rows) ? rows : [];
  for (const row of safeRows) {
    if (!row || typeof row !== 'object') continue;
    const candidates = [];
    if (typeof row.name_value === 'string') {
      for (const part of row.name_value.split(/\r?\n/)) candidates.push(part);
    }
    if (typeof row.common_name === 'string') candidates.push(row.common_name);
    for (const c of candidates) {
      const h = normalizeHostname(c);
      if (!h) continue;
      if (!isInScope(h, domain)) continue; // never leak out-of-scope names
      if (h.startsWith('*.')) sawWildcard = true;
      set.add(h);
    }
  }
  const hostnames = Array.from(set).sort();
  return { hostnames, wildcard: sawWildcard, count: hostnames.length };
}

/**
 * Classify a hostname's left-most labels against the RISKY_LABELS heuristics.
 * Returns { risky:boolean, labels:[{label,reason}] }. The apex domain itself is
 * never "risky" (it is expected to be public).
 */
function classifyHostname(host, domain) {
  const out = { risky: false, labels: [] };
  if (!host) return out;
  const bare = host.replace(/^\*\./, '');
  if (bare === domain) return out; // apex is expected-public
  const sub = bare.endsWith(`.${domain}`) ? bare.slice(0, -(`.${domain}`).length) : bare;
  const labels = sub.split('.').filter(Boolean);
  const seen = new Set();
  for (const label of labels) {
    for (const key of Object.keys(RISKY_LABELS)) {
      if (label === key || label.includes(key)) {
        if (seen.has(key)) continue;
        seen.add(key);
        out.labels.push({ label: key, reason: RISKY_LABELS[key] });
      }
    }
  }
  out.risky = out.labels.length > 0;
  return out;
}

/**
 * Grade overall CT exposure into an A–F band. The grade is about RISK SURFACE,
 * not a value judgement: a handful of expected public hosts is fine (A/B); many
 * risky internal-looking hosts and/or a broad wildcard is worse.
 *
 * Every deduction carries a cited `reason` so the grade is auditable.
 */
function gradeExposure({ count, riskyCount, wildcard }) {
  const deductions = [];
  let score = 100;

  if (count === 0) {
    // No certs found at all — nothing published (or none logged). Honest A with a note.
    return {
      score: 100,
      band: 'A',
      deductions: [{
        code: 'NO_CT_RECORDS',
        weight: 0,
        reason: 'No certificates for this domain were found in the queried CT index. Nothing is published (or the index returned nothing).',
      }],
    };
  }

  if (riskyCount > 0) {
    const w = Math.min(40, 10 + riskyCount * 8);
    score -= w;
    deductions.push({
      code: 'RISKY_HOSTNAMES',
      weight: w,
      reason: `${riskyCount} published hostname(s) carry sensitive labels (admin/staging/vpn/internal/…) that reveal internal services (OWASP sensitive-subdomain surface).`,
    });
  }
  if (wildcard) {
    score -= 10;
    deductions.push({
      code: 'WILDCARD_CERT',
      weight: 10,
      reason: 'A wildcard ("*.") certificate is published. A single leaked wildcard key would cover every subdomain; prefer named certs for sensitive hosts (RFC 6962 exposure).',
    });
  }
  if (count > 50) {
    score -= 10;
    deductions.push({
      code: 'LARGE_SURFACE',
      weight: 10,
      reason: `${count} distinct hostnames are published in CT logs — a large attack surface to keep patched and inventoried.`,
    });
  }

  score = Math.max(0, Math.min(100, score));
  let band = 'A';
  if (score < 50) band = 'F';
  else if (score < 65) band = 'D';
  else if (score < 80) band = 'C';
  else if (score < 92) band = 'B';
  return { score, band, deductions };
}

// ───────────────────────────── typed module-events ─────────────────────────────

function baseEvent(eventType, domain, confidence, status, data) {
  return {
    record_type: RECORD_TYPE,
    event_type: eventType,
    source_module: SOURCE_MODULE,
    domain: domain || null, // correlation co-occurrence key (SpiderFoot model)
    record_status: status,  // 'present' | 'not_found'
    confidence: clampConfidence(confidence),
    data: data || {},
  };
}

function makeHostnameEvent({ domain, host, classification }) {
  const c = classification || classifyHostname(host, domain);
  return baseEvent(EVENT_TYPES.HOSTNAME, domain, 95, 'present', {
    hostname: host,
    is_wildcard: host.startsWith('*.'),
    risky: c.risky,
    risk_labels: c.labels,
    advice: c.risky
      ? 'This hostname names a sensitive service that is now publicly discoverable via CT logs. If it should not be public, put it behind auth/VPN, decommission it, or scope its certificate.'
      : 'This hostname is published in public CT logs. Keep it patched and inventoried.',
  });
}

function makeWildcardEvent({ domain, host }) {
  return baseEvent(EVENT_TYPES.WILDCARD, domain, 90, 'present', {
    hostname: host,
    advice: 'A wildcard certificate covers every subdomain. If its key leaks, all subdomains are impersonable. Prefer named certificates for sensitive hosts (RFC 6962).',
  });
}

function makeRiskyEvent({ domain, host, classification }) {
  const c = classification || classifyHostname(host, domain);
  return baseEvent(EVENT_TYPES.RISKY, domain, 90, 'present', {
    hostname: host,
    risk_labels: c.labels,
    advice: 'A sensitive-looking host should not be publicly discoverable. Decommission it, put it behind auth/VPN, or rename + re-scope its certificate.',
  });
}

/**
 * Roll-up summary event with the A–F grade. NO FAKE DATA: when nothing was
 * found, status is 'not_found' and the summary says so honestly.
 */
function makeSummaryEvent({ domain, subjectLabel, scopeType, parsed, grade }) {
  const count = parsed.count || 0;
  return {
    record_type: 'ct_exposure_summary',
    event_type: EVENT_TYPES.SUMMARY,
    source_module: SOURCE_MODULE,
    domain: domain || null,
    record_status: count > 0 ? 'present' : 'not_found',
    confidence: 100,
    data: {
      subject_label: subjectLabel || '',
      scope_type: scopeType || null,
      hostname_count: count,
      risky_count: Array.isArray(parsed.risky_hostnames) ? parsed.risky_hostnames.length : 0,
      wildcard: Boolean(parsed.wildcard),
      score: grade.score,
      band: grade.band,
      deductions: grade.deductions,
      framing: 'Self-exposure: these are hostnames YOU have published to public CT logs, with fixes for the risky ones — not reconnaissance of anyone.',
    },
    generated_at: new Date().toISOString(),
  };
}

/**
 * Convenience: turn a parsed crt.sh result into the full typed-event set + grade
 * in one pure step (used by the actor and exercised directly by the self-test).
 */
function buildFindings({ domain, subjectLabel, scopeType, parsed }) {
  const events = [];
  const riskyHostnames = [];
  for (const host of parsed.hostnames) {
    const classification = classifyHostname(host, domain);
    events.push(makeHostnameEvent({ domain, host, classification }));
    if (host.startsWith('*.')) {
      events.push(makeWildcardEvent({ domain, host }));
    }
    if (classification.risky) {
      riskyHostnames.push(host);
      events.push(makeRiskyEvent({ domain, host, classification }));
    }
  }
  const grade = gradeExposure({
    count: parsed.count,
    riskyCount: riskyHostnames.length,
    wildcard: parsed.wildcard,
  });
  const summary = makeSummaryEvent({
    domain,
    subjectLabel,
    scopeType,
    parsed: { ...parsed, risky_hostnames: riskyHostnames },
    grade,
  });
  return { events, summary, grade, riskyHostnames };
}

module.exports = {
  SOURCE_MODULE,
  RECORD_TYPE,
  EVENT_TYPES,
  RISKY_LABELS,
  clampConfidence,
  normalizeDomain,
  normalizeHostname,
  isInScope,
  parseCrtShRows,
  classifyHostname,
  gradeExposure,
  makeHostnameEvent,
  makeWildcardEvent,
  makeRiskyEvent,
  makeSummaryEvent,
  buildFindings,
};
