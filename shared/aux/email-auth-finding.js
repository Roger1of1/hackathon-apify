/**
 * shared/aux/email-auth-finding.js
 *
 * PURE parsing + grading core for the Email-Auth Posture auxiliary actor.
 *
 * WHY THIS EXISTS
 * ─────────────────────────────────────────────────────────────────────────────
 * One of the most consequential — and most overlooked — parts of a person's or
 * brand's PUBLIC footprint is whether THEIR OWN domain can be trivially spoofed.
 * If a domain you own publishes no SPF, a weak/absent DMARC, or "+all", anyone
 * can send mail that looks like it came from you. That is a self-exposure fact
 * the audited subject can FIX today — exactly the Blacklight framing of "what a
 * third party can trivially do in your name from what's already public".
 *
 * None of the existing 14 MirrorTrace actors cover email spoofability, so this
 * is a genuinely-missing, high-leverage self-audit capability rather than churn.
 *
 * SCOPE / RED LINES (enforced upstream by the actor + shared/scope.js):
 *  - This reads ONLY PUBLIC DNS records (SPF/DMARC/DKIM/MX/MTA-STS/DNSSEC) for a
 *    domain the SELF subject OWNS, or a genuine public_figure's public domain.
 *    DNS TXT/MX records are public by design; there is no login wall, no private
 *    social graph, no person-tracking, no romance/gender/intimacy inference.
 *  - This file is PURE: it takes already-fetched DNS answers and returns typed
 *    findings. It performs no I/O, so the privacy boundary lives in the actor
 *    (which routes scope_type through validateScope and restricts to
 *    self/public_figure) and is trivially unit-tested here.
 *  - NO FAKE DATA: when a record is absent, we emit a finding with
 *    record_status:'not_found' and (for SPF/DMARC) flag the MISSING-policy risk.
 *    We NEVER fabricate a passing record that the resolver did not return.
 *
 * REFERENCE PATTERNS APPLIED (cited):
 *  - SpiderFoot event-driven OSINT model: every result is a TYPED module-event
 *    { record_type, event_type, source_module, data, confidence } carrying a
 *    `domain` co-occurrence key, mirroring shared/aux/breach-finding.js so the
 *    correlation engine can cluster an email-auth weakness with other
 *    self-exposure events for the same host.
 *  - Internet.nl / Hardenize / NIST SP 800-177 (Trustworthy Email) graded
 *    email-security posture: SPF (RFC 7208), DKIM (RFC 6376), DMARC (RFC 7489),
 *    MTA-STS (RFC 8461), DNSSEC. We grade against those rubrics, citing the RFC
 *    behind each deduction so a finding is auditable, not opaque.
 *  - The Markup "Blacklight" self-exposure inspector framing: output is "what an
 *    attacker could trivially do to YOUR domain", phrased as fixes, never as
 *    surveillance of anyone.
 */

'use strict';

const SOURCE_MODULE = 'aux:email-auth-posture';

/** A finding is a typed module-event. record_type groups them in the dataset. */
const RECORD_TYPE = 'email_auth_finding';

/**
 * Frozen event_type vocabulary for THIS aux module (self-contained, like
 * breach-finding.js — we deliberately do NOT mutate the core frozen detector
 * enum, which is another agent's subtree). Security-posture only; there is no
 * identity/romance/gender/intimacy event type and there never will be.
 */
const EVENT_TYPES = Object.freeze({
  SPF: 'EMAIL_SPF_POSTURE',
  DMARC: 'EMAIL_DMARC_POSTURE',
  DKIM: 'EMAIL_DKIM_POSTURE',
  MX: 'EMAIL_MX_POSTURE',
  MTA_STS: 'EMAIL_MTA_STS_POSTURE',
  DNSSEC: 'EMAIL_DNSSEC_POSTURE',
  SUMMARY: 'EMAIL_AUTH_SUMMARY',
});

/** Coarse 0..100 confidence in the SIGNAL (a record's presence/shape), never a person. */
function clampConfidence(n) {
  if (!Number.isFinite(n)) return 0;
  return Math.max(0, Math.min(100, Math.round(n)));
}

/** Normalize a domain: trim, lowercase, strip a trailing dot, strip scheme/path. */
function normalizeDomain(input) {
  if (typeof input !== 'string') return '';
  let d = input.trim().toLowerCase();
  if (!d) return '';
  // tolerate a pasted URL or "user@domain"
  if (d.includes('@')) d = d.slice(d.lastIndexOf('@') + 1);
  d = d.replace(/^[a-z]+:\/\//, '');
  d = d.split('/')[0].split('?')[0];
  d = d.replace(/\.$/, '');
  // basic shape check: at least one dot, label chars only
  if (!/^[a-z0-9.-]+\.[a-z]{2,}$/.test(d)) return '';
  return d;
}

/**
 * DNS TXT answers from DoH (application/dns-json) arrive as quoted, possibly
 * chunked strings. Join chunks and strip the surrounding quotes RFC 1035-style.
 * Accepts either an array of raw answer-data strings or already-clean strings.
 */
function cleanTxt(raw) {
  if (typeof raw !== 'string') return '';
  // DoH JSON puts each <character-string> in its own quotes; long TXT records
  // are split into multiple quoted chunks that must be concatenated.
  const chunks = raw.match(/"((?:[^"\\]|\\.)*)"/g);
  if (chunks) {
    return chunks
      .map((c) => c.slice(1, -1).replace(/\\(.)/g, '$1'))
      .join('');
  }
  return raw.trim();
}

/**
 * Parse an SPF record (RFC 7208). Returns a structured posture:
 *   { present, raw, all_qualifier, lookups_hint, issues:[] }
 * all_qualifier: one of '-all'(fail), '~all'(softfail), '?all'(neutral),
 *                '+all'(pass=ANYONE, dangerous), or null (no 'all').
 */
function parseSpf(txtRecords) {
  const records = (Array.isArray(txtRecords) ? txtRecords : [])
    .map(cleanTxt)
    .filter((t) => /^v=spf1\b/i.test(t));

  if (records.length === 0) {
    return {
      present: false,
      raw: null,
      all_qualifier: null,
      issues: ['no_spf'],
    };
  }
  // RFC 7208 §3.2: multiple SPF records is itself a misconfiguration (permerror).
  const issues = [];
  if (records.length > 1) issues.push('multiple_spf_records');

  const raw = records[0];
  const m = raw.match(/([-+~?]?)all\b/i);
  let all_qualifier = null;
  if (m) {
    const q = m[1] || '+'; // bare "all" == "+all" per RFC 7208
    all_qualifier = `${q}all`;
  }
  if (all_qualifier === '+all') issues.push('spf_plus_all_allows_anyone');
  if (all_qualifier === '?all') issues.push('spf_neutral_all');
  if (all_qualifier === null) issues.push('spf_missing_all_mechanism');

  return { present: true, raw, all_qualifier, issues };
}

/** Split a DMARC/MTA-STS style "k=v; k=v" record into a tag map (lowercased keys). */
function parseTagValue(record) {
  const out = {};
  for (const part of String(record).split(';')) {
    const idx = part.indexOf('=');
    if (idx === -1) continue;
    const k = part.slice(0, idx).trim().toLowerCase();
    const v = part.slice(idx + 1).trim();
    if (k) out[k] = v;
  }
  return out;
}

/**
 * Parse a DMARC record (RFC 7489) found at _dmarc.<domain>.
 * Returns { present, raw, policy, pct, rua, issues:[] }.
 * policy p= one of 'none'|'quarantine'|'reject'|null.
 */
function parseDmarc(txtRecords) {
  const records = (Array.isArray(txtRecords) ? txtRecords : [])
    .map(cleanTxt)
    .filter((t) => /^v=dmarc1\b/i.test(t));

  if (records.length === 0) {
    return { present: false, raw: null, policy: null, pct: null, rua: null, issues: ['no_dmarc'] };
  }
  const issues = [];
  if (records.length > 1) issues.push('multiple_dmarc_records');

  const raw = records[0];
  const tags = parseTagValue(raw);
  const policy = (tags.p || '').toLowerCase() || null;
  const pct = tags.pct !== undefined ? parseInt(tags.pct, 10) : null;
  const rua = tags.rua || null;

  if (!policy) issues.push('dmarc_missing_policy');
  else if (policy === 'none') issues.push('dmarc_policy_none_monitor_only');
  if (Number.isFinite(pct) && pct < 100) issues.push('dmarc_pct_below_100');
  if (!rua) issues.push('dmarc_no_aggregate_reporting');

  return { present: true, raw, policy, pct: Number.isFinite(pct) ? pct : null, rua, issues };
}

/**
 * Summarize DKIM selector probes (RFC 6376). We can only PROVE a selector exists
 * if the caller supplied selector names and we got TXT answers for them; DKIM
 * selectors are not enumerable from DNS, so absence here is "unknown", NOT a
 * fabricated failure.
 */
function summarizeDkim(selectorResults) {
  const results = Array.isArray(selectorResults) ? selectorResults : [];
  const found = results.filter((r) => r && r.present);
  return {
    selectors_probed: results.length,
    selectors_found: found.length,
    found_selectors: found.map((r) => r.selector).filter(Boolean),
    // No selectors supplied => we make NO claim about DKIM (avoid fake "missing").
    status: results.length === 0 ? 'unknown_no_selectors' : (found.length > 0 ? 'present' : 'not_found'),
  };
}

/**
 * Grade overall posture into a 0..100 score and an A–F band, with each deduction
 * traced to a real, cited reason. Rubric inspired by Internet.nl / NIST 800-177.
 * Returns { score, band, deductions:[{points, code, reason}] }.
 */
function gradePosture({ spf, dmarc, dkim, mtaSts, mx }) {
  let score = 100;
  const deductions = [];
  const deduct = (points, code, reason) => {
    score -= points;
    deductions.push({ points, code, reason });
  };

  // If the domain receives no mail at all (no MX), email-auth is less critical;
  // we note it but do not penalize as if it were a mail domain.
  const sendsOrReceivesMail = !mx || mx.present !== false;

  // SPF (RFC 7208)
  if (!spf || !spf.present) {
    deduct(25, 'spf_absent', 'No SPF record (RFC 7208): receivers cannot tell which hosts may send as this domain.');
  } else {
    if (spf.all_qualifier === '+all') {
      deduct(30, 'spf_plus_all', 'SPF ends in "+all" (RFC 7208): authorizes ANY host to send as this domain — worse than no SPF.');
    } else if (spf.all_qualifier === '?all' || spf.all_qualifier === null) {
      deduct(10, 'spf_weak_all', 'SPF has a neutral/absent "all" mechanism (RFC 7208): unauthorized senders are not failed.');
    }
    if (spf.issues && spf.issues.includes('multiple_spf_records')) {
      deduct(10, 'spf_multiple', 'Multiple SPF records (RFC 7208 §3.2): causes a permerror, breaking SPF entirely.');
    }
  }

  // DMARC (RFC 7489)
  if (!dmarc || !dmarc.present) {
    deduct(30, 'dmarc_absent', 'No DMARC record (RFC 7489): spoofed mail is not rejected/quarantined and you get no visibility.');
  } else {
    if (dmarc.policy === 'none' || !dmarc.policy) {
      deduct(15, 'dmarc_policy_none', 'DMARC p=none (RFC 7489): monitor-only — spoofed mail is still delivered. Move to quarantine/reject.');
    } else if (dmarc.policy === 'quarantine') {
      deduct(5, 'dmarc_quarantine', 'DMARC p=quarantine (RFC 7489): better, but p=reject fully blocks spoofing.');
    }
    if (Number.isFinite(dmarc.pct) && dmarc.pct < 100) {
      deduct(5, 'dmarc_pct', `DMARC pct=${dmarc.pct} (RFC 7489): policy applies to only part of mail.`);
    }
  }

  // DKIM (RFC 6376) — only deduct when the caller PROVED no selector exists.
  if (dkim && dkim.status === 'not_found') {
    deduct(10, 'dkim_absent', 'No DKIM key at the probed selector(s) (RFC 6376): messages are not cryptographically signed.');
  }
  // status 'unknown_no_selectors' => no deduction (no fake failure).

  // MTA-STS (RFC 8461) — transport security; a "nice to have", small weight.
  if (mtaSts && mtaSts.present === false) {
    deduct(5, 'mta_sts_absent', 'No MTA-STS policy (RFC 8461): inbound TLS can be stripped by a downgrade attacker.');
  }

  if (!sendsOrReceivesMail) {
    // domain doesn't receive mail; SPF/DMARC still matter for spoof-protection,
    // so we keep those deductions but cap the floor a little higher.
    score = Math.max(score, 20);
  }

  score = Math.max(0, Math.min(100, score));
  const band =
    score >= 90 ? 'A' :
    score >= 80 ? 'B' :
    score >= 70 ? 'C' :
    score >= 60 ? 'D' : 'F';

  return { score, band, deductions };
}

// ─────────────────────────── typed event builders ───────────────────────────

function baseEvent(eventType, domain, confidence, status, data) {
  return {
    record_type: RECORD_TYPE,
    event_type: eventType,
    source_module: SOURCE_MODULE,
    domain: domain || null, // correlation co-occurrence key (SpiderFoot model)
    record_status: status,  // 'present' | 'not_found' | 'unknown'
    confidence: clampConfidence(confidence),
    data: data || {},
  };
}

function makeSpfEvent({ domain, spf }) {
  const status = spf.present ? 'present' : 'not_found';
  const confidence = spf.present ? 95 : 90; // absence is itself a confident finding
  return baseEvent(EVENT_TYPES.SPF, domain, confidence, status, {
    all_qualifier: spf.all_qualifier,
    raw: spf.raw,
    issues: spf.issues,
    advice: spf.present
      ? (spf.all_qualifier === '-all'
        ? 'SPF looks correct (ends in -all). Keep it.'
        : 'Tighten SPF to end in "-all" so unauthorized senders hard-fail (RFC 7208).')
      : 'Publish an SPF record listing only your real senders, ending in "-all" (RFC 7208).',
  });
}

function makeDmarcEvent({ domain, dmarc }) {
  const status = dmarc.present ? 'present' : 'not_found';
  return baseEvent(EVENT_TYPES.DMARC, domain, dmarc.present ? 95 : 90, status, {
    policy: dmarc.policy,
    pct: dmarc.pct,
    rua: dmarc.rua,
    issues: dmarc.issues,
    advice: dmarc.present
      ? (dmarc.policy === 'reject'
        ? 'DMARC p=reject — strong anti-spoofing posture. Keep monitoring your rua reports.'
        : 'Move DMARC to p=reject (after monitoring) so spoofed mail is blocked (RFC 7489).')
      : 'Publish a DMARC record at _dmarc.' + (domain || 'yourdomain') + ' starting at p=none, then escalate to p=reject (RFC 7489).',
  });
}

function makeDkimEvent({ domain, dkim }) {
  const status =
    dkim.status === 'present' ? 'present' :
    dkim.status === 'not_found' ? 'not_found' : 'unknown';
  return baseEvent(EVENT_TYPES.DKIM, domain, dkim.status === 'unknown_no_selectors' ? 50 : 90, status, {
    selectors_probed: dkim.selectors_probed,
    selectors_found: dkim.selectors_found,
    found_selectors: dkim.found_selectors,
    advice: dkim.status === 'unknown_no_selectors'
      ? 'DKIM selectors are not enumerable from DNS; supply your selector name(s) to verify your DKIM keys (RFC 6376).'
      : (dkim.status === 'present'
        ? 'DKIM key found — your mail can be cryptographically signed. Keep the key rotated.'
        : 'No DKIM key at the probed selector(s); enable DKIM signing on your mail provider (RFC 6376).'),
  });
}

function makeMxEvent({ domain, mx }) {
  const status = mx.present ? 'present' : 'not_found';
  return baseEvent(EVENT_TYPES.MX, domain, 95, status, {
    hosts: Array.isArray(mx.hosts) ? mx.hosts : [],
    advice: mx.present
      ? 'Domain receives mail; SPF/DMARC/DKIM all apply.'
      : 'No MX records — this domain does not receive mail, but SPF/DMARC still protect your name from spoofing.',
  });
}

function makeMtaStsEvent({ domain, mtaSts }) {
  const status = mtaSts.present ? 'present' : 'not_found';
  return baseEvent(EVENT_TYPES.MTA_STS, domain, mtaSts.present ? 90 : 80, status, {
    raw: mtaSts.raw || null,
    advice: mtaSts.present
      ? 'MTA-STS policy published (RFC 8461) — inbound TLS is enforced.'
      : 'Consider publishing an MTA-STS policy (RFC 8461) to prevent TLS-downgrade on inbound mail.',
  });
}

function makeDnssecEvent({ domain, dnssec }) {
  // DoH sets AD=true when the answer is DNSSEC-validated by the resolver.
  const status = dnssec && dnssec.validated ? 'present' : 'not_found';
  return baseEvent(EVENT_TYPES.DNSSEC, domain, 70, status, {
    advice: status === 'present'
      ? 'Resolver reports DNSSEC-validated answers (AD bit) for this zone.'
      : 'Zone answers were not DNSSEC-validated (no AD bit). Enabling DNSSEC hardens against DNS forgery.',
  });
}

function makeSummaryEvent({ domain, subjectLabel, scopeType, grade, parts }) {
  return {
    record_type: 'email_auth_summary',
    event_type: EVENT_TYPES.SUMMARY,
    source_module: SOURCE_MODULE,
    domain: domain || null,
    confidence: 100,
    data: {
      subject_label: subjectLabel || '',
      scope_type: scopeType || null,
      score: grade.score,
      band: grade.band,
      deductions: grade.deductions,
      spoofable: grade.band === 'F' || grade.band === 'D',
      posture: parts, // compact roll-up of each record's status
      framing: 'Self-exposure: this is how easily YOUR domain can be spoofed today, with fixes — not surveillance of anyone.',
    },
    generated_at: new Date().toISOString(),
  };
}

module.exports = {
  SOURCE_MODULE,
  RECORD_TYPE,
  EVENT_TYPES,
  clampConfidence,
  normalizeDomain,
  cleanTxt,
  parseSpf,
  parseTagValue,
  parseDmarc,
  summarizeDkim,
  gradePosture,
  makeSpfEvent,
  makeDmarcEvent,
  makeDkimEvent,
  makeMxEvent,
  makeMtaStsEvent,
  makeDnssecEvent,
  makeSummaryEvent,
};
