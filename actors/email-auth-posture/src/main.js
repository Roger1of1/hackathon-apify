/**
 * AUX — Email-Auth Posture Self-Check (SPF / DMARC / DKIM / MX / MTA-STS / DNSSEC)
 *
 * An auxiliary actor that orbits the core Ex-Ditector self-footprint pipeline.
 * It answers ONE compliant, high-value question about a domain the SELF subject
 * OWNS (or a genuine public_figure's public domain): "how easily can someone
 * spoof email FROM my domain right now?" — a self-exposure fact the subject can
 * fix today, which none of the other Ex-Ditector actors cover.
 *
 * ───────────────────────── COMPLIANCE BOUNDARY ─────────────────────────
 * 1. Scope gate: every run routes through shared/scope.js validateScope and is
 *    additionally restricted to scope_type ∈ {self, public_figure}. Auditing a
 *    domain's email-auth posture is a self-/public-only activity here; the
 *    free-text laundering scan still runs over subject_label so e.g. "find my
 *    ex's mail server" is rejected even under a legal-looking scope.
 * 2. PUBLIC DNS ONLY: we read SPF/DMARC/DKIM/MX/MTA-STS records, which are
 *    published in public DNS by design. There is NO login wall, NO private
 *    social graph, NO person-tracking, NO romance/gender/intimacy inference,
 *    and NO bypassing of any control. We use DNS-over-HTTPS (RFC 8484) against a
 *    single public resolver and HONOR its rate limits (back off on 429, never
 *    hammer).
 * 3. NO FAKE DATA: if a record is absent, we emit record_status:'not_found' and
 *    grade the real risk; we NEVER fabricate a passing record. DKIM selectors
 *    are not enumerable from DNS, so with no selector supplied we report
 *    'unknown', not a fake failure.
 * ─────────────────────────────────────────────────────────────────────────
 *
 * REFERENCE PATTERNS APPLIED:
 *  - Apify SDK Actor lifecycle: Actor.main / Actor.getInput / Actor.pushData /
 *    Actor.setValue / Actor.fail, dataset-as-output (mirrors actors/breach-check).
 *    Runnable locally with `apify run` + an INPUT.json under the actor's default
 *    key-value store; results land in the local dataset (apify_storage/).
 *  - SpiderFoot event-driven OSINT model: each result is a TYPED module-event
 *    carrying a `domain` co-occurrence key, so shared/correlation.js can cluster
 *    an email-auth weakness with other self-exposure events for the same host.
 *  - Internet.nl / Hardenize / NIST SP 800-177 graded email-security posture:
 *    SPF (RFC 7208), DKIM (RFC 6376), DMARC (RFC 7489), MTA-STS (RFC 8461),
 *    DNSSEC — each deduction is traced to a cited RFC in shared/aux/email-auth-finding.js.
 *  - The Markup "Blacklight" self-exposure inspector framing: output is phrased
 *    as fixes to YOUR own domain, never as surveillance of anyone.
 */

'use strict';

const { Actor, log } = require('apify');
const { gotScraping } = require('got-scraping');

const { validateScope, ALLOWED_SCOPES } = require('../../../shared/scope.js');
const {
  normalizeDomain,
  parseSpf,
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
} = require('../../../shared/aux/email-auth-finding.js');

// Dual-use posture audit: ONLY self + public_figure (subset of ALLOWED_SCOPES).
const POSTURE_SCOPES = new Set(['self', 'public_figure']);

// Public DNS-over-HTTPS resolver (RFC 8484, application/dns-json). Cloudflare's
// 1.1.1.1 endpoint is well-documented and DNSSEC-validating (sets AD bit).
const DEFAULT_DOH = 'https://cloudflare-dns.com/dns-query';
const USER_AGENT = 'ex-ditector-self-footprint-audit';

/**
 * One DoH query. Returns { Answer:[], ad:boolean } on success or null on any
 * failure. We back off (return null) on 429 rather than evade rate limits.
 */
async function dohQuery(resolver, name, type) {
  try {
    const res = await gotScraping({
      url: resolver,
      method: 'GET',
      searchParams: { name, type },
      headers: {
        accept: 'application/dns-json',
        'User-Agent': USER_AGENT,
      },
      responseType: 'json',
      throwHttpErrors: false,
      timeout: { request: 15000 },
      retry: { limit: 1 },
    });
    if (res.statusCode === 429) {
      log.warning(`DoH 429 for ${type} ${name}; backing off (not evading).`);
      return null;
    }
    if (res.statusCode !== 200 || !res.body || typeof res.body !== 'object') {
      log.warning(`DoH non-200 (${res.statusCode}) for ${type} ${name}.`);
      return null;
    }
    return res.body;
  } catch (err) {
    log.warning(`DoH query failed for ${type} ${name}: ${err.message}`);
    return null;
  }
}

/** Extract TXT record strings from a DoH answer (type 16). */
function txtAnswers(body) {
  if (!body || !Array.isArray(body.Answer)) return [];
  return body.Answer.filter((a) => a && a.type === 16 && typeof a.data === 'string').map((a) => a.data);
}

/** Extract MX host names from a DoH answer (type 15, data is "<pref> <host>."). */
function mxAnswers(body) {
  if (!body || !Array.isArray(body.Answer)) return [];
  return body.Answer
    .filter((a) => a && a.type === 15 && typeof a.data === 'string')
    .map((a) => a.data.replace(/^\d+\s+/, '').replace(/\.$/, ''))
    .filter(Boolean);
}

Actor.main(async () => {
  const input = (await Actor.getInput()) || {};
  const scopeType = typeof input.scope_type === 'string' ? input.scope_type.trim() : '';
  const domain = normalizeDomain(input.domain);

  // ── Gate 1: canonical scope gate (same chokepoint the whole product uses). ──
  // This actor's only "target" is a domain we own; we hand the gate a host-free
  // synthetic self URL ONLY to satisfy its target check, while still getting its
  // prohibited-scope / prohibited-intent rejection and free-text laundering scan.
  const gateDecision = validateScope({
    scope_type: scopeType,
    target_urls: ['https://example.invalid/self-email-auth-audit'],
    subject_label: input.subject_label,
    description: input.subject_label,
  });
  if (!gateDecision.allowed) {
    log.error('Email-auth posture refused by scope gate.', {
      reasons: gateDecision.reasons,
      violated: gateDecision.violated_red_lines,
    });
    await Actor.pushData({
      record_type: 'email_auth_finding',
      event_type: 'REFUSED',
      source_module: 'aux:email-auth-posture',
      confidence: 100,
      data: {
        reasons: gateDecision.reasons,
        violated_red_lines: gateDecision.violated_red_lines,
        alternatives: gateDecision.alternatives,
      },
    });
    await Actor.fail('Email-auth posture rejected by compliance gate.');
    return;
  }

  // ── Gate 2: dual-use restriction. Even legal scopes brand/consented/
  // safety_evidence cannot run this posture audit. ──
  if (!ALLOWED_SCOPES.includes(scopeType) || !POSTURE_SCOPES.has(scopeType)) {
    log.error('Email-auth posture refused: restricted to self/public_figure.', { scope_type: scopeType });
    await Actor.fail('Email-auth posture is allowed only for scope_type=self or public_figure.');
    return;
  }

  if (!domain) {
    log.error('No valid domain supplied (a registrable domain like "example.com" is required).');
    await Actor.fail('A valid domain you own is required (e.g. "example.com").');
    return;
  }

  const resolver = (typeof input.doh_resolver === 'string' && /^https:\/\//.test(input.doh_resolver))
    ? input.doh_resolver.trim()
    : DEFAULT_DOH;

  const dkimSelectors = Array.isArray(input.dkim_selectors)
    ? input.dkim_selectors.filter((s) => typeof s === 'string' && s.trim().length > 0).map((s) => s.trim())
    : [];

  // Optional case linkage (mirrors breach-check), so the report-builder can join.
  const caseStoreName = input.case_store_name || 'ex-ditector-case';
  let caseId = input.case_id || null;
  try {
    const caseStore = await Actor.openKeyValueStore(caseStoreName);
    const caseRecord = await caseStore.getValue('CASE');
    if (caseRecord && caseRecord.case_id) caseId = caseRecord.case_id;
  } catch (err) {
    log.debug(`No case store available (${err.message}); running standalone.`);
  }
  if (!caseId) caseId = 'standalone_email_auth';

  log.info(`Auditing PUBLIC email-auth posture for ${domain} via ${resolver} (DNS-over-HTTPS).`);

  // ───────────────────────── REAL public DNS lookups ─────────────────────────
  const spfBody = await dohQuery(resolver, domain, 'TXT');
  const dmarcBody = await dohQuery(resolver, `_dmarc.${domain}`, 'TXT');
  const mxBody = await dohQuery(resolver, domain, 'MX');
  const mtaStsBody = await dohQuery(resolver, `_mta-sts.${domain}`, 'TXT');

  const dkimResults = [];
  for (const sel of dkimSelectors) {
    const body = await dohQuery(resolver, `${sel}._domainkey.${domain}`, 'TXT');
    const txt = txtAnswers(body);
    const present = txt.some((t) => /v=dkim1|k=rsa|p=/i.test(t));
    dkimResults.push({ selector: sel, present });
  }

  // ───────────────────────── shape into typed findings ───────────────────────
  const spf = parseSpf(txtAnswers(spfBody));
  const dmarc = parseDmarc(txtAnswers(dmarcBody));
  const dkim = summarizeDkim(dkimResults);
  const mxHosts = mxAnswers(mxBody);
  const mx = { present: mxHosts.length > 0, hosts: mxHosts };
  const mtaStsTxt = txtAnswers(mtaStsBody);
  const mtaSts = { present: mtaStsTxt.some((t) => /v=stsv1/i.test(t)), raw: mtaStsTxt[0] || null };
  // DNSSEC: AD bit on a validated answer from the resolver (any of our queries).
  const dnssec = { validated: Boolean((spfBody && spfBody.AD) || (mxBody && mxBody.AD)) };

  const grade = gradePosture({ spf, dmarc, dkim, mtaSts, mx });

  const events = [
    makeSpfEvent({ domain, spf }),
    makeDmarcEvent({ domain, dmarc }),
    makeDkimEvent({ domain, dkim }),
    makeMxEvent({ domain, mx }),
    makeMtaStsEvent({ domain, mtaSts }),
    makeDnssecEvent({ domain, dnssec }),
  ];
  for (const evt of events) {
    evt.case_id = caseId;
    await Actor.pushData(evt);
  }

  const summary = makeSummaryEvent({
    domain,
    subjectLabel: typeof input.subject_label === 'string' ? input.subject_label : '',
    scopeType,
    grade,
    parts: {
      spf: spf.present ? (spf.all_qualifier || 'no-all') : 'not_found',
      dmarc: dmarc.present ? (dmarc.policy || 'no-policy') : 'not_found',
      dkim: dkim.status,
      mx: mx.present ? 'present' : 'not_found',
      mta_sts: mtaSts.present ? 'present' : 'not_found',
      dnssec: dnssec.validated ? 'validated' : 'not_validated',
    },
  });
  summary.case_id = caseId;
  await Actor.pushData(summary);
  await Actor.setValue('EMAIL_AUTH_SUMMARY', summary);

  log.info(`Email-auth posture complete: ${domain} graded ${grade.band} (${grade.score}/100).`, {
    spoofable: summary.data.spoofable,
    deductions: grade.deductions.length,
  });
});
