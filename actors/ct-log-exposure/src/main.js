/**
 * AUX — Certificate-Transparency Exposure Self-Check (CT logs / crt.sh)
 *
 * An auxiliary actor that orbits the core MirrorTrace self-footprint pipeline.
 * It answers ONE compliant, high-value question about a domain the SELF subject
 * OWNS (or a genuine public_figure's public domain): "which hostnames have I
 * already published to the public Certificate Transparency logs, and which of
 * them name sensitive internal services I forgot were reachable?" — a self-
 * exposure fact the subject can fix today (decommission/auth/scope the cert),
 * which none of the other MirrorTrace actors cover.
 *
 * ───────────────────────── COMPLIANCE BOUNDARY ─────────────────────────
 * 1. Scope gate: every run routes through shared/scope.js validateScope and is
 *    additionally restricted to scope_type ∈ {self, public_figure}. Subdomain
 *    ENUMERATION is a recognised dual-use technique, so it is allowed ONLY for
 *    self/public_figure and chokepointed through the same gate the whole product
 *    uses; the free-text laundering scan still runs over subject_label so e.g.
 *    "find a private person's servers" is rejected even under a legal-looking scope.
 * 2. PUBLIC CT LOGS ONLY: Certificate Transparency logs (RFC 6962) are public,
 *    append-only logs of issued TLS certificates, read here via the public crt.sh
 *    index. There is NO login wall, NO captcha bypass, NO private social graph,
 *    NO person-tracking, NO romance/gender/sexuality/intimacy inference, and NO
 *    bypassing of any control. We HONOR rate limits (back off on 429, never
 *    hammer) and read only hostnames already published by the subject's own certs.
 * 3. NO FAKE DATA: if the CT index returns nothing, we emit a summary with
 *    record_status:'not_found' and grade it honestly. We NEVER invent a hostname,
 *    and an out-of-scope name returned by the index is dropped, never reported.
 * ─────────────────────────────────────────────────────────────────────────
 *
 * REFERENCE PATTERNS APPLIED:
 *  - Apify SDK Actor lifecycle: Actor.main / Actor.getInput / Actor.pushData /
 *    Actor.setValue / Actor.fail, dataset-as-output (mirrors actors/breach-check
 *    and actors/email-auth-posture). Runnable locally with `apify run` + an
 *    INPUT.json under the actor's default key-value store; results land in the
 *    local dataset (apify_storage/).
 *  - RFC 6962 Certificate Transparency + crt.sh public JSON index (?output=json):
 *    the canonical, public way to read a domain's own issued certificates.
 *  - SpiderFoot's `sfp_crt` CT-enumeration model: each result is a TYPED module-
 *    event carrying a `domain` co-occurrence key, so shared/correlation.js can
 *    cluster a leaked hostname with other self-exposure events for the same host.
 *  - The Markup "Blacklight" self-exposure inspector framing: output is phrased as
 *    fixes to YOUR own published hostnames, never as reconnaissance of anyone.
 */

'use strict';

const { Actor, log } = require('apify');
const { gotScraping } = require('got-scraping');

const { validateScope, ALLOWED_SCOPES } = require('../../../shared/scope.js');
const {
  normalizeDomain,
  parseCrtShRows,
  buildFindings,
} = require('../../../shared/aux/ct-log-finding.js');

// Dual-use enumeration: ONLY self + public_figure (subset of ALLOWED_SCOPES).
const ENUM_SCOPES = new Set(['self', 'public_figure']);

// Public CT index. crt.sh serves JSON with ?output=json. Identity uses %25 (URL
// wildcard) to include subdomains the subject has published certs for.
const DEFAULT_CT_INDEX = 'https://crt.sh/';
const USER_AGENT = 'mirrortrace-self-footprint-audit';

/**
 * One crt.sh query for a domain. Returns the parsed JSON array on success, or
 * null on any failure. We back off (return null) on 429 rather than evade limits.
 */
async function queryCrtSh(indexBase, domain) {
  try {
    const res = await gotScraping({
      url: indexBase,
      method: 'GET',
      // identity=%.domain  →  the domain and all subdomains the subject published
      searchParams: { identity: `%.${domain}`, output: 'json' },
      headers: { accept: 'application/json', 'User-Agent': USER_AGENT },
      responseType: 'json',
      throwHttpErrors: false,
      timeout: { request: 30000 },
      retry: { limit: 1 },
    });
    if (res.statusCode === 429) {
      log.warning(`CT index 429 for ${domain}; backing off (not evading rate limits).`);
      return null;
    }
    if (res.statusCode !== 200 || !res.body) {
      log.warning(`CT index non-200 (${res.statusCode}) for ${domain}.`);
      return null;
    }
    // crt.sh returns a JSON array; tolerate a string body that needs parsing.
    if (Array.isArray(res.body)) return res.body;
    if (typeof res.body === 'string') {
      try { return JSON.parse(res.body); } catch { return null; }
    }
    return null;
  } catch (err) {
    log.warning(`CT index query failed for ${domain}: ${err.message}`);
    return null;
  }
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
    target_urls: ['https://example.invalid/self-ct-exposure-audit'],
    subject_label: input.subject_label,
    description: input.subject_label,
  });
  if (!gateDecision.allowed) {
    log.error('CT exposure refused by scope gate.', {
      reasons: gateDecision.reasons,
      violated: gateDecision.violated_red_lines,
    });
    await Actor.pushData({
      record_type: 'ct_log_finding',
      event_type: 'REFUSED',
      source_module: 'aux:ct-log-exposure',
      confidence: 100,
      data: {
        reasons: gateDecision.reasons,
        violated_red_lines: gateDecision.violated_red_lines,
        alternatives: gateDecision.alternatives,
      },
    });
    await Actor.fail('CT exposure rejected by compliance gate.');
    return;
  }

  // ── Gate 2: dual-use restriction. Even legal scopes brand/consented/
  // safety_evidence cannot run CT subdomain enumeration. ──
  if (!ALLOWED_SCOPES.includes(scopeType) || !ENUM_SCOPES.has(scopeType)) {
    log.error('CT exposure refused: enumeration restricted to self/public_figure.', { scope_type: scopeType });
    await Actor.fail('CT exposure is allowed only for scope_type=self or public_figure.');
    return;
  }

  if (!domain) {
    log.error('No valid domain supplied (a registrable domain like "example.com" is required).');
    await Actor.fail('A valid domain you own is required (e.g. "example.com").');
    return;
  }

  const indexBase = (typeof input.ct_index_url === 'string' && /^https:\/\//.test(input.ct_index_url))
    ? input.ct_index_url.trim()
    : DEFAULT_CT_INDEX;

  // Optional case linkage (mirrors breach-check / email-auth), so report-builder can join.
  const caseStoreName = input.case_store_name || 'mirrortrace-case';
  let caseId = input.case_id || null;
  try {
    const caseStore = await Actor.openKeyValueStore(caseStoreName);
    const caseRecord = await caseStore.getValue('CASE');
    if (caseRecord && caseRecord.case_id) caseId = caseRecord.case_id;
  } catch (err) {
    log.debug(`No case store available (${err.message}); running standalone.`);
  }
  if (!caseId) caseId = 'standalone_ct_exposure';

  log.info(`Auditing PUBLIC CT-log exposure for ${domain} via ${indexBase} (Certificate Transparency / RFC 6962).`);

  // ───────────────────────── REAL public CT lookup ─────────────────────────
  const rows = await queryCrtSh(indexBase, domain);
  const parsed = parseCrtShRows(rows, domain); // PURE: only in-scope, real hostnames

  if (rows === null) {
    log.warning('CT index returned no usable response (network/limit). Emitting an honest empty summary.');
  }

  // ───────────────────────── shape into typed findings ───────────────────────
  const { events, summary, grade, riskyHostnames } = buildFindings({
    domain,
    subjectLabel: typeof input.subject_label === 'string' ? input.subject_label : '',
    scopeType,
    parsed,
  });

  for (const evt of events) {
    evt.case_id = caseId;
    await Actor.pushData(evt);
  }
  summary.case_id = caseId;
  await Actor.pushData(summary);
  await Actor.setValue('CT_EXPOSURE_SUMMARY', summary);

  log.info(`CT exposure complete: ${domain} graded ${grade.band} (${grade.score}/100).`, {
    hostnames: parsed.count,
    risky: riskyHostnames.length,
    wildcard: parsed.wildcard,
  });
});
