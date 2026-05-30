/**
 * AUX — Public Attack-Surface Self-Scan (Certificate Transparency + WHOIS)
 *
 * An auxiliary actor that orbits the core Ex-Ditector pipeline. It answers ONE
 * compliant question about a domain the SELF subject OWNS: "what can a stranger
 * trivially discover about my domain's attack surface from PUBLIC records?" — so
 * the user can lock down forgotten dev/admin hosts and enable WHOIS privacy.
 *
 * ───────────────────────── COMPLIANCE BOUNDARY ─────────────────────────
 * 1. Scope gate: every run routes through shared/scope.js validateScope and is
 *    additionally restricted to scope_type ∈ {self, public_figure}. Subdomain
 *    enumeration is a DUAL-USE attack-surface technique; per the product rules
 *    it is allowed ONLY for these scopes. The operator must ALSO assert domain
 *    ownership (i_own_this_domain) or the run is refused.
 * 2. PUBLIC sources only: Certificate Transparency logs (crt.sh, RFC 6962) are
 *    deliberately public, append-only audit logs; public WHOIS via RDAP. No
 *    login is bypassed, no captcha/rate-limit is evaded, no port is scanned, no
 *    private host is touched. We back off on 429, never hammer.
 * 3. Self-inventory only: a CT entry's SANs are filtered to hosts that BELONG to
 *    the asserted apex (belongsToDomain). A cert that merely shares a SAN with
 *    someone else's domain can never leak that third party's host into output.
 * 4. NO third-party identity resolution / NO romance/gender/intimacy/location
 *    inference. The only personal datum touched is the subject's OWN registrant
 *    email, and it is reduced to a k-anonymity prefix + masked display.
 * 5. NO FAKE DATA: every host/email is emitted ONLY if it really appears in the
 *    response. Empty / non-200 responses yield an empty inventory, never an
 *    invented surface.
 * ─────────────────────────────────────────────────────────────────────────
 *
 * REFERENCE PATTERNS APPLIED:
 *  - OWASP Amass / Subfinder attack-surface-management subdomain discovery via
 *    Certificate Transparency (crt.sh) — reframed as a SELF inventory.
 *  - The Markup "Blacklight" self-exposure framing: output is "what a third
 *    party could trivially learn about MY surface", with concrete fix advice.
 *  - SpiderFoot typed event-driven modules + correlation engine: every result
 *    is a frozen-vocabulary module_event (shared/detectors/event-types.js) so
 *    the correlation pass and report builder consume it like any other module.
 */

'use strict';

const { Actor, log } = require('apify');
const { gotScraping } = require('got-scraping');

const { validateScope, ALLOWED_SCOPES } = require('../../../shared/scope.js');
const {
  normalizeHost,
  belongsToDomain,
  makeSubdomainEvent,
  makeWhoisEmailEvent,
  makeSummaryEvent,
} = require('../../../shared/aux/asm-finding.js');

// Dual-use attack-surface discovery: ONLY self + public_figure.
const ASM_SCOPES = new Set(['self', 'public_figure']);

const CRTSH_URL = 'https://crt.sh/';
const RDAP_URL = 'https://rdap.org/domain/';
const USER_AGENT = 'ex-ditector-self-footprint-audit';

/**
 * Extract candidate hostnames from a crt.sh JSON row. `name_value` can hold
 * multiple newline-separated SANs; `common_name` holds one. We normalize and
 * keep only those that belong to the asserted apex.
 */
function hostsFromCrtRow(row, apex) {
  const out = [];
  const push = (raw) => {
    const h = normalizeHost(raw);
    if (h && belongsToDomain(h, apex)) out.push(h);
  };
  if (row && typeof row.name_value === 'string') {
    for (const part of row.name_value.split(/\n+/)) push(part);
  }
  if (row && typeof row.common_name === 'string') push(row.common_name);
  return out;
}

/**
 * Pull a registrant email out of an RDAP response. RDAP entities carry a
 * jCard ("vcardArray") whose entries look like ["email", {}, "text", "a@b.com"].
 * We return the first one found, or null. Public RDAP often redacts this (good
 * for the user); a null simply means "no email exposed" — never fabricated.
 */
function registrantEmailFromRdap(body) {
  if (!body || !Array.isArray(body.entities)) return null;
  for (const entity of body.entities) {
    const card = entity && Array.isArray(entity.vcardArray) ? entity.vcardArray[1] : null;
    if (!Array.isArray(card)) continue;
    for (const field of card) {
      if (Array.isArray(field) && field[0] === 'email' && typeof field[3] === 'string' && field[3].includes('@')) {
        return field[3];
      }
    }
  }
  return null;
}

Actor.main(async () => {
  const input = (await Actor.getInput()) || {};
  const scopeType = typeof input.scope_type === 'string' ? input.scope_type.trim() : '';
  const apex = normalizeHost(input.domain);

  // ── Gate 1: canonical scope gate (same chokepoint the whole product uses). ──
  // The domain doubles as the target URL so the gate's host/intent checks run.
  const gateDecision = validateScope({
    scope_type: scopeType,
    target_urls: apex ? [`https://${apex}`] : ['https://example.invalid/self-asm'],
    subject_label: input.subject_label,
    description: input.subject_label,
  });

  if (!gateDecision.allowed) {
    log.error('Attack-surface scan refused by scope gate.', {
      reasons: gateDecision.reasons,
      violated: gateDecision.violated_red_lines,
    });
    await Actor.pushData({
      record_type: 'module_event',
      event_type: 'EXPOSURE_SUMMARY',
      source_module: 'aux:attack-surface-scan',
      confidence: 1,
      data: { refused: true },
      meta: {
        reasons: gateDecision.reasons,
        violated_red_lines: gateDecision.violated_red_lines,
        alternatives: gateDecision.alternatives,
      },
    });
    await Actor.fail('Attack-surface scan rejected by compliance gate.');
    return;
  }

  // ── Gate 2: dual-use restriction — only self/public_figure. ──
  if (!ALLOWED_SCOPES.includes(scopeType) || !ASM_SCOPES.has(scopeType)) {
    log.error('Refused: attack-surface discovery is restricted to self/public_figure.', { scope_type: scopeType });
    await Actor.fail('Attack-surface discovery is allowed only for scope_type=self or public_figure.');
    return;
  }

  // ── Gate 3: explicit ownership assertion + a real domain. ──
  if (!apex) {
    await Actor.fail('A valid apex domain (e.g. "example.com") is required.');
    return;
  }
  if (input.i_own_this_domain !== true) {
    log.error('Refused: you must confirm you own / are authorized to audit this domain.');
    await Actor.fail('Refused: set i_own_this_domain=true to confirm this is your own domain.');
    return;
  }

  const caseStoreName = input.case_store_name || 'ex-ditector-case';
  let caseId = input.case_id || null;
  try {
    const caseStore = await Actor.openKeyValueStore(caseStoreName);
    const caseRecord = await caseStore.getValue('CASE');
    if (caseRecord && caseRecord.case_id) caseId = caseRecord.case_id;
  } catch (err) {
    log.debug(`No case store available (${err.message}); running standalone.`);
  }
  if (!caseId) caseId = 'standalone_attack_surface_scan';

  const maxSubdomains = Number.isInteger(input.max_subdomains) ? input.max_subdomains : 200;
  const events = [];
  const seenHosts = new Set();

  // ───────────── Subdomain discovery via Certificate Transparency ─────────────
  // crt.sh exposes a public JSON view; identity=%.<domain> matches the apex and
  // all subdomains. This is a read of a PUBLIC audit log — the intended use.
  try {
    const res = await gotScraping({
      url: CRTSH_URL,
      method: 'GET',
      searchParams: { q: `%.${apex}`, output: 'json' },
      headers: { 'User-Agent': USER_AGENT, Accept: 'application/json' },
      responseType: 'json',
      throwHttpErrors: false,
      timeout: { request: 30000 },
      retry: { limit: 1 },
    });

    if (res.statusCode === 429) {
      log.warning('crt.sh returned 429; backing off, not evading.');
    } else if (res.statusCode === 200 && Array.isArray(res.body)) {
      for (const row of res.body) {
        for (const host of hostsFromCrtRow(row, apex)) {
          if (seenHosts.has(host)) continue;
          if (seenHosts.size >= maxSubdomains) break;
          seenHosts.add(host);
          const evt = makeSubdomainEvent({ host, apex, firstSeen: row && row.not_before });
          if (!evt) continue;
          evt.case_id = caseId;
          events.push(evt);
          await Actor.pushData(evt);
        }
      }
      log.info(`Certificate-transparency discovery complete: ${seenHosts.size} host(s) belonging to ${apex}.`);
    } else {
      log.warning(`crt.sh non-200 (${res.statusCode}); reporting no CT hosts (no fake data).`);
    }
  } catch (err) {
    log.warning(`crt.sh query failed: ${err.message}; reporting no CT hosts.`);
  }

  // ───────────────── Public WHOIS / RDAP registrant-email check ─────────────────
  // Detects the subject's OWN email leaked into the public WHOIS record. A
  // redacted (privacy-protected) record returns no email — which is the GOOD
  // outcome we report as "no exposure", never a fabricated address.
  if (input.check_whois !== false) {
    try {
      const res = await gotScraping({
        url: RDAP_URL + encodeURIComponent(apex),
        method: 'GET',
        headers: { 'User-Agent': USER_AGENT, Accept: 'application/rdap+json, application/json' },
        responseType: 'json',
        throwHttpErrors: false,
        timeout: { request: 20000 },
        retry: { limit: 1 },
      });
      if (res.statusCode === 429) {
        log.warning('RDAP returned 429; backing off, not evading.');
      } else if (res.statusCode === 200 && res.body && typeof res.body === 'object') {
        const email = registrantEmailFromRdap(res.body);
        if (email) {
          const evt = makeWhoisEmailEvent({ apex, registrantEmail: email });
          if (evt) {
            evt.case_id = caseId;
            events.push(evt);
            await Actor.pushData(evt);
            log.info('Registrant email exposed in public WHOIS (reduced to a k-anon prefix + masked form).');
          }
        } else {
          log.info('No registrant email in the public WHOIS record (privacy-protected or redacted).');
        }
      } else {
        log.warning(`RDAP non-200 (${res.statusCode}); reporting no WHOIS email (no fake data).`);
      }
    } catch (err) {
      log.warning(`RDAP query failed: ${err.message}; reporting no WHOIS email.`);
    }
  }

  // ── Blacklight-style summary: what a third party can trivially learn. ──
  const summary = makeSummaryEvent({ apex, events, scopeType });
  summary.case_id = caseId;
  await Actor.pushData(summary);
  await Actor.setValue('ATTACK_SURFACE_SUMMARY', {
    record_type: 'attack_surface_summary',
    source_module: 'aux:attack-surface-scan',
    case_id: caseId,
    scope_type: scopeType,
    subject_label: typeof input.subject_label === 'string' ? input.subject_label : '',
    apex_domain: apex,
    counts: summary.data,
    event_count: events.length,
    generated_at: new Date().toISOString(),
    privacy_note: 'PUBLIC certificate-transparency + WHOIS only. No login/captcha/rate-limit bypass, no port scan, no third-party identity resolution. The registrant email left as a k-anonymity prefix + masked display, never plaintext.',
  });

  log.info('Attack-surface self-scan complete.', summary.data);
});
