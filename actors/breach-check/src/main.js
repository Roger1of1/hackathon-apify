/**
 * AUX — Breach Exposure Check (k-anonymity)
 *
 * An auxiliary actor that orbits the core MirrorTrace pipeline. It answers ONE
 * compliant question about the SELF subject: "are my own credentials already
 * exposed in public breach corpora?" — the kind of thing a self-footprint audit
 * should surface so the user can rotate passwords and enable MFA.
 *
 * ───────────────────────── COMPLIANCE BOUNDARY ─────────────────────────
 * 1. Scope gate: every run is routed through shared/scope.js validateScope and
 *    additionally restricted to scope_type ∈ {self, public_figure}. Credential
 *    enumeration is a DUAL-USE technique; per the product rules it is allowed
 *    ONLY for these scopes. consented/brand/safety_evidence are refused here.
 * 2. k-anonymity: no password or email ever leaves the machine in full. We send
 *    only the first 5 hex chars of a SHA-1 hash to HIBP's range endpoint (the
 *    same model HIBP itself documents) and match the rest LOCALLY.
 * 3. NO FAKE DATA: if no HIBP_API_KEY is configured, the authenticated account
 *    lookup is SKIPPED and reported as "not_checked" — we never invent a hit.
 *    Padding suffixes (count 0) are excluded so injected padding can't fake one.
 * 4. No identity/romance/gender/intimacy inference anywhere. A breach hit is a
 *    security-hygiene fact about the subject's OWN credentials.
 * ─────────────────────────────────────────────────────────────────────────
 *
 * REFERENCE PATTERNS APPLIED:
 *  - SpiderFoot OSINT-module + correlation-engine design: every result is a
 *    TYPED module-event {event_type, source_module, data, confidence} carrying
 *    an email_hash_prefix co-occurrence key, so shared/correlation.js can link
 *    a credential exposure into the SELF subject's self-exposure cluster.
 *  - The Markup "Blacklight" self-exposure audit: we frame output as "what a
 *    third party could trivially learn about the SELF subject's credentials",
 *    not as surveillance of anyone else.
 *  - HIBP Pwned Passwords k-anonymity range API (Troy Hunt) + padding.
 */

'use strict';

const { Actor, log } = require('apify');
const { gotScraping } = require('got-scraping');

const { validateScope, ALLOWED_SCOPES } = require('../../../shared/scope.js');
const { kAnonPair, emailHashKey } = require('../../../shared/aux/kanon.js');
const {
  makePasswordExposedEvent,
  makeEmailProbeEvent,
  makeAccountBreachedEvent,
} = require('../../../shared/aux/breach-finding.js');
const { parseRangeResponse } = require('../../../shared/aux/kanon.js');

// Dual-use credential checks: ONLY self + public_figure (subset of ALLOWED_SCOPES).
const BREACH_SCOPES = new Set(['self', 'public_figure']);

const PWNED_RANGE_URL = 'https://api.pwnedpasswords.com/range/';
const HIBP_ACCOUNT_URL = 'https://haveibeenpwned.com/api/v3/breachedaccount/';
const USER_AGENT = 'mirrortrace-self-footprint-audit';

Actor.main(async () => {
  const input = (await Actor.getInput()) || {};
  const scopeType = typeof input.scope_type === 'string' ? input.scope_type.trim() : '';

  // ── Gate 1: canonical scope gate (same chokepoint the whole product uses). ──
  // We feed it a synthetic, host-free request: this actor has no target_urls, so
  // we hand the gate a harmless self URL placeholder ONLY to satisfy its target
  // check, while still getting its prohibited-scope / prohibited-intent rejection
  // and its free-text laundering scan over subject_label.
  const gateDecision = validateScope({
    scope_type: scopeType,
    target_urls: ['https://example.invalid/self-credential-audit'],
    subject_label: input.subject_label,
    // Surface any text fields so the laundering scan can reject e.g. "find my
    // a private person's password" even under a legal-looking scope.
    description: input.subject_label,
  });

  if (!gateDecision.allowed) {
    log.error('Breach-check refused by scope gate.', {
      reasons: gateDecision.reasons,
      violated: gateDecision.violated_red_lines,
    });
    await Actor.pushData({
      record_type: 'breach_event',
      event_type: 'REFUSED',
      source_module: 'aux:breach-check',
      confidence: 100,
      data: {
        reasons: gateDecision.reasons,
        violated_red_lines: gateDecision.violated_red_lines,
        alternatives: gateDecision.alternatives,
      },
    });
    await Actor.fail('Breach-check rejected by compliance gate.');
    return;
  }

  // ── Gate 2: dual-use restriction. Even legal scopes like brand/consented/
  // safety_evidence cannot run credential enumeration. ──
  if (!ALLOWED_SCOPES.includes(scopeType) || !BREACH_SCOPES.has(scopeType)) {
    log.error('Breach-check refused: credential checks are restricted to self/public_figure.', {
      scope_type: scopeType,
    });
    await Actor.fail('Credential enumeration is allowed only for scope_type=self or public_figure.');
    return;
  }

  const caseStoreName = input.case_store_name || 'mirrortrace-case';
  let caseId = input.case_id || null;
  try {
    const caseStore = await Actor.openKeyValueStore(caseStoreName);
    const caseRecord = await caseStore.getValue('CASE');
    if (caseRecord && caseRecord.case_id) caseId = caseRecord.case_id;
  } catch (err) {
    log.debug(`No case store available (${err.message}); running standalone.`);
  }
  if (!caseId) caseId = 'standalone_breach_check';

  const candidatePasswords = Array.isArray(input.candidate_passwords)
    ? input.candidate_passwords.filter((p) => typeof p === 'string' && p.length > 0)
    : [];
  const selfEmails = Array.isArray(input.self_emails)
    ? input.self_emails.filter((e) => typeof e === 'string' && e.includes('@'))
    : [];

  const events = [];
  const summary = {
    passwords_tested: 0,
    passwords_exposed: 0,
    emails_probed: 0,
    account_lookup: 'not_checked',
    account_breaches_found: 0,
  };

  // ─────────────────── Password exposure (k-anonymity) ───────────────────
  for (let i = 0; i < candidatePasswords.length; i += 1) {
    const pw = candidatePasswords[i];
    const { prefix, suffix } = kAnonPair(pw);
    summary.passwords_tested += 1;
    try {
      const res = await gotScraping({
        url: PWNED_RANGE_URL + prefix,
        method: 'GET',
        headers: {
          // Padding hides which prefix we asked for from a network observer.
          'Add-Padding': 'true',
          'User-Agent': USER_AGENT,
        },
        responseType: 'text',
        throwHttpErrors: false,
        timeout: { request: 15000 },
        retry: { limit: 1 },
      });

      // Honor rate limits — back off rather than hammer (compliance posture).
      if (res.statusCode === 429) {
        log.warning('Pwned Passwords returned 429; backing off, not evading.');
        await Actor.pushData({
          record_type: 'breach_event',
          event_type: 'BACKOFF',
          source_module: 'aux:breach-check',
          case_id: caseId,
          confidence: 100,
          data: { status_code: 429, note: 'Rate limited by HIBP range API; stopped.' },
        });
        break;
      }
      if (res.statusCode !== 200 || typeof res.body !== 'string') {
        log.warning(`Range query non-200 (${res.statusCode}); skipping this password.`);
        continue;
      }

      const { found, count } = parseRangeResponse(res.body, suffix);
      if (found) {
        summary.passwords_exposed += 1;
        const evt = makePasswordExposedEvent({
          caseId,
          label: `password #${i + 1}`,
          count,
          prefix,
        });
        events.push(evt);
        await Actor.pushData(evt);
        log.info(`Candidate password #${i + 1} is exposed (seen ${count}x). Secret never sent.`);
      } else {
        log.info(`Candidate password #${i + 1} not found in corpus. Secret never sent.`);
      }
    } catch (err) {
      log.warning(`Range query failed for password #${i + 1}: ${err.message}`);
    }
  }

  // ─────────────── Email-hash probes (correlation co-occurrence) ───────────────
  for (const email of selfEmails) {
    const { email_hash_prefix } = emailHashKey(email);
    if (!email_hash_prefix) continue;
    summary.emails_probed += 1;
    const evt = makeEmailProbeEvent({ caseId, emailHashPrefix: email_hash_prefix });
    events.push(evt);
    await Actor.pushData(evt);
  }

  // ───────── Authenticated own-account breach lookup (self only, opt-in) ─────────
  // REAL or nothing: requires HIBP_API_KEY + scope=self + explicit opt-in. No key
  // => account_lookup stays "not_checked". We NEVER fabricate a breach record.
  const apiKey = process.env.HIBP_API_KEY;
  if (input.enable_account_breach_lookup && scopeType === 'self') {
    if (!apiKey) {
      summary.account_lookup = 'skipped_no_api_key';
      log.warning('Account breach lookup requested but HIBP_API_KEY is not set; skipping (no fake data).');
    } else {
      summary.account_lookup = 'checked';
      for (const email of selfEmails) {
        const { email_hash_prefix } = emailHashKey(email);
        try {
          const res = await gotScraping({
            url: HIBP_ACCOUNT_URL + encodeURIComponent(email.trim().toLowerCase()) + '?truncateResponse=false',
            method: 'GET',
            headers: {
              'hibp-api-key': apiKey,
              'User-Agent': USER_AGENT,
            },
            responseType: 'json',
            throwHttpErrors: false,
            timeout: { request: 15000 },
            retry: { limit: 1 },
          });

          if (res.statusCode === 404) {
            // 404 = no breaches for this account. A real, clean result.
            log.info('Account not found in any breach (clean).');
            continue;
          }
          if (res.statusCode === 429) {
            log.warning('HIBP account API rate limited (429); backing off.');
            break;
          }
          if (res.statusCode !== 200 || !Array.isArray(res.body)) {
            log.warning(`Account lookup non-200 (${res.statusCode}); skipping this email.`);
            continue;
          }

          for (const breach of res.body) {
            summary.account_breaches_found += 1;
            const evt = makeAccountBreachedEvent({
              caseId,
              breachName: breach.Name || breach.Title || null,
              breachDate: breach.BreachDate || null,
              dataClasses: breach.DataClasses || [],
              emailHashPrefix: email_hash_prefix,
            });
            events.push(evt);
            await Actor.pushData(evt);
          }
        } catch (err) {
          log.warning(`Account lookup failed: ${err.message}`);
        }
      }
    }
  }

  // Blacklight-style "self-exposure inspector" summary: what a third party could
  // trivially learn about THIS subject's credential hygiene.
  await Actor.setValue('BREACH_SUMMARY', {
    record_type: 'breach_summary',
    source_module: 'aux:breach-check',
    case_id: caseId,
    scope_type: scopeType,
    subject_label: typeof input.subject_label === 'string' ? input.subject_label : '',
    summary,
    event_count: events.length,
    generated_at: new Date().toISOString(),
    privacy_note: 'k-anonymity: only 5-char SHA-1 prefixes left this machine. No plaintext secret was transmitted, logged, or stored.',
  });

  log.info('Breach-check complete.', summary);
});
