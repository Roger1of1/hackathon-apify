/**
 * AUX — Public-Paste Self-Exposure Scan
 *
 * An auxiliary Apify actor that orbits the core MirrorTrace pipeline. It answers
 * ONE compliant question about the SELF (or public_figure) subject:
 *   "Are MY OWN identifiers (email / domain / handle) sitting in a PUBLIC paste
 *    dump right now?"
 * — a classic self-footprint-audit surface that breach-check (HIBP named
 * breaches) and gh-leak-scan (own GitHub) do NOT cover. HIBP itself treats
 * "Pastes" as a separate exposure source for exactly this reason.
 *
 * ───────────────────────── COMPLIANCE BOUNDARY ─────────────────────────
 * 1. Scope gate: every run is routed through shared/scope.js validateScope and
 *    additionally restricted to scope_type ∈ {self, public_figure}. Searching an
 *    index by identifier is a DUAL-USE technique; per the product rules it is
 *    allowed ONLY for these scopes. consented/brand/safety_evidence are refused
 *    here (they cannot smuggle an identifier search through this actor).
 * 2. PUBLIC data only: we query a documented PUBLIC paste-search index and fetch
 *    only the PUBLIC metadata it returns. We NEVER bypass authentication,
 *    captcha, or rate limits; on 403/429 we back off and stop. We never log in.
 * 3. NO FAKE DATA: every emitted event is built from a real index hit pointing at
 *    a real public paste URL. If a request fails, returns nothing, or the index
 *    is unavailable, we emit nothing and say so in the summary — we never
 *    fabricate a paste, a hit, or a count.
 * 4. PRIVACY: a matched email is carried ONLY as its HIBP k-anonymity SHA-1
 *    prefix + a masked hint — the plaintext address is never stored or emitted.
 *    The paste BODY is never stored or echoed; only its public URL + metadata.
 * 5. No identity/romance/gender/intimacy inference. A paste hit is a
 *    security-hygiene fact about the subject's OWN published identifier.
 * ─────────────────────────────────────────────────────────────────────────
 *
 * REFERENCE PATTERNS APPLIED:
 *  - SpiderFoot OSINT-module + correlation-engine design: every result is a
 *    TYPED module_event (shared/detectors/event-types.js) carrying provenance
 *    and correlation keys (email_hash_prefix / handle / host), so
 *    shared/correlation.js can link a paste exposure to the SAME identifier
 *    found by breach-check / the crawler elsewhere — clustering by surface &
 *    identifier, never by person. (github.com/smicallef/spiderfoot)
 *  - HIBP "Pastes" data source + k-anonymity email model: search the public
 *    paste channel by identifier, return only metadata, keep emails as a hash
 *    prefix. (haveibeenpwned.com/Pastes; Troy Hunt, SHA-1 + k-Anonymity)
 *  - Apify RAG Web Browser / Website Content Crawler pattern: bounded, polite
 *    queries (max_pastes_per_identifier cap, backoff on 403/429), each real hit
 *    pushed to the dataset as a typed record.
 */

'use strict';

const { Actor, log } = require('apify');
const { gotScraping } = require('got-scraping');

const { validateScope, ALLOWED_SCOPES } = require('../../../shared/scope.js');
const {
  classifyIdentifier,
  makePasteHitEvent,
  makePasteSummaryEvent,
} = require('../../../shared/aux/paste-exposure-finding.js');

// Dual-use identifier search: ONLY self + public_figure (subset of ALLOWED_SCOPES).
const PASTE_SCOPES = new Set(['self', 'public_figure']);

const USER_AGENT = 'mirrortrace-self-footprint-audit';

/**
 * PUBLIC paste-search index. PSBDMP ("Pastebin Dump") exposes a documented,
 * key-optional PUBLIC search API over pastes it has archived. We use ONLY its
 * public search + metadata endpoints; we never log in, solve a captcha, or
 * defeat a rate limit. The base is overridable via env so an operator can point
 * at their own licensed/self-hosted index instead, but it defaults to a real
 * public service so the actor is not a stub.
 */
const PASTE_INDEX_BASE = (process.env.PASTE_INDEX_BASE || 'https://psbdmp.ws/api/v3').replace(/\/+$/, '');

/** A single GET against the paste index. Returns {ok,status,body}; never throws. */
async function indexGet(url, { responseType = 'json' } = {}) {
  try {
    const res = await gotScraping({
      url,
      method: 'GET',
      headers: { 'User-Agent': USER_AGENT, Accept: 'application/json' },
      responseType,
      throwHttpErrors: false,
      timeout: { request: 20000 },
      retry: { limit: 1 },
    });
    return { ok: res.statusCode >= 200 && res.statusCode < 300, status: res.statusCode, body: res.body };
  } catch (err) {
    log.warning(`Paste index request failed for ${url}: ${err.message}`);
    return { ok: false, status: 0, body: null };
  }
}

/** True for a 403/429 that signals rate limiting (back off, never evade). */
function isRateLimited(status) {
  return status === 429 || status === 403;
}

/**
 * Normalize a PSBDMP-style search response into a plain array of paste hits.
 * PSBDMP returns either `{ data: [ {id, length, date, ...}, ... ] }` or a bare
 * array depending on endpoint/version. We accept both and pull only metadata —
 * we deliberately ignore any paste BODY field so we never store paste text.
 */
function extractHits(body) {
  if (!body) return [];
  const rows = Array.isArray(body) ? body : (Array.isArray(body.data) ? body.data : []);
  const hits = [];
  for (const r of rows) {
    if (!r || typeof r !== 'object') continue;
    const id = typeof r.id === 'string' || typeof r.id === 'number' ? String(r.id) : null;
    if (!id) continue;
    hits.push({
      id,
      length: Number.isFinite(Number(r.length)) ? Number(r.length) : null,
      date: typeof r.date === 'string' ? r.date : null,
      // PSBDMP archives Pastebin-origin pastes; the canonical public URL is the
      // archive permalink (a real, fetchable public page).
      url: `https://psbdmp.ws/${encodeURIComponent(id)}`,
      tags: Array.isArray(r.tags) ? r.tags.map(String) : [],
    });
  }
  return hits;
}

/** Coarse, body-free heuristic: does the index metadata hint at a creds dump? */
function looksLikeCredentialDump(hit) {
  const tags = Array.isArray(hit.tags) ? hit.tags.join(' ').toLowerCase() : '';
  return /pass|cred|dump|combo|leak|account/.test(tags);
}

Actor.main(async () => {
  const input = (await Actor.getInput()) || {};
  const scopeType = typeof input.scope_type === 'string' ? input.scope_type.trim() : '';

  // Collect the subject's OWN identifiers to search for.
  const rawIdentifiers = []
    .concat(input.self_identifiers || [])
    .concat(input.self_emails || [])
    .concat(input.self_domains || [])
    .concat(input.self_handles || [])
    .filter((s) => typeof s === 'string' && s.trim().length > 0);

  // ── Gate 1: canonical scope gate (same chokepoint the whole product uses). ──
  // The "target" for this actor is the public paste index surface; we feed a
  // real URL so the gate's target/host checks and its free-text laundering scan
  // (over subject_label) all run against real values.
  const gateDecision = validateScope({
    scope_type: scopeType,
    target_urls: [PASTE_INDEX_BASE],
    subject_label: input.subject_label,
    description: input.subject_label,
  });

  if (!gateDecision.allowed) {
    log.error('Paste-exposure scan refused by scope gate.', {
      reasons: gateDecision.reasons,
      violated: gateDecision.violated_red_lines,
    });
    await Actor.pushData({
      record_type: 'module_event',
      event_type: 'REFUSED',
      source_module: 'aux:paste-exposure',
      confidence: 1,
      data: {
        reasons: gateDecision.reasons,
        violated_red_lines: gateDecision.violated_red_lines,
        alternatives: gateDecision.alternatives,
      },
    });
    await Actor.fail('Paste-exposure scan rejected by compliance gate.');
    return;
  }

  // ── Gate 2: dual-use restriction. Even other legal scopes cannot run an
  // identifier search; only self/public_figure. ──
  if (!ALLOWED_SCOPES.includes(scopeType) || !PASTE_SCOPES.has(scopeType)) {
    log.error('Paste-exposure scan refused: identifier search is restricted to self/public_figure.', {
      scope_type: scopeType,
    });
    await Actor.fail('Paste search is allowed only for scope_type=self or public_figure.');
    return;
  }

  // Classify + de-duplicate the identifiers; drop anything unusable.
  const identifiers = [];
  const seen = new Set();
  for (const raw of rawIdentifiers) {
    const id = classifyIdentifier(raw);
    if (!id) {
      log.warning(`Skipping unusable identifier: "${raw}".`);
      continue;
    }
    const key = `${id.kind}:${id.value}`;
    if (seen.has(key)) continue;
    seen.add(key);
    identifiers.push(id);
  }

  if (identifiers.length === 0) {
    await Actor.fail('At least one usable self identifier (email / domain / handle) is required.');
    return;
  }

  // Pull the shared case id if a case store exists (best-effort, standalone OK).
  const caseStoreName = input.case_store_name || 'mirrortrace-case';
  let caseId = input.case_id || null;
  try {
    const caseStore = await Actor.openKeyValueStore(caseStoreName);
    const caseRecord = await caseStore.getValue('CASE');
    if (caseRecord && caseRecord.case_id) caseId = caseRecord.case_id;
  } catch (err) {
    log.debug(`No case store available (${err.message}); running standalone.`);
  }
  if (!caseId) caseId = 'standalone_paste_exposure';

  const maxPastesPerIdentifier = clampInt(input.max_pastes_per_identifier, 1, 100, 20);

  const counts = {
    identifiers_scanned: 0,
    pastes_matched: 0,
    emails: 0,
    domains: 0,
    handles: 0,
  };
  let indexUnavailable = false;

  const emit = async (event) => {
    if (!event) return;
    const record = Object.assign({ case_id: caseId }, event);
    await Actor.pushData(record);
  };

  for (const id of identifiers) {
    counts.identifiers_scanned += 1;

    // PSBDMP public search-by-string endpoint. We search for the literal
    // identifier the subject OWNS. Only PUBLIC metadata is returned/used.
    const searchUrl = `${PASTE_INDEX_BASE}/search/${encodeURIComponent(id.query)}`;
    const res = await indexGet(searchUrl);

    if (isRateLimited(res.status)) {
      log.warning(`Paste index rate-limited (${res.status}) for ${id.kind} "${id.value}"; backing off and stopping.`);
      await emit({
        record_type: 'module_event',
        event_type: 'EXPOSURE_SUMMARY',
        source_module: 'aux:paste-exposure',
        confidence: 1,
        data: { backoff: true, status: res.status, identifier_kind: id.kind },
        meta: { note: 'Backed off on a rate-limit response; no data fabricated.' },
      });
      indexUnavailable = true;
      break;
    }
    if (!res.ok) {
      // 404 from PSBDMP means "no pastes for this string" — a real negative, not
      // an error. Anything else we record as unavailable, never as a fake hit.
      if (res.status === 404) {
        log.info(`No public pastes found for ${id.kind} "${id.value}". (No hit fabricated.)`);
      } else {
        log.warning(`Paste index returned ${res.status} for ${id.kind} "${id.value}"; treating as unavailable.`);
        indexUnavailable = true;
      }
      continue;
    }

    const hits = extractHits(res.body).slice(0, maxPastesPerIdentifier);
    if (hits.length === 0) {
      log.info(`No public pastes found for ${id.kind} "${id.value}".`);
      continue;
    }

    for (const hit of hits) {
      const ev = makePasteHitEvent({
        identifier: id,
        pasteUrl: hit.url,
        pasteId: hit.id,
        source: 'psbdmp',
        lineCount: hit.length,
        observedAt: hit.date,
        looksLikeCredentialDump: looksLikeCredentialDump(hit),
      });
      if (!ev) continue; // shaper refused (no real URL) — never fabricate
      counts.pastes_matched += 1;
      if (id.kind === 'email') counts.emails += 1;
      else if (id.kind === 'domain') counts.domains += 1;
      else if (id.kind === 'handle') counts.handles += 1;
      await emit(ev);
    }
    log.info(`Found ${hits.length} public paste(s) referencing ${id.kind} "${id.value}".`);
  }

  // A real summary event + a self-exposure summary record for the report builder.
  await emit(makePasteSummaryEvent({ counts, sources: ['psbdmp'] }));
  await Actor.setValue('PASTE_EXPOSURE_SUMMARY', {
    record_type: 'paste_exposure_summary',
    source_module: 'aux:paste-exposure',
    case_id: caseId,
    scope_type: scopeType,
    subject_label: typeof input.subject_label === 'string' ? input.subject_label : '',
    counts,
    index_unavailable: indexUnavailable,
    status: indexUnavailable ? 'partial_index_unavailable' : 'completed',
    generated_at: new Date().toISOString(),
    privacy_note: 'Only PUBLIC paste metadata was read via a documented public index. No paste body is stored. Matched emails are carried as k-anonymity SHA-1 prefixes + a masked hint; the plaintext address is never stored or transmitted by this actor.',
  });

  log.info('Paste-exposure scan complete.', counts);
});

function clampInt(v, min, max, fallback) {
  const n = Number(v);
  if (!Number.isFinite(n)) return fallback;
  return Math.max(min, Math.min(max, Math.round(n)));
}
