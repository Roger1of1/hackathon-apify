/**
 * AUX — Public-Archive Self-Exposure Audit
 *
 * An auxiliary actor that orbits the core Ex-Ditector pipeline. It answers ONE
 * compliant question about the SELF subject: "what did I publish that I LATER
 * deleted, but which still lives in a PUBLIC web archive?" A live-only audit
 * misses this entirely. The Internet Archive Wayback Machine keeps public
 * snapshots forever, so an old page that exposed the subject's email, phone, or
 * a former handle is still trivially retrievable by anyone — until the subject
 * requests its removal. This actor surfaces exactly those archived exposures.
 *
 * ───────────────────────── COMPLIANCE BOUNDARY ─────────────────────────
 * 1. Scope gate (FAIL-CLOSED, runs BEFORE any network call): every run is routed
 *    through shared/scope.js validateScope, and additionally restricted to
 *    scope_type ∈ {self, public_figure}. Querying every archived snapshot under a
 *    URL prefix is a DUAL-USE technique; per the product rules it is allowed ONLY
 *    for these scopes. consented/brand/safety_evidence are refused here.
 * 2. PUBLIC data only: we call the Internet Archive's documented public CDX index
 *    and fetch PUBLIC archived snapshots. We NEVER bypass authentication, captcha,
 *    or rate limits — on 429/403 we back off, we do not evade.
 * 3. NO FAKE DATA: every emitted event is built from a CDX row actually returned
 *    or a snapshot actually fetched. Empty archive ⇒ zero events, never a
 *    fabricated snapshot, URL, or PII hit.
 * 4. No identity/romance/gender/intimacy inference, no third-private-party data.
 *    An archived snapshot is a public fact about the SELF subject's OWN page.
 * ─────────────────────────────────────────────────────────────────────────
 *
 * REFERENCE PATTERNS APPLIED (both this round's assigned architectures):
 *  - OpenCTI / MISP + STIX 2.1 evidence-object model: a Wayback CDX row is an
 *    *observation of a URL at a time, with a content digest* — i.e. a STIX 2.1
 *    Observed Data object. We carry the REAL snapshot timestamp + digest so
 *    shared/enrich/stix-evidence.js dates each Observed Data to the true capture
 *    time (first_observed/last_observed), making the finding portable into a
 *    takedown desk, OpenCTI, or MISP as a standard STIX bundle.
 *    (OASIS STIX 2.1 Observed Data SDO; OpenCTI/MISP STIX 2.1 interop.)
 *  - Apify Website Content Crawler + RAG Web Browser ingestion pattern: a
 *    bounded, polite fetch of PUBLIC web content (max_snapshots cap, backoff on
 *    429/403, text extraction), each fetched item mapped into a typed dataset
 *    record. WCC's job is "turn a URL into clean text for downstream processing";
 *    we do the same for archived snapshots, then run the SHARED pii detector over
 *    the extracted text instead of reinventing extraction/detection.
 *    (apify/website-content-crawler, apify/rag-web-browser.)
 *  - SpiderFoot event-driven OSINT modules: every result is a TYPED module_event
 *    (event_type/source_module/data/confidence/source_url) so the shared
 *    correlation engine can link an archived exposure to the SAME surface found
 *    live by the crawler. (github.com/smicallef/spiderfoot)
 */

'use strict';

const { Actor, log } = require('apify');
const { gotScraping } = require('got-scraping');

const { validateScope, ALLOWED_SCOPES } = require('../../../shared/scope.js');
const { detectPii } = require('../../../shared/detectors/pii-detector.js');
const {
  MODULE,
  waybackTimestampToISO,
  waybackReplayUrl,
  makeArchivedUrlEvent,
  makeArchivedPiiEvent,
  makeSummaryEvent,
} = require('../../../shared/aux/archive-finding.js');
const { VISIBILITY } = require('../../../shared/detectors/event-types.js');

// Dual-use archive enumeration: ONLY self + public_figure (subset of ALLOWED_SCOPES).
const ARCHIVE_SCOPES = new Set(['self', 'public_figure']);

const CDX_ENDPOINT = 'https://web.archive.org/cdx/search/cdx';
const USER_AGENT = 'ex-ditector-self-footprint-audit';
const MAX_SNAPSHOT_BYTES = 1024 * 1024; // 1 MB cap per snapshot; we only need text

/** True for a 429/403 that signals rate limiting — back off, never evade. */
function isRateLimited(status) {
  return status === 429 || status === 403;
}

/** A single GET via got-scraping. Returns { ok, status, body }; never throws. */
async function httpGet(url, { responseType = 'text' } = {}) {
  try {
    const res = await gotScraping({
      url,
      method: 'GET',
      headers: { 'User-Agent': USER_AGENT },
      responseType,
      throwHttpErrors: false,
      timeout: { request: 30000 },
      retry: { limit: 1 },
    });
    return { ok: res.statusCode >= 200 && res.statusCode < 300, status: res.statusCode, body: res.body };
  } catch (err) {
    log.warning(`Archive request failed for ${url}: ${err.message}`);
    return { ok: false, status: 0, body: null };
  }
}

function clampInt(v, min, max, fallback) {
  const n = Number(v);
  if (!Number.isFinite(n)) return fallback;
  return Math.max(min, Math.min(max, Math.round(n)));
}

/** Strip HTML to plain text for the shared PII detector (WCC-style extraction). */
function htmlToText(html) {
  if (typeof html !== 'string') return '';
  return html
    .replace(/<script[\s\S]*?<\/script>/gi, ' ')
    .replace(/<style[\s\S]*?<\/style>/gi, ' ')
    .replace(/<[^>]+>/g, ' ')
    .replace(/&nbsp;/gi, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

Actor.main(async () => {
  const input = (await Actor.getInput()) || {};
  const scopeType = typeof input.scope_type === 'string' ? input.scope_type.trim() : '';
  const subjectUrl = typeof input.subject_url === 'string' ? input.subject_url.trim() : '';

  // ── Gate 1: canonical scope gate (same chokepoint the whole product uses). ──
  // FAIL-CLOSED: this runs BEFORE any archive query. The subject's own URL is the
  // real target, so the gate's target/host checks and its free-text laundering
  // scan over subject_label/description all run against real values.
  const gateDecision = validateScope({
    scope_type: scopeType,
    target_urls: subjectUrl ? [subjectUrl] : [],
    subject_label: input.subject_label,
    description: input.subject_label,
  });

  if (!gateDecision.allowed) {
    log.error('Archive self-exposure audit refused by scope gate.', {
      reasons: gateDecision.reasons,
      violated: gateDecision.violated_red_lines,
    });
    await Actor.pushData({
      record_type: 'archive_event',
      event_type: 'REFUSED',
      source_module: MODULE,
      confidence: 1,
      data: {
        reasons: gateDecision.reasons,
        violated_red_lines: gateDecision.violated_red_lines,
        alternatives: gateDecision.alternatives,
      },
    });
    await Actor.fail('Archive self-exposure audit rejected by compliance gate.');
    return;
  }

  // ── Gate 2: dual-use restriction. Even other legal scopes cannot enumerate an
  // archive prefix; only self/public_figure. ──
  if (!ALLOWED_SCOPES.includes(scopeType) || !ARCHIVE_SCOPES.has(scopeType)) {
    log.error('Archive audit refused: archive enumeration is restricted to self/public_figure.', {
      scope_type: scopeType,
    });
    await Actor.fail('Archive enumeration is allowed only for scope_type=self or public_figure.');
    return;
  }

  if (!subjectUrl) {
    await Actor.fail('A subject_url (a URL/host you own) is required.');
    return;
  }

  // Pull the shared case id if a case store exists (best-effort, standalone OK).
  const caseStoreName = input.case_store_name || 'ex-ditector-case';
  let caseId = input.case_id || null;
  try {
    const caseStore = await Actor.openKeyValueStore(caseStoreName);
    const caseRecord = await caseStore.getValue('CASE');
    if (caseRecord && caseRecord.case_id) caseId = caseRecord.case_id;
  } catch (err) {
    log.debug(`No case store available (${err.message}); running standalone.`);
  }
  if (!caseId) caseId = 'standalone_archive_exposure';

  const matchPrefix = input.match_prefix !== false; // default: prefix match the whole host/path
  const maxSnapshots = clampInt(input.max_snapshots, 1, 500, 50);
  const scanPii = input.scan_snapshot_pii === true; // default off: listing is cheaper & sufficient

  const emit = async (event) => {
    const record = Object.assign({ case_id: caseId, record_type: 'archive_event' }, event);
    await Actor.pushData(record);
    return record;
  };

  // ── Step 1: query the PUBLIC Wayback CDX index for snapshots of the subject URL.
  // collapse=digest dedupes identical captures; limit caps the result set. ──
  const cdxParams = new URLSearchParams({
    url: matchPrefix ? `${subjectUrl}*` : subjectUrl,
    output: 'json',
    fl: 'original,timestamp,digest,mimetype,statuscode',
    collapse: 'digest',
    limit: String(maxSnapshots),
  });
  const cdxUrl = `${CDX_ENDPOINT}?${cdxParams.toString()}`;

  const cdxRes = await httpGet(cdxUrl, { responseType: 'json' });
  if (isRateLimited(cdxRes.status)) {
    log.warning('Internet Archive rate limited the CDX query; backing off (no data fabricated).');
    await emit({ event_type: 'BACKOFF', source_module: MODULE, confidence: 1, data: { status: cdxRes.status } });
    return;
  }
  if (!cdxRes.ok || !Array.isArray(cdxRes.body)) {
    log.info('No archive index returned (or empty). Nothing archived to surface — no event fabricated.');
    await Actor.setValue('ARCHIVE_SUMMARY', summaryRecord(caseId, scopeType, input, subjectUrl, { snapshots: 0, unique_urls: 0, pii_in_archive: 0 }, 'no_archive_data'));
    return;
  }

  // CDX JSON: first row is the header ["original","timestamp","digest",...].
  const rows = cdxRes.body.slice(1).filter((r) => Array.isArray(r) && r.length >= 2);
  if (rows.length === 0) {
    log.info(`No public archived snapshots found for ${subjectUrl}. (Honest empty result.)`);
    await Actor.setValue('ARCHIVE_SUMMARY', summaryRecord(caseId, scopeType, input, subjectUrl, { snapshots: 0, unique_urls: 0, pii_in_archive: 0 }, 'no_snapshots'));
    return;
  }

  const counts = { snapshots: 0, unique_urls: 0, pii_in_archive: 0 };
  const seenUrls = new Set();
  let earliestISO = null;
  let latestISO = null;

  for (const row of rows) {
    const [original, timestamp, digest, mimetype, statuscode] = row;
    const event = makeArchivedUrlEvent({
      original,
      timestamp,
      digest,
      mimetype,
      statuscode,
      subjectUrlPrefix: subjectUrl,
    });
    if (!event) continue; // unparseable row → skip, never fabricate

    counts.snapshots += 1;
    if (typeof original === 'string') seenUrls.add(original);

    const observedISO = event.meta.observed_at;
    if (observedISO) {
      if (!earliestISO || observedISO < earliestISO) earliestISO = observedISO;
      if (!latestISO || observedISO > latestISO) latestISO = observedISO;
    }

    await emit(event);

    // ── Step 2 (optional): fetch the archived snapshot text and run the SHARED
    // PII detector over it (WCC-style: URL → clean text → typed records). Only
    // a self/public_figure scope reaches here; the value is the subject's OWN. ──
    if (scanPii) {
      const replayUrl = waybackReplayUrl(timestamp, original);
      if (replayUrl) {
        const snapRes = await httpGet(replayUrl, { responseType: 'text' });
        if (isRateLimited(snapRes.status)) {
          log.warning('Rate limited fetching an archived snapshot; stopping snapshot PII scan.');
          break;
        }
        if (snapRes.ok && typeof snapRes.body === 'string' && snapRes.body.length <= MAX_SNAPSHOT_BYTES) {
          const text = htmlToText(snapRes.body);
          // Reuse the shared detector — do NOT reimplement PII regexes here.
          const piiEvents = detectPii({ text, url: replayUrl, visibility: VISIBILITY.INDEXED });
          for (const pii of piiEvents) {
            const archived = makeArchivedPiiEvent({
              event_type: pii.event_type,
              data: pii.data,
              replayUrl,
              observedISO,
              original,
              confidence: pii.confidence,
            });
            if (archived) {
              // carry the detector's correlation keys (e.g. email_hash_prefix).
              archived.meta = Object.assign({}, pii.meta, archived.meta);
              counts.pii_in_archive += 1;
              await emit(archived);
              log.info(`PII (${pii.event_type}) found in archived snapshot ${replayUrl}.`);
            }
          }
        }
      }
    }
  }

  counts.unique_urls = seenUrls.size;

  // ── Step 3: a real summary event + a Blacklight-style self-exposure record. ──
  await emit(makeSummaryEvent({ subjectUrlPrefix: subjectUrl, counts, earliestISO, latestISO }));
  await Actor.setValue(
    'ARCHIVE_SUMMARY',
    summaryRecord(caseId, scopeType, input, subjectUrl, counts, 'completed', { earliestISO, latestISO }),
  );

  log.info('Archive self-exposure audit complete.', counts);
});

function summaryRecord(caseId, scopeType, input, subjectUrl, counts, status, extra = {}) {
  return {
    record_type: 'archive_summary',
    source_module: MODULE,
    case_id: caseId,
    scope_type: scopeType,
    subject_label: typeof input.subject_label === 'string' ? input.subject_label : '',
    subject_url: subjectUrl,
    status,
    counts,
    earliest_observed: extra.earliestISO || null,
    latest_observed: extra.latestISO || null,
    generated_at: new Date().toISOString(),
    privacy_note: 'Only PUBLIC Internet Archive (Wayback) snapshots were read via the documented CDX API. Each finding carries the true archive capture time + content digest so it can be exported as a STIX 2.1 Observed Data object for a takedown request.',
  };
}
