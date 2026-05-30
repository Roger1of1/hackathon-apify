/**
 * AUX — Metadata Exposure Scanner (EXIF / XMP / IPTC / PDF info)
 *
 * An auxiliary actor that orbits the core Ex-Ditector pipeline. It answers ONE
 * compliant self-footprint question: "what is leaking out of the files I have
 * ALREADY published publicly?" — GPS coordinates baked into a photo, a camera
 * serial, the editing software, an author name, or a contact email embedded in
 * a PDF. These are classic, fixable self-exposures the subject usually does not
 * know they shipped.
 *
 * ───────────────────────── COMPLIANCE BOUNDARY ─────────────────────────
 * 1. Scope gate: every run is routed through shared/scope.js validateScope, with
 *    the real asset hostnames passed as target_urls so the gate can block
 *    private-social hosts (IG/FB/Tinder…) and laundered intents. It is then
 *    additionally restricted to scope_type ∈ {self, public_figure}: reading
 *    embedded device/location metadata is a DUAL-USE technique and per the
 *    product rules is allowed ONLY for these scopes. We fail CLOSED otherwise.
 * 2. PUBLIC + SELF only: we fetch only URLs the operator supplies as their OWN
 *    (or a public figure's public) assets, logged-out, with no login/captcha/
 *    rate-limit evasion. A 401/403/429 is honored as a STOP, never bypassed.
 * 3. NO FAKE DATA: metadata is parsed from the real downloaded bytes only. A
 *    file with no metadata yields no events. We never invent a coordinate, a
 *    serial, or an author. GPS is coarsened on purpose so we don't re-publish a
 *    pinpoint of the subject's own leak.
 * 4. No romance/gender/sexuality/intimacy/live-location inference anywhere. GPS
 *    in a file the subject published is reported as THEIR geo-hint to strip,
 *    routed through the frozen EVENT_TYPES enum (an unknown type throws).
 * ─────────────────────────────────────────────────────────────────────────
 *
 * REFERENCE PATTERNS APPLIED:
 *  - Crawlee/Apify request-pipeline + Scrapy item-pipeline: each asset URL is a
 *    request; download → parse → map-to-event → push is a linear pipeline stage,
 *    and the scope gate is the first middleware that can drop a request before
 *    any bytes are fetched. Concurrency/back-off mirror polite-crawler defaults.
 *  - SpiderFoot OSINT modules + correlation engine: every result is a TYPED
 *    module-event {event_type, source_module, data, confidence} carrying a
 *    host/email co-occurrence key, so shared/correlation.js can cluster a
 *    metadata leak into the subject's self-exposure cluster.
 *  - HIBP k-anonymity: when an embedded author field is an email, only the
 *    5-char SHA-1 prefix is emitted as a correlation key (via shared/aux/kanon).
 *  - The Markup "Blacklight" self-exposure inspector: output is framed as "what
 *    a third party trivially learns about YOU from your own published files".
 */

'use strict';

const { Actor, log } = require('apify');
const { gotScraping } = require('got-scraping');
const exifr = require('exifr');

const { validateScope, ALLOWED_SCOPES } = require('../../../shared/scope.js');
const { exposureScore } = require('../../../shared/scoring.js');
const {
  SOURCE_MODULE,
  metadataEventsForAsset,
  metadataSummaryEvent,
} = require('../../../shared/aux/metadata-finding.js');

// Dual-use embedded-metadata extraction: ONLY self + public_figure.
const METADATA_SCOPES = new Set(['self', 'public_figure']);

const USER_AGENT = 'ex-ditector-self-footprint-audit';
const MAX_BYTES = 25 * 1024 * 1024; // never download an enormous asset; cap at 25 MB.

function hostnameOf(u) {
  try {
    return new URL(u).hostname;
  } catch {
    return null;
  }
}

Actor.main(async () => {
  const input = (await Actor.getInput()) || {};
  const scopeType = typeof input.scope_type === 'string' ? input.scope_type.trim() : '';

  const assetUrls = (Array.isArray(input.asset_urls) ? input.asset_urls : [])
    .filter((u) => typeof u === 'string' && /^https?:\/\//i.test(u));

  // ── Gate 1: canonical scope gate (the chokepoint the whole product shares). ──
  // We pass the REAL asset URLs so the gate can reject private-social hosts and
  // laundered intents, plus surface subject_label to its free-text scan.
  const gateDecision = validateScope({
    scope_type: scopeType,
    target_urls: assetUrls.length ? assetUrls : ['https://example.invalid/self-metadata-audit'],
    subject_label: input.subject_label,
    description: input.subject_label,
  });

  if (!gateDecision.allowed) {
    log.error('Metadata-exposure refused by scope gate.', {
      reasons: gateDecision.reasons,
      violated: gateDecision.violated_red_lines,
    });
    await Actor.pushData({
      record_type: 'module_event',
      event_type: 'EXPOSURE_SUMMARY',
      source_module: SOURCE_MODULE,
      confidence: 1,
      data: {
        refused: true,
        reasons: gateDecision.reasons,
        violated_red_lines: gateDecision.violated_red_lines,
        alternatives: gateDecision.alternatives,
      },
    });
    await Actor.fail('Metadata-exposure rejected by compliance gate.');
    return;
  }

  // ── Gate 2: dual-use restriction. Even other compliant scopes can't run this. ──
  if (!ALLOWED_SCOPES.includes(scopeType) || !METADATA_SCOPES.has(scopeType)) {
    log.error('Metadata-exposure refused: embedded-metadata extraction is restricted to self/public_figure.', {
      scope_type: scopeType,
    });
    await Actor.fail('Embedded-metadata extraction is allowed only for scope_type=self or public_figure.');
    return;
  }

  // Resolve case id from the shared case store, like the other actors.
  const caseStoreName = input.case_store_name || 'ex-ditector-case';
  let caseId = input.case_id || null;
  try {
    const caseStore = await Actor.openKeyValueStore(caseStoreName);
    const caseRecord = await caseStore.getValue('CASE');
    if (caseRecord && caseRecord.case_id) caseId = caseRecord.case_id;
  } catch (err) {
    log.debug(`No case store available (${err.message}); running standalone.`);
  }
  if (!caseId) caseId = 'standalone_metadata_exposure';

  if (assetUrls.length === 0) {
    log.warning('No asset_urls provided; nothing to scan. (No fake data — empty result.)');
  }

  const allEvents = [];
  let assetsScanned = 0;
  let assetsWithMetadata = 0;
  const distinctHosts = new Set();

  // ── Pipeline: for each asset URL, download → parse → map-to-events → push. ──
  // (Crawlee/Scrapy item-pipeline shape: one stage feeds the next; the gate
  // already acted as the dropping middleware before we got here.)
  for (const url of assetUrls) {
    assetsScanned += 1;
    const host = hostnameOf(url);
    if (host) distinctHosts.add(host);

    let body;
    try {
      const res = await gotScraping({
        url,
        method: 'GET',
        headers: { 'User-Agent': USER_AGENT },
        responseType: 'buffer',
        throwHttpErrors: false,
        timeout: { request: 20000 },
        retry: { limit: 1 },
      });

      // Honor access controls and rate limits — STOP, never evade. (Red line.)
      if (res.statusCode === 401 || res.statusCode === 403) {
        log.warning(`Asset ${url} requires auth (${res.statusCode}); skipping — we do not bypass logins.`);
        continue;
      }
      if (res.statusCode === 429) {
        log.warning('Asset host rate-limited (429); backing off, not evading.');
        await Actor.pushData({
          record_type: 'module_event',
          event_type: 'EXPOSURE_SUMMARY',
          source_module: SOURCE_MODULE,
          case_id: caseId,
          confidence: 1,
          data: { backoff: true, status_code: 429, note: 'Rate limited; stopped fetching.' },
        });
        break;
      }
      if (res.statusCode !== 200 || !Buffer.isBuffer(res.body)) {
        log.warning(`Asset ${url} returned ${res.statusCode}; skipping.`);
        continue;
      }
      if (res.body.length > MAX_BYTES) {
        log.warning(`Asset ${url} exceeds ${MAX_BYTES} bytes; skipping to stay polite.`);
        continue;
      }
      body = res.body;
    } catch (err) {
      log.warning(`Fetch failed for ${url}: ${err.message}`);
      continue;
    }

    // REAL parse only. exifr returns undefined/{} when there is no metadata; we
    // emit nothing in that case (NO FAKE DATA).
    let meta = null;
    try {
      meta = await exifr.parse(body, {
        // Pull the tag groups that actually carry self-exposure.
        gps: true,
        xmp: true,
        iptc: true,
        ifd0: true,
        exif: true,
        // Be defensive: never let one bad tag throw the whole parse.
        translateValues: true,
        reviveValues: true,
      });
    } catch (err) {
      log.debug(`No parseable metadata in ${url}: ${err.message}`);
      meta = null;
    }

    if (!meta || (typeof meta === 'object' && Object.keys(meta).length === 0)) {
      log.info(`Asset ${url} carried no extractable metadata (clean).`);
      continue;
    }

    const events = metadataEventsForAsset({ sourceUrl: url, meta });
    if (events.length === 0) {
      log.info(`Asset ${url} had metadata but nothing sensitive to flag.`);
      continue;
    }
    assetsWithMetadata += 1;
    for (const evt of events) {
      const record = { ...evt, case_id: caseId };
      allEvents.push(record);
      await Actor.pushData(record);
    }
    log.info(`Asset ${url}: ${events.length} metadata exposure event(s).`);
  }

  // Reuse the product's ONLY exposure model — do not reinvent scoring.
  const score = exposureScore({
    reachablePages: assetsScanned,
    distinctHosts: distinctHosts.size,
    indexablePages: assetsWithMetadata,
  });

  const summaryEvent = {
    ...metadataSummaryEvent({
      assetsScanned,
      assetsWithMetadata,
      events: allEvents,
      exposureScore: score,
    }),
    case_id: caseId,
  };
  await Actor.pushData(summaryEvent);

  // Blacklight-style self-exposure inspector summary.
  await Actor.setValue('METADATA_SUMMARY', {
    record_type: 'metadata_summary',
    source_module: SOURCE_MODULE,
    case_id: caseId,
    scope_type: scopeType,
    subject_label: typeof input.subject_label === 'string' ? input.subject_label : '',
    assets_scanned: assetsScanned,
    assets_with_metadata: assetsWithMetadata,
    distinct_hosts: distinctHosts.size,
    exposure_score: score,
    event_count: allEvents.length,
    generated_at: new Date().toISOString(),
    privacy_note:
      'Only metadata you already published was read. GPS is coarsened on purpose; no plaintext author email is stored (only its k-anonymity prefix).',
  });

  log.info('Metadata-exposure complete.', {
    assetsScanned,
    assetsWithMetadata,
    events: allEvents.length,
    exposure_score: score,
  });
});
