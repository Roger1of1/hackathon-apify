/**
 * A3 — Crawler
 *
 * Captures the public pages in the frontier using Crawlee's
 * AdaptivePlaywrightCrawler. For each page we store:
 *   - sha256(normalized visible text)  -> content_sha256 (change detection)
 *   - sha256(raw html)                 -> html_sha256    (tamper fingerprint)
 *   - the raw html                     -> KV  (html_key)
 *   - a full-page screenshot           -> KV  (screenshot_key)
 *
 * ───────────────────────── COMPLIANCE BOUNDARY ─────────────────────────
 * If a source responds 401 / 403 / 429 (auth required / forbidden / rate
 * limited) we treat that as the site telling us to stop. We push a
 * `backoff_for_human_review` record and ABORT the crawl. We DO NOT rotate
 * fingerprints, swap proxies, solve captchas, or otherwise evade the block.
 * This product preserves PUBLIC evidence; defeating access controls is a hard
 * red line. The failedRequestHandler below is where that line is enforced —
 * do not "fix" it by adding evasion.
 * ─────────────────────────────────────────────────────────────────────────
 *
 * Apify rate facts honored: default 60 rps / 200 rps KV. We cap concurrency low,
 * cap total pages (maxRequestsPerCrawl), and back off rather than push limits.
 */

'use strict';

const { Actor, log } = require('apify');
const { AdaptivePlaywrightCrawler } = require('@crawlee/playwright');
const { hashPage } = require('../../../shared/hashing.js');
const { ALLOWED_SCOPES, hostOf, PRIVATE_SOCIAL_HOSTS } = require('../../../shared/scope.js');
const { makeCaptureRecord, makeBackoffRecord } = require('../../../shared/schemas.js');

// HUMAN CONFIG: set DIFF_ACTOR_ID to "roger_1of1/mirrortrace-diff-evidence".
const DIFF_ACTOR_ID = process.env.DIFF_ACTOR_ID || 'roger_1of1/mirrortrace-diff-evidence';

// Status codes that mean "the source is telling us to stop". We honor them.
const BACKOFF_STATUS = new Set([401, 403, 429]);

// Resource types we block to cut cost and avoid hammering CDNs. We only need
// the DOM + a screenshot; fonts/media/big images are noise here.
const BLOCKED_RESOURCE_TYPES = ['media', 'font', 'websocket', 'manifest', 'other'];

Actor.main(async () => {
  const input = (await Actor.getInput()) || {};
  const caseStoreName = input.case_store_name || 'mirrortrace-case';
  const queueName = input.queue_name;
  const maxPages = typeof input.max_pages === 'number' ? input.max_pages : 50;

  // Defense in depth: re-validate scope_type even though we have no target_urls
  // here (the frontier is in the named queue, already vetted at the gate). A bad
  // scope must never reach the crawl, so we refuse anything off the allow-list.
  if (!ALLOWED_SCOPES.includes(input.scope_type)) {
    log.error('Crawler refused: disallowed scope_type.', { scope_type: input.scope_type });
    await Actor.fail('Crawler rejected scope_type.');
    return;
  }

  if (!queueName) {
    log.error('No queue_name provided; the crawler must be reached after discovery.');
    await Actor.fail('Missing queue_name; run discovery first.');
    return;
  }

  const caseStore = await Actor.openKeyValueStore(caseStoreName);
  const caseRecord = await caseStore.getValue('CASE');
  const caseId = (caseRecord && caseRecord.case_id) || input.case_id || 'unknown_case';

  // Open the SAME named queue discovery filled (storage inherited via metamorph).
  const requestQueue = await Actor.openRequestQueue(queueName);

  // Named KV store for binary evidence (html + screenshots). Keyed per case.
  const evidenceStore = await Actor.openKeyValueStore(`mirrortrace-evidence-${caseId}`);

  let captured = 0;
  let aborted = false;

  const crawler = new AdaptivePlaywrightCrawler({
    requestQueue,

    // Cost cap: hard ceiling on pages, mirrors max_pages from the gate.
    maxRequestsPerCrawl: maxPages,

    // Keep concurrency low and polite — we are not trying to max out rate limits.
    maxConcurrency: 3,

    // Let Crawlee learn per-domain whether plain HTTP suffices vs. needing a
    // browser render. Sampling ~25% of requests with the browser keeps cost down
    // while still catching JS-rendered pages.
    renderingTypeDetectionRatio: 0.25,

    // One retry max; if a page keeps failing we move on rather than pound it.
    maxRequestRetries: 1,

    // Block heavy resources before they load (cost + politeness).
    preNavigationHooks: [
      async ({ blockRequests }) => {
        if (typeof blockRequests === 'function') {
          await blockRequests({ extraUrlPatterns: [], resourceTypes: BLOCKED_RESOURCE_TYPES });
        }
      },
    ],

    async requestHandler(ctx) {
      const { request, response, page, parseWithCheerio, enqueueLinks, pushData } = ctx;
      const url = request.url;

      // Final safety net: never capture a private-social/login-walled host even
      // if one slipped into the queue.
      const h = hostOf(url);
      if (h && PRIVATE_SOCIAL_HOSTS.includes(h)) {
        log.warning(`Skipping blocked private-social host at crawl time: ${h}`);
        return;
      }

      const status = response ? response.status() : null;

      // ── COMPLIANCE BOUNDARY (also checked here for browser-mode responses) ──
      // Some servers return 403/429 with a 200-looking navigation; catch it.
      if (status && BACKOFF_STATUS.has(status)) {
        await pushData(makeBackoffRecord({ caseId, url, statusCode: status }));
        log.warning(`Backoff status ${status} at ${url}. Stopping — NOT evading.`);
        aborted = true;
        await crawler.autoscaledPool?.abort();
        return;
      }

      // Extract raw html + visible text. AdaptivePlaywrightCrawler gives us a
      // Cheerio handle even in browser mode via parseWithCheerio.
      let html = '';
      let text = '';
      if (typeof parseWithCheerio === 'function') {
        const $ = await parseWithCheerio();
        html = $.html();
        text = $('body').text() || $.root().text();
      }
      // If a real browser page is available, prefer its rendered text.
      if (page) {
        try {
          html = await page.content();
          text = await page.evaluate(() => document.body ? document.body.innerText : '');
        } catch (err) {
          log.debug(`page content read failed, using cheerio fallback: ${err.message}`);
        }
      }

      const { content_sha256, html_sha256 } = hashPage({ text, html });

      // Persist binary evidence. Keys embed the content hash so identical content
      // overwrites to the same key (idempotent) and is verifiable.
      const safe = encodeURIComponent(url).slice(0, 80);
      const htmlKey = `html-${safe}-${content_sha256.slice(0, 12)}`;
      await evidenceStore.setValue(htmlKey, html, { contentType: 'text/html; charset=utf-8' });

      let screenshotKey = null;
      if (page) {
        try {
          const shot = await page.screenshot({ fullPage: true, type: 'png' });
          screenshotKey = `shot-${safe}-${content_sha256.slice(0, 12)}`;
          await evidenceStore.setValue(screenshotKey, shot, { contentType: 'image/png' });
        } catch (err) {
          log.debug(`screenshot failed for ${url}: ${err.message}`);
        }
      }

      await pushData(makeCaptureRecord({
        caseId,
        url,
        content_sha256,
        html_sha256,
        html_key: htmlKey,
        screenshot_key: screenshotKey,
        statusCode: status,
      }));

      captured += 1;

      // Same-host expansion ONLY, and only while under the page cap. We never
      // wander off the vetted seeds' hosts.
      if (captured < maxPages && typeof enqueueLinks === 'function') {
        await enqueueLinks({
          strategy: 'same-hostname',
          userData: { caseId, depth: (request.userData?.depth || 0) + 1, source: 'expand' },
        });
      }
    },

    // ──────────────────── COMPLIANCE BOUNDARY ────────────────────
    // On a hard block we STOP. No fingerprint rotation, no proxy swap, no
    // captcha solving. The backoff record is the deliverable: it tells a human
    // "this source blocked us; review/contact them" instead of silently evading.
    async failedRequestHandler({ request, response }, error) {
      const status = response ? response.status() : (error && error.statusCode) || null;
      if (status && BACKOFF_STATUS.has(status)) {
        await Actor.pushData(makeBackoffRecord({
          caseId,
          url: request.url,
          statusCode: status,
          note: `Source returned ${status}. Stopped instead of evading rate limits / login walls. Needs human review.`,
        }));
        log.warning(`COMPLIANCE STOP: ${status} on ${request.url}. Aborting crawl, not rotating fingerprints.`);
        aborted = true;
        await crawler.autoscaledPool?.abort();
        return;
      }
      // Other failures (timeouts, DNS) are just logged; not a compliance event.
      await Actor.pushData(makeBackoffRecord({
        caseId,
        url: request.url,
        statusCode: status,
        note: `Request failed (${error ? error.message : 'unknown'}). Logged for review.`,
      }));
      log.error(`Request failed for ${request.url}: ${error ? error.message : 'unknown'}`);
    },
  });

  log.info('Crawler starting.', { caseId, queueName, maxPages });
  await crawler.run();
  log.info('Crawl finished.', { caseId, captured, aborted });

  // Hand off to the diff/evidence stage regardless — even a partial/aborted
  // crawl produced real captures worth diffing. We never fabricate the rest.
  await Actor.metamorph(DIFF_ACTOR_ID, {
    case_id: caseId,
    case_store_name: caseStoreName,
    evidence_store_name: `mirrortrace-evidence-${caseId}`,
    scope_type: input.scope_type,
    checks_per_day: input.checks_per_day || 0,
    crawl_aborted: aborted,
    captured_count: captured,
  });
});
