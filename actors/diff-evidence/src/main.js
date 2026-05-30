/**
 * A5 — Diff & Evidence Index
 *
 * Compares this run's captures against the LAST KNOWN content_sha256 per URL,
 * stored in a named KV store. Emits an IMMUTABLE evidence index of only REAL
 * changes (new URLs, or URLs whose content hash actually changed). Unchanged
 * pages are not re-reported — we never fabricate "activity".
 *
 * The previous-state store persists across runs so repeat audits become true
 * change monitoring. After diffing, we update the baseline to the current run's
 * hashes so the NEXT run diffs against today.
 *
 * Evidence index entries are append-only: each carries its own timestamp + the
 * content/html hashes + the KV keys of the preserved html and screenshot, so the
 * index is a verifiable, tamper-evident record.
 *
 * No fabrication: if there were no captures (e.g. the crawl was blocked and
 * aborted), we emit an empty index and say so honestly.
 */

'use strict';

const { Actor, log } = require('apify');
const { makeEvidenceIndexEntry } = require('../../../shared/schemas.js');

// HUMAN CONFIG: set REPORT_ACTOR_ID to "<YOUR_USERNAME>/mirrortrace-report-builder".
const REPORT_ACTOR_ID = process.env.REPORT_ACTOR_ID || 'YOUR_USERNAME/mirrortrace-report-builder';

/**
 * Read every `capture` record this case produced from the default dataset.
 * Captures were pushed by the crawler before it metamorphed into us (datasets
 * are inherited across metamorph), so they are all here.
 */
async function loadCaptures(caseId) {
  const dataset = await Actor.openDataset();
  const captures = [];
  await dataset.forEach((item) => {
    if (item && item.record_type === 'capture' && item.case_id === caseId) {
      captures.push(item);
    }
  });
  // If the same URL was captured multiple times in one run, keep the latest.
  const byUrl = new Map();
  for (const c of captures) {
    const prev = byUrl.get(c.url);
    if (!prev || new Date(c.captured_at) >= new Date(prev.captured_at)) {
      byUrl.set(c.url, c);
    }
  }
  return [...byUrl.values()];
}

Actor.main(async () => {
  const input = (await Actor.getInput()) || {};
  const caseStoreName = input.case_store_name || 'mirrortrace-case';
  const caseStore = await Actor.openKeyValueStore(caseStoreName);
  const caseRecord = await caseStore.getValue('CASE');
  const caseId = (caseRecord && caseRecord.case_id) || input.case_id || 'unknown_case';

  // Named baseline store: maps url -> { content_sha256, ... } from the LAST run.
  const baselineStore = await Actor.openKeyValueStore(`mirrortrace-baseline-${caseId}`);

  const captures = await loadCaptures(caseId);
  log.info('Diff stage loaded captures.', { caseId, count: captures.length });

  const evidenceIndex = [];
  let changed = 0;
  let newCount = 0;
  let unchanged = 0;

  for (const cap of captures) {
    // KV keys cannot contain arbitrary chars; mirror the crawler's encoding.
    const baselineKey = `base-${encodeURIComponent(cap.url).slice(0, 90)}`;
    const prev = await baselineStore.getValue(baselineKey);

    let change;
    if (!prev) {
      change = 'new';
      newCount += 1;
    } else if (prev.content_sha256 !== cap.content_sha256) {
      change = 'changed';
      changed += 1;
    } else {
      unchanged += 1;
      continue; // REAL changes only — skip unchanged pages entirely.
    }

    const entry = makeEvidenceIndexEntry({
      caseId,
      url: cap.url,
      content_sha256: cap.content_sha256,
      html_sha256: cap.html_sha256,
      screenshot_key: cap.screenshot_key,
      html_key: cap.html_key,
      change,
    });
    if (prev) entry.previous_content_sha256 = prev.content_sha256;

    evidenceIndex.push(entry);
    await Actor.pushData(entry); // append-only audit record in the dataset

    // Update the baseline so the NEXT run diffs against today.
    await baselineStore.setValue(baselineKey, {
      url: cap.url,
      content_sha256: cap.content_sha256,
      html_sha256: cap.html_sha256,
      html_key: cap.html_key,
      screenshot_key: cap.screenshot_key,
      updated_at: new Date().toISOString(),
    });
  }

  // Persist the full immutable index for this run under a stable key for the
  // report builder to consume.
  await caseStore.setValue('EVIDENCE_INDEX', {
    case_id: caseId,
    generated_at: new Date().toISOString(),
    summary: {
      captures: captures.length,
      new: newCount,
      changed,
      unchanged,
      crawl_aborted: !!input.crawl_aborted,
    },
    entries: evidenceIndex,
  });

  log.info('Diff complete.', { caseId, new: newCount, changed, unchanged });

  // Hand off to the report builder.
  await Actor.metamorph(REPORT_ACTOR_ID, {
    case_id: caseId,
    case_store_name: caseStoreName,
    scope_type: input.scope_type,
    checks_per_day: input.checks_per_day || 0,
  });
});
