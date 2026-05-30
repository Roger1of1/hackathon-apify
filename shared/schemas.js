/**
 * shared/schemas.js
 *
 * Lightweight, dependency-free shape builders + validators for the records that
 * flow between actors and into named storages. Keeping them in one place means
 * every actor emits the SAME structure, so the diff and report stages can rely
 * on it. These are plain objects, not a schema framework, to keep the actor
 * images small.
 */

'use strict';

/**
 * The immutable CASE record written by the Policy Gate. Once written it is the
 * authorization-of-record for everything downstream.
 */
function makeCaseRecord({ caseId, scope_type, target_urls, subject_label, authorization_evidence_url, runId, actorId }) {
  return {
    record_type: 'case',
    case_id: caseId,
    scope_type,
    target_urls: Array.isArray(target_urls) ? target_urls : [],
    subject_label: subject_label || '',
    authorization_evidence_url: authorization_evidence_url || null,
    opened_at: new Date().toISOString(),
    opened_by_run_id: runId || null,
    opened_by_actor_id: actorId || null,
    immutable: true,
  };
}

/**
 * A decision-log entry. Both passes AND rejections are logged for audit.
 */
function makeDecisionLog({ caseId, decision, validation, runId }) {
  return {
    record_type: 'decision_log',
    case_id: caseId || null,
    decision, // 'allow' | 'reject'
    allowed: validation.allowed,
    reasons: validation.reasons,
    violated_red_lines: validation.violated_red_lines,
    alternatives: validation.alternatives,
    scope_type: validation.scope_type,
    decided_at: new Date().toISOString(),
    run_id: runId || null,
  };
}

/**
 * One discovered URL queued for crawling.
 */
function makeDiscoveryRecord({ caseId, url, source, depth = 0 }) {
  return {
    record_type: 'discovery',
    case_id: caseId || null,
    url,
    source: source || 'seed',
    depth,
    discovered_at: new Date().toISOString(),
  };
}

/**
 * A captured page result from the crawler.
 */
function makeCaptureRecord({ caseId, url, content_sha256, html_sha256, html_key, screenshot_key, statusCode }) {
  return {
    record_type: 'capture',
    case_id: caseId || null,
    url,
    content_sha256,
    html_sha256,
    html_key: html_key || null,
    screenshot_key: screenshot_key || null,
    status_code: statusCode || null,
    captured_at: new Date().toISOString(),
  };
}

/**
 * The compliance "stop" record emitted when we hit a block (401/403/429).
 * Its existence is itself the signal that we refused to evade.
 */
function makeBackoffRecord({ caseId, url, statusCode, note }) {
  return {
    record_type: 'backoff_for_human_review',
    case_id: caseId || null,
    url,
    status_code: statusCode || null,
    note: note || 'Blocked by source. Stopped instead of evading. Needs human review.',
    flagged_at: new Date().toISOString(),
  };
}

/**
 * An immutable evidence-index entry (output of the diff stage).
 */
function makeEvidenceIndexEntry({ caseId, url, content_sha256, html_sha256, screenshot_key, html_key, change }) {
  return {
    record_type: 'evidence_index',
    case_id: caseId || null,
    url,
    timestamp: new Date().toISOString(),
    content_sha256,
    html_sha256,
    screenshot_key: screenshot_key || null,
    html_key: html_key || null,
    change: change || 'new', // 'new' | 'changed'
    immutable: true,
  };
}

module.exports = {
  makeCaseRecord,
  makeDecisionLog,
  makeDiscoveryRecord,
  makeCaptureRecord,
  makeBackoffRecord,
  makeEvidenceIndexEntry,
};
