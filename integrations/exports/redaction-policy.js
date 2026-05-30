/**
 * integrations/exports/redaction-policy.js
 *
 * The compliance chokepoint for Apify DATASET VIEWS + EXPORTS.
 *
 * Apify lets you export any dataset over the API in json/csv/xlsx/... with
 * `fields`/`omit`/`clean`/`flatten` query params, and lets you predefine "views"
 * (transformation + display) in .actor/actor.json so the Console output tab and
 * downstream consumers see a SHAPED projection of the raw items
 * (https://docs.apify.com/platform/actors/development/actor-definition/dataset-schema,
 *  https://docs.apify.com/api/v2/dataset-items-get).
 *
 * The danger of that power for THIS product: a raw evidence dataset contains
 * real public URLs, screenshot/html storage keys, and subject labels. Exporting
 * that verbatim to a third party (Slack/Make/n8n, a shared link, a CSV emailed
 * to a "friend") would leak more than the audit subject consented to. So every
 * export and every view must pass through a REDACTION POLICY that is keyed on a
 * STIX/MISP-style DISTRIBUTION MARKING and is FAIL-CLOSED: an unknown field at a
 * shareable marking is dropped, an unknown marking is refused, and the `fields`
 * the API ultimately receives are DERIVED here, never trusted from the caller.
 *
 * Reference architectures borrowed here (assigned for this product):
 *
 *   1. OpenCTI / MISP + STIX evidence object model.
 *      OpenCTI TAXII collections / MISP events carry a `marking-definition`
 *      (TLP / distribution level) and data segregation filters every export so a
 *      consumer only ever receives the subset their marking allows
 *      (https://docs.opencti.io/latest/deployment/connectors/,
 *       https://medium.com/@julien.richard/opencti-data-sharing-6da7dc045d14).
 *      We mirror that: each MARKING below is a TLP-like band, and a band can
 *      ONLY emit a field that has been explicitly whitelisted for it. Raw
 *      locators (url, *_key, subject_label) are TLP:RED-only, exactly as raw
 *      indicators in MISP are restricted while hashes/observables can be shared
 *      more widely (MISP-STIX indicator/observable fingerprinting,
 *      https://www.misp-project.org/2026/03/16/misp-stix_indicator_and_observable_fingerprinting.html/).
 *
 *   2. Apify RAG Web Browser + Website Content Crawler.
 *      Those actors deliberately project a crawl into a SMALL set of stable
 *      output fields (url, title, markdown/content, crawled_at) so a downstream
 *      RAG/vector pipeline reads a predictable shape rather than the raw DOM
 *      (https://apify.com/apify/website-content-crawler/input-schema,
 *       https://apify.com/apify/rag-web-browser/input-schema). A dataset VIEW is
 *      that same "post-extraction projection" idea: we publish a thin, typed,
 *      pre-redacted view instead of the raw capture record, so consumers never
 *      touch the wide internal record.
 *
 * This module ships NO credentials, performs NO I/O, and asserts NO deployment.
 */

'use strict';

/**
 * Distribution markings, ordered from most-restricted to least. A higher index
 * == wider audience == fewer fields allowed. Named after TLP so anyone from the
 * threat-intel world reads them instantly.
 */
const MARKINGS = Object.freeze(['TLP:RED', 'TLP:AMBER', 'TLP:GREEN']);

/**
 * Field-level export allow-list, keyed by record_type then marking.
 *
 * The rule the whole product turns on: RAW LOCATORS THAT COULD RE-IDENTIFY OR
 * RE-TARGET A SUBJECT NEVER LEAVE TLP:RED. That means `url`, `html_key`,
 * `screenshot_key`, and any free-text `note`/`subject_label` are RED-only. The
 * shareable bands keep only content/markup HASHES (sha256), coarse status,
 * change flags, and timestamps — enough to PROVE "something at a source changed"
 * without handing over WHERE or a viewable artifact.
 *
 * Anything not listed for a marking is DROPPED at that marking (fail-closed).
 * `#`-prefixed fields are Apify "hidden" fields and are stripped by clean=true
 * regardless; we also never whitelist them.
 */
const FIELD_POLICY = Object.freeze({
  capture: {
    'TLP:RED': ['record_type', 'case_id', 'url', 'content_sha256', 'html_sha256', 'html_key', 'screenshot_key', 'status_code', 'captured_at'],
    'TLP:AMBER': ['record_type', 'case_id', 'content_sha256', 'html_sha256', 'status_code', 'captured_at'],
    'TLP:GREEN': ['record_type', 'content_sha256', 'status_code', 'captured_at'],
  },
  evidence_index: {
    'TLP:RED': ['record_type', 'case_id', 'url', 'timestamp', 'content_sha256', 'html_sha256', 'screenshot_key', 'html_key', 'change', 'immutable'],
    'TLP:AMBER': ['record_type', 'case_id', 'timestamp', 'content_sha256', 'html_sha256', 'change', 'immutable'],
    'TLP:GREEN': ['record_type', 'timestamp', 'content_sha256', 'change', 'immutable'],
  },
  backoff_for_human_review: {
    // The mere EXISTENCE of a backoff record is the compliance signal ("we
    // refused to evade"). The url and note are RED; the fact + status can be
    // shared as a count/flag without leaking the source.
    'TLP:RED': ['record_type', 'case_id', 'url', 'status_code', 'note', 'flagged_at'],
    'TLP:AMBER': ['record_type', 'case_id', 'status_code', 'flagged_at'],
    'TLP:GREEN': ['record_type', 'status_code', 'flagged_at'],
  },
  decision_log: {
    'TLP:RED': ['record_type', 'case_id', 'decision', 'validation', 'logged_at'],
    'TLP:AMBER': ['record_type', 'case_id', 'decision', 'logged_at'],
    'TLP:GREEN': ['record_type', 'decision', 'logged_at'],
  },
});

/**
 * Fields that must NEVER appear in any non-RED export, enforced as a second,
 * independent backstop on top of the per-record allow-lists. Belt and braces:
 * even if a future edit accidentally adds `url` to a GREEN allow-list, this
 * tripwire catches it (see redactFields below).
 */
const NEVER_SHARE_BELOW_RED = Object.freeze([
  'url', 'html_key', 'screenshot_key', 'note', 'subject_label', 'target_urls',
  'authorization_evidence_url', 'subject_token', 'email', 'handle',
]);

function isMarking(m) {
  return typeof m === 'string' && MARKINGS.includes(m);
}

function isRecordType(t) {
  return typeof t === 'string' && Object.prototype.hasOwnProperty.call(FIELD_POLICY, t);
}

/**
 * The allowed field list for (record_type, marking). FAIL-CLOSED: an unknown
 * marking or unknown record_type returns [] (export nothing) rather than
 * throwing or defaulting wide — refusing to share beats over-sharing.
 */
function allowedFields(record_type, marking) {
  if (!isMarking(marking)) return [];
  if (!isRecordType(record_type)) return [];
  const byMarking = FIELD_POLICY[record_type];
  const fields = byMarking[marking];
  if (!Array.isArray(fields)) return [];
  // Second backstop: at non-RED markings, strip anything on the never-share
  // tripwire even if it slipped into the allow-list.
  if (marking === 'TLP:RED') return fields.slice();
  return fields.filter((f) => !NEVER_SHARE_BELOW_RED.includes(f));
}

/**
 * Project a single raw record to the marking's allowed shape. Returns null if
 * the record's type is not exportable at this marking (so callers can drop it
 * from the export entirely — never a half-redacted leak).
 */
function redactRecord(record, marking) {
  if (!record || typeof record !== 'object') return null;
  const fields = allowedFields(record.record_type, marking);
  if (fields.length === 0) return null;
  const out = {};
  for (const f of fields) {
    if (Object.prototype.hasOwnProperty.call(record, f)) out[f] = record[f];
  }
  return out;
}

/**
 * Build the Apify export query params for a marking. We pass `fields` (the
 * positive allow-list) AND `omit` (the never-share tripwire) AND `clean=1`.
 * Per Apify, when both `fields` and `omit` name the same field, `omit` wins —
 * so the tripwire is authoritative even server-side
 * (https://docs.apify.com/api/v2/dataset-items-get).
 *
 * NOTE: the Apify items endpoint applies ONE field set across the whole dataset,
 * so for a mixed-record dataset we pass the UNION of allowed fields for the
 * given marking and rely on (a) omit + (b) clean=1 (skipEmpty) to keep each
 * row's irrelevant columns blank. The exact per-record shaping is still done by
 * redactRecord() when the caller post-processes; the query params are the
 * server-side first line of defence.
 */
function exportQueryFor(marking, { format = 'json', recordTypes = Object.keys(FIELD_POLICY) } = {}) {
  if (!isMarking(marking)) {
    return { error: `unknown marking "${marking}"; refusing to build an export (fail-closed)` };
  }
  const ALLOWED_FORMATS = ['json', 'jsonl', 'csv', 'xlsx', 'xml', 'rss', 'html'];
  if (!ALLOWED_FORMATS.includes(format)) {
    return { error: `unsupported export format "${format}"` };
  }
  const fieldSet = new Set();
  for (const rt of recordTypes) {
    for (const f of allowedFields(rt, marking)) fieldSet.add(f);
  }
  const params = {
    format,
    clean: '1', // = skipHidden + skipEmpty
    fields: Array.from(fieldSet).join(','),
  };
  // Belt: explicitly omit the never-share fields below RED (omit wins over fields).
  if (marking !== 'TLP:RED') {
    params.omit = NEVER_SHARE_BELOW_RED.join(',');
  }
  return { params };
}

module.exports = {
  MARKINGS,
  FIELD_POLICY,
  NEVER_SHARE_BELOW_RED,
  isMarking,
  isRecordType,
  allowedFields,
  redactRecord,
  exportQueryFor,
};
