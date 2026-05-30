/**
 * integrations/webhooks/output-health.js
 *
 * Output-health evaluation for Apify run webhooks.
 *
 * ── WHY THIS EXISTS ─────────────────────────────────────────────────────────
 * Apify fires `ACTOR.RUN.SUCCEEDED` whenever a run *exits cleanly*. But for this
 * product, a clean exit is NOT the same as a useful, honest result. A run can
 * "succeed" while having:
 *   - produced an EMPTY dataset / missing OUTPUT (nothing was actually captured),
 *   - emitted only `backoff_for_human_review` records (every source told us to
 *     stop — a COMPLIANCE STOP, not a failure to paper over),
 *   - produced a report whose required scoring fields are missing or malformed.
 *
 * Treating any of those as "success" would be a quiet form of FAKE DATA: telling
 * the user "your audit is ready" when nothing real was gathered. This module is
 * the chokepoint that forbids that. It classifies a finished run into an honest
 * health verdict that the receiver then routes (notify user / alert / human
 * review) WITHOUT ever fabricating a result.
 *
 * Design borrowed from two reference architectures:
 *  - SpiderFoot (https://github.com/smicallef/spiderfoot): its scan engine treats
 *    every finding as a typed *event* and its v4 correlation engine reasons over
 *    those events with declarative rules. Here we mirror that: a finished run is
 *    summarized into typed record counts (capture / backoff / report) and a small
 *    set of declarative health checks reasons over them — a correlation pass on
 *    run output rather than on OSINT events.
 *  - The Markup's Blacklight (https://themarkup.org/blacklight): a real-time
 *    *inspector* that reports concretely what it observed rather than a vague
 *    pass/fail. We adopt that "show your work" stance: every verdict carries the
 *    observed counts and the specific reasons, so the user sees WHY a run is or
 *    is not trustworthy.
 *
 * This module is PURE (no network, no apify SDK, no fs) so it can be unit-tested
 * and reused by the receiver, by a CLI, or by a future actor. It never invents
 * data: if the caller passes nothing, it reports "unknown / not yet inspected".
 * ─────────────────────────────────────────────────────────────────────────────
 */

'use strict';

/** Health verdicts, ordered from best to worst for easy comparison. */
const HEALTH = Object.freeze({
  HEALTHY: 'healthy',                 // real, complete output the user can trust
  COMPLIANCE_STOP: 'compliance_stop', // sources blocked us; we stopped (by design)
  DEGRADED: 'degraded',               // produced output but it is thin / partial
  EMPTY: 'empty',                     // clean exit but nothing real was produced
  MALFORMED: 'malformed',             // output exists but required fields missing
  FAILED: 'failed',                   // the run itself did not succeed
  UNKNOWN: 'unknown',                 // not enough info to judge (never guess up)
});

/** Apify run statuses we treat as a clean process exit. */
const SUCCEEDED_STATUSES = Object.freeze(['SUCCEEDED']);
const FAILURE_STATUSES = Object.freeze(['FAILED', 'TIMED-OUT', 'TIMED_OUT', 'ABORTED']);

/**
 * The compliant scoring fields a finished report MUST contain. These mirror
 * shared/scoring.js exactly; a report missing any of them is MALFORMED, not
 * "successful". We intentionally do NOT accept extra/foreign score fields here.
 */
const REQUIRED_SCORE_FIELDS = Object.freeze([
  'exposure_score',
  'evidence_quality_score',
  'actionability_score',
  'distress_risk_score',
]);

/**
 * Summarize a dataset's items into typed counts, the way SpiderFoot buckets
 * findings by event type before correlating. We only look at `record_type`,
 * which every actor stamps via shared/schemas.js — no content inspection, no
 * inference about people.
 *
 * @param {Array<object>} items - dataset items (may be empty / undefined).
 * @returns {{ total:number, captures:number, backoffs:number, reports:number,
 *             discoveries:number, decisions:number, other:number }}
 */
function summarizeDataset(items) {
  const summary = {
    total: 0,
    captures: 0,
    backoffs: 0,
    reports: 0,
    discoveries: 0,
    decisions: 0,
    other: 0,
  };
  if (!Array.isArray(items)) return summary;
  for (const it of items) {
    summary.total += 1;
    const t = it && typeof it.record_type === 'string' ? it.record_type : '';
    switch (t) {
      case 'capture': summary.captures += 1; break;
      case 'backoff_for_human_review': summary.backoffs += 1; break;
      case 'report': summary.reports += 1; break;
      case 'discovery': summary.discoveries += 1; break;
      case 'decision_log': summary.decisions += 1; break;
      default: summary.other += 1; break;
    }
  }
  return summary;
}

/**
 * Check that an OUTPUT/report bundle carries the required compliant score fields
 * with finite numeric values. Returns the list of MISSING field names (empty if
 * all present and valid).
 *
 * @param {object|null|undefined} output - the run's OUTPUT object (report bundle).
 * @returns {string[]} missing-or-invalid field names.
 */
function missingScoreFields(output) {
  if (!output || typeof output !== 'object') return [...REQUIRED_SCORE_FIELDS];
  // Scores may live at output.scores (report bundle) or at top level (summary row).
  const scores = output.scores && typeof output.scores === 'object' ? output.scores : output;
  const missing = [];
  for (const f of REQUIRED_SCORE_FIELDS) {
    const v = scores[f];
    if (typeof v !== 'number' || !Number.isFinite(v)) missing.push(f);
  }
  return missing;
}

/**
 * evaluateOutputHealth — the core correlation pass.
 *
 * Reasons over a finished run's *status* + *typed record counts* + *OUTPUT
 * shape* and returns an honest verdict. It NEVER upgrades a thin/empty result
 * into "healthy"; the only direction it ever rounds is down.
 *
 * @param {object} args
 * @param {string}  args.status        - Apify run status (e.g. 'SUCCEEDED').
 * @param {string} [args.eventType]    - Apify event type (e.g. 'ACTOR.RUN.SUCCEEDED').
 * @param {Array}  [args.datasetItems] - default-dataset items, if fetched.
 * @param {object} [args.output]       - run OUTPUT (report bundle), if fetched.
 * @param {boolean}[args.datasetFetched] - whether we actually fetched the dataset.
 * @param {boolean}[args.outputFetched]  - whether we actually fetched OUTPUT.
 * @returns {{
 *   health: string,
 *   ok: boolean,                 // true only for HEALTHY
 *   needs_human_review: boolean, // compliance stops + malformed
 *   reasons: string[],           // Blacklight-style "show your work"
 *   dataset_summary: object,
 *   missing_score_fields: string[],
 * }}
 */
function evaluateOutputHealth(args = {}) {
  const {
    status = '',
    eventType = '',
    datasetItems,
    output,
    datasetFetched = Array.isArray(datasetItems),
    outputFetched = output !== undefined,
  } = args;

  const reasons = [];
  const normStatus = String(status || '').toUpperCase().replace('_', '-');

  // 1) Run-level failure short-circuits everything. A failed/timed-out/aborted
  //    run has no trustworthy output by definition.
  if (FAILURE_STATUSES.includes(normStatus) || /FAILED|TIMED|ABORTED/.test(eventType)) {
    reasons.push(`Run status is "${status || normStatus || eventType}" — not a clean success.`);
    return verdict(HEALTH.FAILED, { reasons, summary: summarizeDataset(datasetItems), missing: [] });
  }

  // If we cannot confirm a success status AND have no event signal, we refuse to
  // guess upward — UNKNOWN, not HEALTHY.
  const looksSucceeded =
    SUCCEEDED_STATUSES.includes(normStatus) || /SUCCEEDED/.test(eventType);
  if (!looksSucceeded && !datasetFetched && !outputFetched) {
    reasons.push('No success status and no fetched output to inspect — cannot confirm a real result.');
    return verdict(HEALTH.UNKNOWN, { reasons, summary: summarizeDataset(datasetItems), missing: [] });
  }

  const summary = summarizeDataset(datasetItems);

  // 2) If we DID fetch the dataset and it is completely empty, a "succeeded" run
  //    produced nothing real. That is EMPTY — never reported to the user as done.
  if (datasetFetched && summary.total === 0) {
    reasons.push('Run exited cleanly but its dataset is EMPTY — nothing was actually captured. Not reporting as a finished audit.');
    return verdict(HEALTH.EMPTY, { reasons, summary, missing: [] });
  }

  // 3) COMPLIANCE STOP correlation: if the only substantive records are backoff
  //    (401/403/429 → we stopped, did NOT evade), this is a compliance outcome,
  //    not a content result. Surface it for human review; do not dress it up.
  if (datasetFetched && summary.backoffs > 0 && summary.captures === 0 && summary.reports === 0) {
    reasons.push(`All ${summary.backoffs} substantive record(s) are "backoff_for_human_review": every source blocked us and we STOPPED (no evasion). Needs human review / takedown request.`);
    return verdict(HEALTH.COMPLIANCE_STOP, { reasons, summary, missing: [] });
  }

  // 4) Report shape check ("show your work"): if OUTPUT was fetched, it must
  //    carry every required compliant score field. Missing/foreign-shaped output
  //    is MALFORMED — we will not claim a valid report exists.
  let missing = [];
  if (outputFetched) {
    missing = missingScoreFields(output);
    if (missing.length > 0) {
      reasons.push(`Report OUTPUT is missing required compliant score field(s): ${missing.join(', ')}. Treated as malformed, not "ready".`);
      return verdict(HEALTH.MALFORMED, { reasons, summary, missing });
    }
  }

  // 5) DEGRADED: produced something real, but it is thin — e.g. mixed in some
  //    backoffs, or we never confirmed any capture/report. Worth delivering, but
  //    flagged honestly as partial.
  const hasRealContent = summary.captures > 0 || summary.reports > 0;
  if (datasetFetched && !hasRealContent) {
    reasons.push('Dataset has records but no captures or report rows — partial / inconclusive output.');
    return verdict(HEALTH.DEGRADED, { reasons, summary, missing });
  }
  if (datasetFetched && summary.backoffs > 0 && hasRealContent) {
    reasons.push(`Partial success: ${summary.captures} capture(s)/${summary.reports} report(s) plus ${summary.backoffs} compliance backoff(s). Some sources blocked us; delivered evidence is real but incomplete.`);
    return verdict(HEALTH.DEGRADED, { reasons, summary, missing });
  }

  // 6) HEALTHY: a clean success with real captures and/or a well-formed report.
  if (hasRealContent || (outputFetched && missing.length === 0)) {
    reasons.push(
      datasetFetched
        ? `Real output confirmed: ${summary.captures} capture(s), ${summary.reports} report(s).`
        : 'Run succeeded and OUTPUT carries all required compliant score fields.',
    );
    return verdict(HEALTH.HEALTHY, { reasons, summary, missing });
  }

  // Fell through: succeeded status but we never fetched anything to verify it.
  // Refuse to claim HEALTHY on faith.
  reasons.push('Run reported success but its output was not inspected — cannot certify it as a real result. Fetch the dataset/OUTPUT to confirm.');
  return verdict(HEALTH.UNKNOWN, { reasons, summary, missing });
}

function verdict(health, { reasons, summary, missing }) {
  return {
    health,
    ok: health === HEALTH.HEALTHY,
    needs_human_review: health === HEALTH.COMPLIANCE_STOP || health === HEALTH.MALFORMED,
    reasons,
    dataset_summary: summary,
    missing_score_fields: missing || [],
  };
}

module.exports = {
  HEALTH,
  REQUIRED_SCORE_FIELDS,
  summarizeDataset,
  missingScoreFields,
  evaluateOutputHealth,
};
