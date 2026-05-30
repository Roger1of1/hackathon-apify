/**
 * shared/scoring.js
 *
 * The ONLY scoring model this product ships. Every score here measures the
 * user's relationship to their OWN footprint, evidence quality, what they can
 * DO about it, and their wellbeing. There are deliberately NO scores about
 * other people's romantic availability, jealousy, attractiveness, or activity.
 *
 * Adding such a score would violate the product's red lines, so this file is
 * the chokepoint: the report builder may use ONLY the functions exported here.
 *
 * All scores are 0..100 integers. Inputs are real, observed crawl results — if
 * there is no data, scores reflect "unknown / low confidence", never fabricated.
 */

'use strict';

function clamp(n, lo = 0, hi = 100) {
  if (Number.isNaN(n) || !Number.isFinite(n)) return lo;
  return Math.max(lo, Math.min(hi, Math.round(n)));
}

/**
 * exposure_score: how discoverable the SELF subject's footprint is, based on
 * how many distinct public surfaces actually returned content about them.
 * Higher = more exposed = more to potentially clean up.
 */
function exposureScore({ reachablePages = 0, distinctHosts = 0, indexablePages = 0 } = {}) {
  // Each reachable surface adds exposure; distinct hosts weigh more (spread),
  // indexable (search-engine visible) pages weigh most.
  const raw = reachablePages * 4 + distinctHosts * 8 + indexablePages * 10;
  return clamp(raw);
}

/**
 * evidence_quality_score: how defensible the preserved evidence is. Driven by
 * whether we have BOTH a stored html artifact and a screenshot, and a content
 * hash, for each evidence item — i.e. is it court-/report-ready.
 */
function evidenceQualityScore({ items = [] } = {}) {
  if (!Array.isArray(items) || items.length === 0) return 0;
  let total = 0;
  for (const it of items) {
    let s = 0;
    if (it.content_sha256) s += 30;
    if (it.html_sha256) s += 20;
    if (it.html_key) s += 25;
    if (it.screenshot_key) s += 25;
    total += s; // each item is already 0..100
  }
  return clamp(total / items.length);
}

/**
 * actionability_score: how much the user can realistically DO about findings —
 * e.g. items on platforms with takedown/removal paths, or self-owned profiles
 * they can edit directly. Higher = more within the user's control.
 */
function actionabilityScore({ items = [] } = {}) {
  if (!Array.isArray(items) || items.length === 0) return 0;
  let actionable = 0;
  for (const it of items) {
    if (it.self_owned || it.has_removal_path) actionable += 1;
  }
  return clamp((actionable / items.length) * 100);
}

/**
 * distress_risk_score: a WELLBEING signal, not a surveillance one. It estimates
 * how likely this audit is to feed compulsive checking, so the report can offer
 * Closure Mode. Driven by check frequency the user self-reports and how
 * emotionally charged the declared scope is — NEVER by anyone's romantic data.
 *
 * @param {{ checks_per_day?: number, scope_type?: string, change_volume?: number }} p
 */
function distressRiskScore({ checks_per_day = 0, scope_type = 'self', change_volume = 0 } = {}) {
  let raw = 0;
  // Frequent re-checking is the strongest compulsion signal.
  raw += clamp(checks_per_day * 12, 0, 60);
  // safety_evidence work is inherently stressful; nudge wellbeing support up.
  if (scope_type === 'safety_evidence') raw += 20;
  // A flood of changes can amplify rumination.
  raw += clamp(change_volume * 3, 0, 20);
  return clamp(raw);
}

/**
 * Convenience: compute the full compliant score bundle for a report.
 */
function computeScores({ crawlSummary = {}, evidenceItems = [], wellbeing = {} } = {}) {
  const exposure = exposureScore(crawlSummary);
  const evidence = evidenceQualityScore({ items: evidenceItems });
  const actionability = actionabilityScore({ items: evidenceItems });
  const distress = distressRiskScore({
    checks_per_day: wellbeing.checks_per_day,
    scope_type: wellbeing.scope_type,
    change_volume: evidenceItems.length,
  });

  return {
    exposure_score: exposure,
    evidence_quality_score: evidence,
    actionability_score: actionability,
    distress_risk_score: distress,
    // Threshold the report uses to surface Closure Mode.
    closure_mode_recommended: distress >= 50,
  };
}

module.exports = {
  clamp,
  exposureScore,
  evidenceQualityScore,
  actionabilityScore,
  distressRiskScore,
  computeScores,
};
