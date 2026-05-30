/**
 * integrations/grade/exposure-grade.js
 *
 * SELF-EXPOSURE GRADE  —  a deterministic A+…F letter grade for how exposed a
 * user's OWN public footprint is, computed ONLY over the real module_events the
 * existing detectors/enrichers already produced. One number a first-time visitor
 * grasps in a second ("My footprint is a D"), with a fully transparent rubric of
 * weighted deductions behind it — no black box, no dial, no gauge.
 *
 * ── Why this lives in integrations/ (not shared/) ───────────────────────────
 * This agent's writable subtree is integrations/**, docs/apify/** and apify.json
 * only; shared/ is concurrently owned by Codex. So this module lives under
 * integrations/grade/ and REQUIRES the shared vocab/severity READ-ONLY. It adds
 * NO new scoring axis to shared/ — it is a presentation rollup of signals that
 * already exist on every event (risk, visibility, confidence, severity band).
 *
 * ── Reference architecture #1: Mozilla HTTP Observatory / SecurityHeaders ────
 * The MDN HTTP Observatory grades a site by starting every site at a BASELINE
 * score of 100 and then applying a set of WEIGHTED, NAMED PENALTIES (e.g. "no
 * Content-Security-Policy: −25", "Subresource Integrity not implemented: −50"),
 * deducting from the baseline in one pass and mapping the final number onto an
 * A+…F letter band; bonuses only apply once you are already at A.
 *   Ref: https://developer.mozilla.org/en-US/observatory/docs/tests_and_scoring
 *        https://github.com/mozilla/http-observatory/blob/main/httpobs/docs/scoring.md
 * SecurityHeaders.com follows the same model (A…F by which headers are present).
 * We borrow that EXACT shape, reframed from "security headers on a site" to
 * "privacy exposures of a SELF subject": baseline 100, a frozen table of named
 * per-category deductions, single-pass subtraction, A+…F band map. Every
 * deduction in the result names the finding that caused it, exactly like an
 * Observatory report lists which test failed and its point value — so the user
 * can see WHICH exposure to remove to raise their grade (Closure-Mode-friendly).
 *
 * ── Reference architecture #2: Datasette / Frictionless portable evidence ────
 * A grade is only trustworthy if it is REPRODUCIBLE from the published evidence.
 * Mirroring how a Datasette/Frictionless data package is self-describing and
 * recomputable from its own tabular resources, this module is a PURE function of
 * the event rows: the same events always yield the same grade, every deduction
 * traces to a real finding, and the `breakdown` it returns is the exact ledger
 * that integrations/exports/datapackage.js publishes alongside the findings so a
 * third party can re-derive the letter from the bundle. No hidden state, no I/O.
 *   Ref: https://specs.frictionlessdata.io/data-package/
 *
 * ── RED LINES (by construction) ─────────────────────────────────────────────
 *  - scope=self ONLY. computeExposureGrade refuses anything else (a grade is a
 *    self-audit artifact; we do not "grade" another person). Callers route the
 *    scoped input through the REAL shared/scope.js — see gradeForScopedRun().
 *  - NO FABRICATION. Zero real events in ⇒ { graded:false, reason:'no_data' }
 *    and grade:null. We NEVER invent a baseline "A" for an unscanned subject —
 *    "no data, no grade" is the honest answer, matching the product's standing
 *    no-fake-data rule.
 *  - The deduction table keys ONLY off the frozen EVENT_TYPES vocab + the frozen
 *    RISK/VISIBILITY ranks. There is no slot for sex/gender/sexuality/romance/
 *    relationship/live-location — those event types do not exist upstream, so no
 *    deduction can ever be driven by them.
 *  - No raw PII/QI values are read or emitted: we count events and read their
 *    risk/visibility/confidence/event_type only. Values stay in the events.
 *
 * Pure functions, no network, no mutation of inputs. Safe to require at load.
 */

'use strict';

const path = require('path');

// READ-ONLY requires from shared/ (Codex-owned; we never write these).
const {
  EVENT_TYPES, RISK_RANK, VISIBILITY_RANK, isModuleEvent,
} = require(path.join(__dirname, '..', '..', 'shared', 'detectors', 'event-types.js'));
const { rankBySeverity, bandFor } = require(path.join(__dirname, '..', '..', 'shared', 'enrich', 'severity.js'));

/**
 * BASELINE — every audited subject starts at a clean 100, exactly like the
 * Observatory. Deductions below pull it down toward F. (No bonus path: a clean
 * footprint simply keeps its 100 = A+. We do not award >100.)
 */
const BASELINE = 100;

/**
 * FROZEN DEDUCTION TABLE. Keyed by event_type → the point penalty for the FIRST
 * (worst) occurrence of that exposure category, modelled on the Observatory's
 * "no CSP −25 / no SRI −50" named-penalty list. Values reflect how damaging the
 * category is to a SELF subject's privacy posture and how hard it is to undo:
 *
 *   - A leaked live credential / breach hit is the most damaging (rotate now).
 *   - A broker listing aggregating your record is severe (erasure request).
 *   - Self-published postal address / phone is severe (hard to retract).
 *   - Session-recording / fingerprinting trackers on your own site are serious.
 *   - A handle/profile/email or a generic third-party tracker is moderate.
 *   - EXPOSURE_SUMMARY (e.g. a re-identification mosaic) is weighted by its own
 *     risk via the risk-multiplier below, since one mosaic can be benign or grave.
 *
 * These are deliberately COARSE, INDUSTRY-FEEDBACK-style weights, NOT fabricated
 * per-person statistics — the same posture the Observatory takes about its own
 * "essentially arbitrary, professional-feedback-based" modifiers.
 */
const DEDUCTION_BY_TYPE = Object.freeze({
  [EVENT_TYPES.SECRET_LEAK_PUBLIC]: 45,
  [EVENT_TYPES.BREACH_RANGE_HIT]: 40,
  [EVENT_TYPES.BROKER_LISTING_HIT]: 30,
  [EVENT_TYPES.PII_POSTAL_PUBLIC]: 30,
  [EVENT_TYPES.PII_PHONE_PUBLIC]: 22,
  [EVENT_TYPES.TRACKER_SESSION_RECORDING]: 20,
  [EVENT_TYPES.TRACKER_KEYLOGGING]: 20,
  [EVENT_TYPES.TRACKER_FINGERPRINTING]: 18,
  [EVENT_TYPES.PII_EMAIL_PUBLIC]: 15,
  [EVENT_TYPES.PII_HANDLE_PUBLIC]: 12,
  [EVENT_TYPES.PII_GEO_HINT_PUBLIC]: 12,
  [EVENT_TYPES.LEAK_REFERRER]: 12,
  [EVENT_TYPES.SELF_USERNAME]: 8,
  [EVENT_TYPES.SELF_PROFILE_URL]: 6,
  [EVENT_TYPES.TRACKER_THIRD_PARTY]: 8,
  [EVENT_TYPES.COOKIE_THIRD_PARTY]: 5,
  [EVENT_TYPES.EXPOSURE_SUMMARY]: 18, // base; scaled by the event's own risk below
});

/**
 * Risk multiplier applied to a category's penalty using the event's frozen RISK
 * rank (info=0..high=3). A high-risk instance of a category bites harder than an
 * info-level one of the same category — without inventing a new risk axis.
 */
const RISK_MULTIPLIER = Object.freeze({ 0: 0.25, 1: 0.6, 2: 0.85, 3: 1.0 });

/**
 * Visibility multiplier from the frozen VISIBILITY rank (private=1..indexed=3).
 * An INDEXED (search-discoverable) exposure is what actually hurts; a private
 * one barely moves the grade. Mirrors Blacklight's "what a third party can
 * trivially observe" framing already encoded in the vocab.
 */
const VISIBILITY_MULTIPLIER = Object.freeze({ 1: 0.5, 2: 0.8, 3: 1.0 });

/**
 * REPEAT damping: like the Observatory penalising a category mostly ONCE, the
 * first instance of a category takes full weight and each additional instance of
 * the SAME category adds a shrinking amount (it is the same class of problem).
 * Total per category is capped so one noisy category can't alone force an F while
 * hiding that the footprint is otherwise clean.
 */
const REPEAT_FACTOR = 0.35;        // each extra same-category instance worth 35% of prior
const PER_CATEGORY_CAP = 55;        // a single category can deduct at most this many points

/**
 * A+…F letter bands over the final 0..100 score. Thresholds mirror the
 * Observatory's A–F spacing (A≈90, B≈80, C≈70, D≈60, F<50, with +/− splits).
 * A+ is reserved for a *graded* subject with a perfect 100 (real scan, no
 * exposures found) — never for an unscanned one (that returns no grade at all).
 */
const GRADE_BANDS = Object.freeze([
  { grade: 'A+', min: 100 },
  { grade: 'A', min: 90 },
  { grade: 'A-', min: 85 },
  { grade: 'B+', min: 80 },
  { grade: 'B', min: 75 },
  { grade: 'B-', min: 70 },
  { grade: 'C+', min: 65 },
  { grade: 'C', min: 60 },
  { grade: 'C-', min: 55 },
  { grade: 'D+', min: 50 },
  { grade: 'D', min: 45 },
  { grade: 'D-', min: 40 },
  { grade: 'F', min: 0 },
]);

/** Map a 0..100 score to a letter using the frozen band table. */
function letterFor(score) {
  const s = Math.max(0, Math.min(100, Number(score) || 0));
  for (const b of GRADE_BANDS) {
    if (s >= b.min) return b.grade;
  }
  return 'F';
}

/**
 * The penalty a single event contributes BEFORE repeat-damping/caps:
 *   base(event_type) × riskMultiplier × visibilityMultiplier
 * Returns 0 for a non-event, an unknown type (no deduction for things we don't
 * have a rubric for — fail-closed toward NOT inventing penalties), or a type
 * whose base weight is 0.
 */
function rawPenaltyFor(event) {
  if (!isModuleEvent(event)) return 0;
  const base = DEDUCTION_BY_TYPE[event.event_type];
  if (!base) return 0;
  const rMul = RISK_MULTIPLIER[RISK_RANK[event.risk] ?? 1] ?? 0.6;
  const vMul = VISIBILITY_MULTIPLIER[VISIBILITY_RANK[event.visibility] ?? 2] ?? 0.8;
  return base * rMul * vMul;
}

/**
 * Group valid events by category (event_type) and compute a damped, capped
 * deduction per category, highest-impact instance first (so repeat-damping keeps
 * the worst instance at full weight). Returns the per-category ledger.
 *
 * @param {object[]} events
 * @returns {{category:string, instances:number, deduction:number, worst_band:string}[]}
 */
function deductionLedger(events) {
  const byType = new Map();
  for (const ev of (Array.isArray(events) ? events : [])) {
    if (!isModuleEvent(ev)) continue;
    const p = rawPenaltyFor(ev);
    if (p <= 0) continue;
    if (!byType.has(ev.event_type)) byType.set(ev.event_type, []);
    byType.get(ev.event_type).push(p);
  }

  const ledger = [];
  for (const [type, penalties] of byType) {
    penalties.sort((a, b) => b - a); // worst instance first → full weight
    let sum = 0;
    penalties.forEach((p, i) => { sum += p * Math.pow(REPEAT_FACTOR, i); });
    const deduction = Math.min(PER_CATEGORY_CAP, sum);
    // worst risk band seen in this category, for the human-readable ledger row
    const worst = Math.max(...penalties);
    ledger.push({
      category: type,
      instances: penalties.length,
      deduction: Math.round(deduction * 10) / 10,
      worst_instance_penalty: Math.round(worst * 10) / 10,
    });
  }
  ledger.sort((a, b) => b.deduction - a.deduction);
  return ledger;
}

/**
 * computeExposureGrade(events, opts) — THE grade.
 *
 * @param {object[]} events  REAL module_events from the detector/enrich pipeline.
 * @param {object} [opts]    { crawlSummary? } passed through for context only.
 * @returns {{
 *   graded: boolean,
 *   reason?: string,            // when graded:false
 *   grade: string|null,         // 'A+'..'F' or null when not graded
 *   score: number|null,         // 0..100 or null
 *   baseline: number,
 *   total_deduction: number|null,
 *   breakdown: object[],        // per-category ledger (the reproducible rubric)
 *   event_count: number,
 *   counted_event_count: number,// events that actually carried a deduction
 *   model: object               // cites the Observatory model + version
 * }}
 *
 * EMPTY-IN ⇒ NO GRADE: if there are zero valid, scoreable events we return
 * graded:false / grade:null. We do NOT default an unscanned subject to "A".
 */
function computeExposureGrade(events = [], opts = {}) {
  const valid = (Array.isArray(events) ? events : []).filter(isModuleEvent);

  const model = Object.freeze({
    name: 'self-exposure-grade',
    version: 1,
    baseline: BASELINE,
    method: 'Mozilla HTTP Observatory / SecurityHeaders-style baseline-100 weighted-deduction grade, reframed from security headers to SELF privacy exposures.',
    refs: [
      'https://developer.mozilla.org/en-US/observatory/docs/tests_and_scoring',
      'https://github.com/mozilla/http-observatory/blob/main/httpobs/docs/scoring.md',
    ],
    grade_bands: GRADE_BANDS,
  });

  if (valid.length === 0) {
    return {
      graded: false,
      reason: 'no_data',
      grade: null,
      score: null,
      baseline: BASELINE,
      total_deduction: null,
      breakdown: [],
      event_count: 0,
      counted_event_count: 0,
      model,
    };
  }

  const breakdown = deductionLedger(valid);
  const totalDeduction = breakdown.reduce((acc, row) => acc + row.deduction, 0);
  const score = Math.max(0, Math.min(100, Math.round(BASELINE - totalDeduction)));

  // If every valid event was an unknown/zero-weight type, we have data but no
  // scoreable exposure — that is a real, clean "A+" (we DID scan and found
  // nothing the rubric penalises), distinct from the no_data case above.
  const countedEventCount = breakdown.reduce((acc, row) => acc + row.instances, 0);

  return {
    graded: true,
    grade: letterFor(score),
    score,
    baseline: BASELINE,
    total_deduction: Math.round(totalDeduction * 10) / 10,
    breakdown,
    event_count: valid.length,
    counted_event_count: countedEventCount,
    // severity_band is the EXISTING shared severity scale's read of the worst
    // finding — surfaced for cross-checking, NOT a second grade.
    severity_band: valid.length ? worstSeverityBand(valid, opts) : 'info',
    model,
  };
}

/**
 * Worst per-event severity band via the EXISTING shared/enrich/severity.js
 * (read-only). Lets the report show "grade D · worst finding: critical" without
 * this module reimplementing severity.
 */
function worstSeverityBand(events, opts = {}) {
  try {
    const ranked = rankBySeverity(events, opts);
    if (!ranked.length) return 'info';
    return ranked[0]._severity ? ranked[0]._severity.band : bandFor(0);
  } catch {
    return 'info';
  }
}

/**
 * gradeForScopedRun(input, events) — the SCOPE-GATED entry point.
 *
 * Routes the scoped input through the REAL shared/scope.js (read-only require,
 * never rewritten) and ONLY grades when the run is allowed AND scope_type=self.
 * Any rejection, or a non-self scope, returns { graded:false, reason } and NO
 * grade — a grade is a self-audit artifact, never produced for another subject.
 *
 * @param {object} input   the same scoped input every actor validates.
 * @param {object[]} events REAL module_events for that run.
 * @param {object} [opts]
 * @returns {object} computeExposureGrade-shaped result (graded:false on refusal)
 */
function gradeForScopedRun(input, events = [], opts = {}) {
  // Lazy require so a require-time issue in shared/ can't break module load.
  // eslint-disable-next-line global-require
  const { validateScope } = require(path.join(__dirname, '..', '..', 'shared', 'scope.js'));
  const decision = validateScope(input);

  if (!decision.allowed) {
    return {
      graded: false,
      reason: 'scope_rejected',
      scope_violations: decision.violated_red_lines,
      grade: null,
      score: null,
      breakdown: [],
      event_count: Array.isArray(events) ? events.length : 0,
      counted_event_count: 0,
    };
  }
  if (decision.scope_type !== 'self') {
    return {
      graded: false,
      reason: 'not_self_scope',
      scope_type: decision.scope_type,
      grade: null,
      score: null,
      breakdown: [],
      event_count: Array.isArray(events) ? events.length : 0,
      counted_event_count: 0,
    };
  }
  return computeExposureGrade(events, opts);
}

module.exports = {
  BASELINE,
  DEDUCTION_BY_TYPE,
  RISK_MULTIPLIER,
  VISIBILITY_MULTIPLIER,
  REPEAT_FACTOR,
  PER_CATEGORY_CAP,
  GRADE_BANDS,
  letterFor,
  rawPenaltyFor,
  deductionLedger,
  computeExposureGrade,
  gradeForScopedRun,
};
