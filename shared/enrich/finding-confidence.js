/**
 * shared/enrich/finding-confidence.js
 *
 * A PER-FINDING TRUST SCORE for detector module_events, built with the exact
 * scoring mechanic Mozilla Observatory / SecurityHeaders use: start every finding
 * at a baseline of 100 and subtract a documented, severity-weighted DEMERIT for
 * each thing that makes the finding less trustworthy as a real, self-relevant
 * exposure. The result is a 0..100 trust score plus an A–F band, so the report
 * and inspector can say "how much should the user believe this finding" the same
 * deterministic way for every detector — no per-detector ad-hoc fudge factors.
 *
 * WHY (consolidate + deepen, not sprawl):
 *  - This adds NO new event type and NO new actor. It enriches existing events.
 *  - It is the bridge between the new false-positive validator
 *    (shared/detectors/finding-validator.js) and the report-level A–F EXPOSURE
 *    grade another track ships (shared/scoring-grade.js): that grade asks "how
 *    exposed am I overall"; THIS asks "how trustworthy is each individual
 *    finding", and feeds the grade only findings the rubric trusts. Two
 *    different questions, one shared Observatory-style rubric mechanic.
 *
 * REFERENCE ARCHITECTURE — Mozilla Observatory / SecurityHeaders scoring rubric
 * ─────────────────────────────────────────────────────────────────────────────
 *  Observatory's published methodology (MDN "Tests & Scoring";
 *  mozilla/http-observatory scanner/grader/grade.py):
 *   • Baseline score = 100.
 *   • Each test that fails imposes a NEGATIVE modifier; magnitude reflects how
 *     important industry feedback deems that test (modifiers are deliberately
 *     "arbitrary but feedback-informed", their words).
 *   • Bonuses are applied ONLY if the pre-bonus score is already ≥ 90 (A).
 *   • Letters come from a GRADE_CHART in 5-point steps: 100→A+, 90/95→A,
 *     85→A-, 80→B+, 75/70→B, …, ≤20→F.  (grade.py GRADE_CHART)
 *  We apply that SAME structure to finding TRUST rather than HTTP headers:
 *  weighted demerits for low confidence, suppression/low-value verdicts, single
 *  un-corroborated sightings, weak preservation, and stale recency; a small
 *  bonus for strongly-corroborated + well-preserved findings, gated at ≥90 just
 *  like Observatory. Everything is documented inline and deterministic.
 *  Refs: https://developer.mozilla.org/en-US/observatory/docs/tests_and_scoring
 *        https://github.com/mozilla/http-observatory (scanner/grader/grade.py)
 *
 * RED LINES: trust is about how believable a finding of the SELF subject's OWN
 * public footprint is. No romance/intimacy/third-party slot exists here, by
 * construction — inputs are only the frozen-vocabulary event fields + the
 * validator verdict + optional real preservation/recency signals.
 *
 * Pure functions, no network, no mutation of inputs. Safe to require at load.
 */

'use strict';

const { isModuleEvent } = require('../detectors/event-types.js');
const { clamp } = require('../scoring.js');
const { classifyFinding, VERDICT } = require('../detectors/finding-validator.js');

const BASELINE = 100;

/**
 * The demerit rubric. Each entry: a stable code, the points subtracted, and a
 * one-line human reason. Magnitudes are Observatory-style: feedback-informed and
 * documented, not magic numbers buried in code. Higher = the finding is less
 * trustworthy as a real, actionable self-exposure.
 */
const DEMERITS = Object.freeze({
  // The validator says this matched a reserved/example/test pattern (RFC 2606/
  // 6761) or a CSS asset token — it almost certainly is NOT a real exposure.
  SUPPRESSED: { points: 70, reason: 'Matched a documented reserved/example/test pattern (validator: suppress).' },
  // Real-shaped but not personally actionable (role / no-reply mailbox).
  LOW_VALUE: { points: 30, reason: 'Role/automation artifact, not a personally-actionable exposure (validator: low_value).' },
  // The detector itself was only weakly sure (e.g. a bare 0.5-0.6 regex hit).
  LOW_CONFIDENCE: { points: 25, reason: 'Detector confidence below 0.6 — weak pattern match.' },
  VERY_LOW_CONFIDENCE: { points: 40, reason: 'Detector confidence below 0.35 — very weak pattern match.' },
  // Seen on only ONE surface: a single sighting is weaker than corroboration
  // across distinct surfaces (HIBP "more sightings = stronger" / Observatory
  // "missing defence-in-depth" framing).
  SINGLE_SIGHTING: { points: 10, reason: 'Observed on a single surface — no cross-surface corroboration yet.' },
  // No preserved artifact (no content hash AND no stored html/screenshot): the
  // finding is real-time-only and not yet defensible/report-ready.
  NO_PRESERVATION: { points: 15, reason: 'No preserved artifact (hash/html/screenshot) — not yet report-ready.' },
  // Last confirmed long ago: a stale finding should be trusted less for action
  // (and routed to Closure Mode), Observatory-style decay.
  STALE: { points: 15, reason: 'Last confirmed long ago — may already be resolved; verify before acting.' },
});

/**
 * Observatory-style bonus: ONLY applied when the pre-bonus score is already ≥ 90
 * (their A threshold). Rewards a finding that is strongly corroborated AND well
 * preserved — i.e. one the user can act on with high confidence.
 */
const BONUS = Object.freeze({
  WELL_CORROBORATED_PRESERVED: { points: 5, reason: 'Strongly corroborated across surfaces and preserved — high-confidence, report-ready.' },
});

/**
 * Mozilla Observatory GRADE_CHART (5-point steps), reproduced from
 * http-observatory scanner/grader/grade.py and mapped to the product's A–F band.
 * Score → letter. We collapse +/- into base letters for a PLAIN hero label, but
 * keep the threshold structure identical so the mapping is auditable.
 */
const GRADE_CHART = Object.freeze([
  { min: 90, grade: 'A' },
  { min: 80, grade: 'B' },
  { min: 65, grade: 'C' },
  { min: 50, grade: 'D' },
  { min: 35, grade: 'E' },
  { min: 0, grade: 'F' },
]);

function gradeForScore(score) {
  for (const g of GRADE_CHART) if (score >= g.min) return g.grade;
  return 'F';
}

/**
 * Recency helper: returns true if a finding's last sighting is older than
 * `staleAfterDays`. Honest — needs a real `last_observed` ISO; with none it is
 * NOT treated as stale (absence of data is not a stale claim).
 */
function isStale(opts, now) {
  const last = opts && opts.last_observed;
  if (typeof last !== 'string') return false;
  const t = Date.parse(last);
  if (Number.isNaN(t)) return false;
  const staleAfterDays = Number(opts.staleAfterDays) > 0 ? Number(opts.staleAfterDays) : 90;
  const ageDays = (Date.parse(now) - t) / (24 * 3600 * 1000);
  return ageDays > staleAfterDays;
}

function hasPreservation(integrity) {
  if (!integrity || typeof integrity !== 'object') return false;
  return !!(integrity.content_sha256 || integrity.html_sha256 || integrity.html_key || integrity.screenshot_key);
}

/**
 * Score ONE finding's trustworthiness with the Observatory rubric mechanic.
 *
 * @param {object} event a module_event
 * @param {object} [opts]
 * @param {object} [opts.validation]   precomputed `_validation`; else recomputed
 * @param {number} [opts.corroborations] distinct surfaces (>=1) showing this exposure
 * @param {object} [opts.integrity]    preservation handles {content_sha256,...}
 * @param {string} [opts.last_observed] ISO of last sighting (for staleness)
 * @param {number} [opts.staleAfterDays] default 90
 * @param {string} [opts.now]          ISO clock (injectable for deterministic tests)
 * @returns {{ trust: number, grade: string, baseline: number, demerits: object[], bonuses: object[] }}
 */
function findingConfidence(event, opts = {}) {
  if (!isModuleEvent(event)) {
    return { trust: 0, grade: 'F', baseline: BASELINE, demerits: [{ code: 'INVALID', points: 100, reason: 'Not a valid module_event.' }], bonuses: [] };
  }
  const now = typeof opts.now === 'string' ? opts.now : new Date().toISOString();
  const validation = opts.validation && opts.validation.verdict
    ? opts.validation
    : (event._validation && event._validation.verdict ? event._validation : classifyFinding(event));

  const demerits = [];
  const add = (code) => demerits.push({ code, points: DEMERITS[code].points, reason: DEMERITS[code].reason });

  // 1) Validator verdict (the heaviest signal — a reserved/example hit).
  if (validation.verdict === VERDICT.SUPPRESS) add('SUPPRESSED');
  else if (validation.verdict === VERDICT.LOW_VALUE) add('LOW_VALUE');

  // 2) Detector confidence band.
  const c = Number.isFinite(event.confidence) ? event.confidence : 0.5;
  if (c < 0.35) add('VERY_LOW_CONFIDENCE');
  else if (c < 0.6) add('LOW_CONFIDENCE');

  // 3) Corroboration (single sighting is weaker).
  const corr = Math.max(1, Number(opts.corroborations) || 1);
  if (corr < 2) add('SINGLE_SIGHTING');

  // 4) Preservation.
  const preserved = hasPreservation(opts.integrity);
  if (!preserved) add('NO_PRESERVATION');

  // 5) Staleness.
  const stale = isStale(opts, now);
  if (stale) add('STALE');

  // Apply demerits to the baseline (Observatory: subtract from 100, floor 0).
  let score = BASELINE - demerits.reduce((s, d) => s + d.points, 0);
  score = clamp(score, 0, 100);

  // Observatory rule: bonuses ONLY if the pre-bonus score is already ≥ 90 (A).
  const bonuses = [];
  if (score >= 90 && corr >= 2 && preserved && !stale) {
    bonuses.push({ code: 'WELL_CORROBORATED_PRESERVED', ...BONUS.WELL_CORROBORATED_PRESERVED });
    score = clamp(score + BONUS.WELL_CORROBORATED_PRESERVED.points, 0, 100);
  }

  return {
    trust: score,
    grade: gradeForScore(score),
    baseline: BASELINE,
    demerits,
    bonuses,
  };
}

function normalizeData(data) {
  if (data === null || data === undefined) return '';
  if (typeof data === 'string') return data.trim().toLowerCase();
  try { return JSON.stringify(data); } catch { return String(data); }
}

/**
 * Enrich a whole batch with `_confidence`. Corroboration is counted honestly
 * from the events themselves (distinct source_urls bearing the same
 * event_type+data) — the SAME co-occurrence notion evidence-quality.js and
 * severity.js use, so all three layers agree. Returns new objects.
 *
 * @param {object[]} events
 * @param {object} [opts] {integrityByUrl, lastObservedByUrl, now, staleAfterDays}
 * @returns {object[]} valid events annotated with `_confidence`
 */
function enrichConfidence(events = [], opts = {}) {
  const valid = (events || []).filter(isModuleEvent);
  const integrityByUrl = (opts && opts.integrityByUrl) || {};
  const lastObservedByUrl = (opts && opts.lastObservedByUrl) || {};

  const surfaces = new Map();
  const keyOf = (ev) => `${ev.event_type}::${normalizeData(ev.data)}`;
  for (const ev of valid) {
    const k = keyOf(ev);
    if (!surfaces.has(k)) surfaces.set(k, new Set());
    if (ev.source_url) surfaces.get(k).add(ev.source_url);
  }

  return valid.map((ev) => {
    const corroborations = Math.max(1, surfaces.get(keyOf(ev)) ? surfaces.get(keyOf(ev)).size : 1);
    const integrity = ev.source_url ? integrityByUrl[ev.source_url] : undefined;
    const last_observed = ev.source_url ? lastObservedByUrl[ev.source_url] : undefined;
    const conf = findingConfidence(ev, {
      corroborations,
      integrity,
      last_observed,
      now: opts.now,
      staleAfterDays: opts.staleAfterDays,
    });
    return { ...ev, _confidence: conf };
  });
}

module.exports = {
  BASELINE,
  DEMERITS,
  BONUS,
  GRADE_CHART,
  gradeForScore,
  findingConfidence,
  enrichConfidence,
};
