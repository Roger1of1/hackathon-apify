/**
 * shared/enrich/severity.js
 *
 * One honest SEVERITY model for detector module_events, so the Blacklight-style
 * inspector panel and the report builder rank exposures the SAME way instead of
 * each inventing an ad-hoc ordering.
 *
 * This is an ENRICHMENT layer — it does NOT introduce a new scoring axis. It
 * combines signals that already exist on every event:
 *   - risk        (RISK_RANK: info<low<medium<high)  — how bad the exposure is
 *   - visibility  (VISIBILITY_RANK: private<linked<indexed) — how findable it is
 *   - confidence  (0..1)                              — how sure the detector is
 * and folds in the per-event evidence-quality already produced by the EXISTING
 * shared/enrich/evidence-quality.js (we call it, never fork it). For the
 * batch-level rollup we feed the EXISTING shared/scoring.js exposureScore the
 * same surface counts shared/detectors/index.js summarizeForExposure derives —
 * we do not reimplement exposure scoring here.
 *
 * RED LINES: severity is about how exposed the SELF subject's OWN footprint is
 * and how confident we are it is real. It is NOT a threat/desirability/intimacy
 * score about any other person. The only inputs are the frozen-vocabulary event
 * fields; there is no slot for romance/gender/sexuality/live-location, by design.
 *
 * Reference patterns applied:
 *   - SpiderFoot/STIX style: every observation carries an independent CONFIDENCE
 *     that gates how heavily its severity counts — a high-risk but low-confidence
 *     signal must not dominate, mirroring how SpiderFoot/STIX separate severity
 *     from confidence rather than collapsing them.
 *   - HIBP-style "more sightings = stronger": corroboration across distinct
 *     public surfaces (already computed by evidence-quality.js) nudges severity
 *     up, because a leak seen in many places is harder to clean up.
 *
 * Pure functions, no network, no mutation of inputs. Safe to require at load.
 */

'use strict';

const { RISK_RANK, VISIBILITY_RANK, isModuleEvent } = require('../detectors/event-types.js');
const { clamp } = require('../scoring.js');
const { eventEvidenceQuality } = require('./evidence-quality.js');

// Map the discrete frozen ranks onto a 0..100 base so they compose with the
// continuous confidence/corroboration signals. Reuses the canonical *_RANK maps
// (info=0..high=3 ; private=1..indexed=3) — never a parallel enum.
const RISK_WEIGHT = Object.freeze({ 0: 0, 1: 35, 2: 65, 3: 100 });        // by RISK_RANK
const VISIBILITY_WEIGHT = Object.freeze({ 1: 30, 2: 65, 3: 100 });        // by VISIBILITY_RANK

// Coarse human-readable bands for the inspector panel. Thresholds chosen so an
// info/low-confidence finding lands in "info" and a high-risk/indexed/confident
// one lands in "critical".
const SEVERITY_BANDS = Object.freeze([
  { band: 'critical', min: 80 },
  { band: 'high', min: 60 },
  { band: 'medium', min: 35 },
  { band: 'low', min: 15 },
  { band: 'info', min: 0 },
]);

function bandFor(score) {
  for (const b of SEVERITY_BANDS) {
    if (score >= b.min) return b.band;
  }
  return 'info';
}

/**
 * Per-event severity (0..100) + the components it was built from, so the panel
 * can explain WHY something ranked where it did (no black box).
 *
 * @param {object} event   a module_event
 * @param {object} [opts]
 * @param {object} [opts.integrity]      preservation handles for evidence-quality
 * @param {number} [opts.corroborations] distinct public surfaces showing this exposure (>=1)
 * @returns {{ severity: number, band: string, components: object }}
 */
function eventSeverity(event, opts = {}) {
  if (!isModuleEvent(event)) {
    return { severity: 0, band: 'info', components: {} };
  }

  const riskComponent = RISK_WEIGHT[RISK_RANK[event.risk] ?? 0] ?? 0;
  const visibilityComponent = VISIBILITY_WEIGHT[VISIBILITY_RANK[event.visibility] ?? 2] ?? 65;

  // Reuse the canonical evidence-quality scorer (which itself reuses scoring.js)
  // for the "how solid is this finding" dimension (integrity+confidence+corrob).
  const eq = eventEvidenceQuality(event, opts);

  // Confidence GATES the impact: a high-risk signal we are only 30% sure of must
  // not outrank a medium-risk signal we are certain of. We scale the
  // risk+visibility impact by confidence, then add a quality bonus.
  const confidence = Number.isFinite(event.confidence) ? event.confidence : 0.5;
  const impact = (riskComponent * 0.6 + visibilityComponent * 0.4); // 0..100
  const gatedImpact = impact * (0.4 + 0.6 * confidence); // confidence never zeroes it entirely
  // Evidence quality (preservation+corroboration) adds up to a modest bonus so a
  // well-corroborated, well-preserved finding edges above a flimsy one.
  const qualityBonus = eq.quality * 0.15;

  const severity = clamp(gatedImpact + qualityBonus);

  return {
    severity,
    band: bandFor(severity),
    components: {
      risk_component: riskComponent,
      visibility_component: visibilityComponent,
      confidence,
      impact: Math.round(impact),
      evidence_quality: eq.quality,
      corroborations: eq.components ? eq.components.corroborations : 1,
    },
  };
}

/**
 * Enrich a whole batch with `_severity`, counting corroboration honestly from the
 * events themselves (distinct source_urls bearing the same event_type+data) —
 * the SAME co-occurrence notion evidence-quality.js uses. Returns events sorted
 * highest-severity-first so the inspector panel and report agree on order.
 *
 * @param {object[]} events
 * @param {object} [opts] {integrityByUrl: {url -> integrity handles}}
 * @returns {object[]} valid events annotated with `_severity`, sorted desc
 */
function rankBySeverity(events = [], opts = {}) {
  const valid = (events || []).filter(isModuleEvent);
  const integrityByUrl = (opts && opts.integrityByUrl) || {};

  // corroboration index: (event_type + normalized data) -> Set(source_url)
  const surfaces = new Map();
  const keyOf = (ev) => `${ev.event_type}::${normalizeData(ev.data)}`;
  for (const ev of valid) {
    const k = keyOf(ev);
    if (!surfaces.has(k)) surfaces.set(k, new Set());
    if (ev.source_url) surfaces.get(k).add(ev.source_url);
  }

  const annotated = valid.map((ev) => {
    const corroborations = Math.max(1, surfaces.get(keyOf(ev)) ? surfaces.get(keyOf(ev)).size : 1);
    const integrity = ev.source_url ? integrityByUrl[ev.source_url] : undefined;
    const sev = eventSeverity(ev, { integrity, corroborations });
    return { ...ev, _severity: sev };
  });

  annotated.sort((a, b) => b._severity.severity - a._severity.severity);
  return annotated;
}

/**
 * A single batch-level severity headline for a report card. We REUSE the
 * canonical shared/scoring.js exposureScore for the surface-spread component (fed
 * the same {reachablePages,distinctHosts,indexablePages} shape the detector
 * registry already produces) and blend it with the worst-case event severity, so
 * one loud critical finding OR broad spread both raise the headline.
 *
 * @param {object[]} events
 * @param {object} crawlSummary {reachablePages,distinctHosts,indexablePages} from summarizeForExposure
 * @param {object} [opts]
 * @returns {{ severity: number, band: string, max_event_severity: number, exposure_score: number, event_count: number }}
 */
function batchSeverity(events = [], crawlSummary = {}, opts = {}) {
  // Lazy require to avoid any import cycle risk with the registry; scoring.js is
  // the canonical exposure scorer and we do not reimplement it.
  const { exposureScore } = require('../scoring.js');
  const ranked = rankBySeverity(events, opts);
  const maxEvent = ranked.length ? ranked[0]._severity.severity : 0;
  const exposure = exposureScore(crawlSummary || {});
  // Headline leans on the worst finding but is lifted by overall spread.
  const severity = clamp(maxEvent * 0.7 + exposure * 0.3);
  return {
    severity,
    band: bandFor(severity),
    max_event_severity: maxEvent,
    exposure_score: exposure,
    event_count: ranked.length,
  };
}

function normalizeData(data) {
  if (data === null || data === undefined) return '';
  if (typeof data === 'string') return data.trim().toLowerCase();
  try { return JSON.stringify(data); } catch { return String(data); }
}

module.exports = {
  RISK_WEIGHT,
  VISIBILITY_WEIGHT,
  SEVERITY_BANDS,
  bandFor,
  eventSeverity,
  rankBySeverity,
  batchSeverity,
};
