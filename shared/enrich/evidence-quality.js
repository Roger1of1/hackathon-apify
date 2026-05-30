/**
 * shared/enrich/evidence-quality.js
 *
 * Enrichment layer on top of the EXISTING shared/scoring.js `evidenceQualityScore`.
 * That canonical function answers "is this artifact court-/report-ready?" purely
 * from integrity handles (content_sha256, html_sha256, html_key, screenshot_key).
 * Detector module_events add two more honest dimensions Blacklight-style audits
 * care about:
 *   - confidence : how strong the detection signal was (regex/API match strength)
 *   - corroboration : the SAME exposure seen on multiple surfaces is more solid
 *
 * We do NOT replace or fork the scoring model — we call it and combine. The
 * report builder is still expected to read its top-line scores from
 * shared/scoring.js; this just annotates per-event evidence quality so the
 * inspector panel can show "how sure are we, and how well preserved is it".
 *
 * Pure functions, no network, no mutation of inputs. Safe to require at load.
 */

'use strict';

const { evidenceQualityScore, clamp } = require('../scoring.js');
const { isModuleEvent } = require('../detectors/event-types.js');

/**
 * Per-event evidence quality: blend the canonical artifact-integrity score with
 * the detection confidence and how many distinct surfaces corroborate it.
 *
 * @param {object} event   a module_event
 * @param {object} [opts]
 * @param {object} [opts.integrity] {content_sha256, html_sha256, html_key, screenshot_key}
 * @param {number} [opts.corroborations] how many distinct surfaces show this exposure (>=1)
 * @returns {{ quality: number, components: object }}
 */
function eventEvidenceQuality(event, opts = {}) {
  if (!isModuleEvent(event)) return { quality: 0, components: {} };

  // Reuse the canonical scorer for the preservation/integrity component.
  const integrity = opts.integrity && typeof opts.integrity === 'object' ? opts.integrity : {};
  const integrityScore = evidenceQualityScore({ items: [integrity] }); // 0..100

  const confidenceScore = clamp((Number(event.confidence) || 0) * 100); // 0..100

  // Corroboration: 1 surface = baseline; each extra distinct surface adds, with
  // diminishing returns, capped. Honest — driven by real co-occurrence counts.
  const corr = Math.max(1, Number(opts.corroborations) || 1);
  const corroborationScore = clamp(40 + Math.log2(corr) * 30); // 1->40, 2->70, 4->100

  // Weighted blend: preservation matters most for "is it usable as evidence",
  // confidence guards against false positives, corroboration adds robustness.
  const quality = clamp(
    integrityScore * 0.5 + confidenceScore * 0.3 + corroborationScore * 0.2,
  );

  return {
    quality,
    components: {
      integrity_score: integrityScore,
      confidence_score: confidenceScore,
      corroboration_score: corroborationScore,
      corroborations: corr,
    },
  };
}

/**
 * Enrich a whole batch of events. Counts corroboration as the number of DISTINCT
 * source_urls on which the same (event_type + normalized data) was observed —
 * a real co-occurrence signal, computed from the events themselves.
 *
 * @param {object[]} events
 * @param {object} [opts] {integrityByUrl: {url -> integrity handles}}
 * @returns {object[]} events annotated with `_evidence_quality`
 */
function enrichEvents(events = [], opts = {}) {
  const valid = (events || []).filter(isModuleEvent);
  const integrityByUrl = (opts && opts.integrityByUrl) || {};

  // Build corroboration index: key -> Set(source_url)
  const surfaces = new Map();
  const keyOf = (ev) => `${ev.event_type}::${normalizeData(ev.data)}`;
  for (const ev of valid) {
    const key = keyOf(ev);
    if (!surfaces.has(key)) surfaces.set(key, new Set());
    if (ev.source_url) surfaces.get(key).add(ev.source_url);
  }

  return valid.map((ev) => {
    const key = keyOf(ev);
    const corroborations = Math.max(1, surfaces.get(key) ? surfaces.get(key).size : 1);
    const integrity = ev.source_url ? integrityByUrl[ev.source_url] : undefined;
    const eq = eventEvidenceQuality(ev, { integrity, corroborations });
    return { ...ev, _evidence_quality: eq };
  });
}

function normalizeData(data) {
  if (data === null || data === undefined) return '';
  if (typeof data === 'string') return data.trim().toLowerCase();
  try { return JSON.stringify(data); } catch { return String(data); }
}

module.exports = { eventEvidenceQuality, enrichEvents };
