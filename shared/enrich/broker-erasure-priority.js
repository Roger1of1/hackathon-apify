/**
 * shared/enrich/broker-erasure-priority.js
 *
 * ENRICHMENT: turn confirmed BROKER_LISTING_HIT events (from
 * shared/detectors/broker-listing-detector.js) into a PRIORITIZED erasure
 * worklist — "which controller should the subject send an opt-out / Article 17
 * request to FIRST?" — without re-implementing any planner.
 *
 * ───────────────────────── WHAT IT IS (AND IS NOT) ─────────────────────────
 *  - It does NOT scrape, fetch, or fabricate anything. It consumes events that
 *    already passed the detector's corroboration gate and orders them.
 *  - It does NOT build the opt-out request or the erasure letter — those remain
 *    shared/aux/broker-optout.js and shared/aux/takedown-letter.js. This module
 *    produces the TRIAGE (ranking + the structured hand-off payload) those
 *    planners consume. Zero duplication.
 *  - RED LINE: every item is, by construction, the SELF subject's OWN record on a
 *    public controller. There is no third-party target and no inference field.
 *
 * REFERENCE ARCHITECTURE #1 — DeleteMe / Aura broker opt-out workflow:
 *   DeleteMe/Aura don't fire every removal at once; they TRIAGE — high-exposure
 *   brokers and confirmed listings first, then re-scan. We reproduce that triage:
 *   rank by the EXISTING severity model (shared/enrich/severity.js, which itself
 *   reuses shared/scoring.js + evidence-quality.js — we never fork it) so a
 *   well-corroborated, highly-visible listing is actioned before a weak one. We
 *   also tag each item with the broker's documented opt-out METHOD + recheck
 *   surface (from the EXISTING shared/aux/broker-registry.js) so the worklist is
 *   directly executable by the opt-out planner and the reappearance re-scan.
 *
 * REFERENCE ARCHITECTURE #2 — GDPR Article 17 RTBF erasure-request automation:
 *   Art.17 erasure tooling routes each request to the right LEGAL BASIS and the
 *   right controller. We surface `jurisdiction_hint` per item (so the letter
 *   builder picks Art.17 vs CCPA §1798.105 language) and a `legal_basis` label,
 *   and we expose the matched-field NAMES as the "data at issue" the request must
 *   identify — exactly the metadata an erasure-request automation needs, and
 *   nothing more (we never echo the matched VALUES).
 *
 * Pure functions, no network, no mutation of inputs. Safe to require at load.
 */

'use strict';

const { isModuleEvent, EVENT_TYPES } = require('../detectors/event-types.js');
const { eventSeverity } = require('./severity.js');
const { getBroker } = require('../aux/broker-registry.js');

// Map a broker jurisdiction hint to the erasure legal basis label the
// downstream letter builder switches on. Honest, coarse — the operator confirms.
const LEGAL_BASIS = Object.freeze({
  eu: { statute: 'GDPR Art.17', label: 'EU/EEA right to erasure (RTBF)' },
  uk: { statute: 'UK GDPR Art.17', label: 'UK right to erasure' },
  us: { statute: 'CCPA §1798.105', label: 'California right to delete (where applicable)' },
});

function legalBasisFor(jurisdictionHint) {
  const key = String(jurisdictionHint || '').toLowerCase();
  return LEGAL_BASIS[key] || {
    statute: 'opt-out',
    label: 'broker self-service opt-out (no statutory basis asserted)',
  };
}

/**
 * Build a single prioritized erasure-worklist item from one BROKER_LISTING_HIT.
 *
 * @param {object} event  a module_event of type BROKER_LISTING_HIT
 * @param {object} [opts] {integrity, corroborations} passed through to severity
 * @returns {object|null} the triage item, or null if not an applicable event
 */
function toErasureItem(event, opts = {}) {
  if (!isModuleEvent(event) || event.event_type !== EVENT_TYPES.BROKER_LISTING_HIT) {
    return null;
  }
  const meta = event.meta || {};
  const broker = getBroker(meta.broker_id) || null;

  // Reuse the canonical severity model (which reuses scoring.js + evidence-quality)
  // — this is the triage rank. We do NOT invent a parallel score.
  const sev = eventSeverity(event, opts);
  const basis = legalBasisFor(meta.jurisdiction_hint || (broker && broker.jurisdiction_hint));

  return {
    record_type: 'erasure_worklist_item',
    broker_id: meta.broker_id || (broker && broker.id) || null,
    broker_name: (broker && broker.name) || (event.data && event.data.broker_name) || null,
    // Triage priority comes straight from the severity model.
    priority: sev.severity,
    priority_band: sev.band,
    // Executable hand-off for the EXISTING planners (we feed, never re-build):
    optout: {
      url: meta.optout_url || (broker && broker.optout_url) || null,
      method: meta.optout_method || (broker && broker.method) || null,
    },
    erasure: {
      statute: basis.statute,
      legal_basis: basis.label,
      jurisdiction_hint: meta.jurisdiction_hint || (broker && broker.jurisdiction_hint) || null,
      // The "data at issue" the request must name — field NAMES only, never values.
      data_at_issue: Array.isArray(meta.matched_fields) ? meta.matched_fields.slice() : [],
    },
    // Reappearance re-scan surface (DeleteMe-style verify loop) — the broker's OWN
    // public page, read via the gated ingest actor named in the registry.
    recheck: meta.recheck || (broker && broker.recheck) || null,
    confidence: event.confidence,
    source_url: event.source_url || null,
    severity_components: sev.components,
    // Self-only invariant restated for any consumer that inspects items directly.
    subject_relationship: 'self_owned_record',
  };
}

/**
 * Build the full prioritized erasure worklist from a batch of events. Non-broker
 * events are ignored. Items are sorted highest-priority-first; ties broken by
 * confidence, then broker id for stable ordering.
 *
 * @param {object[]} events
 * @param {object} [opts] {integrityByUrl: {url -> integrity handles}}
 * @returns {{ items: object[], total: number, by_band: Record<string,number>, brokers: string[] }}
 */
function buildErasureWorklist(events = [], opts = {}) {
  const integrityByUrl = (opts && opts.integrityByUrl) || {};

  // Corroboration index across distinct surfaces for the SAME broker listing —
  // the same co-occurrence notion severity.js/evidence-quality.js use. A broker
  // record confirmed on two captured surfaces is even harder to clean ⇒ ranks up.
  const surfaces = new Map();
  const keyOf = (ev) => `BROKER::${(ev.meta && ev.meta.broker_id) || ''}`;
  const applicable = (events || []).filter(
    (ev) => isModuleEvent(ev) && ev.event_type === EVENT_TYPES.BROKER_LISTING_HIT,
  );
  for (const ev of applicable) {
    const k = keyOf(ev);
    if (!surfaces.has(k)) surfaces.set(k, new Set());
    if (ev.source_url) surfaces.get(k).add(ev.source_url);
  }

  const items = applicable.map((ev) => {
    const corroborations = Math.max(1, surfaces.get(keyOf(ev)) ? surfaces.get(keyOf(ev)).size : 1);
    const integrity = ev.source_url ? integrityByUrl[ev.source_url] : undefined;
    return toErasureItem(ev, { integrity, corroborations });
  }).filter(Boolean);

  items.sort((a, b) => {
    if (b.priority !== a.priority) return b.priority - a.priority;
    if ((b.confidence || 0) !== (a.confidence || 0)) return (b.confidence || 0) - (a.confidence || 0);
    return String(a.broker_id).localeCompare(String(b.broker_id));
  });

  const by_band = {};
  const brokers = [];
  for (const it of items) {
    by_band[it.priority_band] = (by_band[it.priority_band] || 0) + 1;
    if (it.broker_id && !brokers.includes(it.broker_id)) brokers.push(it.broker_id);
  }

  return { items, total: items.length, by_band, brokers };
}

module.exports = {
  LEGAL_BASIS,
  legalBasisFor,
  toErasureItem,
  buildErasureWorklist,
};
