/**
 * shared/enrich/reidentification.js
 *
 * RE-IDENTIFICATION ("mosaic effect") risk enrichment.
 *
 * Every other detector answers "is THIS single thing leaked?" (an email, a
 * tracker, a breached password). The genuinely-missing self-audit capability is
 * the COMBINATION question Latanya Sweeney's landmark result poses:
 *
 *   "87% of the U.S. population is uniquely identified by the triple
 *    { 5-digit ZIP, date of birth, sex }."  — Sweeney, 2000.
 *
 * None of those three fields is sensitive ALONE — a city, a birth year, a job
 * title each feel harmless. Together they form a QUASI-IDENTIFIER that can pick
 * one person out of a population. A self-audit that flags single leaks but never
 * flags the mosaic is incomplete. This module supplies exactly that missing
 * layer: it takes the SELF subject's OWN already-detected public facts, groups
 * the quasi-identifying ones that co-occur on the same surface/cluster, and
 * estimates how small an ANONYMITY SET those facts narrow the subject down to —
 * i.e. how re-identifiable the subject has made themselves by publishing them.
 *
 * ---- How the two assigned reference architectures are applied ----
 *
 *   OASIS STIX 2.1 Observed Data + OpenCTI/MISP interop:
 *     A re-identification finding is itself a derived OBSERVATION ("this set of
 *     public facts, observed together, narrows the subject to ~N people"). We
 *     emit it as a STIX 2.1 `observed-data` object by REUSING the existing
 *     shared/enrich/stix-evidence.js `toObservedData` (we do NOT duplicate STIX
 *     shaping) over a synthetic EXPOSURE_SUMMARY module_event, so the combination
 *     finding is portable into OpenCTI/MISP/a report exactly like every other
 *     finding. The quasi-identifier values are REDACTED in the STIX object (we
 *     carry only field NAMES + the anonymity-set size, never the raw city/DOB),
 *     mirroring how stix-indicator.js already refuses to export raw PII.
 *
 *   Apify Website Content Crawler + RAG Web Browser ingestion:
 *     The quasi-identifiers we read are extracted from page TEXT that the Website
 *     Content Crawler / RAG Web Browser already cleaned into the PAGE_TEXT
 *     artifacts the PII detector consumes (WCC strips nav/boilerplate and yields
 *     the main readable text; RAG Web Browser returns that text for downstream
 *     analysis). We add NO new crawl — we enrich the events the WCC/RAG-fed
 *     pipeline already produced. The re-check cadence that would re-evaluate this
 *     risk after the subject removes a field rides the same WCC ingestion path.
 *     Refs: apify.com/apify/website-content-crawler ;
 *           apify.com/apify/rag-web-browser
 *
 * ---- What it REUSES (never forks) ----
 *   - shared/detectors/event-types.js  frozen EVENT_TYPES vocab + makeEvent/isModuleEvent
 *   - shared/enrich/k-anonymity.js     the anonymity-set / k threshold concept (HIBP model)
 *   - shared/enrich/cluster-keys.js    hostOf / surface grouping (SpiderFoot entity linking)
 *   - shared/enrich/stix-evidence.js   toObservedData (STIX 2.1 Observed Data shaping)
 *   - shared/enrich/severity.js        bandFor (the canonical 0..100 -> band map)
 *
 * ---- RED LINES (enforced by construction) ----
 *   - Quasi-identifiers here are ONLY fields the SELF (or public_figure) subject
 *     PUBLISHED ABOUT THEMSELVES and that the existing detectors already emitted
 *     (city hint, postal, handle, self-published birth-year text, employer text).
 *     There is NO field for gender/sexuality/romance/intimacy/relationship, and
 *     NO live-location field — the QUASI_IDENTIFIER map below is the only set of
 *     fields that can ever contribute, and it is frozen. Sweeney's triple uses
 *     "sex"; we deliberately do NOT, because inferring/recording it would cross a
 *     red line, so our model uses only self-published, non-protected attributes.
 *   - The population priors are a CLEARLY-LABELLED TEMPLATE (coarse public
 *     reference magnitudes, source-cited), never fabricated per-person data. The
 *     output states `prior_basis: 'TEMPLATE'` so no reader mistakes the estimate
 *     for a real population query. With no real priors wired, the estimate is an
 *     explicit order-of-magnitude bound, not a precise count.
 *   - We never store or export the raw quasi-identifier VALUES in the STIX
 *     object — only the field names and the resulting anonymity-set magnitude.
 *
 * Pure functions, no network, no mutation of inputs. Safe to require at load.
 */

'use strict';

const {
  EVENT_TYPES, VISIBILITY, RISK, makeEvent, isModuleEvent,
} = require('../detectors/event-types.js');
const { DEFAULT_K } = require('./k-anonymity.js');
const { hostOf } = require('./cluster-keys.js');
const { toObservedData } = require('./stix-evidence.js');
const { bandFor } = require('./severity.js');

/**
 * The FROZEN set of quasi-identifier fields. Each maps a detector EVENT_TYPE to:
 *  - field:   a stable, non-PII field name used in output (never the raw value)
 *  - power:   a coarse "distinguishing power" weight (how much this field tends
 *             to shrink an anonymity set). Higher = more identifying. These are
 *             ORDER-OF-MAGNITUDE template weights, NOT exact statistics.
 *
 * Sweeney's triple is { ZIP, DOB, sex }. We map onto the self-published analogues
 * the existing detectors emit, and POINTEDLY omit sex/gender (red line). A
 * precise street address is by far the most identifying (close to unique), a
 * coarse city far less so, a birth-year moderately, a handle highly (often
 * globally unique), an employer moderately.
 */
const QUASI_IDENTIFIER = Object.freeze({
  [EVENT_TYPES.PII_POSTAL_PUBLIC]: { field: 'postal_address', power: 0.95 },
  [EVENT_TYPES.PII_GEO_HINT_PUBLIC]: { field: 'city_hint', power: 0.45 },
  [EVENT_TYPES.PII_HANDLE_PUBLIC]: { field: 'handle', power: 0.85 },
  [EVENT_TYPES.SELF_USERNAME]: { field: 'handle', power: 0.85 },
  // Birth-year / employer are not their OWN event types; they ride in as PII text
  // with a meta.qi_field tag the PII layer can set. We accept them only via that
  // explicit tag so nothing is inferred — see qiFieldFor().
});

/**
 * Additional quasi-identifier fields a detector may declare EXPLICITLY in
 * event.meta.qi_field (so we never INFER birth-year/employer from free text — a
 * detector must have positively identified it). Frozen; no protected attributes.
 */
const TAGGED_QI_POWER = Object.freeze({
  birth_year: 0.55,
  employer: 0.5,
  job_title: 0.35,
  school: 0.45,
});

/**
 * CLEARLY-LABELLED TEMPLATE population prior. This is the reference magnitude the
 * estimate generalizes against — the size of the crowd a subject "hides in"
 * before any quasi-identifier narrows it. It is a coarse public order-of-
 * magnitude (roughly a large metro population), NOT a real census query and NOT
 * per-person data. Swapping in a real population table is the only thing needed
 * to make the estimate precise; until then `prior_basis: 'TEMPLATE'` is emitted.
 *
 * Ref for the modelling approach (k-anonymity generalization + the {ZIP,DOB,sex}
 * uniqueness result): L. Sweeney, "Simple Demographics Often Identify People
 * Uniquely", Carnegie Mellon, 2000; "k-anonymity: a model for protecting
 * privacy", 2002.
 */
const TEMPLATE_PRIORS = Object.freeze({
  prior_basis: 'TEMPLATE',
  // Starting anonymity set: the crowd before any narrowing. ~1e6 ≈ a metro.
  base_population: 1_000_000,
  note: 'TEMPLATE coarse public magnitude (≈ one large metro). Not a real census '
    + 'query and not per-person data. Replace with a real population table to make '
    + 'the estimate precise; basis is reported as TEMPLATE until then.',
  source: 'Sweeney 2000/2002 (k-anonymity generalization, {ZIP,DOB,sex} uniqueness).',
});

/**
 * Resolve the quasi-identifier field for an event, honestly:
 *  - by frozen EVENT_TYPE map, OR
 *  - by an EXPLICIT event.meta.qi_field tag whose value is in TAGGED_QI_POWER.
 * Returns null for anything else — we never infer a QI from raw text here.
 *
 * @param {object} event a module_event
 * @returns {{ field:string, power:number }|null}
 */
function qiFieldFor(event) {
  if (!isModuleEvent(event)) return null;

  // An EXPLICIT, allow-listed meta.qi_field tag takes PRECEDENCE: a detector
  // positively asserting "this string is an employer/birth_year" is more
  // specific than the carrier event_type it rode in on. The allow-list
  // (TAGGED_QI_POWER) is frozen and contains no protected attribute, so a tag
  // for sex/gender/etc. simply isn't in it and is refused below.
  const tagRaw = event.meta && typeof event.meta.qi_field === 'string' ? event.meta.qi_field : null;
  if (tagRaw) {
    // A tag is a deliberate assertion. If it names an allowed field, honor it;
    // if it names a DISALLOWED field (e.g. a red-line attribute), REFUSE the
    // whole event — we do not silently fall back to the carrier type, because
    // that would let a banned tag smuggle the event in via its event_type.
    if (Object.prototype.hasOwnProperty.call(TAGGED_QI_POWER, tagRaw)) {
      return { field: tagRaw, power: TAGGED_QI_POWER[tagRaw] };
    }
    return null;
  }

  // No tag: fall back to the frozen EVENT_TYPE -> QI map.
  const byType = QUASI_IDENTIFIER[event.event_type];
  return byType || null;
}

/**
 * Group a flat module_event[] by the SURFACE the subject published them on (the
 * host of source_url), keeping only quasi-identifying events. Co-publishing
 * multiple QIs on ONE surface is the mosaic that re-identifies — this is the
 * SpiderFoot "events sharing an entity (the host) are linked" idea reused.
 *
 * Events with no source_url are grouped under a single '(no-surface)' bucket so
 * they still contribute, but are flagged as unlocated.
 *
 * @param {object[]} events
 * @returns {Map<string, object[]>} surface key -> quasi-identifying events
 */
function groupQuasiIdentifiersBySurface(events = []) {
  const groups = new Map();
  for (const ev of (Array.isArray(events) ? events : [])) {
    if (!qiFieldFor(ev)) continue;
    const host = hostOf(ev.source_url) || '(no-surface)';
    if (!groups.has(host)) groups.set(host, []);
    groups.get(host).push(ev);
  }
  return groups;
}

/**
 * Estimate the ANONYMITY SET size for a set of co-published quasi-identifiers:
 * how many people in the template population still match after all these fields
 * are known. Smaller = more re-identifiable (k-anonymity: k is this size).
 *
 * Model (honest + coarse, TEMPLATE-based): each DISTINCT quasi-identifier field
 * multiplies the population by a "retained fraction" derived from its
 * distinguishing power — a high-power field keeps a small fraction of the crowd.
 * We take the strongest occurrence per field (publishing two city hints is not
 * more identifying than one), exactly as k-anonymity generalizes per attribute.
 *
 * retainedFraction(power) = 10^(-2*power)  → power 0.5 keeps ~1/10, power 0.95
 * keeps ~1/79 (a precise street address alone nearly singles you out). These are
 * order-of-magnitude template weights, reported as such.
 *
 * @param {object[]} qiEvents quasi-identifying module_events (one surface/cluster)
 * @param {object} [opts] {priors?: typeof TEMPLATE_PRIORS}
 * @returns {{
 *   anonymity_set:number, fields:string[], distinct_field_count:number,
 *   unique:boolean, prior_basis:string, base_population:number, retained_fraction:number
 * }}
 */
function estimateAnonymitySet(qiEvents = [], opts = {}) {
  const priors = (opts && opts.priors) || TEMPLATE_PRIORS;
  const base = Number.isFinite(priors.base_population) && priors.base_population > 0
    ? priors.base_population : TEMPLATE_PRIORS.base_population;

  // Strongest power per DISTINCT field name (k-anonymity generalizes per
  // attribute; duplicates of the same attribute don't add independent narrowing).
  const bestPowerByField = new Map();
  for (const ev of (Array.isArray(qiEvents) ? qiEvents : [])) {
    const qi = qiFieldFor(ev);
    if (!qi) continue;
    const prev = bestPowerByField.get(qi.field);
    if (prev === undefined || qi.power > prev) bestPowerByField.set(qi.field, qi.power);
  }

  const fields = Array.from(bestPowerByField.keys()).sort();
  let retained = 1;
  for (const power of bestPowerByField.values()) {
    retained *= Math.pow(10, -2 * power); // retained fraction for this field
  }

  // Anonymity set: people still matching. Floor at 1 (you are always >=1: you).
  const rawSet = base * retained;
  const anonymitySet = Math.max(1, Math.round(rawSet));

  return {
    anonymity_set: anonymitySet,
    fields,
    distinct_field_count: fields.length,
    unique: anonymitySet <= 1,
    prior_basis: priors.prior_basis || 'TEMPLATE',
    base_population: base,
    retained_fraction: retained,
  };
}

/**
 * Map an anonymity-set size to a 0..100 re-identification risk + the canonical
 * severity band. k below DEFAULT_K (the same k-anonymity threshold HIBP uses for
 * "your query was identifying") is the danger zone; k==1 (unique) is maximal.
 * Reuses bandFor from severity.js so this risk lands on the SAME band scale.
 *
 * @param {number} anonymitySet
 * @param {number} [k] anonymity threshold (default DEFAULT_K)
 * @returns {{ risk_score:number, band:string, k_threshold:number, below_k:boolean }}
 */
function reidentificationRisk(anonymitySet, k = DEFAULT_K) {
  const setSize = Math.max(1, Number(anonymitySet) || 1);
  const threshold = Number.isFinite(k) && k > 0 ? k : DEFAULT_K;

  // Risk falls off as the anonymity set grows. Unique (1) -> ~100; at the k
  // threshold -> ~50; far above k -> low. Log scale, since identifiability is
  // about orders of magnitude, not linear counts.
  // score = 100 * (1 - log10(setSize) / log10(base_for_zero))
  // We anchor "0 risk" at a comfortably-large crowd (1e6 ~ the template base).
  const upper = 1_000_000;
  const lr = Math.log10(setSize);
  const lu = Math.log10(upper);
  let score = 100 * (1 - lr / lu);
  if (setSize <= 1) score = 100;
  score = Math.max(0, Math.min(100, Math.round(score)));

  return {
    risk_score: score,
    band: bandFor(score),
    k_threshold: threshold,
    below_k: setSize < threshold,
  };
}

/**
 * Build a re-identification FINDING for one surface's co-published quasi-
 * identifiers. Returns null if fewer than 2 distinct QI fields co-occur (a
 * single field is not a mosaic — it's already reported by the base detector).
 *
 * The finding carries a synthetic EXPOSURE_SUMMARY module_event (so it flows
 * through the SAME severity/report/STIX machinery as every other finding) whose
 * data is the anonymity-set summary — NEVER the raw quasi-identifier values.
 *
 * @param {string} surface  host key the QIs were co-published on
 * @param {object[]} qiEvents quasi-identifying events on that surface
 * @param {object} [opts] {priors?, k?, now?}
 * @returns {object|null} a finding { event, anonymity, risk, surface, contributing_event_types }
 */
function buildSurfaceFinding(surface, qiEvents = [], opts = {}) {
  const anonymity = estimateAnonymitySet(qiEvents, opts);
  if (anonymity.distinct_field_count < 2) return null; // not a mosaic

  const risk = reidentificationRisk(anonymity.anonymity_set, opts && opts.k);

  // Map risk band -> the frozen RISK enum the event vocabulary allows.
  const riskEnum = anonymity.unique
    ? RISK.HIGH
    : (risk.below_k ? RISK.MEDIUM : RISK.LOW);

  // The most identifying contributing surface determines visibility; if any
  // contributing QI is INDEXED (search-discoverable), the mosaic is too.
  const anyIndexed = qiEvents.some((e) => e.visibility === VISIBILITY.INDEXED);
  const sourceUrl = (qiEvents.find((e) => typeof e.source_url === 'string') || {}).source_url || null;

  const contributing = Array.from(new Set(qiEvents.map((e) => e.event_type))).sort();

  const event = makeEvent({
    event_type: EVENT_TYPES.EXPOSURE_SUMMARY,
    source_module: 'reidentification_enricher',
    // DATA carries ONLY field names + anonymity magnitude — never raw QI values.
    data: {
      kind: 'reidentification_mosaic',
      surface,
      quasi_identifier_fields: anonymity.fields,
      anonymity_set: anonymity.anonymity_set,
      unique: anonymity.unique,
      prior_basis: anonymity.prior_basis,
    },
    // Confidence reflects the model's coarseness honestly: a TEMPLATE-prior
    // estimate is an order-of-magnitude signal, not a precise certainty.
    confidence: anonymity.prior_basis === 'TEMPLATE' ? 0.6 : 0.85,
    visibility: anyIndexed ? VISIBILITY.INDEXED : VISIBILITY.LINKED,
    risk: riskEnum,
    source_url: sourceUrl,
    meta: {
      method: 'kanonymity_generalization',
      model_ref: 'Sweeney 2000/2002 {ZIP,DOB,sex} uniqueness; sex deliberately omitted (red line)',
      prior_basis: anonymity.prior_basis,
      base_population: anonymity.base_population,
      retained_fraction: anonymity.retained_fraction,
      risk_score: risk.risk_score,
      below_k: risk.below_k,
      k_threshold: risk.k_threshold,
      distinct_field_count: anonymity.distinct_field_count,
      contributing_event_types: contributing,
    },
  });

  return {
    event,
    surface,
    anonymity,
    risk,
    contributing_event_types: contributing,
  };
}

/**
 * The public enricher: scan a flat module_event[], find every surface where the
 * subject co-published >=2 distinct quasi-identifiers, and produce a
 * re-identification finding per such surface (Closure-Mode-friendly: it tells
 * the user WHICH small set of fields to remove to grow their anonymity set).
 *
 * @param {object[]} events  detector module_events (WCC/RAG-fed pipeline output)
 * @param {object} [opts] {priors?, k?, now?}
 * @returns {{
 *   findings: object[],          // surface findings, highest risk first
 *   events: object[],            // the synthetic EXPOSURE_SUMMARY events (feed scoring/report)
 *   worst_anonymity_set:number,  // smallest crowd the subject narrows to (null if none)
 *   prior_basis:string
 * }}
 */
function enrichReidentification(events = [], opts = {}) {
  const groups = groupQuasiIdentifiersBySurface(events);
  const findings = [];

  for (const [surface, qiEvents] of groups) {
    const finding = buildSurfaceFinding(surface, qiEvents, opts);
    if (finding) findings.push(finding);
  }

  // Highest risk (smallest anonymity set) first.
  findings.sort((a, b) => b.risk.risk_score - a.risk.risk_score);

  const worst = findings.length
    ? Math.min(...findings.map((f) => f.anonymity.anonymity_set))
    : null;

  return {
    findings,
    events: findings.map((f) => f.event),
    worst_anonymity_set: worst,
    prior_basis: (opts && opts.priors && opts.priors.prior_basis) || TEMPLATE_PRIORS.prior_basis,
  };
}

/**
 * Emit a re-identification finding as a STIX 2.1 Observed Data object by REUSING
 * the existing stix-evidence.js toObservedData (no STIX shaping duplicated). The
 * finding's synthetic EXPOSURE_SUMMARY event already redacts the raw values, so
 * the exported Observed Data carries only field names + anonymity magnitude —
 * portable into OpenCTI/MISP/a report without leaking the quasi-identifiers.
 *
 * @param {object} finding  a finding from enrichReidentification().findings
 * @param {object} [opts]   {now?: ISO string}  forwarded to toObservedData
 * @returns {object|null}   STIX observed-data, or null if invalid
 */
function findingToObservedData(finding, opts = {}) {
  if (!finding || !isModuleEvent(finding.event)) return null;
  return toObservedData(finding.event, { now: opts && opts.now });
}

module.exports = {
  QUASI_IDENTIFIER,
  TAGGED_QI_POWER,
  TEMPLATE_PRIORS,
  qiFieldFor,
  groupQuasiIdentifiersBySurface,
  estimateAnonymitySet,
  reidentificationRisk,
  buildSurfaceFinding,
  enrichReidentification,
  findingToObservedData,
};
