/**
 * shared/enrich/stix-indicator.js
 *
 * The MISSING interop half of shared/enrich/stix-evidence.js.
 *
 * stix-evidence.js emits the "what was SEEN" half of a finding as a STIX 2.1
 * `observed-data` object. But the de-facto OpenCTI / MISP interchange for a
 * detection is a PAIR:
 *
 *     [Indicator]  --(relationship: "based-on")-->  [Observed Data]
 *
 * i.e. the Indicator carries the reusable DETECTION PATTERN ("what to look
 * for"), the Observed Data carries the concrete SIGHTING ("what was seen"), and
 * a `based-on` Relationship ties them together. This is exactly how the
 * MISP-STIX converter renders a MISP attribute with `to_ids=true` (it produces
 * BOTH an Indicator with a STIX patterning expression AND an Observed Data
 * object, linked by a Relationship), and how OpenCTI ingests/correlates
 * indicators. Emitting only the Observed Data half means a user could NOT hand a
 * finding to OpenCTI/MISP/a SIEM as an actionable detection — only as a flat
 * observation. This module closes that gap.
 *
 * Refs (studied + applied):
 *   - OASIS STIX 2.1 (CS01): the `indicator` SDO, the STIX *Patterning* grammar
 *     (`[ <object-type>:<property> = '<value>' ]`), and the `based-on`
 *     Relationship from Indicator -> Observed Data (added in 2.1, replacing the
 *     older `derived-from` usage). docs.oasis-open.org/cti/stix/v2.1/cs01/
 *   - MISP-STIX converter: a detectable attribute => Indicator(pattern) +
 *     Observed Data, joined by a Relationship ("what was seen vs the detection
 *     pattern"). github.com/MISP/misp-stix
 *   - STIX 2.1 Interoperability Test Doc v1.0: Indicator-sharing + Observed-Data
 *     sharing use cases (the shape OpenCTI/MISP exchange).
 *
 * RED LINES (unchanged, enforced by construction):
 *   - An Indicator here is a pattern over the SELF subject's OWN public
 *     footprint ("my email/secret/tracker is publicly visible"), so the subject
 *     can find, preserve, and remediate it. It is NOT a watch-rule about another
 *     private person. The pattern object-types below are limited to the frozen
 *     OBSERVABLE_CATEGORY vocabulary; there is no romance/intimacy/identity/
 *     live-location object type to pattern on, by design.
 *   - Pattern VALUES are NEVER raw secrets. For credential exposures we pattern
 *     on the privacy-preserving k-anonymity hash PREFIX (HIBP range model), not
 *     the plaintext — so an exported Indicator never leaks the secret it warns
 *     about. PII values are redacted to a non-reversible shape too.
 *
 * Pure + deterministic given input + injectable clock. No network, no mutation.
 */

'use strict';

const { isModuleEvent } = require('../detectors/event-types.js');
const { OBSERVABLE_CATEGORY, deterministicId, toObservedData } = require('./stix-evidence.js');
const { rangeOf } = require('./k-anonymity.js');

// STIX patterning uses Cyber-observable Object types (SCO types). Map our coarse
// OBSERVABLE_CATEGORY onto the closest real STIX 2.1 SCO type + the property the
// pattern compares. Where no exact SCO type exists for a self-audit concept we
// use a clearly x_-prefixed custom type (STIX 2.1 permits custom object types),
// keeping the export honest rather than mis-tagging it as a standard SCO.
const PATTERN_SHAPE = Object.freeze({
  'email-addr': { sco: 'email-addr', prop: 'value' },
  'phone-number': { sco: 'x-phone-number', prop: 'value' },
  'postal-address': { sco: 'x-postal-address', prop: 'value' },
  'user-account': { sco: 'user-account', prop: 'account_login' },
  'location-hint': { sco: 'x-location-hint', prop: 'value' },
  'credential-exposure': { sco: 'x-credential-exposure', prop: 'hash_prefix' },
  url: { sco: 'url', prop: 'value' },
  'tracking-tech': { sco: 'x-tracking-tech', prop: 'vendor' },
  cookie: { sco: 'x-cookie', prop: 'name' },
  'observed-data': { sco: 'x-observation', prop: 'value' },
});

// STIX 2.1 indicator_types open-vocab values, mapped from our event semantics.
// Self-audit findings are best described as data/information exposures.
function indicatorTypesFor(eventType) {
  if (eventType === 'BREACH_RANGE_HIT' || eventType === 'SECRET_LEAK_PUBLIC') {
    return ['compromised'];
  }
  if (eventType && eventType.startsWith('TRACKER_')) return ['anomalous-activity'];
  if (eventType === 'COOKIE_THIRD_PARTY' || eventType === 'LEAK_REFERRER') {
    return ['anomalous-activity'];
  }
  return ['benign']; // a PII/profile exposure is not malicious — it is the subject's own data
}

// Escape a value for a single-quoted STIX pattern literal (grammar: backslash
// and single-quote are the escapable chars). Keeps the emitted pattern valid.
function escapePatternValue(v) {
  return String(v).replace(/\\/g, '\\\\').replace(/'/g, "\\'");
}

/**
 * Produce a privacy-preserving, non-reversible pattern VALUE for a finding.
 * - credential exposures: the k-anonymity SHA-1 hash PREFIX (HIBP range model),
 *   never the secret. We pattern on equality of the prefix.
 * - plain string data: used as-is for non-sensitive observables (url, vendor),
 *   but PII strings (email/phone/postal/geo) are reduced to a redacted token so
 *   an exported Indicator does not re-publish the very PII it warns about.
 *
 * @returns {{ value: string, redacted: boolean, note: string }}
 */
function patternValueFor(event, category) {
  const raw = event.data;
  const asString = raw === null || raw === undefined
    ? ''
    : (typeof raw === 'string' ? raw : safeJson(raw));

  if (category === 'credential-exposure') {
    // Never emit the secret. Pattern on the HIBP-style hash prefix instead.
    // If the detector already carried a prefix in meta, honor it; else derive.
    const metaPrefix = event.meta && (event.meta.hash_prefix || event.meta.prefix);
    let prefix = typeof metaPrefix === 'string' && metaPrefix ? metaPrefix.toUpperCase() : null;
    if (!prefix && asString) {
      try { prefix = rangeOf(asString).prefix; } catch { prefix = null; }
    }
    return {
      value: prefix || 'UNKNOWN',
      redacted: true,
      note: 'credential value redacted; pattern compares the k-anonymity SHA-1 hash prefix (HIBP range model), never the secret',
    };
  }

  if (
    category === 'email-addr'
    || category === 'phone-number'
    || category === 'postal-address'
    || category === 'location-hint'
  ) {
    // Redact PII to a stable, non-reversible token so the exported detection
    // pattern does not itself leak the subject's PII.
    let token = 'REDACTED';
    try { token = `redacted:${rangeOf(asString.trim().toLowerCase()).prefix}`; } catch { /* keep REDACTED */ }
    return {
      value: token,
      redacted: true,
      note: 'self PII redacted to a non-reversible token; pattern matches on the redaction token, not the raw PII',
    };
  }

  // Non-sensitive observables (url, tracker vendor, cookie name, handle) can be
  // patterned on directly — they are public surface identifiers, not secrets.
  return { value: asString, redacted: false, note: 'public surface identifier; not sensitive' };
}

/**
 * Build a STIX 2.1 patterning expression string for an event, e.g.
 *   [url:value = 'https://me.example/contact']
 *   [x-credential-exposure:hash_prefix = 'A94A8']
 *
 * @returns {{ pattern: string, shape: object, value_info: object }}
 */
function buildPattern(event) {
  const category = OBSERVABLE_CATEGORY[event.event_type] || 'observed-data';
  const shape = PATTERN_SHAPE[category] || PATTERN_SHAPE['observed-data'];
  const valueInfo = patternValueFor(event, category);
  const pattern = `[${shape.sco}:${shape.prop} = '${escapePatternValue(valueInfo.value)}']`;
  return { pattern, shape, value_info: valueInfo, category };
}

/**
 * Convert a single detector module_event into a STIX 2.1 `indicator` SDO with a
 * real patterning expression. This is the "detection rule" half of the pair.
 *
 * @param {object} event   a module_event from shared/detectors
 * @param {object} [opts]  {now?: ISO string}
 * @returns {object|null}  STIX indicator, or null if not a valid event
 */
function toIndicator(event, opts = {}) {
  if (!isModuleEvent(event)) return null;
  const now = typeof opts.now === 'string' ? opts.now : new Date().toISOString();
  const { pattern, shape, value_info, category } = buildPattern(event);

  const id = deterministicId('indicator', event.event_type, pattern);

  return {
    type: 'indicator',
    spec_version: '2.1',
    id,
    created: now,
    modified: now,
    name: `Self-footprint exposure: ${event.event_type}`,
    description:
      'Detection pattern for a PUBLIC exposure of the SELF subject\'s own footprint, '
      + 'so it can be found and remediated. Not a watch-rule about any other person.',
    indicator_types: indicatorTypesFor(event.event_type),
    pattern,
    pattern_type: 'stix',
    pattern_version: '2.1',
    valid_from: now,
    // Provenance + honesty annotations (x_ custom props are STIX 2.1-legal).
    x_source_module: event.source_module,
    x_event_type: event.event_type,
    x_observable_category: category,
    x_sco_type: shape.sco,
    x_confidence: event.confidence,
    x_value_redacted: value_info.redacted,
    x_value_note: value_info.note,
    x_scope_note:
      'Self-audit indicator over the subject\'s OWN public footprint. No third-party-private inference; '
      + 'credential/PII values are redacted to non-reversible forms.',
    x_data_status: 'template', // NO real scraped data unless a real crawl populated the event
  };
}

/**
 * Build the canonical OpenCTI/MISP-style PAIR for one finding: an Indicator and
 * its Observed Data, joined by a STIX `relationship` of type `based-on`.
 *
 * @param {object} event
 * @param {object} [opts]  {now?, integrity?}  (integrity forwarded to Observed Data)
 * @returns {{ indicator: object, observed_data: object, relationship: object }|null}
 */
function toIndicatorPair(event, opts = {}) {
  if (!isModuleEvent(event)) return null;
  const now = typeof opts.now === 'string' ? opts.now : new Date().toISOString();
  const indicator = toIndicator(event, { now });
  const observed = toObservedData(event, { now, integrity: opts.integrity });
  if (!indicator || !observed) return null;

  const relationship = {
    type: 'relationship',
    spec_version: '2.1',
    id: deterministicId('relationship', 'based-on', indicator.id, observed.id),
    created: now,
    modified: now,
    relationship_type: 'based-on', // STIX 2.1: Indicator --based-on--> Observed Data
    source_ref: indicator.id,
    target_ref: observed.id,
    x_scope_note: 'Indicator (detection pattern) is based-on this Observed Data (the sighting).',
  };

  return { indicator, observed_data: observed, relationship };
}

/**
 * Build a full STIX 2.1 bundle of Indicator+ObservedData+Relationship triples
 * for a batch of events — the exact shape OpenCTI / MISP ingest. Deduplicates
 * identical Indicators (same pattern) so a leak seen on many surfaces yields ONE
 * reusable detection rule linked (based-on) to EACH sighting, mirroring how
 * OpenCTI correlates one indicator across multiple observations.
 *
 * @param {object[]} events
 * @param {object} [opts]  {now?, integrityByUrl?: {url -> integrity}}
 * @returns {object} STIX bundle {type:'bundle', objects:[...]}
 */
function toInteropBundle(events = [], opts = {}) {
  const now = typeof opts.now === 'string' ? opts.now : new Date().toISOString();
  const integrityByUrl = (opts && opts.integrityByUrl) || {};

  const indicatorsById = new Map();    // dedupe Indicators by id (same pattern)
  const observedById = new Map();      // dedupe Observed Data by id (same sighting)
  const relationships = [];

  for (const ev of events) {
    if (!isModuleEvent(ev)) continue;
    const integrity = ev.source_url ? integrityByUrl[ev.source_url] : undefined;
    const pair = toIndicatorPair(ev, { now, integrity });
    if (!pair) continue;

    if (!indicatorsById.has(pair.indicator.id)) {
      indicatorsById.set(pair.indicator.id, pair.indicator);
    }
    if (!observedById.has(pair.observed_data.id)) {
      observedById.set(pair.observed_data.id, pair.observed_data);
    }
    // One based-on edge per (indicator, sighting). Dedupe by relationship id.
    if (!relationships.some((r) => r.id === pair.relationship.id)) {
      relationships.push(pair.relationship);
    }
  }

  const objects = [
    ...indicatorsById.values(),
    ...observedById.values(),
    ...relationships,
  ];

  return {
    type: 'bundle',
    id: deterministicId('bundle', 'interop', objects.map((o) => o.id).join(',')),
    spec_version: '2.1',
    x_bundle_kind: 'indicator-observed-data-interop',
    x_interop_note:
      'OpenCTI/MISP-style Indicator(pattern) --based-on--> Observed Data triples. '
      + 'Credential/PII pattern values are redacted (k-anonymity prefix / token); no secrets exported.',
    objects,
  };
}

function safeJson(x) {
  try { return JSON.stringify(x); } catch { return String(x); }
}

module.exports = {
  PATTERN_SHAPE,
  indicatorTypesFor,
  buildPattern,
  patternValueFor,
  toIndicator,
  toIndicatorPair,
  toInteropBundle,
};
