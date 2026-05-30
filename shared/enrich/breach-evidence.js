/**
 * shared/enrich/breach-evidence.js
 *
 * ENRICHMENT layer for BREACH_RANGE_HIT events. A breach finding is special: it
 * is the ONE detector result whose trustworthiness depends not just on the match
 * but on HOW the lookup was performed — specifically, how large the k-anonymity
 * bucket was (the "k"). A hit confirmed inside a healthy anonymity set is a clean
 * security-hygiene signal; a hit "confirmed" against a bucket of size 1 means the
 * query itself leaked the credential's prefix space and the privacy mechanic
 * failed. This module makes that distinction explicit and honest.
 *
 * It does NOT introduce a new score or fork detection. It:
 *   1. REUSES shared/detectors/breach-range-contract.js `kAnonymityQuality` to
 *      read the REAL returned bucket size (never fabricated).
 *   2. REUSES shared/enrich/evidence-quality.js `eventEvidenceQuality` and
 *      shared/enrich/severity.js `eventSeverity` (the canonical enrich models)
 *      for the event's preservation/confidence/risk dimensions.
 *   3. Combines them into a single per-breach "evidence note" the report and
 *      inspector panel can render, with a plain-language rationale.
 *
 * The combine is honest and conservative: the anonymity quality acts as a CAP /
 * caveat on confidence, never a booster. A real suffix match is high-confidence
 * by itself; a tiny bucket can only ADD a caveat ("this hit was found with weak
 * query anonymity"), it can never manufacture a hit that wasn't matched.
 *
 * Refs:
 *   Have I Been Pwned Pwned Passwords range API + k-anonymity (bucket = the k) —
 *     Troy Hunt, "Understanding HIBP's Use of SHA-1 and k-Anonymity".
 *   SpiderFoot/STIX separation of severity from CONFIDENCE — the bucket health
 *     adjusts confidence, not the underlying risk band.
 *
 * RED LINE: a breach hit is a fact about the SELF subject's OWN credential. No
 * identity/romance/intimacy inference exists here, by construction. The only
 * inputs are a frozen-vocabulary BREACH_RANGE_HIT event + an integer bucket size.
 *
 * Pure functions, no network, no mutation of inputs. Safe to require at load.
 */

'use strict';

const { EVENT_TYPES, isModuleEvent } = require('../detectors/event-types.js');
const { kAnonymityQuality } = require('../detectors/breach-range-contract.js');
const { eventEvidenceQuality } = require('./evidence-quality.js');
const { eventSeverity } = require('./severity.js');
const { clamp } = require('../scoring.js');

/**
 * Is this event a breach-range hit we should enrich? (Non-breach events are
 * passed through unchanged by enrichBreachEvents.)
 */
function isBreachHit(event) {
  return isModuleEvent(event) && event.event_type === EVENT_TYPES.BREACH_RANGE_HIT;
}

/**
 * Read the observed k-anonymity bucket size off a breach event. The breach
 * actor is expected to record the REAL number of suffixes the range endpoint
 * returned for the prefix in `meta.bucket_size` (a.k.a. the k). If it is absent,
 * we honestly report "unknown" rather than guessing a number.
 *
 * @param {object} event a BREACH_RANGE_HIT module_event
 * @returns {number|null}
 */
function observedBucketSize(event) {
  const meta = event && event.meta && typeof event.meta === 'object' ? event.meta : {};
  const candidates = [meta.bucket_size, meta.k, meta.range_bucket_size];
  for (const c of candidates) {
    if (typeof c === 'number' && Number.isFinite(c) && c >= 0) return Math.floor(c);
  }
  return null;
}

/**
 * Per-breach evidence read: combines the canonical evidence-quality + severity
 * with the k-anonymity quality of the lookup. Returns an honest, explainable
 * note. The `effective_confidence` is the event confidence CAPPED by how anonymous
 * the query was, so a hit found with a degenerate (size-1) bucket is flagged as
 * privacy-compromised rather than silently trusted at full confidence.
 *
 * @param {object} event a BREACH_RANGE_HIT module_event
 * @param {object} [opts]
 * @param {number} [opts.bucketSize] override/inject the observed bucket size (k)
 * @param {object} [opts.integrity]  preservation handles for evidence-quality
 * @param {number} [opts.corroborations] distinct surfaces (>=1)
 * @returns {{
 *   ok:boolean,
 *   breach_count:number|null,
 *   kanon:{k:number|null,band:string,anonymous:boolean,note:string},
 *   evidence_quality:number,
 *   severity:number, severity_band:string,
 *   effective_confidence:number,
 *   rationale:string
 * }|null}
 */
function breachEvidence(event, opts = {}) {
  if (!isBreachHit(event)) return null;

  const bucketSize = typeof opts.bucketSize === 'number'
    ? opts.bucketSize
    : observedBucketSize(event);
  const kanon = kAnonymityQuality(bucketSize);

  const eq = eventEvidenceQuality(event, opts);
  const sev = eventSeverity(event, opts);

  // Honest, non-secret breach count (the detector stores it in data + meta).
  const meta = event.meta && typeof event.meta === 'object' ? event.meta : {};
  const breachCount = typeof meta.breach_count === 'number'
    ? meta.breach_count
    : (event.data && typeof event.data === 'object' && typeof event.data.breach_count === 'number'
      ? event.data.breach_count
      : null);

  // Anonymity acts as a CAP on confidence, never a booster:
  //   strong/adequate -> no penalty (1.0)
  //   weak            -> mild caveat (0.85)
  //   none            -> strong caveat: the query had no anonymity set (0.6)
  //   unknown         -> we couldn't verify the mechanic, so cap to 0.8
  const ANON_CAP = { strong: 1, adequate: 1, weak: 0.85, none: 0.6, unknown: 0.8 };
  const cap = ANON_CAP[kanon.band] != null ? ANON_CAP[kanon.band] : 0.8;
  const baseConfidence = Number.isFinite(event.confidence) ? event.confidence : 0.5;
  const effectiveConfidence = Math.min(baseConfidence, baseConfidence * cap);

  let rationale;
  if (kanon.band === 'unknown') {
    rationale =
      'Exact suffix match confirms exposure of this credential, but the bucket size ' +
      'was not recorded, so the privacy of the lookup itself cannot be asserted.';
  } else if (kanon.band === 'none') {
    rationale =
      'Suffix matched, but the range bucket held effectively only this candidate — ' +
      'the k-anonymity query had no anonymity set, so treat this lookup as privacy-compromised.';
  } else {
    rationale =
      `Exact suffix match inside a k=${kanon.k} bucket (${kanon.band} anonymity): ` +
      'a clean security-hygiene confirmation that this credential is breached. Rotate it.';
  }

  return {
    ok: true,
    breach_count: breachCount,
    kanon,
    evidence_quality: eq.quality,
    severity: sev.severity,
    severity_band: sev.band,
    effective_confidence: clamp(effectiveConfidence * 100) / 100, // round to 2dp via 0..100 clamp
    rationale,
  };
}

/**
 * Annotate a batch: every BREACH_RANGE_HIT gets a `_breach_evidence`; all other
 * events pass through untouched (so this can run over a mixed module_event[]).
 *
 * @param {object[]} events
 * @param {object} [opts] {integrityByUrl:{url->integrity}}
 * @returns {object[]} same array shape, breach events annotated
 */
function enrichBreachEvents(events = [], opts = {}) {
  const list = Array.isArray(events) ? events : [];
  const integrityByUrl = (opts && opts.integrityByUrl) || {};
  return list.map((ev) => {
    if (!isBreachHit(ev)) return ev;
    const integrity = ev.source_url ? integrityByUrl[ev.source_url] : undefined;
    const be = breachEvidence(ev, { integrity });
    return { ...ev, _breach_evidence: be };
  });
}

module.exports = {
  isBreachHit,
  observedBucketSize,
  breachEvidence,
  enrichBreachEvents,
};
