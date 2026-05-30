/**
 * shared/enrich/freshness.js
 *
 * TEMPORAL FRESHNESS / DECAY enrichment for detector findings.
 *
 * Every existing enrich module reasons about a finding in the PRESENT tense
 * ("how severe / how re-identifying / how preservable is this exposure now?").
 * The genuinely-missing dimension — nothing in shared/ tracks it — is TIME:
 *
 *   - Is this exposure still LIVE (re-confirmed on a recent re-crawl), so the
 *     user should act on it now?
 *   - Or is it STALE (first seen long ago, NOT seen on the latest re-crawls), so
 *     it has very likely already been removed and re-checking it is wasted,
 *     anxiety-inducing effort?
 *
 * That second question is the entire point of the product's Closure Mode: a
 * self-audit that keeps re-surfacing a exposure the user already cleaned up is
 * the compulsive-checking behaviour the product exists to REDUCE. So freshness
 * is not cosmetic — it directly drives "you can stop checking this one".
 *
 * ──── The two reference architectures applied ───────────────────────────────
 *
 *   (1) HAVE I BEEN PWNED's recency model. HIBP attaches to each breach a
 *       `BreachDate` (when it occurred) and an `AddedDate` (when it entered the
 *       corpus), and its UX ranks/contextualises results by recency — a breach
 *       from this month reads very differently from one from a decade ago. We
 *       mirror that: a finding carries its OWN observation timestamps and we
 *       derive an honest age + recency-of-last-confirmation from them, never a
 *       fabricated date. (Troy Hunt / haveibeenpwned.com breach metadata model.)
 *
 *   (2) OASIS STIX 2.1 SIGHTING / Observed-Data temporal semantics:
 *       `first_observed`, `last_observed`, and `number_observed` are THE standard
 *       fields for "we saw this thing, this many times, between these instants".
 *       This module REUSES the project's existing STIX shaping
 *       (shared/enrich/stix-evidence.js `toObservedData`) and FILLS those three
 *       fields with the finding's REAL temporal history (instead of stamping them
 *       all to `now`, which the base shaper does when no history is supplied), so
 *       a freshness-annotated finding stays portable into OpenCTI/MISP/a report.
 *       Ref: OASIS STIX 2.1 — Sighting SRO & Observed Data SDO.
 *
 * ──── What it REUSES (never forks) ──────────────────────────────────────────
 *   - shared/detectors/event-types.js  isModuleEvent (input contract)
 *   - shared/enrich/stix-evidence.js   toObservedData (STIX temporal shaping)
 *   - shared/scoring.js                clamp (canonical 0..100 clamp)
 *
 * ──── RED LINES (by construction) ───────────────────────────────────────────
 *   - Works ONLY from observation timestamps the pipeline actually recorded for a
 *     finding (first_observed / last_observed / a list of sighting instants). If a
 *     finding has NO temporal history, it gets `basis:'unknown'` and NO fabricated
 *     age — we never invent when something was seen.
 *   - It reasons about the SELF subject's OWN exposure over time. It records and
 *     infers nothing about any person; there is no slot for
 *     romance/gender/sexuality/relationship/live-location, by design. Timestamps
 *     are about a PUBLIC artifact's presence, not a human's movements.
 *
 * Pure, deterministic given the input + an injectable clock. No network, no
 * mutation of inputs. Safe to require at module load.
 */

'use strict';

const { isModuleEvent } = require('../detectors/event-types.js');
const { toObservedData } = require('./stix-evidence.js');
const { clamp } = require('../scoring.js');

const DAY_MS = 24 * 60 * 60 * 1000;

/**
 * Lifecycle states a finding can be in, ordered by how much the user should care
 * RIGHT NOW. "live" = act; "decaying" = probably still there but cooling;
 * "stale" = very likely already gone (Closure-Mode candidate); "unknown" = we
 * have no temporal history and refuse to guess.
 */
const LIFECYCLE = Object.freeze({
  LIVE: 'live',
  DECAYING: 'decaying',
  STALE: 'stale',
  UNKNOWN: 'unknown',
});

/**
 * Default thresholds (days). Deliberately conservative and CLEARLY a tunable
 * default, not a fabricated per-finding fact. The pipeline can pass its own
 * cadence-derived thresholds via opts.
 */
const DEFAULT_THRESHOLDS = Object.freeze({
  liveWithinDays: 14,   // last confirmed within 2 weeks => treat as live
  staleAfterDays: 60,   // not confirmed in 2 months => treat as stale
});

function toMs(t) {
  if (t == null) return null;
  if (t instanceof Date) return Number.isFinite(t.getTime()) ? t.getTime() : null;
  const ms = Date.parse(String(t));
  return Number.isFinite(ms) ? ms : null;
}

/**
 * Extract the real temporal history of a finding from whatever the pipeline
 * recorded, WITHOUT inventing anything. Accepts, in order of preference:
 *   - history.observed_at : array of ISO instants the finding was confirmed
 *   - history.first_observed / history.last_observed : explicit bounds
 * Returns null bounds if nothing usable is present (=> basis 'unknown').
 *
 * @param {object} [history]
 * @returns {{ first:number|null, last:number|null, count:number }}
 */
function temporalBounds(history = {}) {
  const instants = Array.isArray(history.observed_at)
    ? history.observed_at.map(toMs).filter((x) => x != null).sort((a, b) => a - b)
    : [];

  let first = instants.length ? instants[0] : toMs(history.first_observed);
  let last = instants.length ? instants[instants.length - 1] : toMs(history.last_observed);

  // If only one bound is known, it is both first and last (a single sighting).
  if (first == null && last != null) first = last;
  if (last == null && first != null) last = first;

  // number_observed: real distinct sightings if we have them, else 1 when we have
  // at least one bound, else 0 (genuinely no observation recorded).
  let count;
  if (instants.length) count = instants.length;
  else if (first != null) count = Math.max(1, Number(history.number_observed) || 1);
  else count = 0;

  return { first, last, count };
}

/**
 * Compute the freshness of a SINGLE finding.
 *
 * @param {object} event   a module_event
 * @param {object} [opts]
 * @param {object} [opts.history]    {observed_at?:string[], first_observed?, last_observed?, number_observed?}
 * @param {string} [opts.now]        ISO clock (injectable for deterministic tests)
 * @param {object} [opts.thresholds] {liveWithinDays, staleAfterDays}
 * @returns {{ lifecycle:string, basis:string, age_days:number|null, days_since_last_seen:number|null,
 *             number_observed:number, recency:number, action_now:boolean, first_observed:string|null,
 *             last_observed:string|null, note:string }}
 */
function findingFreshness(event, opts = {}) {
  if (!isModuleEvent(event)) {
    return {
      lifecycle: LIFECYCLE.UNKNOWN, basis: 'invalid', age_days: null,
      days_since_last_seen: null, number_observed: 0, recency: 0,
      action_now: false, first_observed: null, last_observed: null,
      note: 'Not a valid module_event.',
    };
  }

  const nowMs = toMs(opts.now) ?? Date.now();
  const th = { ...DEFAULT_THRESHOLDS, ...(opts.thresholds || {}) };
  const { first, last, count } = temporalBounds(opts.history || {});

  // No temporal history => we refuse to guess. Honest "unknown".
  if (first == null || last == null) {
    return {
      lifecycle: LIFECYCLE.UNKNOWN,
      basis: 'unknown',
      age_days: null,
      days_since_last_seen: null,
      number_observed: count, // 0
      recency: 0,
      action_now: false,
      first_observed: null,
      last_observed: null,
      note: 'No observation timestamps recorded for this finding — freshness cannot be assessed (no fabricated age).',
    };
  }

  const ageDays = Math.max(0, (nowMs - first) / DAY_MS);
  const sinceLast = Math.max(0, (nowMs - last) / DAY_MS);

  // recency: 100 when just-confirmed, decaying smoothly to 0 by staleAfterDays.
  // Linear, transparent, explainable — no opaque curve.
  const recency = clamp(100 * (1 - sinceLast / th.staleAfterDays));

  let lifecycle;
  if (sinceLast <= th.liveWithinDays) lifecycle = LIFECYCLE.LIVE;
  else if (sinceLast >= th.staleAfterDays) lifecycle = LIFECYCLE.STALE;
  else lifecycle = LIFECYCLE.DECAYING;

  const note = (() => {
    switch (lifecycle) {
      case LIFECYCLE.LIVE:
        return 'Re-confirmed recently — this exposure is live. Worth acting on now.';
      case LIFECYCLE.STALE:
        return 'Not seen on recent re-crawls — very likely already removed. Safe to stop re-checking (Closure Mode).';
      default:
        return 'Cooling off — last confirmed a while ago but not yet stale. Re-check on the normal cadence, no urgency.';
    }
  })();

  return {
    lifecycle,
    basis: count > 1 ? 'observed' : 'single-sighting',
    age_days: round1(ageDays),
    days_since_last_seen: round1(sinceLast),
    number_observed: count,
    recency,
    action_now: lifecycle === LIFECYCLE.LIVE,
    first_observed: new Date(first).toISOString(),
    last_observed: new Date(last).toISOString(),
    note,
  };
}

/**
 * Annotate a batch of findings with `_freshness`, then sort so the findings the
 * user should act on (live) float to the top and stale ones sink — directly
 * serving Closure Mode's "you can stop checking these" list at the bottom.
 *
 * @param {object[]} events
 * @param {object} [opts]
 * @param {object} [opts.historyById] map from a finding key -> history object
 * @param {function} [opts.keyOf]     how to key a finding into historyById
 *                                    (default: event_type::source_url::data)
 * @param {string} [opts.now]
 * @param {object} [opts.thresholds]
 * @returns {object[]} valid events annotated with `_freshness`, sorted live-first
 */
function enrichFreshness(events = [], opts = {}) {
  const valid = (events || []).filter(isModuleEvent);
  const historyById = (opts && opts.historyById) || {};
  const keyOf = (opts && typeof opts.keyOf === 'function')
    ? opts.keyOf
    : defaultKey;

  const annotated = valid.map((ev) => {
    const history = historyById[keyOf(ev)] || {};
    const fr = findingFreshness(ev, { history, now: opts.now, thresholds: opts.thresholds });
    return { ...ev, _freshness: fr };
  });

  // Sort: live > decaying > unknown > stale (stale sinks to the bottom). Within a
  // band, most-recently-confirmed first.
  const order = { live: 0, decaying: 1, unknown: 2, stale: 3 };
  annotated.sort((a, b) => {
    const o = (order[a._freshness.lifecycle] ?? 2) - (order[b._freshness.lifecycle] ?? 2);
    if (o) return o;
    return (b._freshness.recency || 0) - (a._freshness.recency || 0);
  });
  return annotated;
}

/**
 * Emit a freshness-aware STIX 2.1 Observed-Data object by REUSING the existing
 * stix-evidence shaper and overwriting ONLY its temporal fields with the
 * finding's REAL history. This is the STIX-Sighting pattern: first_observed /
 * last_observed / number_observed reflect actual sightings, not the export clock.
 *
 * @param {object} event
 * @param {object} [opts] {history, now, integrity}
 * @returns {object|null} STIX observed-data with real temporal bounds, or null
 */
function toObservedDataWithFreshness(event, opts = {}) {
  const base = toObservedData(event, { now: opts.now, integrity: opts.integrity });
  if (!base) return null;
  const fr = findingFreshness(event, { history: opts.history, now: opts.now, thresholds: opts.thresholds });
  if (fr.basis === 'unknown' || fr.basis === 'invalid') {
    // No real history => leave the base shaper's fields untouched but record WHY,
    // so a downstream reader knows the bounds are the export clock, not sightings.
    return { ...base, x_freshness: { lifecycle: fr.lifecycle, basis: fr.basis, note: fr.note } };
  }
  return {
    ...base,
    first_observed: fr.first_observed,
    last_observed: fr.last_observed,
    number_observed: fr.number_observed,
    x_freshness: {
      lifecycle: fr.lifecycle,
      basis: fr.basis,
      age_days: fr.age_days,
      days_since_last_seen: fr.days_since_last_seen,
      recency: fr.recency,
      action_now: fr.action_now,
      note: fr.note,
    },
  };
}

/**
 * Partition a batch into "act now" vs "you can stop checking" — the exact two
 * lists Closure Mode renders. Honest: an unknown-history finding is neither
 * urgent nor dismissible, so it lands in `review`.
 *
 * @param {object[]} annotatedOrRaw events (will be enriched if not already)
 * @param {object} [opts] same as enrichFreshness
 * @returns {{ act_now:object[], cooling:object[], can_stop_checking:object[], review:object[] }}
 */
function closureBuckets(events = [], opts = {}) {
  const annotated = (events || []).every((e) => e && e._freshness)
    ? (events || []).filter(isModuleEvent)
    : enrichFreshness(events, opts);

  const buckets = { act_now: [], cooling: [], can_stop_checking: [], review: [] };
  for (const ev of annotated) {
    const lc = ev._freshness ? ev._freshness.lifecycle : LIFECYCLE.UNKNOWN;
    if (lc === LIFECYCLE.LIVE) buckets.act_now.push(ev);
    else if (lc === LIFECYCLE.DECAYING) buckets.cooling.push(ev);
    else if (lc === LIFECYCLE.STALE) buckets.can_stop_checking.push(ev);
    else buckets.review.push(ev);
  }
  return buckets;
}

function defaultKey(ev) {
  const d = ev && ev.data;
  const ds = d == null ? '' : (typeof d === 'string' ? d : safeJson(d));
  return `${ev.event_type}::${ev.source_url || ''}::${ds}`;
}

function safeJson(x) {
  try { return JSON.stringify(x); } catch { return String(x); }
}

function round1(n) {
  return Math.round(n * 10) / 10;
}

module.exports = {
  LIFECYCLE,
  DEFAULT_THRESHOLDS,
  temporalBounds,
  findingFreshness,
  enrichFreshness,
  toObservedDataWithFreshness,
  closureBuckets,
};
