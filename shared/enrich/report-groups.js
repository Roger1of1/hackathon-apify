/**
 * shared/enrich/report-groups.js
 *
 * The presentation-ready GROUPING layer that turns a flat detector
 * module_event[] into the Blacklight-style "what we found on YOUR public
 * footprint" report: a small fixed set of plain-language CATEGORIES (PII /
 * trackers / secret leaks / breach-range / metadata / self surfaces), each with
 * a one-line explanation of *why it matters*, a severity badge, a count, and the
 * per-finding severity + evidence-quality notes the inspector panel renders.
 *
 * This is a pure ENRICHMENT/VIEW transform. It introduces NO new score and NO
 * new detection — it only REUSES the canonical enrich functions:
 *   - shared/enrich/severity.js        rankBySeverity / batchSeverity / bandFor
 *   - shared/enrich/evidence-quality.js  (via severity, which calls it)
 * and the frozen vocabulary in shared/detectors/event-types.js. The web report
 * (a sibling builder's deliverable) consumes the object this returns directly,
 * so it never has to know detector internals or invent its own ordering.
 *
 * Reference patterns applied:
 *   - The Markup BLACKLIGHT — a self-exposure inspector that groups findings
 *     into a handful of clear surveillance/exposure categories, and for EACH
 *     category states in plain language what it is and why a visitor/owner
 *     should care. We mirror that report framing 1:1: stable category ids,
 *     human labels, and a "why_it_matters" sentence per category.
 *     Refs: https://themarkup.org/blacklight ;
 *           themarkup.org/blacklight/2020/09/22/how-we-built-it
 *   - SpiderFoot — the detector/module taxonomy surfaced as grouped finding
 *     categories. Every event already carries its `source_module`/`event_type`;
 *     we fold the module taxonomy up into a small set of user-facing buckets so
 *     the SpiderFoot module structure becomes a scannable category list.
 *     Ref: https://github.com/smicallef/spiderfoot
 *
 * RED LINES: categories describe the SELF subject's OWN public exposure and
 * security hygiene. There is no category — and no possible event type — for
 * romance/intimacy/gender/sexuality/relationship or live location. The bucket
 * map below is exhaustive over the frozen EVENT_TYPES enum, so an event can
 * never silently land in an un-vetted bucket.
 *
 * Pure functions, no network, no mutation of inputs. Safe to require at load.
 */

'use strict';

const { EVENT_TYPES, isModuleEvent } = require('../detectors/event-types.js');
const { rankBySeverity, batchSeverity, bandFor } = require('./severity.js');

/**
 * The fixed, user-facing report categories. Order is the display order in the
 * report (highest-stakes first). Each category states, in plain language, what
 * it is and why it matters — the Blacklight per-section explainer pattern.
 *
 * `event_types` lists exactly which frozen EVENT_TYPES fall in this bucket; the
 * union across categories MUST cover every EVENT_TYPES value (asserted in the
 * self-test) so nothing is ever dropped or mis-bucketed.
 */
const CATEGORIES = Object.freeze([
  {
    id: 'secret_leaks',
    label: 'Leaked secrets',
    short: 'API keys / tokens you published by accident',
    why_it_matters:
      'A secret you posted publicly (an API key, access token, or private-key '
      + 'header) can be used by anyone who finds it. Rotate it and remove the page.',
    event_types: [EVENT_TYPES.SECRET_LEAK_PUBLIC],
  },
  {
    id: 'breach_exposure',
    label: 'Breach exposure',
    short: 'Your own credential appears in a known breach corpus',
    why_it_matters:
      'One of your own credentials matched a known breach range (checked via '
      + 'k-anonymity — the full secret never left your device). Change it '
      + 'everywhere you reused it.',
    event_types: [EVENT_TYPES.BREACH_RANGE_HIT],
  },
  {
    id: 'pii',
    label: 'Personal info you published',
    short: 'Contact details a stranger can copy off your pages',
    why_it_matters:
      'Email, phone, postal address, or a self-stated city you put on a public '
      + 'page can be harvested by anyone. Decide what you actually want visible.',
    event_types: [
      EVENT_TYPES.PII_EMAIL_PUBLIC,
      EVENT_TYPES.PII_PHONE_PUBLIC,
      EVENT_TYPES.PII_POSTAL_PUBLIC,
      EVENT_TYPES.PII_GEO_HINT_PUBLIC,
    ],
  },
  {
    id: 'trackers',
    label: 'Trackers on your own site',
    short: 'What third parties learn about visitors to your pages',
    why_it_matters:
      'These third-party trackers, cookies, fingerprinting, session recorders '
      + 'or key-loggers run on pages YOU control and watch your visitors. You '
      + 'can remove or disclose them.',
    event_types: [
      EVENT_TYPES.TRACKER_THIRD_PARTY,
      EVENT_TYPES.TRACKER_FINGERPRINTING,
      EVENT_TYPES.TRACKER_SESSION_RECORDING,
      EVENT_TYPES.TRACKER_KEYLOGGING,
      EVENT_TYPES.COOKIE_THIRD_PARTY,
      EVENT_TYPES.LEAK_REFERRER,
    ],
  },
  {
    id: 'self_surfaces',
    label: 'Accounts & profiles',
    short: 'Handles and profile pages tied to you',
    why_it_matters:
      'Public usernames and profile URLs link your separate presences together. '
      + 'Review which ones you still want connected to your name.',
    event_types: [
      EVENT_TYPES.PII_HANDLE_PUBLIC,
      EVENT_TYPES.SELF_USERNAME,
      EVENT_TYPES.SELF_PROFILE_URL,
    ],
  },
  {
    id: 'summary',
    label: 'Scan summary',
    short: 'Aggregate notes from the scan',
    why_it_matters:
      'Roll-up observations from the scan (counts and coverage), not individual '
      + 'findings.',
    event_types: [EVENT_TYPES.EXPOSURE_SUMMARY],
  },
]);

// Reverse lookup: event_type -> category id. Built once, frozen.
const CATEGORY_BY_EVENT_TYPE = (() => {
  const map = {};
  for (const cat of CATEGORIES) {
    for (const et of cat.event_types) map[et] = cat.id;
  }
  return Object.freeze(map);
})();

/** The category id a single event belongs to, or null for a non-event. */
function categoryOf(event) {
  if (!isModuleEvent(event)) return null;
  return CATEGORY_BY_EVENT_TYPE[event.event_type] || null;
}

/**
 * Group an enriched, severity-ranked event list into the report categories.
 *
 * @param {object[]} events  detector module_event[]
 * @param {object} [opts]
 * @param {object} [opts.integrityByUrl] {url -> integrity handles} for evidence quality
 * @param {object} [opts.crawlSummary]   {reachablePages,distinctHosts,indexablePages}
 *                                        for the canonical batch headline (optional)
 * @param {boolean} [opts.includeEmpty=false] keep categories with zero findings
 * @returns {{
 *   headline: object,
 *   categories: Array<{
 *     id:string,label:string,short:string,why_it_matters:string,
 *     count:number, band:string, top_severity:number, findings:object[]
 *   }>,
 *   total_findings:number
 * }}
 */
function buildReport(events = [], opts = {}) {
  const integrityByUrl = (opts && opts.integrityByUrl) || {};
  const includeEmpty = !!(opts && opts.includeEmpty);

  // Rank ONCE with the canonical severity model (it also attaches _severity and
  // pulls in evidence-quality). We never re-sort by an ad-hoc rule.
  const ranked = rankBySeverity(events, { integrityByUrl });

  // Bucket the ranked events, preserving the highest-severity-first order within
  // each category (ranked is already sorted desc, so push order is correct).
  const byCat = new Map();
  for (const cat of CATEGORIES) byCat.set(cat.id, []);
  for (const ev of ranked) {
    const id = categoryOf(ev);
    if (id && byCat.has(id)) byCat.get(id).push(ev);
  }

  const categories = [];
  for (const cat of CATEGORIES) {
    const findings = byCat.get(cat.id) || [];
    if (!findings.length && !includeEmpty) continue;
    const topSeverity = findings.length ? findings[0]._severity.severity : 0;
    categories.push({
      id: cat.id,
      label: cat.label,
      short: cat.short,
      why_it_matters: cat.why_it_matters,
      count: findings.length,
      band: findings.length ? bandFor(topSeverity) : 'info',
      top_severity: topSeverity,
      findings,
    });
  }

  // Canonical batch headline (reuses scoring.js via severity.batchSeverity).
  const headline = batchSeverity(ranked, opts.crawlSummary || {}, { integrityByUrl });

  return {
    headline,
    categories,
    total_findings: ranked.length,
  };
}

/**
 * A compact one-finding "card" projection for the inspector panel — only the
 * fields the UI needs, with the plain-language category attached. Keeps the web
 * layer from reaching into raw event internals. Non-events return null.
 *
 * @param {object} rankedEvent an event already annotated with `_severity`
 *                             (i.e. an element of buildReport(...).categories[].findings)
 * @returns {object|null}
 */
function toCard(rankedEvent) {
  if (!isModuleEvent(rankedEvent)) return null;
  const sev = rankedEvent._severity || {};
  const catId = categoryOf(rankedEvent);
  const cat = CATEGORIES.find((c) => c.id === catId) || null;
  return {
    event_type: rankedEvent.event_type,
    category: catId,
    category_label: cat ? cat.label : null,
    source_module: rankedEvent.source_module,
    source_url: rankedEvent.source_url,
    data: rankedEvent.data,
    visibility: rankedEvent.visibility,
    risk: rankedEvent.risk,
    confidence: rankedEvent.confidence,
    severity: typeof sev.severity === 'number' ? sev.severity : null,
    severity_band: sev.band || null,
    // Evidence-quality note (corroborations + how solid), surfaced from the
    // severity components so the panel can show "how sure / how preserved".
    evidence_quality: sev.components ? sev.components.evidence_quality : null,
    corroborations: sev.components ? sev.components.corroborations : 1,
    meta: rankedEvent.meta || {},
  };
}

module.exports = {
  CATEGORIES,
  CATEGORY_BY_EVENT_TYPE,
  categoryOf,
  buildReport,
  toCard,
};
