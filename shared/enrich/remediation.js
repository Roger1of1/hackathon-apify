/**
 * shared/enrich/remediation.js
 *
 * ENRICHMENT: turn a flat detector module_event[] into a PRIORITIZED, plain-
 * language SUGGESTED-ACTIONS worklist — "what should I actually DO about each
 * exposure of my OWN public footprint, and in what order?" This is the missing
 * bridge between detection (what we found) and the report's action column (what
 * the user does next). The web report's suggested-actions list (round B5R1) is
 * meant to be driven from THIS, not from a hand-written static list.
 *
 * ───────────────────────── WHAT IT IS (AND IS NOT) ─────────────────────────
 *  - It does NOT detect, scrape, fetch, or fabricate. It consumes events that
 *    already passed the scope gate + detectors and maps each to a vetted, fixed
 *    remediation recommendation. No finding ⇒ no action (honest empty state).
 *  - It does NOT re-rank with an ad-hoc score: priority comes straight from the
 *    CANONICAL severity model (shared/enrich/severity.js, which itself reuses
 *    shared/scoring.js + evidence-quality.js). Same triage mechanic as
 *    shared/enrich/broker-erasure-priority.js — zero parallel scoring.
 *  - It does NOT re-implement the broker erasure worklist: for BROKER_LISTING_HIT
 *    it DELEGATES to buildErasureWorklist() and folds those items in as actions,
 *    so the executable opt-out/Article-17 hand-off stays single-sourced.
 *  - RED LINE: every action concerns the SELF (or public_figure) subject's OWN
 *    public exposure / security hygiene. There is no third-party action, no
 *    "contact this person", and — by construction over the frozen EVENT_TYPES
 *    enum — no romance/intimacy/relationship/live-location action is expressible.
 *
 * ───────────────────── REFERENCE ARCHITECTURES APPLIED ─────────────────────
 *  #1 — THE MARKUP / BLACKLIGHT self-audit report. Blacklight pairs each
 *       surveillance/exposure finding with a SHORT, plain "what this means / what
 *       you can do" note rather than jargon. We reproduce that 1:1: every
 *       recommendation has a `title` (imperative, scannable), a one-sentence
 *       `why`, and concrete `steps[]` in plain language — the per-finding "what
 *       you can do" column from the Blacklight report.
 *       Refs: https://themarkup.org/blacklight ;
 *             themarkup.org/blacklight/2020/09/22/how-we-built-it
 *  #2 — HAVE I BEEN PWNED "what do I do next" guidance + OWASP/NIST remediation
 *       framing. HIBP, after a breach hit, gives a fixed, reusable next-step set
 *       (change + stop reusing the password, enable 2FA) keyed to the finding
 *       TYPE, not improvised per-incident. We mirror that: a stable
 *       RECOMMENDATION map keyed by EVENT_TYPES, each carrying an `effort` and an
 *       `impact` band (OWASP-style remediation triage) so the worklist can show
 *       "high impact / low effort first" — quick wins up top, exactly the
 *       prioritisation users expect.
 *       Refs: https://haveibeenpwned.com/ (post-breach guidance);
 *             OWASP / NIST SP 800-something remediation-prioritisation framing.
 *
 * Pure functions, no network, no mutation of inputs. Safe to require at load.
 */

'use strict';

const { EVENT_TYPES, isModuleEvent } = require('../detectors/event-types.js');
const { eventSeverity, bandFor } = require('./severity.js');
const { buildErasureWorklist } = require('./broker-erasure-priority.js');

/**
 * Effort to perform an action (the user's side), coarse and honest. Lower effort
 * + higher impact ⇒ a "quick win" the worklist floats up.
 */
const EFFORT = Object.freeze({ LOW: 'low', MEDIUM: 'medium', HIGH: 'high' });
const EFFORT_RANK = Object.freeze({ low: 1, medium: 2, high: 3 });

/**
 * Expected privacy/security impact of doing the action. Independent of severity
 * (severity = how bad the exposure is now; impact = how much the fix helps).
 */
const IMPACT = Object.freeze({ LOW: 'low', MEDIUM: 'medium', HIGH: 'high' });
const IMPACT_RANK = Object.freeze({ low: 1, medium: 2, high: 3 });

/**
 * The fixed RECOMMENDATION rubric, keyed by frozen EVENT_TYPES. Each is a vetted,
 * Blacklight-style "what you can do" record: an imperative `title`, a one-line
 * `why`, plain `steps[]`, plus OWASP/HIBP-style `effort`/`impact` triage bands.
 *
 * The key set MUST cover every EVENT_TYPES value (asserted in the self-test) so a
 * detected finding can never end up with NO guidance.
 */
const RECOMMENDATIONS = Object.freeze({
  [EVENT_TYPES.SECRET_LEAK_PUBLIC]: {
    code: 'rotate_leaked_secret',
    title: 'Rotate the leaked secret and remove the page',
    why: 'A key or token you published publicly can be used by anyone who finds it.',
    steps: [
      'Revoke / rotate the exposed credential at its provider immediately.',
      'Remove or unpublish the page/file that exposed it.',
      'Check provider logs for any use before rotation.',
    ],
    effort: EFFORT.MEDIUM,
    impact: IMPACT.HIGH,
  },
  [EVENT_TYPES.BREACH_RANGE_HIT]: {
    code: 'change_breached_credential',
    title: 'Change this credential everywhere you reused it',
    why: 'One of your own credentials matched a known breach range (checked via k-anonymity — the full secret never left your device).',
    steps: [
      'Change the password on this account.',
      'Change it anywhere you reused the same password.',
      'Turn on two-factor authentication where available.',
      'Use a password manager so each site has a unique secret.',
    ],
    effort: EFFORT.MEDIUM,
    impact: IMPACT.HIGH,
  },
  [EVENT_TYPES.BROKER_LISTING_HIT]: {
    // Delegated to buildErasureWorklist(); this entry is the fallback label only.
    code: 'request_broker_removal',
    title: 'Request removal from this data broker',
    why: 'A people-search site aggregated a public profile of you; you can opt out and, where it applies, request erasure.',
    steps: [
      "Use the broker's documented opt-out method.",
      'Where GDPR/CCPA applies, send a right-to-erasure / right-to-delete request.',
      'Re-scan later to confirm the listing stayed down.',
    ],
    effort: EFFORT.MEDIUM,
    impact: IMPACT.HIGH,
  },
  [EVENT_TYPES.PII_POSTAL_PUBLIC]: {
    code: 'remove_public_address',
    title: 'Remove or mask your public postal address',
    why: 'A self-published street address is the highest-value detail a stranger can copy off your pages.',
    steps: [
      'Delete the address from the page, or replace it with a PO box / contact form.',
      'Check older posts and cached copies for the same address.',
    ],
    effort: EFFORT.LOW,
    impact: IMPACT.HIGH,
  },
  [EVENT_TYPES.PII_PHONE_PUBLIC]: {
    code: 'review_public_phone',
    title: 'Decide whether your phone number should stay public',
    why: 'A phone number on a public page can be harvested for spam, SIM-swap, or doxxing.',
    steps: [
      'Remove it, or swap to a contact form / forwarding number you can revoke.',
      'Search for the same number elsewhere it may have propagated.',
    ],
    effort: EFFORT.LOW,
    impact: IMPACT.MEDIUM,
  },
  [EVENT_TYPES.PII_EMAIL_PUBLIC]: {
    code: 'review_public_email',
    title: 'Review the email address you published',
    why: 'A public email is harvested for spam and is a credential-stuffing target.',
    steps: [
      'Use an alias / plus-address you can rotate, or a contact form.',
      'Confirm the address is not reused as a login on high-value accounts.',
    ],
    effort: EFFORT.LOW,
    impact: IMPACT.MEDIUM,
  },
  [EVENT_TYPES.PII_GEO_HINT_PUBLIC]: {
    code: 'review_location_text',
    title: 'Review the location you state about yourself',
    why: 'A self-stated city narrows you down; combined with other details it aids re-identification.',
    steps: [
      'Decide if a coarser region (or none) is enough for your purpose.',
      'Remove precise location text from bios that do not need it.',
    ],
    effort: EFFORT.LOW,
    impact: IMPACT.LOW,
  },
  [EVENT_TYPES.PII_HANDLE_PUBLIC]: {
    code: 'review_linked_handle',
    title: 'Review handles that link your presences together',
    why: 'A reused @handle ties your separate profiles into one identity a stranger can follow across sites.',
    steps: [
      'Decide which presences you want connected under this handle.',
      'Use distinct handles for contexts you want kept separate.',
    ],
    effort: EFFORT.MEDIUM,
    impact: IMPACT.LOW,
  },
  [EVENT_TYPES.SELF_USERNAME]: {
    code: 'review_username_footprint',
    title: 'Review accounts found under this username',
    why: 'Public usernames let anyone enumerate the profiles tied to you across services.',
    steps: [
      'Close or lock down accounts you no longer use.',
      'Vary usernames where you want presences kept separate.',
    ],
    effort: EFFORT.MEDIUM,
    impact: IMPACT.LOW,
  },
  [EVENT_TYPES.SELF_PROFILE_URL]: {
    code: 'review_profile_url',
    title: 'Review this public profile page',
    why: 'A public profile URL is an entry point to everything you have shared there.',
    steps: [
      'Check the profile’s privacy/visibility settings.',
      'Remove details you no longer want public.',
    ],
    effort: EFFORT.LOW,
    impact: IMPACT.LOW,
  },
  [EVENT_TYPES.TRACKER_KEYLOGGING]: {
    code: 'remove_keylogger',
    title: 'Remove the key-logging script from your site',
    why: 'A key-logger captures what visitors type on pages YOU control — a serious privacy and legal exposure.',
    steps: [
      'Identify and remove the script (often a session-replay/analytics SDK).',
      'Audit any vendor that claimed to be "just analytics".',
    ],
    effort: EFFORT.MEDIUM,
    impact: IMPACT.HIGH,
  },
  [EVENT_TYPES.TRACKER_SESSION_RECORDING]: {
    code: 'remove_session_recorder',
    title: 'Remove or disclose the session recorder',
    why: 'Session-replay records visitors’ mouse/keystrokes on your pages — often without their knowledge.',
    steps: [
      'Remove the session-recording vendor, or gate it behind real consent.',
      'Disclose it in your privacy notice if you keep it.',
    ],
    effort: EFFORT.MEDIUM,
    impact: IMPACT.HIGH,
  },
  [EVENT_TYPES.TRACKER_FINGERPRINTING]: {
    code: 'remove_fingerprinting',
    title: 'Remove the browser-fingerprinting script',
    why: 'Fingerprinting tracks visitors without cookies, defeating their privacy choices.',
    steps: [
      'Identify the fingerprinting vendor and remove it.',
      'Prefer privacy-preserving analytics that do not fingerprint.',
    ],
    effort: EFFORT.MEDIUM,
    impact: IMPACT.MEDIUM,
  },
  [EVENT_TYPES.TRACKER_THIRD_PARTY]: {
    code: 'review_third_party_trackers',
    title: 'Review third-party trackers on your site',
    why: 'Third-party trackers on pages you control share your visitors’ data with other companies.',
    steps: [
      'List the third-party domains loaded and remove the ones you do not need.',
      'Add a consent banner / privacy notice for any you keep.',
    ],
    effort: EFFORT.MEDIUM,
    impact: IMPACT.MEDIUM,
  },
  [EVENT_TYPES.COOKIE_THIRD_PARTY]: {
    code: 'review_third_party_cookies',
    title: 'Review third-party cookies set on your site',
    why: 'Third-party cookies let other companies track your visitors across the web.',
    steps: [
      'Drop cookies you do not need; mark the rest SameSite and disclose them.',
    ],
    effort: EFFORT.LOW,
    impact: IMPACT.LOW,
  },
  [EVENT_TYPES.LEAK_REFERRER]: {
    code: 'fix_referrer_leak',
    title: 'Stop your URLs leaking identity via the referrer',
    why: 'URLs that carry your identity are leaked to third parties through the Referer header.',
    steps: [
      'Set a strict Referrer-Policy (e.g. strict-origin-when-cross-origin).',
      'Keep identifying tokens out of URLs that load third-party resources.',
    ],
    effort: EFFORT.LOW,
    impact: IMPACT.MEDIUM,
  },
  [EVENT_TYPES.EXPOSURE_SUMMARY]: {
    code: 'review_discoverability',
    title: 'Review how discoverable this page is',
    why: 'Indexing directives decide whether strangers can trivially find this page and the details on it.',
    steps: [
      'If it should be private, add noindex / restrict access and request de-indexing.',
      'If it must stay public, minimise the personal details it carries.',
    ],
    effort: EFFORT.MEDIUM,
    impact: IMPACT.LOW,
  },
});

/** The recommendation record for one event_type (deep copy), or null. */
function recommendationFor(eventType) {
  const rec = RECOMMENDATIONS[eventType];
  return rec ? { ...rec, steps: rec.steps.slice() } : null;
}

/**
 * Build one suggested-action item from a single (non-broker) finding. Priority is
 * the CANONICAL severity (we never invent a score). A `quick_win` flag marks
 * low-effort + high-impact actions (OWASP-style "do these first").
 *
 * @param {object} event  a module_event
 * @param {object} [opts] {integrity, corroborations} passed through to severity
 * @returns {object|null}
 */
function toActionItem(event, opts = {}) {
  if (!isModuleEvent(event)) return null;
  const rec = RECOMMENDATIONS[event.event_type];
  if (!rec) return null;

  const sev = eventSeverity(event, opts);

  return {
    record_type: 'suggested_action',
    action_code: rec.code,
    title: rec.title,
    why: rec.why,
    steps: rec.steps.slice(),
    // Triage signals, all from canonical/vetted sources (no ad-hoc number):
    priority: sev.severity,        // canonical severity model
    priority_band: sev.band,
    effort: rec.effort,
    impact: rec.impact,
    quick_win: rec.effort === EFFORT.LOW && rec.impact === IMPACT.HIGH,
    // Provenance back to the finding (no PII value echoed — type + surface only).
    event_type: event.event_type,
    source_module: event.source_module,
    source_url: event.source_url || null,
    confidence: event.confidence,
    severity_components: sev.components,
    // Self-only invariant restated for any direct consumer.
    subject_relationship: 'self_owned_exposure',
  };
}

/**
 * Stable sort key: highest severity first; ties → higher impact, then lower
 * effort (so a quick win outranks an equal-impact slog), then action_code.
 */
function compareActions(a, b) {
  if (b.priority !== a.priority) return b.priority - a.priority;
  const ai = IMPACT_RANK[a.impact] || 0;
  const bi = IMPACT_RANK[b.impact] || 0;
  if (bi !== ai) return bi - ai;
  const ae = EFFORT_RANK[a.effort] || 0;
  const be = EFFORT_RANK[b.effort] || 0;
  if (ae !== be) return ae - be; // lower effort first
  return String(a.action_code).localeCompare(String(b.action_code));
}

/**
 * Build the full prioritized suggested-actions worklist from a batch of events.
 *
 * Broker findings are DELEGATED to the canonical erasure worklist and folded in
 * as actions (so the executable opt-out / Art.17 hand-off is single-sourced).
 * Identical (action_code, source_url) actions are de-duplicated; corroboration is
 * counted honestly from distinct surfaces bearing the same event_type+data, the
 * SAME co-occurrence notion the other enrich layers use.
 *
 * @param {object[]} events
 * @param {object} [opts] {integrityByUrl: {url -> integrity handles}}
 * @returns {{
 *   items: object[], total: number,
 *   by_band: Record<string, number>, quick_wins: number,
 *   erasure: { items: object[], total: number, by_band: object, brokers: string[] }
 * }}
 */
function buildSuggestedActions(events = [], opts = {}) {
  const integrityByUrl = (opts && opts.integrityByUrl) || {};
  const valid = (events || []).filter(isModuleEvent);

  // Corroboration index across distinct surfaces for the SAME finding identity.
  const surfaces = new Map();
  const normData = (d) => {
    if (d === null || d === undefined) return '';
    if (typeof d === 'string') return d.trim().toLowerCase();
    try { return JSON.stringify(d); } catch { return String(d); }
  };
  const keyOf = (ev) => `${ev.event_type}::${normData(ev.data)}`;
  for (const ev of valid) {
    const k = keyOf(ev);
    if (!surfaces.has(k)) surfaces.set(k, new Set());
    if (ev.source_url) surfaces.get(k).add(ev.source_url);
  }
  const corrFor = (ev) => Math.max(1, surfaces.get(keyOf(ev)) ? surfaces.get(keyOf(ev)).size : 1);

  // 1) Non-broker findings → action items here.
  const nonBroker = valid.filter((ev) => ev.event_type !== EVENT_TYPES.BROKER_LISTING_HIT);
  let items = nonBroker.map((ev) => toActionItem(ev, {
    integrity: ev.source_url ? integrityByUrl[ev.source_url] : undefined,
    corroborations: corrFor(ev),
  })).filter(Boolean);

  // 2) Broker findings → DELEGATE to the canonical erasure worklist, then fold
  //    each erasure item into a suggested action (no re-implementation).
  const erasure = buildErasureWorklist(valid, { integrityByUrl });
  for (const it of erasure.items) {
    const rec = RECOMMENDATIONS[EVENT_TYPES.BROKER_LISTING_HIT];
    items.push({
      record_type: 'suggested_action',
      action_code: rec.code,
      title: it.broker_name
        ? `Request removal from ${it.broker_name}`
        : rec.title,
      why: rec.why,
      steps: rec.steps.slice(),
      priority: it.priority,
      priority_band: it.priority_band,
      effort: rec.effort,
      impact: rec.impact,
      quick_win: false,
      event_type: EVENT_TYPES.BROKER_LISTING_HIT,
      source_module: 'broker_listing_detector',
      source_url: it.source_url || null,
      confidence: it.confidence,
      severity_components: it.severity_components,
      subject_relationship: 'self_owned_exposure',
      // Executable hand-off carried straight from the canonical worklist item.
      erasure: { optout: it.optout, erasure: it.erasure, recheck: it.recheck, broker_id: it.broker_id },
    });
  }

  // De-dupe identical (action_code, source_url) actions; keep the highest priority.
  const seen = new Map();
  for (const it of items) {
    const dk = `${it.action_code}::${it.source_url || ''}`;
    const prev = seen.get(dk);
    if (!prev || it.priority > prev.priority) seen.set(dk, it);
  }
  items = Array.from(seen.values()).sort(compareActions);

  const by_band = {};
  let quick_wins = 0;
  for (const it of items) {
    by_band[it.priority_band] = (by_band[it.priority_band] || 0) + 1;
    if (it.quick_win) quick_wins += 1;
  }

  return { items, total: items.length, by_band, quick_wins, erasure };
}

module.exports = {
  EFFORT,
  IMPACT,
  RECOMMENDATIONS,
  recommendationFor,
  toActionItem,
  compareActions,
  buildSuggestedActions,
};
