/**
 * shared/aux/takedown-letter.js
 *
 * Turns the SELF subject's REAL detector findings (typed module_events produced
 * by the other MirrorTrace actors) into structured, legally-grounded *takedown /
 * removal request* packets the subject can review, sign, and send. This is the
 * "now what do I DO about it?" step — it closes the loop from "here is your
 * public exposure" (audit) to "here is a concrete remediation action" without
 * the subject having to hand-write a GDPR/CCPA letter from scratch.
 *
 * WHY THIS IS COMPLIANT-BY-CONSTRUCTION
 * ─────────────────────────────────────────────────────────────────────────────
 *  - It acts ONLY on the subject's OWN exposure (scope self / public_figure,
 *    gated upstream in the actor via shared/scope.js). A takedown request is a
 *    first-person assertion ("remove information about ME"), the literal opposite
 *    of tracking someone else.
 *  - It produces NO new intelligence about any third party. It only reformats
 *    findings the subject already has into the standard legal request shapes.
 *  - There is deliberately no romance/gender/sexuality/intimacy/live-location
 *    pathway. It reads the FROZEN EVENT_TYPES enum; an unknown type is ignored.
 *
 * NO FAKE DATA (the hard rule)
 *  - Every letter is a DETERMINISTIC template filled ONLY from fields that exist
 *    in the real event. Nothing is invented: no fabricated URL, recipient, or
 *    "it was removed" success. Each generated letter is explicitly marked as a
 *    DRAFT TEMPLATE the subject must review and personalize before sending, and
 *    carries `is_template: true` plus a visible review banner.
 *  - If there are no actionable findings, this module returns an empty plan. It
 *    never manufactures a finding just to have something to send.
 *
 * REFERENCE PATTERNS APPLIED
 *  - SpiderFoot correlation engine: instead of one letter per raw event, we
 *    CLUSTER events by co-occurrence key (host / email-prefix / handle) using the
 *    same shared/enrich/cluster-keys.js the report builder uses, so one removal
 *    request can cover all the leaks on one host — mirroring how SpiderFoot's
 *    correlation engine groups related events into a single finding.
 *  - The Markup "Blacklight" self-exposure inspector: each request includes a
 *    plain-language "why this matters to YOU" line in the subject's own voice,
 *    the same self-audit framing Blacklight uses ("here's what this means for
 *    you"), rather than legalese alone.
 *
 * Pure + dependency-light: requires only sibling pure modules (event-types,
 * cluster-keys). No I/O, no network. Trivially unit-testable.
 */

'use strict';

const { EVENT_TYPES, isModuleEvent } = require('../detectors/event-types.js');
const { clusterKeysFor, hostOf } = require('../enrich/cluster-keys.js');

const SOURCE_MODULE = 'aux:takedown-generator';

/**
 * The removal "channels" we know how to draft. Each is a real, widely-used
 * remediation route. We never claim to act on the subject's behalf — we draft a
 * request the SUBJECT sends. Keys are stable for the report builder to switch on.
 */
const REQUEST_KINDS = Object.freeze({
  GDPR_ERASURE: 'gdpr_erasure',            // EU/UK GDPR Art.17 right to erasure
  CCPA_DELETE: 'ccpa_delete',              // California CCPA/CPRA right to delete
  SEARCH_DEINDEX: 'search_deindex',        // Google "Results about you" / deindex
  CREDENTIAL_ROTATION: 'credential_rotation', // self-remediation for breach/secret leaks
  SELF_REMOVAL: 'self_removal',            // subject controls the surface; just delete/strip it
});

/**
 * Map each frozen EVENT_TYPE to the remediation channel(s) that actually apply.
 * Anything not listed yields no draft (we never invent a route for it).
 *  - PII the subject published themselves on a surface THEY control → SELF_REMOVAL.
 *  - PII/handle exposed on a THIRD-PARTY host → GDPR/CCPA data-subject request +
 *    optional search de-index.
 *  - Embedded GPS / device serial in a published file → SELF_REMOVAL (strip EXIF).
 *  - A leaked secret or breach-range hit → CREDENTIAL_ROTATION (rotate/secure it);
 *    no third party can "take down" a credential the subject must rotate.
 *  - Trackers on the subject's own site → SELF_REMOVAL (the subject can remove the
 *    tracker); they aren't a takedown target elsewhere.
 */
const EVENT_PLAYBOOK = Object.freeze({
  [EVENT_TYPES.PII_EMAIL_PUBLIC]: ['third_party_pii'],
  [EVENT_TYPES.PII_PHONE_PUBLIC]: ['third_party_pii'],
  [EVENT_TYPES.PII_POSTAL_PUBLIC]: ['third_party_pii'],
  [EVENT_TYPES.PII_HANDLE_PUBLIC]: ['third_party_pii'],
  [EVENT_TYPES.PII_GEO_HINT_PUBLIC]: ['self_strip'],
  [EVENT_TYPES.SECRET_LEAK_PUBLIC]: ['rotate'],
  [EVENT_TYPES.BREACH_RANGE_HIT]: ['rotate'],
  [EVENT_TYPES.SELF_PROFILE_URL]: ['self_strip'],
  [EVENT_TYPES.SELF_USERNAME]: ['self_strip'],
  [EVENT_TYPES.TRACKER_THIRD_PARTY]: ['self_strip'],
  [EVENT_TYPES.TRACKER_FINGERPRINTING]: ['self_strip'],
  [EVENT_TYPES.TRACKER_SESSION_RECORDING]: ['self_strip'],
  [EVENT_TYPES.TRACKER_KEYLOGGING]: ['self_strip'],
  [EVENT_TYPES.COOKIE_THIRD_PARTY]: ['self_strip'],
  [EVENT_TYPES.LEAK_REFERRER]: ['self_strip'],
  // EXPOSURE_SUMMARY is meta — never a takedown target.
});

const PLACEHOLDER = '[[ FILL IN ]]';
const REVIEW_BANNER =
  'DRAFT TEMPLATE — review, verify every fact, fill in [[ FILL IN ]] fields, and ' +
  'confirm the recipient before sending. Generated from your own audit findings; ' +
  'nothing was sent and nothing was removed automatically.';

/** Plain-language label for an event type (Blacklight "what this means" voice). */
const HUMAN_LABEL = Object.freeze({
  [EVENT_TYPES.PII_EMAIL_PUBLIC]: 'an email address tied to you',
  [EVENT_TYPES.PII_PHONE_PUBLIC]: 'a phone number tied to you',
  [EVENT_TYPES.PII_POSTAL_PUBLIC]: 'a postal address tied to you',
  [EVENT_TYPES.PII_HANDLE_PUBLIC]: 'a personal handle/identifier tied to you',
  [EVENT_TYPES.PII_GEO_HINT_PUBLIC]: 'a location hint embedded in a file you published',
  [EVENT_TYPES.SECRET_LEAK_PUBLIC]: 'a secret/credential you accidentally published',
  [EVENT_TYPES.BREACH_RANGE_HIT]: 'a credential of yours that appears in a known breach',
  [EVENT_TYPES.SELF_PROFILE_URL]: 'a profile page you control',
  [EVENT_TYPES.SELF_USERNAME]: 'a username you use publicly',
  [EVENT_TYPES.TRACKER_THIRD_PARTY]: 'a third-party tracker on a site you control',
  [EVENT_TYPES.TRACKER_FINGERPRINTING]: 'browser-fingerprinting code on a site you control',
  [EVENT_TYPES.TRACKER_SESSION_RECORDING]: 'session-recording code on a site you control',
  [EVENT_TYPES.TRACKER_KEYLOGGING]: 'key-logging behavior on a site you control',
  [EVENT_TYPES.COOKIE_THIRD_PARTY]: 'third-party cookies set by a site you control',
  [EVENT_TYPES.LEAK_REFERRER]: 'a URL that leaks your identity to third parties',
});

function safeStr(v) {
  return typeof v === 'string' && v.trim() ? v.trim() : '';
}

/** Stable, sorted dedupe of an array of strings (drops empties). */
function uniqSorted(list) {
  return Array.from(new Set((list || []).filter(Boolean))).sort();
}

/**
 * Group the subject's real events into remediation clusters by co-occurrence
 * host (falling back to a per-event group when no host is known). We reuse the
 * SpiderFoot-style cluster keys so one request can cover every leak on one host.
 *
 * @param {object[]} events  module_event records (the other actors' real output)
 * @returns {Map<string, object[]>} groupKey -> events
 */
function groupEventsForTakedown(events) {
  const groups = new Map();
  const list = Array.isArray(events) ? events : [];
  for (let i = 0; i < list.length; i += 1) {
    const evt = list[i];
    if (!isModuleEvent(evt)) continue;
    if (evt.event_type === EVENT_TYPES.EXPOSURE_SUMMARY) continue; // meta, never actionable
    if (!EVENT_PLAYBOOK[evt.event_type]) continue;                 // no known remediation route

    // Prefer the host co-occurrence key (SpiderFoot correlation key) so all
    // leaks on one site collapse into a single removal request.
    const keys = clusterKeysFor(evt);
    const hostKey = keys.find((k) => k.startsWith('host:'));
    const groupKey = hostKey || `event:${i}`;
    if (!groups.has(groupKey)) groups.set(groupKey, []);
    groups.get(groupKey).push(evt);
  }
  return groups;
}

/**
 * Decide which request kind(s) a group of events needs, and what the request is
 * "about". A host the subject controls → SELF_REMOVAL; a third-party host → a
 * data-subject erasure/delete request (GDPR + CCPA) plus optional de-index;
 * rotation events → CREDENTIAL_ROTATION self-remediation.
 *
 * @param {object[]} events events in one group
 * @param {Set<string>} ownedHosts hosts the subject asserts they control
 * @returns {string[]} REQUEST_KINDS values (deduped, stable order)
 */
function requestKindsForGroup(events, ownedHosts) {
  const owned = ownedHosts instanceof Set ? ownedHosts : new Set();
  const kinds = new Set();
  for (const evt of events) {
    const routes = EVENT_PLAYBOOK[evt.event_type] || [];
    const host = hostOf(evt.source_url);
    const isOwn = host ? owned.has(host) : false;
    for (const route of routes) {
      if (route === 'rotate') {
        kinds.add(REQUEST_KINDS.CREDENTIAL_ROTATION);
      } else if (route === 'self_strip') {
        kinds.add(REQUEST_KINDS.SELF_REMOVAL);
      } else if (route === 'third_party_pii') {
        if (isOwn) {
          // It's PII on a surface the subject controls — they can just remove it.
          kinds.add(REQUEST_KINDS.SELF_REMOVAL);
        } else {
          // Third-party host holding the subject's PII → data-subject requests.
          kinds.add(REQUEST_KINDS.GDPR_ERASURE);
          kinds.add(REQUEST_KINDS.CCPA_DELETE);
          kinds.add(REQUEST_KINDS.SEARCH_DEINDEX);
        }
      }
    }
  }
  // Stable order matters for deterministic output (NO FAKE DATA → reproducible).
  const order = [
    REQUEST_KINDS.GDPR_ERASURE,
    REQUEST_KINDS.CCPA_DELETE,
    REQUEST_KINDS.SEARCH_DEINDEX,
    REQUEST_KINDS.SELF_REMOVAL,
    REQUEST_KINDS.CREDENTIAL_ROTATION,
  ];
  return order.filter((k) => kinds.has(k));
}

/**
 * Build the body text for ONE request kind, filled only from real fields.
 * Legal-route paragraphs are fixed boilerplate (a template the subject reviews);
 * every subject-specific blank is an explicit [[ FILL IN ]] placeholder so the
 * subject must consciously supply it. We never auto-fill identity we don't have.
 *
 * @returns {{ subject: string, body_text: string, statute_refs: string[] }}
 */
function draftBody({ kind, host, urls, exposureLabels, subjectName }) {
  const name = safeStr(subjectName) || PLACEHOLDER;
  const target = safeStr(host) || PLACEHOLDER;
  const urlBlock = urls.length
    ? urls.map((u) => `  - ${u}`).join('\n')
    : `  - ${PLACEHOLDER} (the exact URL where the information appears)`;
  const what = exposureLabels.length ? exposureLabels.join('; ') : PLACEHOLDER;

  if (kind === REQUEST_KINDS.GDPR_ERASURE) {
    return {
      subject: `Right to erasure request (GDPR Art. 17) — ${target}`,
      statute_refs: ['GDPR Article 17', 'GDPR Article 15'],
      body_text:
        `To the Data Protection Officer / Privacy Team at ${target},\n\n` +
        `I, ${name}, am exercising my right to erasure under Article 17 of the ` +
        `EU/UK General Data Protection Regulation. You are processing the ` +
        `following personal data about me, which I am asking you to erase:\n\n` +
        `  ${what}\n\nIt appears at:\n${urlBlock}\n\n` +
        `Please confirm erasure, or your lawful basis for refusing, within one ` +
        `month as required by Article 12(3). If you are not the controller, ` +
        `please forward this request and tell me who is.\n\n` +
        `My contact for your reply: ${PLACEHOLDER}\n` +
        `Identity verification (if you require it): ${PLACEHOLDER}\n\n` +
        `Sincerely,\n${name}`,
    };
  }

  if (kind === REQUEST_KINDS.CCPA_DELETE) {
    return {
      subject: `Request to delete personal information (CCPA/CPRA) — ${target}`,
      statute_refs: ['Cal. Civ. Code § 1798.105 (CCPA/CPRA right to delete)'],
      body_text:
        `To the Privacy Team at ${target},\n\n` +
        `I, ${name}, a California resident, request that you delete the personal ` +
        `information you have collected about me, under California Civil Code ` +
        `§ 1798.105. The information includes:\n\n  ${what}\n\nVisible at:\n` +
        `${urlBlock}\n\nPlease confirm deletion within 45 days. Do not sell or ` +
        `share my personal information.\n\nReply to: ${PLACEHOLDER}\n\n${name}`,
    };
  }

  if (kind === REQUEST_KINDS.SEARCH_DEINDEX) {
    return {
      subject: `Search result removal request — content about ${name}`,
      statute_refs: ['Google "Results about you" / personal-info removal policy'],
      body_text:
        `Search engine removal request.\n\n` +
        `I, ${name}, am requesting removal of search results that surface my ` +
        `personal contact information. The content concerns:\n\n  ${what}\n\n` +
        `URL(s) to remove from results for my name:\n${urlBlock}\n\n` +
        `Submit this through the engine's personal-information removal form ` +
        `(e.g. Google "Results about you"); de-indexing does not delete the ` +
        `source page, so also send the erasure request above to ${target}.`,
    };
  }

  if (kind === REQUEST_KINDS.SELF_REMOVAL) {
    return {
      subject: `Self-remediation checklist — ${target}`,
      statute_refs: [],
      body_text:
        `This surface is one YOU control, so no letter is needed — you can fix ` +
        `it directly. On ${target}:\n\n  ${what}\n\nAffected URL(s):\n` +
        `${urlBlock}\n\nSuggested actions:\n` +
        `  - Remove or redact the information from the page/profile.\n` +
        `  - For files: strip EXIF/metadata (location, device serial, author) ` +
        `before re-uploading.\n` +
        `  - For trackers: remove the third-party script/tag from your site.\n` +
        `  - Then request re-crawl so caches update.`,
    };
  }

  if (kind === REQUEST_KINDS.CREDENTIAL_ROTATION) {
    return {
      subject: 'Credential remediation — rotate and secure (not a takedown)',
      statute_refs: [],
      body_text:
        `No third party can "take this down" — it is a credential only YOU can ` +
        `secure. Detected via k-anonymity range check (the secret itself never ` +
        `left your machine), this concerns:\n\n  ${what}\n\nAct now:\n` +
        `  - Rotate/revoke the exposed credential immediately.\n` +
        `  - Enable multi-factor authentication on the affected account.\n` +
        `  - Stop reusing this password anywhere else.\n` +
        `  - If it was committed to a repo, purge it from history (it stays in ` +
        `clones/caches until rotated).\n\nObserved at:\n${urlBlock}`,
    };
  }

  // Unknown kind → no draft. Never fabricate.
  return null;
}

/**
 * Produce ONE structured takedown packet for a group of events.
 * @returns {object|null} a packet record, or null if nothing actionable.
 */
function packetForGroup({ groupKey, events, ownedHosts, subjectName }) {
  const kinds = requestKindsForGroup(events, ownedHosts);
  if (kinds.length === 0) return null;

  const host =
    groupKey.startsWith('host:') ? groupKey.slice('host:'.length) : hostOf(events[0].source_url);
  const urls = uniqSorted(events.map((e) => safeStr(e.source_url)));
  const exposureLabels = uniqSorted(
    events.map((e) => HUMAN_LABEL[e.event_type]).filter(Boolean),
  );
  const eventTypes = uniqSorted(events.map((e) => e.event_type));

  // Highest risk band present drives the packet's urgency (no inventing one).
  const riskRank = { info: 0, low: 1, medium: 2, high: 3 };
  let topRisk = 'info';
  for (const e of events) {
    if ((riskRank[e.risk] || 0) > (riskRank[topRisk] || 0)) topRisk = e.risk;
  }

  const letters = [];
  for (const kind of kinds) {
    const drafted = draftBody({ kind, host, urls, exposureLabels, subjectName });
    if (!drafted) continue;
    letters.push({
      request_kind: kind,
      is_template: true,
      review_banner: REVIEW_BANNER,
      subject_line: drafted.subject,
      body_text: drafted.body_text,
      statute_refs: drafted.statute_refs,
    });
  }
  if (letters.length === 0) return null;

  // Why-this-matters, Blacklight self-exposure voice (subject's own perspective).
  const why =
    exposureLabels.length === 1
      ? `A third party can find ${exposureLabels[0]} here. Removing it shrinks ` +
        `what strangers learn about you.`
      : `A third party can find these about you on one surface: ` +
        `${exposureLabels.join('; ')}. Handling them together removes the cluster ` +
        `in one request.`;

  return {
    record_type: 'takedown_packet',
    source_module: SOURCE_MODULE,
    group_key: groupKey,
    host: host || null,
    target_urls: urls,
    event_types: eventTypes,
    finding_count: events.length,
    top_risk: topRisk,
    why_it_matters: why,
    request_kinds: kinds,
    letters,
    is_template: true,
    disclaimer:
      'These are draft templates generated from your own audit findings. They ' +
      'are not legal advice and were not sent. Review every fact and the ' +
      'recipient before sending.',
  };
}

/**
 * Build the full takedown PLAN from the subject's real events.
 *
 * @param {object} p
 * @param {object[]} p.events       module_event records from the other actors
 * @param {string[]} [p.ownedHosts] hosts the subject asserts they control
 * @param {string}  [p.subjectName] the subject's name, for the letter (optional)
 * @returns {{ record_type: string, source_module: string, packet_count: number,
 *            letter_count: number, packets: object[], is_template: boolean }}
 */
function buildTakedownPlan({ events, ownedHosts = [], subjectName } = {}) {
  const owned = new Set(
    (Array.isArray(ownedHosts) ? ownedHosts : [])
      .map((h) => (typeof h === 'string' ? h.trim().toLowerCase() : ''))
      .filter(Boolean),
  );

  const groups = groupEventsForTakedown(events);
  const packets = [];
  // Sort group keys for deterministic, reproducible output.
  for (const groupKey of Array.from(groups.keys()).sort()) {
    const packet = packetForGroup({
      groupKey,
      events: groups.get(groupKey),
      ownedHosts: owned,
      subjectName,
    });
    if (packet) packets.push(packet);
  }

  const letterCount = packets.reduce((n, p) => n + p.letters.length, 0);
  return {
    record_type: 'takedown_plan',
    source_module: SOURCE_MODULE,
    packet_count: packets.length,
    letter_count: letterCount,
    packets,
    is_template: true,
    generated_note:
      'Drafted from your own audit findings only. No data about third parties ' +
      'was created; nothing was sent or removed automatically.',
  };
}

module.exports = {
  SOURCE_MODULE,
  REQUEST_KINDS,
  EVENT_PLAYBOOK,
  REVIEW_BANNER,
  PLACEHOLDER,
  groupEventsForTakedown,
  requestKindsForGroup,
  packetForGroup,
  buildTakedownPlan,
};
