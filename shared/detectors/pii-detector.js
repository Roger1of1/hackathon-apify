/**
 * shared/detectors/pii-detector.js
 *
 * SpiderFoot-style detector MODULE: given the already-captured PUBLIC text of a
 * page the SELF (or public_figure) subject controls, emit typed module_events
 * for personally-identifying data the subject has *themselves published*.
 *
 * Why this is inside the red lines:
 *  - It runs ONLY on text already fetched from a public, logged-out page that
 *    passed the scope gate (scope=self|public_figure). It does not fetch.
 *  - It DETECTS strings the subject published; it does not de-anonymize, link to
 *    a private person, or infer any attribute (no gender/romance/intimacy).
 *  - Its whole purpose is "what can a stranger trivially harvest about ME" —
 *    Blacklight's self-audit framing applied to PII rather than trackers.
 *
 * SpiderFoot patterns borrowed:
 *  - A named module (`MODULE`) that consumes one input "event" (a captured page)
 *    and produces typed output events with provenance + confidence.
 *  - Confidence reflects match strength, not certainty about a human — honest.
 *
 * Pure function, no network, no state. Safe to require at load.
 * Ref: https://github.com/smicallef/spiderfoot
 */

'use strict';

const { EVENT_TYPES, VISIBILITY, RISK, makeEvent } = require('./event-types.js');
// k-anonymity email fingerprint (HIBP range model). We import the SAME pure
// helper the breach auxiliary + correlation engine use so a public email found
// on a page and a breach event for that email share an identical
// `email_hash_prefix` co-occurrence key — never the plaintext address. This is
// what lets the SpiderFoot-style correlation pass cluster the two together.
// Ref: Troy Hunt, "Understanding HIBP's Use of SHA-1 and k-Anonymity".
const { emailHashKey } = require('../aux/kanon.js');

const MODULE = 'pii_detector';

// Conservative patterns. We favour precision over recall: a missed match is
// fine (no fake data), a false PII claim is worse.
const EMAIL_RE = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,24}\b/g;

// E.164-ish / common separators. Deliberately NOT matching bare 4-9 digit runs
// (those are usually IDs, prices, years) to keep precision high.
const PHONE_RE = /(?:\+\d{1,3}[\s.-]?)?(?:\(\d{2,4}\)[\s.-]?)?\d{3}[\s.-]\d{3,4}[\s.-]?\d{0,4}/g;

// @handles (twitter/mastodon-style) the subject lists about themselves.
const HANDLE_RE = /(?:^|[\s(>])@([A-Za-z0-9_]{2,30})(?=$|[\s).,<])/g;

// Coarse self-published location text only ("Based in <City>"). This is the
// subject's OWN stated city, NOT live tracking — we capture the city token, and
// only when it follows an explicit self-location preposition.
const GEO_RE = /\b(?:based in|located in|lives? in|home town|hometown|based out of)\s+([A-Z][A-Za-z.'-]+(?:[ ,][A-Z][A-Za-z.'-]+){0,3})/g;

// Street-address shape (number + street + suffix). Coarse, precision-first.
const POSTAL_RE = /\b\d{1,5}\s+[A-Za-z0-9.'-]+(?:\s+[A-Za-z0-9.'-]+){0,3}\s+(?:St|Street|Ave|Avenue|Rd|Road|Blvd|Boulevard|Ln|Lane|Dr|Drive|Way|Ct|Court|Pl|Place)\b\.?/gi;

function dedupe(values) {
  return Array.from(new Set(values));
}

/**
 * Run the PII module on one captured page.
 *
 * @param {object} page
 * @param {string} page.text   normalized visible text (already captured)
 * @param {string} [page.url]  the public URL it came from
 * @param {string} [page.scope_type] gate-approved scope (self|public_figure…)
 * @param {string} [page.visibility] VISIBILITY for this surface (default linked)
 * @returns {object[]} module_event[]
 */
function detectPii(page = {}) {
  const text = typeof page.text === 'string' ? page.text : '';
  if (!text) return [];

  const url = typeof page.url === 'string' ? page.url : null;
  const visibility = page.visibility || VISIBILITY.LINKED;
  const events = [];

  const emails = dedupe(text.match(EMAIL_RE) || []);
  for (const email of emails) {
    // Emit the k-anonymity prefix as a correlation key alongside the (already
    // public) address. The plaintext stays in `data` because the subject
    // themselves published it on a public page; the prefix is the *cross-source*
    // join key the correlation engine uses to co-occur this with breach events
    // for the same address without re-deriving it elsewhere.
    const { email_hash_prefix } = emailHashKey(email);
    events.push(makeEvent({
      event_type: EVENT_TYPES.PII_EMAIL_PUBLIC,
      source_module: MODULE,
      data: email,
      confidence: 0.95,
      visibility,
      risk: RISK.MEDIUM,
      source_url: url,
      meta: {
        local_part: email.split('@')[0] || '',
        domain: email.split('@')[1] || '',
        // Co-occurrence key for shared/correlation.js (SpiderFoot-style cluster
        // on a shared entity), privacy-preserving per HIBP k-anonymity.
        email_hash_prefix,
      },
    }));
  }

  const phones = dedupe((text.match(PHONE_RE) || []).map((s) => s.trim()).filter((s) => {
    const digits = s.replace(/\D/g, '');
    return digits.length >= 7 && digits.length <= 15; // plausible phone, not an ID
  }));
  for (const phone of phones) {
    events.push(makeEvent({
      event_type: EVENT_TYPES.PII_PHONE_PUBLIC,
      source_module: MODULE,
      data: phone,
      confidence: 0.7,
      visibility,
      risk: RISK.MEDIUM,
      source_url: url,
      meta: { digit_count: phone.replace(/\D/g, '').length },
    }));
  }

  let m;
  const handles = new Set();
  HANDLE_RE.lastIndex = 0;
  while ((m = HANDLE_RE.exec(text)) !== null) handles.add(m[1]);
  for (const handle of handles) {
    events.push(makeEvent({
      event_type: EVENT_TYPES.PII_HANDLE_PUBLIC,
      source_module: MODULE,
      data: `@${handle}`,
      confidence: 0.6,
      visibility,
      risk: RISK.LOW,
      source_url: url,
      meta: { handle },
    }));
  }

  const geos = new Set();
  GEO_RE.lastIndex = 0;
  while ((m = GEO_RE.exec(text)) !== null) geos.add(m[1].trim().replace(/[ ,]+$/, ''));
  for (const place of geos) {
    events.push(makeEvent({
      event_type: EVENT_TYPES.PII_GEO_HINT_PUBLIC,
      source_module: MODULE,
      data: place,
      confidence: 0.55,
      visibility,
      risk: RISK.LOW,
      source_url: url,
      // Explicitly coarse: this is a self-stated home city, not live location.
      meta: { kind: 'self_stated_city', note: 'coarse, self-published; not live location' },
    }));
  }

  const postals = dedupe((text.match(POSTAL_RE) || []).map((s) => s.trim()));
  for (const addr of postals) {
    events.push(makeEvent({
      event_type: EVENT_TYPES.PII_POSTAL_PUBLIC,
      source_module: MODULE,
      data: addr,
      confidence: 0.5,
      visibility,
      risk: RISK.HIGH, // a self-published street address is the highest-value leak
      source_url: url,
      meta: { kind: 'street_address_shape' },
    }));
  }

  return events;
}

module.exports = { MODULE, detectPii };
