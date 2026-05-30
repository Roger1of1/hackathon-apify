/**
 * shared/detectors/tracker-detector.js
 *
 * Blacklight-style detector MODULE. The Markup's Blacklight loads a site in a
 * headless browser and reports the surveillance tech it finds: third-party
 * trackers, third-party cookies, canvas/fingerprinting, session recording, and
 * key-logging. We apply the SAME audit to a page the SELF subject CONTROLS, so
 * the subject can see what trackers harvest from *their own visitors* and fix
 * it. This is a privacy-hygiene audit of your own property, not surveillance.
 *
 * Ref (Blacklight):
 *   https://themarkup.org/blacklight
 *   "How We Built a Real-time Privacy Inspector" — themarkup.org/blacklight/2020/09/22
 * Ref (SpiderFoot module/event pattern): https://github.com/smicallef/spiderfoot
 *
 * IMPORTANT compliance note: this module is given ALREADY-COLLECTED, structured
 * page artifacts (script src list, set-cookie headers, detected JS API usage)
 * captured by the crawler from a public, gate-approved page. It performs NO
 * network calls and renders nothing itself. It classifies known patterns; it
 * never profiles a human.
 *
 * Pure function, no I/O. Safe to require at load.
 */

'use strict';

const { EVENT_TYPES, VISIBILITY, RISK, makeEvent } = require('./event-types.js');

const MODULE = 'tracker_detector';

/**
 * Known third-party tracking vendors keyed by a host substring. This mirrors
 * Blacklight's approach of matching network requests against a known-tracker
 * inventory (they use a public blocklist; we ship a small honest seed list and
 * clearly label it as a non-exhaustive seed — NOT fabricated results).
 *
 * Each detected request to one of these is a real, observed exposure on the
 * subject's own page.
 */
const TRACKER_VENDORS = Object.freeze([
  { match: 'google-analytics.com', vendor: 'Google Analytics', kind: 'analytics' },
  { match: 'googletagmanager.com', vendor: 'Google Tag Manager', kind: 'analytics' },
  { match: 'doubleclick.net', vendor: 'Google DoubleClick', kind: 'ad' },
  { match: 'connect.facebook.net', vendor: 'Meta Pixel', kind: 'ad' },
  { match: 'facebook.com/tr', vendor: 'Meta Pixel', kind: 'ad' },
  { match: 'hotjar.com', vendor: 'Hotjar', kind: 'session_recording' },
  { match: 'fullstory.com', vendor: 'FullStory', kind: 'session_recording' },
  { match: 'clarity.ms', vendor: 'Microsoft Clarity', kind: 'session_recording' },
  { match: 'mouseflow.com', vendor: 'Mouseflow', kind: 'session_recording' },
  { match: 'inspectlet.com', vendor: 'Inspectlet', kind: 'session_recording' },
  { match: 'segment.com', vendor: 'Segment', kind: 'analytics' },
  { match: 'amplitude.com', vendor: 'Amplitude', kind: 'analytics' },
  { match: 'mixpanel.com', vendor: 'Mixpanel', kind: 'analytics' },
]);

// JS-API usage signatures Blacklight watches for. The crawler reports which of
// these APIs a page actually invoked (observed instrumentation), and we map
// them to exposure event types. We do NOT guess — absence of a signal = no event.
const FINGERPRINTING_APIS = Object.freeze([
  'canvas.toDataURL',
  'canvas.getImageData',
  'WebGLRenderingContext.getParameter',
  'navigator.plugins',
  'AudioContext.createOscillator',
]);

const KEYLOGGING_APIS = Object.freeze([
  'input.keydown.exfil', // a keystroke handler that ships to a 3p before submit
  'input.keystroke.beacon',
]);

function vendorFor(urlOrHost) {
  const s = String(urlOrHost || '').toLowerCase();
  for (const v of TRACKER_VENDORS) {
    if (s.includes(v.match)) return v;
  }
  return null;
}

/**
 * Run the tracker module against a captured page artifact.
 *
 * @param {object} artifact
 * @param {string} [artifact.url]              first-party page URL
 * @param {string[]} [artifact.scripts]        observed <script src> / request URLs
 * @param {Array}  [artifact.cookies]          observed cookies: {name, domain, third_party}
 * @param {string[]} [artifact.js_api_calls]   observed instrumented JS API names
 * @param {string[]} [artifact.outbound_links] links that may leak referrer/identity
 * @returns {object[]} module_event[]
 */
function detectTrackers(artifact = {}) {
  const url = typeof artifact.url === 'string' ? artifact.url : null;
  const firstPartyHost = (() => {
    try { return url ? new URL(url).hostname.toLowerCase() : null; } catch { return null; }
  })();

  const events = [];
  const scripts = Array.isArray(artifact.scripts) ? artifact.scripts : [];
  const cookies = Array.isArray(artifact.cookies) ? artifact.cookies : [];
  const apis = Array.isArray(artifact.js_api_calls) ? artifact.js_api_calls : [];
  const links = Array.isArray(artifact.outbound_links) ? artifact.outbound_links : [];

  // 1) Third-party trackers (and session-recording vendors get a stronger type).
  const seenVendorOnKind = new Set();
  for (const src of scripts) {
    const v = vendorFor(src);
    if (!v) continue;
    const key = `${v.vendor}|${v.kind}`;
    if (seenVendorOnKind.has(key)) continue; // de-dupe per vendor+kind per page
    seenVendorOnKind.add(key);

    if (v.kind === 'session_recording') {
      events.push(makeEvent({
        event_type: EVENT_TYPES.TRACKER_SESSION_RECORDING,
        source_module: MODULE,
        data: v.vendor,
        confidence: 0.85,
        visibility: VISIBILITY.INDEXED,
        risk: RISK.HIGH, // records every visitor interaction — Blacklight flags this strongly
        source_url: url,
        meta: { vendor: v.vendor, kind: v.kind, signature: String(src) },
      }));
    } else {
      events.push(makeEvent({
        event_type: EVENT_TYPES.TRACKER_THIRD_PARTY,
        source_module: MODULE,
        data: v.vendor,
        confidence: 0.85,
        visibility: VISIBILITY.INDEXED,
        risk: v.kind === 'ad' ? RISK.MEDIUM : RISK.LOW,
        source_url: url,
        meta: { vendor: v.vendor, kind: v.kind, signature: String(src) },
      }));
    }
  }

  // 2) Third-party cookies (set-cookie whose domain != first party).
  for (const c of cookies) {
    if (!c || typeof c !== 'object') continue;
    const dom = String(c.domain || '').toLowerCase().replace(/^\./, '');
    const isThird = c.third_party === true
      || (firstPartyHost && dom && !firstPartyHost.endsWith(dom) && !dom.endsWith(firstPartyHost));
    if (!isThird) continue;
    events.push(makeEvent({
      event_type: EVENT_TYPES.COOKIE_THIRD_PARTY,
      source_module: MODULE,
      data: c.name || '(unnamed)',
      confidence: 0.9,
      visibility: VISIBILITY.INDEXED,
      risk: RISK.MEDIUM,
      source_url: url,
      meta: { cookie_domain: dom },
    }));
  }

  // 3) Fingerprinting / key-logging via observed JS API usage.
  const fpHits = apis.filter((a) => FINGERPRINTING_APIS.includes(a));
  if (fpHits.length) {
    events.push(makeEvent({
      event_type: EVENT_TYPES.TRACKER_FINGERPRINTING,
      source_module: MODULE,
      data: fpHits,
      // confidence scales with how many fingerprinting APIs were actually seen
      confidence: Math.min(0.95, 0.5 + 0.15 * fpHits.length),
      visibility: VISIBILITY.INDEXED,
      risk: RISK.HIGH,
      source_url: url,
      meta: { apis: fpHits, note: 'canvas/webgl/audio fingerprinting signatures observed' },
    }));
  }

  const klHits = apis.filter((a) => KEYLOGGING_APIS.includes(a));
  if (klHits.length) {
    events.push(makeEvent({
      event_type: EVENT_TYPES.TRACKER_KEYLOGGING,
      source_module: MODULE,
      data: klHits,
      confidence: 0.8,
      visibility: VISIBILITY.INDEXED,
      risk: RISK.HIGH,
      source_url: url,
      meta: { apis: klHits },
    }));
  }

  // 4) Referrer / identity leak in outbound links (e.g. an email or username in
  // a query string sent to a third party). Blacklight flags URL-based leakage.
  for (const link of links) {
    const s = String(link || '');
    let host = null;
    try { host = new URL(s).hostname.toLowerCase(); } catch { /* ignore */ }
    if (!host || (firstPartyHost && host === firstPartyHost)) continue;
    if (/[?&](email|e|user|uid|name|phone|tel)=/.test(s)) {
      events.push(makeEvent({
        event_type: EVENT_TYPES.LEAK_REFERRER,
        source_module: MODULE,
        data: s,
        confidence: 0.6,
        visibility: VISIBILITY.LINKED,
        risk: RISK.MEDIUM,
        source_url: url,
        meta: { third_party_host: host },
      }));
    }
  }

  return events;
}

module.exports = { MODULE, detectTrackers, TRACKER_VENDORS, FINGERPRINTING_APIS };
