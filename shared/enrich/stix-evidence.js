/**
 * shared/enrich/stix-evidence.js
 *
 * Wrap a detector module_event as a STIX 2.1-style "Observed Data" object so the
 * preserved evidence is interoperable and self-describing. We borrow STIX's
 * Observed-Data + Indicator vocabulary (the de-facto standard for sharing
 * cyber/OSINT observations, and the lingua franca SpiderFoot-class tools export
 * to) WITHOUT pulling a STIX library — we emit the plain JSON shape.
 *
 * Why STIX here: a exposure finding ("this email is public on this page,
 * observed at time T, with this content hash") is exactly an Observed Data
 * object with first_observed / last_observed and an objects bag. Using the
 * standard shape makes evidence portable into a report, a SIEM, or a takedown
 * request, and keeps provenance explicit — which is the entire point of the
 * evidence-preservation half of this product.
 *
 * RED LINE: an Observed Data object only describes a public observation of the
 * SELF subject's footprint. It carries NO inference, NO third-private-party
 * identity, NO romance/intimacy field. The schema below has no slot for any of
 * that, by design.
 *
 * Pure, deterministic given the input + an injectable clock. No network.
 * Ref (STIX 2.1 Observed Data / Indicator): OASIS STIX specification.
 */

'use strict';

const { isModuleEvent } = require('../detectors/event-types.js');

// Map our event types to a coarse STIX-ish observable category. Kept honest:
// these are categories of *public observation*, not identity assertions.
const OBSERVABLE_CATEGORY = Object.freeze({
  PII_EMAIL_PUBLIC: 'email-addr',
  PII_PHONE_PUBLIC: 'phone-number',
  PII_POSTAL_PUBLIC: 'postal-address',
  PII_HANDLE_PUBLIC: 'user-account',
  PII_GEO_HINT_PUBLIC: 'location-hint',
  SECRET_LEAK_PUBLIC: 'credential-exposure',
  SELF_PROFILE_URL: 'url',
  SELF_USERNAME: 'user-account',
  TRACKER_THIRD_PARTY: 'tracking-tech',
  TRACKER_FINGERPRINTING: 'tracking-tech',
  TRACKER_SESSION_RECORDING: 'tracking-tech',
  TRACKER_KEYLOGGING: 'tracking-tech',
  COOKIE_THIRD_PARTY: 'cookie',
  LEAK_REFERRER: 'url',
  BREACH_RANGE_HIT: 'credential-exposure',
  BROKER_LISTING_HIT: 'data-broker-record',
  EXPOSURE_SUMMARY: 'observed-data',
});

/**
 * Deterministic STIX-style id from stable parts. Not a real UUID; we use a
 * sha-free djb2 hash so the function stays dependency-free and reproducible in
 * tests. Format mimics STIX: "<type>--<hex>".
 */
function deterministicId(type, ...parts) {
  const s = parts.map((p) => String(p)).join('|');
  let h = 5381;
  for (let i = 0; i < s.length; i += 1) h = ((h << 5) + h + s.charCodeAt(i)) >>> 0;
  const hex = h.toString(16).padStart(8, '0');
  return `${type}--${hex}`;
}

/**
 * Convert a single detector module_event into a STIX-style Observed Data object.
 *
 * @param {object} event   a module_event from shared/detectors
 * @param {object} [opts]
 * @param {string} [opts.now]  ISO timestamp (injectable for deterministic tests)
 * @param {object} [opts.integrity]  optional {content_sha256, html_sha256, html_key, screenshot_key}
 * @returns {object|null}  STIX-style observed-data, or null if not a valid event
 */
function toObservedData(event, opts = {}) {
  if (!isModuleEvent(event)) return null;
  const now = typeof opts.now === 'string' ? opts.now : new Date().toISOString();
  const integrity = opts.integrity && typeof opts.integrity === 'object' ? opts.integrity : {};
  const category = OBSERVABLE_CATEGORY[event.event_type] || 'observed-data';

  const id = deterministicId('observed-data', event.event_type, event.source_url || '', JSON.stringify(event.data));

  return {
    type: 'observed-data',
    spec_version: '2.1',
    id,
    created: now,
    modified: now,
    first_observed: now,
    last_observed: now,
    number_observed: 1,
    // Provenance: which detector module saw it (SpiderFoot-style source_module).
    x_source_module: event.source_module,
    x_event_type: event.event_type,
    x_scope_note: 'Public observation of the SELF subject footprint. No third-party-private inference.',
    x_confidence: event.confidence,
    x_visibility: event.visibility,
    x_risk: event.risk,
    x_source_url: event.source_url,
    // Tamper-evidence handles from the crawler/diff stage, if available.
    x_integrity: {
      content_sha256: integrity.content_sha256 || null,
      html_sha256: integrity.html_sha256 || null,
      html_key: integrity.html_key || null,
      screenshot_key: integrity.screenshot_key || null,
    },
    objects: {
      0: {
        type: category,
        x_value: event.data,
        x_meta: event.meta || {},
      },
    },
  };
}

/**
 * Build a STIX-style bundle from many events (the report's evidence package).
 *
 * @param {object[]} events
 * @param {object} [opts]  passed through to toObservedData; opts.integrityByUrl
 *                         optionally maps source_url -> integrity handles.
 * @returns {object} STIX-style bundle
 */
function toBundle(events = [], opts = {}) {
  const integrityByUrl = (opts && opts.integrityByUrl) || {};
  const objects = [];
  for (const ev of events) {
    const integrity = ev && ev.source_url ? integrityByUrl[ev.source_url] : undefined;
    const od = toObservedData(ev, { now: opts.now, integrity });
    if (od) objects.push(od);
  }
  return {
    type: 'bundle',
    id: deterministicId('bundle', objects.length, objects.map((o) => o.id).join(',')),
    spec_version: '2.1',
    objects,
  };
}

module.exports = { OBSERVABLE_CATEGORY, deterministicId, toObservedData, toBundle };
