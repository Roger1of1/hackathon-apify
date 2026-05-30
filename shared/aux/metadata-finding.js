/**
 * shared/aux/metadata-finding.js
 *
 * Maps RAW file metadata (EXIF / XMP / IPTC / PDF info) extracted from the SELF
 * subject's OWN public assets into TYPED module-events that slot directly into
 * the frozen detector vocabulary (shared/detectors/event-types.js) and the
 * SpiderFoot-style correlation engine (shared/correlation.js).
 *
 * WHY THIS EXISTS
 * People routinely publish photos and PDFs on their own sites/profiles without
 * realizing the file itself carries GPS coordinates, a camera/phone serial, the
 * editing software, the author's real name, or an embedded contact email. This
 * is a classic self-footprint leak — exactly the Blacklight framing of "what a
 * third party can trivially learn about YOU from what you already published".
 * This helper turns those leaks into the same {event_type, source_module, data,
 * confidence, ...} shape every other detector emits, so the correlation engine
 * can cluster a metadata leak with other self-exposure events for the same host
 * or email (using only the k-anonymity prefix, never the plaintext address).
 *
 * RED LINES (enforced by construction, not by hope):
 *  - We map ONLY into the frozen EVENT_TYPES enum via makeEvent(); an unknown or
 *    forbidden type THROWS. There is no romance/gender/sexuality/intimacy/live-
 *    location event type to emit.
 *  - GPS found in a file the subject published is reported as a SELF geo-hint to
 *    FIX (PII_GEO_HINT_PUBLIC), never as live tracking of anyone. This actor is
 *    scope-gated to self/public_figure upstream, so we are only ever describing
 *    a subject's own published exposure.
 *  - NO FAKE DATA: every event here is built only from real extracted fields. If
 *    a file carried no metadata, this module emits nothing for it.
 *
 * REFERENCE PATTERNS APPLIED
 *  - SpiderFoot event-driven OSINT modules: typed events flow between producers
 *    and a correlation engine links them by shared entity (host / email).
 *  - HIBP k-anonymity: when EXIF Artist/author is itself an email, we emit only
 *    the 5-char SHA-1 prefix as a correlation key — the address never leaves.
 *
 * Pure + side-effect free (only requires sibling pure modules). Safe to unit test.
 */

'use strict';

const { makeEvent, EVENT_TYPES, VISIBILITY, RISK } = require('../detectors/event-types.js');
const { emailHashKey } = require('./kanon.js');

const SOURCE_MODULE = 'aux:metadata-exposure';

const EMAIL_RE = /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/i;

/**
 * Coarse, defensive numeric coercion for GPS so a malformed tag can never crash
 * the actor or fabricate a coordinate. Returns null when not a finite number.
 */
function asFiniteNumber(v) {
  const n = typeof v === 'number' ? v : Number(v);
  return Number.isFinite(n) ? n : null;
}

/**
 * Reduce a precise GPS coordinate to a COARSE hint (~1.1 km, 2 decimals). The
 * product audits self-exposure; we deliberately do NOT echo back the subject's
 * exact published coordinates at full precision in our own dataset — coarsening
 * is enough to tell them "this file leaks roughly-here" without us re-publishing
 * a pinpoint. The fact that the leak EXISTS is the finding; precision is not.
 */
function coarsenCoord(n) {
  const v = asFiniteNumber(n);
  return v === null ? null : Math.round(v * 100) / 100;
}

/**
 * Build the module-events for ONE asset's extracted metadata.
 *
 * @param {object} p
 * @param {string} p.sourceUrl      the public asset URL the subject published
 * @param {object} p.meta           raw extracted metadata object (exifr output etc.)
 * @returns {object[]} array of module_event records (possibly empty)
 */
function metadataEventsForAsset({ sourceUrl, meta }) {
  const events = [];
  if (!meta || typeof meta !== 'object') return events;

  const url = typeof sourceUrl === 'string' ? sourceUrl : null;

  // ── GPS leak → coarse SELF geo-hint the subject can strip ──
  const lat = coarsenCoord(meta.latitude ?? meta.GPSLatitude);
  const lon = coarsenCoord(meta.longitude ?? meta.GPSLongitude);
  if (lat !== null && lon !== null) {
    events.push(
      makeEvent({
        event_type: EVENT_TYPES.PII_GEO_HINT_PUBLIC,
        source_module: SOURCE_MODULE,
        data: { lat_coarse: lat, lon_coarse: lon },
        confidence: 0.95, // an embedded GPS tag is a hard, observed fact
        visibility: VISIBILITY.INDEXED, // anyone who downloads the file gets it
        risk: RISK.HIGH,
        source_url: url,
        meta: {
          leak_kind: 'exif_gps',
          advice: 'Strip EXIF location before re-publishing; coarsened here on purpose.',
        },
      }),
    );
  }

  // ── Author / Artist / Creator → a self handle or, if an email, a correlation key ──
  const authorRaw =
    meta.Artist || meta.author || meta.Author || meta.Creator || meta.creator || null;
  if (typeof authorRaw === 'string' && authorRaw.trim()) {
    const author = authorRaw.trim();
    const emailMatch = author.match(EMAIL_RE);
    if (emailMatch) {
      // The author field is an email — emit a PII_EMAIL_PUBLIC event plus the
      // k-anonymity prefix so correlation can co-occur it with breach/probe
      // events for the same address WITHOUT storing the plaintext.
      const { email_hash_prefix } = emailHashKey(emailMatch[0]);
      events.push(
        makeEvent({
          event_type: EVENT_TYPES.PII_EMAIL_PUBLIC,
          source_module: SOURCE_MODULE,
          // We keep the local-part only label out; store just the domain so the
          // report is useful but we are not re-publishing the full address.
          data: { domain: emailMatch[0].split('@')[1] || null },
          confidence: 0.9,
          visibility: VISIBILITY.INDEXED,
          risk: RISK.MEDIUM,
          source_url: url,
          // Hoisted co-occurrence key the correlation engine reads directly.
          meta: { leak_kind: 'exif_author_email', email_hash_prefix },
        }),
      );
    } else {
      events.push(
        makeEvent({
          event_type: EVENT_TYPES.SELF_USERNAME,
          source_module: SOURCE_MODULE,
          data: author,
          confidence: 0.8,
          visibility: VISIBILITY.INDEXED,
          risk: RISK.LOW,
          source_url: url,
          meta: { leak_kind: 'exif_author' },
        }),
      );
    }
  }

  // ── Device / software fingerprint → low-risk self handle-ish exposure ──
  // A camera model + serial, or editing software, fingerprints the subject's
  // gear. We surface it as INFO so they know it travels with their files.
  const make = typeof meta.Make === 'string' ? meta.Make.trim() : '';
  const model = typeof meta.Model === 'string' ? meta.Model.trim() : '';
  const software = typeof meta.Software === 'string' ? meta.Software.trim() : '';
  const serial =
    (typeof meta.SerialNumber === 'string' && meta.SerialNumber.trim()) ||
    (typeof meta.BodySerialNumber === 'string' && meta.BodySerialNumber.trim()) ||
    '';
  if (make || model || software || serial) {
    events.push(
      makeEvent({
        event_type: EVENT_TYPES.PII_HANDLE_PUBLIC, // device fingerprint behaves like a handle
        source_module: SOURCE_MODULE,
        data: {
          device: [make, model].filter(Boolean).join(' ') || null,
          software: software || null,
          // A serial is sensitive (uniquely identifies the device) → flag, don't echo full.
          has_serial: Boolean(serial),
        },
        confidence: 0.7,
        visibility: VISIBILITY.LINKED,
        risk: serial ? RISK.MEDIUM : RISK.INFO,
        source_url: url,
        meta: { leak_kind: 'exif_device' },
      }),
    );
  }

  return events;
}

/**
 * Aggregate EXPOSURE_SUMMARY event for one run. Counts only real events emitted.
 * @param {object} p
 * @param {number} p.assetsScanned
 * @param {number} p.assetsWithMetadata
 * @param {object[]} p.events  the real events already produced this run
 * @param {number} [p.exposureScore]
 */
function metadataSummaryEvent({ assetsScanned, assetsWithMetadata, events, exposureScore }) {
  const evts = Array.isArray(events) ? events : [];
  const counts = {};
  for (const e of evts) {
    counts[e.event_type] = (counts[e.event_type] || 0) + 1;
  }
  return makeEvent({
    event_type: EVENT_TYPES.EXPOSURE_SUMMARY,
    source_module: SOURCE_MODULE,
    data: {
      assets_scanned: Number.isFinite(assetsScanned) ? assetsScanned : 0,
      assets_with_metadata: Number.isFinite(assetsWithMetadata) ? assetsWithMetadata : 0,
      event_type_counts: counts,
      exposure_score: Number.isFinite(exposureScore) ? exposureScore : 0,
    },
    confidence: 1, // a count of real events is certain
    visibility: VISIBILITY.PRIVATE,
    risk: RISK.INFO,
  });
}

module.exports = {
  SOURCE_MODULE,
  EMAIL_RE,
  coarsenCoord,
  metadataEventsForAsset,
  metadataSummaryEvent,
};
