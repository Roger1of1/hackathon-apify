/**
 * shared/aux/archive-finding.js
 *
 * Pure shapers for the AUX "Public-Archive Self-Exposure" actor.
 *
 * THE FEATURE
 * ───────────
 * Web pages get deleted, but their snapshots live on forever in public web
 * archives (the Internet Archive Wayback Machine, via its public CDX index).
 * A self-footprint audit is incomplete if it only looks at what's live RIGHT
 * NOW: the SELF subject may have removed a page that still exposes their email,
 * phone, or an old handle in an archived snapshot a third party can pull up in
 * seconds. This module shapes those PUBLIC archive snapshots into the same
 * typed module_events every other detector emits, so the report and the
 * SpiderFoot-style correlation engine treat an archived exposure exactly like a
 * live one — and the user can request its removal.
 *
 * WHY THIS MAPS CLEANLY ONTO STIX
 * ───────────────────────────────
 * A Wayback CDX row is literally an *observation of a URL at a point in time*
 * with a content digest. That is, almost verbatim, a STIX 2.1 Observed Data
 * object: the snapshot timestamp → first_observed / last_observed, the CDX
 * `digest` → a content-hash observable, the original URL → a `url` observable.
 * We therefore emit SELF_PROFILE_URL / PII_*_PUBLIC module_events carrying the
 * real archive timestamp + digest in `meta`, so shared/enrich/stix-evidence.js
 * can wrap each into an Observed Data object whose first_observed/last_observed
 * are the TRUE archive capture time (not "now"). This is the OpenCTI/MISP +
 * STIX evidence-object model: portable, provenance-first, hand-off-ready.
 *
 * Refs:
 *  - OASIS STIX 2.1 Observed Data / Indicator SDO (the interop shape OpenCTI &
 *    MISP ingest/export for sharing observations). STIX Observed Data carries
 *    first_observed/last_observed/number_observed + an objects bag — exactly the
 *    fields a Wayback snapshot provides.  https://docs.oasis-open.org/cti/stix/
 *  - OpenCTI / MISP interop: both round-trip STIX 2.1 bundles, so emitting the
 *    standard shape lets a user hand a finding to a takedown desk or a SIEM.
 *  - Internet Archive Wayback CDX Server API (public index): each row is
 *    [urlkey, timestamp, original, mimetype, statuscode, digest, length].
 *    https://github.com/internetarchive/wayback/tree/master/wayback-cdx-server
 *  - Apify Website Content Crawler / RAG Web Browser ingestion pattern: a
 *    bounded, polite fetch of public web content mapped into typed records. We
 *    mirror that mapping step here (CDX rows → typed module_events), while the
 *    live-fetch half lives in the actor.
 *
 * RED LINES (by construction, not by policy text):
 *  - Only PUBLIC archive snapshots of a URL/host the SELF subject (or a genuine
 *    public_figure) controls are shaped. There is NO event type, field, or code
 *    path here for romance/intimacy/gender inference, follower/like scraping,
 *    third-private-party identity, or live location. The frozen EVENT_TYPES
 *    vocabulary simply has no slot for any of that.
 *  - Pure + deterministic + offline. No network, no clock dependence except via
 *    the archive timestamp the caller passes in. Safe to require at load.
 */

'use strict';

const { makeEvent, EVENT_TYPES, VISIBILITY, RISK } = require('../detectors/event-types.js');

const MODULE = 'aux:archive-exposure';

/**
 * Parse a 14-digit Wayback timestamp (YYYYMMDDhhmmss) into an ISO-8601 string.
 * Returns null for anything that isn't a real 14-digit stamp — we never invent
 * a time (NO FAKE DATA). This ISO value becomes the STIX first/last_observed.
 *
 * @param {string} ts  e.g. "20190731164102"
 * @returns {string|null} e.g. "2019-07-31T16:41:02.000Z"
 */
function waybackTimestampToISO(ts) {
  if (typeof ts !== 'string' || !/^\d{14}$/.test(ts)) return null;
  const y = ts.slice(0, 4);
  const mo = ts.slice(4, 6);
  const d = ts.slice(6, 8);
  const h = ts.slice(8, 10);
  const mi = ts.slice(10, 12);
  const s = ts.slice(12, 14);
  const iso = `${y}-${mo}-${d}T${h}:${mi}:${s}.000Z`;
  const parsed = new Date(iso);
  if (Number.isNaN(parsed.getTime())) return null;
  return parsed.toISOString();
}

/** Build the public Wayback replay URL for a snapshot (real, linkable). */
function waybackReplayUrl(timestamp, originalUrl) {
  if (typeof timestamp !== 'string' || !/^\d{14}$/.test(timestamp)) return null;
  if (typeof originalUrl !== 'string' || !originalUrl) return null;
  return `https://web.archive.org/web/${timestamp}/${originalUrl}`;
}

/**
 * Shape a single Wayback CDX row into a SELF_PROFILE_URL module_event.
 *
 * A CDX row is the array
 *   [urlkey, timestamp, original, mimetype, statuscode, digest, length].
 * We pass the parsed fields. The event records the REAL archive capture time
 * and content digest in meta so the STIX layer can use them as
 * first_observed/last_observed + a content-hash observable — true provenance,
 * never a fabricated "observed now".
 *
 * @param {object} p
 * @param {string} p.original     the archived original URL
 * @param {string} p.timestamp    14-digit Wayback timestamp
 * @param {string} [p.digest]     CDX content digest (base32 SHA-1 of payload)
 * @param {string} [p.mimetype]
 * @param {string|number} [p.statuscode]
 * @param {string} [p.subjectUrlPrefix]  the self-owned URL/host the run is scoped to
 * @returns {object|null} a module_event, or null for an unparseable row
 */
function makeArchivedUrlEvent({
  original,
  timestamp,
  digest = null,
  mimetype = null,
  statuscode = null,
  subjectUrlPrefix = null,
}) {
  const observedISO = waybackTimestampToISO(timestamp);
  const replayUrl = waybackReplayUrl(timestamp, original);
  if (!observedISO || !replayUrl) return null; // unparseable → emit nothing

  return makeEvent({
    event_type: EVENT_TYPES.SELF_PROFILE_URL,
    source_module: MODULE,
    data: original,
    confidence: 0.95, // CDX rows are concrete archival facts, not inferences
    visibility: VISIBILITY.INDEXED, // anyone can pull it up by searching the archive
    risk: RISK.MEDIUM, // a exposure the subject may have *thought* they removed
    source_url: replayUrl,
    meta: {
      surface_kind: 'archive_snapshot',
      archive: 'wayback',
      // These three feed STIX first_observed / last_observed / content-hash.
      observed_at: observedISO,
      content_digest: typeof digest === 'string' && digest ? digest : null,
      digest_algo: digest ? 'cdx-sha1-base32' : null,
      mimetype: typeof mimetype === 'string' ? mimetype : null,
      statuscode: statuscode != null ? String(statuscode) : null,
      original_url: original,
      subject_url_prefix: subjectUrlPrefix || null,
    },
  });
}

/**
 * Shape a PII string that was found INSIDE an archived snapshot's text into the
 * matching PII_*_PUBLIC module_event. The PII detection itself is done by the
 * shared detectors (reused by the actor); this only wraps an already-detected
 * value with archive provenance so the STIX layer dates it to the snapshot.
 *
 * @param {object} p
 * @param {string} p.event_type  one of the PII_*_PUBLIC EVENT_TYPES
 * @param {*}      p.data         the detected value (already redacted/normalised upstream)
 * @param {string} p.replayUrl   the wayback replay URL the value was found on
 * @param {string} p.observedISO ISO time of the snapshot (from waybackTimestampToISO)
 * @param {string} [p.original]  original archived URL
 * @param {number} [p.confidence]
 * @returns {object|null}
 */
function makeArchivedPiiEvent({
  event_type,
  data,
  replayUrl,
  observedISO,
  original = null,
  confidence = 0.7,
}) {
  const PII = new Set([
    EVENT_TYPES.PII_EMAIL_PUBLIC,
    EVENT_TYPES.PII_PHONE_PUBLIC,
    EVENT_TYPES.PII_POSTAL_PUBLIC,
    EVENT_TYPES.PII_HANDLE_PUBLIC,
    EVENT_TYPES.PII_GEO_HINT_PUBLIC,
  ]);
  if (!PII.has(event_type)) return null;
  if (typeof replayUrl !== 'string' || !replayUrl) return null;
  if (typeof observedISO !== 'string' || !observedISO) return null;

  return makeEvent({
    event_type,
    source_module: MODULE,
    data,
    confidence,
    visibility: VISIBILITY.INDEXED,
    risk: RISK.HIGH, // PII surviving in a deleted page is the worst-case exposure
    source_url: replayUrl,
    meta: {
      surface_kind: 'archive_snapshot',
      archive: 'wayback',
      observed_at: observedISO,
      original_url: original,
      note: 'PII detected inside a PUBLIC archived snapshot; subject may have removed the live page.',
    },
  });
}

/**
 * A real aggregate summary event. Counts only — never fabricated. If nothing was
 * archived, the counts are zero and that is the honest answer.
 *
 * @param {object} p
 * @param {string} p.subjectUrlPrefix
 * @param {{snapshots:number,unique_urls:number,pii_in_archive:number}} p.counts
 * @param {string} [p.earliestISO]
 * @param {string} [p.latestISO]
 */
function makeSummaryEvent({ subjectUrlPrefix, counts, earliestISO = null, latestISO = null }) {
  const c = counts && typeof counts === 'object' ? counts : {};
  return makeEvent({
    event_type: EVENT_TYPES.EXPOSURE_SUMMARY,
    source_module: MODULE,
    data: {
      subject_url_prefix: subjectUrlPrefix || null,
      snapshots: Number(c.snapshots) || 0,
      unique_urls: Number(c.unique_urls) || 0,
      pii_in_archive: Number(c.pii_in_archive) || 0,
      earliest_observed: earliestISO,
      latest_observed: latestISO,
    },
    confidence: 1,
    visibility: VISIBILITY.INDEXED,
    risk: RISK.INFO,
    source_url: null,
    meta: { archive: 'wayback' },
  });
}

module.exports = {
  MODULE,
  waybackTimestampToISO,
  waybackReplayUrl,
  makeArchivedUrlEvent,
  makeArchivedPiiEvent,
  makeSummaryEvent,
};
