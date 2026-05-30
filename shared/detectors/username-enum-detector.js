/**
 * shared/detectors/username-enum-detector.js
 *
 * SpiderFoot-style detector MODULE for USERNAME ENUMERATION — the classic OSINT
 * "is this handle taken on platform X?" sweep (Sherlock / WhatsMyName /
 * SpiderFoot's sfp_accounts module). This is a DUAL-USE technique: the same
 * "probe a username across many sites" mechanic can be used to stalk a stranger,
 * so the product's red lines allow it ONLY for scope=self or scope=public_figure
 * and ONLY for a handle the subject already owns / publicly acknowledges.
 *
 * This module is the chokepoint that makes the dual-use technique compliant:
 *   - It NEVER fetches anything. It classifies probe results an upstream,
 *     scope-gated actor already collected (account exists / not-found / unknown)
 *     for a handle the subject themselves supplied. No network at import or call.
 *   - It REFUSES to emit anything unless scope_type is self|public_figure — the
 *     exact dual-use guard shared/detectors/breach-range-detector.js uses. The
 *     canonical authority is still shared/scope.js; we fail closed locally too.
 *   - It produces ONLY frozen-vocabulary events (SELF_USERNAME / SELF_PROFILE_URL)
 *     via makeEvent(), so an unknown/forbidden type THROWS. There is deliberately
 *     no "who follows them / likes / is dating" output — only "this is a surface
 *     bearing MY handle that I should know about / lock down / reclaim".
 *   - NO FAKE DATA: a site is only reported as a hit when the probe result
 *     honestly says `exists === true`. `unknown`/error results emit nothing — we
 *     never fabricate an account presence we did not actually observe.
 *
 * SpiderFoot patterns borrowed:
 *   - A named module (`MODULE`) consuming one captured artifact (a batch of
 *     username probe results) and producing typed module_events with provenance
 *     + honest confidence (sfp_accounts emits an ACCOUNT_EXTERNAL_OWNED event per
 *     confirmed site).
 *   - Confidence reflects how the probe was confirmed (HTTP 200 + a positive
 *     content marker is stronger than a bare status code), never certainty about
 *     a human.
 *
 * Refs:
 *   SpiderFoot sfp_accounts (account enumeration module) + correlation engine —
 *     github.com/smicallef/spiderfoot
 *   Sherlock / WhatsMyName username-presence methodology (status + content
 *     markers per site) — github.com/sherlock-project/sherlock
 *
 * Pure function, no network, no state. Safe to require at load.
 */

'use strict';

const { EVENT_TYPES, VISIBILITY, RISK, makeEvent } = require('./event-types.js');
const { normalizeHandle } = require('../enrich/cluster-keys.js');

const MODULE = 'username_enum_detector';

// Scopes under which this dual-use technique may run AT ALL. Mirrors the breach
// detector's guard; the real gate is shared/scope.js (we never edit it), this is
// defense-in-depth that fails closed.
const ALLOWED_SCOPES = Object.freeze(new Set(['self', 'public_figure']));

// How a probe was confirmed → an honest confidence. A status-only "200" is weaker
// than a 200 that also matched a positive content marker (the username actually
// rendered on the profile), which is itself weaker than the platform exposing a
// canonical profile URL. These mirror Sherlock/WhatsMyName detection methods.
const METHOD_CONFIDENCE = Object.freeze({
  status_and_content: 0.9, // HTTP 200 AND a positive marker (handle rendered)
  canonical_profile: 0.85, // platform returned a canonical profile URL for the handle
  status_only: 0.6,        // bare HTTP 200 — weaker, may be a soft-404 / catch-all
});

/**
 * Coerce a probe result to a normalized internal shape, or null if it is not a
 * usable, *positive* observation. Anything that is not an explicit `exists:true`
 * (including 'unknown', errors, or not-found) returns null so we emit nothing —
 * never a fabricated hit.
 *
 * @param {object} probe
 * @param {string} probe.platform   e.g. "github"
 * @param {boolean} [probe.exists]  TRUE only when the upstream actor confirmed presence
 * @param {string} [probe.method]   one of METHOD_CONFIDENCE keys
 * @param {string} [probe.profile_url]  canonical public URL, if the platform gave one
 * @param {number} [probe.http_status]  observed status code (provenance only)
 */
function normalizeProbe(probe) {
  if (!probe || typeof probe !== 'object') return null;
  if (probe.exists !== true) return null; // honest: only confirmed presence counts

  const platform = typeof probe.platform === 'string' ? probe.platform.trim().toLowerCase() : '';
  if (!platform) return null;

  const method = typeof probe.method === 'string' && METHOD_CONFIDENCE[probe.method]
    ? probe.method
    : 'status_only';

  const profileUrl = typeof probe.profile_url === 'string' && /^https?:\/\//i.test(probe.profile_url)
    ? probe.profile_url
    : null;

  const httpStatus = Number.isFinite(probe.http_status) ? probe.http_status : null;

  return { platform, method, profileUrl, httpStatus };
}

/**
 * Run the username-enumeration module over one batch of probe results.
 *
 * @param {object} artifact
 * @param {string}  artifact.handle        the handle the SUBJECT supplied/owns (e.g. "@jane")
 * @param {object[]} artifact.probes       upstream-collected per-platform probe results
 * @param {string} [artifact.scope_type]   must be self|public_figure to proceed
 * @param {string} [artifact.visibility]   VISIBILITY for the discovered surfaces
 * @returns {object[]} module_event[]  (empty unless scope is allowed AND there are real hits)
 */
function detectUsernameAccounts(artifact = {}) {
  const scope = artifact.scope_type;
  // Dual-use chokepoint: refuse outright for any scope but self/public_figure.
  if (!ALLOWED_SCOPES.has(scope)) return [];

  const handle = normalizeHandle(artifact.handle);
  if (!handle) return []; // no honest subject handle => nothing to enumerate

  const probes = Array.isArray(artifact.probes) ? artifact.probes : [];
  const visibility = artifact.visibility || VISIBILITY.INDEXED; // a public profile is trivially discoverable
  const events = [];
  const seenPlatforms = new Set();

  for (const raw of probes) {
    const p = normalizeProbe(raw);
    if (!p) continue;                       // skip unknown/not-found/error => no fabrication
    if (seenPlatforms.has(p.platform)) continue; // de-dupe per platform
    seenPlatforms.add(p.platform);

    const confidence = METHOD_CONFIDENCE[p.method];

    // The handle's presence itself: a SELF_USERNAME surface the subject can audit.
    events.push(makeEvent({
      event_type: EVENT_TYPES.SELF_USERNAME,
      source_module: MODULE,
      data: `@${handle}`,
      confidence,
      visibility,
      // Reusing a handle across many platforms is a linkability exposure (one
      // handle ties the subject's surfaces together). Low base risk; the report
      // can escalate on spread. This is hygiene about the SELF subject, not a
      // statement about anyone else.
      risk: RISK.LOW,
      source_url: p.profileUrl,
      meta: {
        platform: p.platform,
        method: p.method,
        http_status: p.httpStatus,
        // Hoisted handle so cluster-keys.js can co-occur this surface with the
        // subject's other handle/profile events via the SAME normalized key.
        handle,
        note: 'Public account presence for a self-owned handle; surface to review/lock down.',
      },
    }));

    // If the platform gave a canonical profile URL, also record it as a concrete
    // SELF_PROFILE_URL surface (a thing the subject can edit/delete/de-index).
    if (p.profileUrl) {
      events.push(makeEvent({
        event_type: EVENT_TYPES.SELF_PROFILE_URL,
        source_module: MODULE,
        data: p.profileUrl,
        confidence,
        visibility,
        risk: RISK.LOW,
        source_url: p.profileUrl,
        meta: { platform: p.platform, handle, note: 'Self-owned profile surface.' },
      }));
    }
  }

  return events;
}

module.exports = {
  MODULE,
  ALLOWED_SCOPES,
  METHOD_CONFIDENCE,
  normalizeProbe,
  detectUsernameAccounts,
};
