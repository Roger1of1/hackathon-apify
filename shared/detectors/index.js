/**
 * shared/detectors/index.js
 *
 * Detector REGISTRY + dispatcher, modelled on SpiderFoot's module manager:
 * SpiderFoot keeps a set of modules, each declaring the event types it consumes
 * and produces, and the engine feeds each module only the inputs it watches.
 * We do the lightweight equivalent: every detector declares `consumes` (the
 * kind of captured artifact it reads) and `produces` (the EVENT_TYPES it can
 * emit). `runDetectors` dispatches a batch of captured artifacts to the matching
 * modules and returns a flat, typed module_event[] ready for the correlation
 * engine (shared/correlation.js, a sibling track) and shared/scoring.js.
 *
 * Ref: SpiderFoot modular event-driven engine — github.com/smicallef/spiderfoot
 *
 * No network, no state beyond the frozen registry. Safe to require at load.
 */

'use strict';

const { EVENT_TYPES, RISK_RANK, VISIBILITY_RANK, makeEvent } = require('./event-types.js');
const pii = require('./pii-detector.js');
const tracker = require('./tracker-detector.js');
const breach = require('./breach-range-detector.js');
const secret = require('./secret-leak-detector.js');
const userenum = require('./username-enum-detector.js');

/**
 * Artifact "kinds" a detector consumes. The crawler tags each captured artifact
 * with one of these so dispatch is explicit (no guessing).
 */
const ARTIFACT_KINDS = Object.freeze({
  PAGE_TEXT: 'page_text',         // normalized visible text of a captured page
  PAGE_RESOURCES: 'page_resources', // scripts/cookies/js_api_calls/links of a page
  BREACH_RANGE: 'breach_range',   // a precomputed k-anon range result for a self credential
  USERNAME_PROBES: 'username_probes', // upstream-collected handle-presence probes (scope-gated)
});

/**
 * The registry. Each entry is a SpiderFoot-style module descriptor.
 */
const REGISTRY = Object.freeze([
  {
    name: pii.MODULE,
    consumes: ARTIFACT_KINDS.PAGE_TEXT,
    produces: [
      EVENT_TYPES.PII_EMAIL_PUBLIC,
      EVENT_TYPES.PII_PHONE_PUBLIC,
      EVENT_TYPES.PII_HANDLE_PUBLIC,
      EVENT_TYPES.PII_GEO_HINT_PUBLIC,
      EVENT_TYPES.PII_POSTAL_PUBLIC,
    ],
    run: (artifact) => pii.detectPii(artifact),
  },
  {
    // Secret-scanning module (TruffleHog/gitleaks-style) over the SAME captured
    // page text the PII module reads. Multiple modules can consume one artifact
    // kind, exactly like SpiderFoot fans an event out to every interested module.
    name: secret.MODULE,
    consumes: ARTIFACT_KINDS.PAGE_TEXT,
    produces: [EVENT_TYPES.SECRET_LEAK_PUBLIC],
    run: (artifact) => secret.detectSecrets(artifact),
  },
  {
    name: tracker.MODULE,
    consumes: ARTIFACT_KINDS.PAGE_RESOURCES,
    produces: [
      EVENT_TYPES.TRACKER_THIRD_PARTY,
      EVENT_TYPES.TRACKER_SESSION_RECORDING,
      EVENT_TYPES.TRACKER_FINGERPRINTING,
      EVENT_TYPES.TRACKER_KEYLOGGING,
      EVENT_TYPES.COOKIE_THIRD_PARTY,
      EVENT_TYPES.LEAK_REFERRER,
    ],
    run: (artifact) => tracker.detectTrackers(artifact),
  },
  {
    name: breach.MODULE,
    consumes: ARTIFACT_KINDS.BREACH_RANGE,
    produces: [EVENT_TYPES.BREACH_RANGE_HIT],
    run: (artifact) => breach.detectBreachInRange(artifact),
  },
  {
    // Username-enumeration module (SpiderFoot sfp_accounts / Sherlock-style).
    // DUAL-USE: it self-refuses unless artifact.scope_type is self|public_figure,
    // so dispatching it for any other scope yields zero events — the technique is
    // available only through the gate, exactly as the red lines require.
    name: userenum.MODULE,
    consumes: ARTIFACT_KINDS.USERNAME_PROBES,
    produces: [EVENT_TYPES.SELF_USERNAME, EVENT_TYPES.SELF_PROFILE_URL],
    run: (artifact) => userenum.detectUsernameAccounts(artifact),
  },
]);

const BY_KIND = (() => {
  const map = new Map();
  for (const mod of REGISTRY) {
    if (!map.has(mod.consumes)) map.set(mod.consumes, []);
    map.get(mod.consumes).push(mod);
  }
  return map;
})();

/**
 * Dispatch a batch of captured artifacts to the matching detector modules.
 *
 * @param {Array<{kind:string, [k:string]:any}>} artifacts  each tagged with a `kind`
 * @returns {{ events: object[], by_module: Record<string, number>, skipped: number }}
 */
function runDetectors(artifacts = []) {
  const events = [];
  const by_module = {};
  let skipped = 0;

  if (!Array.isArray(artifacts)) return { events, by_module, skipped };

  for (const artifact of artifacts) {
    const kind = artifact && artifact.kind;
    const mods = BY_KIND.get(kind);
    if (!mods) { skipped += 1; continue; }
    for (const mod of mods) {
      const out = mod.run(artifact) || [];
      for (const ev of out) {
        events.push(ev);
        by_module[mod.name] = (by_module[mod.name] || 0) + 1;
      }
    }
  }

  return { events, by_module, skipped };
}

/**
 * Reduce a module_event[] into the crawl-summary shape that the EXISTING
 * shared/scoring.js `exposureScore` consumes ({reachablePages, distinctHosts,
 * indexablePages}). We do NOT reimplement scoring — we feed the canonical one.
 * "indexable" maps to events whose visibility is `indexed` (trivially
 * discoverable), exactly the Blacklight framing.
 *
 * @param {object[]} events module_event[]
 * @returns {{reachablePages:number, distinctHosts:number, indexablePages:number}}
 */
function summarizeForExposure(events = []) {
  const urls = new Set();
  const hosts = new Set();
  let indexable = 0;
  for (const ev of events) {
    if (!ev || ev.record_type !== 'module_event') continue;
    if (ev.source_url) {
      urls.add(ev.source_url);
      try { hosts.add(new URL(ev.source_url).hostname.toLowerCase()); } catch { /* skip */ }
    }
    if (ev.visibility === 'indexed') indexable += 1;
  }
  return {
    reachablePages: urls.size,
    distinctHosts: hosts.size,
    indexablePages: indexable,
  };
}

/**
 * Highest-severity-first ordering helper for the Blacklight-style inspector
 * panel: sort by risk, then visibility, then confidence.
 */
function rankEvents(events = []) {
  return [...events].filter((e) => e && e.record_type === 'module_event').sort((a, b) => {
    const r = (RISK_RANK[b.risk] || 0) - (RISK_RANK[a.risk] || 0);
    if (r) return r;
    const v = (VISIBILITY_RANK[b.visibility] || 0) - (VISIBILITY_RANK[a.visibility] || 0);
    if (v) return v;
    return (b.confidence || 0) - (a.confidence || 0);
  });
}

module.exports = {
  ARTIFACT_KINDS,
  REGISTRY,
  runDetectors,
  summarizeForExposure,
  rankEvents,
  makeEvent, // re-export for convenience
  EVENT_TYPES,
};
