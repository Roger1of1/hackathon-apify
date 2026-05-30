/**
 * shared/aux/github-leak-finding.js
 *
 * Helpers for the AUX "Public GitHub Leak Scan" actor. They turn raw public
 * GitHub artifacts (a profile, a repo the subject controls, the text of a file
 * the subject committed publicly) into TYPED module_events from the frozen
 * shared/detectors vocabulary, so the SpiderFoot-style correlation engine
 * (shared/correlation.js) can cluster a leaked key found on GitHub with the same
 * key found elsewhere — keyed on host / handle / secret fingerprint, NEVER on a
 * person.
 *
 * Why this lives in shared/aux (not in the actor): the actor does network I/O
 * (Apify SDK), but the *shaping* of findings is pure, deterministic, and
 * unit-testable here with no network — the same split breach-check uses
 * (shared/aux/breach-finding.js).
 *
 * COMPLIANCE / RED LINES baked in:
 *  - We only ever describe what the SELF (or public_figure) subject has THEMSELF
 *    published on accounts/repos THEY control. We emit SELF_USERNAME,
 *    SELF_PROFILE_URL and (via the shared secret detector) SECRET_LEAK_PUBLIC —
 *    all "audit your own footprint" event types. There is deliberately NO event
 *    type here for another person, a relationship, gender, intimacy, or location
 *    tracking — the enum in event-types.js forbids them by construction, and
 *    makeEvent throws on anything outside it.
 *  - Secrets are NEVER echoed: the secret detector redacts to a fingerprint +
 *    masked hint before an event is created.
 *  - NO FAKE DATA: every event here is constructed only from a real artifact the
 *    actor actually fetched. Empty input => empty output (see selftest).
 *
 * Reference patterns applied:
 *  - SpiderFoot module/event model: a named module emits typed events with
 *    provenance + honest confidence; correlation links them later.
 *    github.com/smicallef/spiderfoot
 *  - GitHub secret-scanning / TruffleHog / gitleaks "scan public repos & gists
 *    for committed credentials", reframed as a SELF-audit (find *my own* leaked
 *    key so I can rotate it), not third-party surveillance.
 *    docs.github.com (secret-scanning), github.com/trufflesecurity/trufflehog
 *
 * Pure functions, no network, no side effects. Safe to require at load.
 */

'use strict';

const {
  EVENT_TYPES,
  VISIBILITY,
  RISK,
  makeEvent,
} = require('../detectors/event-types.js');
const { detectSecrets } = require('../detectors/secret-leak-detector.js');

const MODULE = 'aux:gh-leak-scan';

/**
 * SELF_USERNAME event for a GitHub handle the subject says is theirs (input),
 * confirmed to resolve to a real public profile by the actor.
 *
 * @param {object} p
 * @param {string} p.handle      the GitHub login (bare, no '@')
 * @param {string} p.profileUrl  https://github.com/<handle>
 * @returns {object} module_event
 */
function makeUsernameEvent({ handle, profileUrl }) {
  const bare = typeof handle === 'string' ? handle.trim().replace(/^@+/, '') : '';
  return makeEvent({
    event_type: EVENT_TYPES.SELF_USERNAME,
    source_module: MODULE,
    data: bare ? `@${bare}` : null,
    // A confirmed, resolvable public handle is a certain fact about the surface.
    confidence: 1,
    visibility: VISIBILITY.INDEXED, // GitHub profiles are search-indexable
    risk: RISK.INFO,
    source_url: typeof profileUrl === 'string' ? profileUrl : null,
    // meta.handle lets cluster-keys.js mint a stable handle:<...> key.
    meta: { handle: bare, platform: 'github' },
  });
}

/**
 * SELF_PROFILE_URL event for a public repository / gist the subject controls.
 *
 * @param {object} p
 * @param {string} p.handle    owner login
 * @param {string} p.repoUrl   html_url of the repo/gist
 * @param {string} [p.name]    repo full_name (owner/name) for display
 * @param {string} [p.kind]    'repo' | 'gist'
 * @returns {object} module_event
 */
function makeRepoSurfaceEvent({ handle, repoUrl, name, kind }) {
  const bare = typeof handle === 'string' ? handle.trim().replace(/^@+/, '') : '';
  return makeEvent({
    event_type: EVENT_TYPES.SELF_PROFILE_URL,
    source_module: MODULE,
    data: typeof repoUrl === 'string' ? repoUrl : null,
    confidence: 1,
    visibility: VISIBILITY.INDEXED,
    risk: RISK.INFO,
    source_url: typeof repoUrl === 'string' ? repoUrl : null,
    meta: {
      handle: bare,
      platform: 'github',
      surface_kind: kind === 'gist' ? 'gist' : 'repo',
      name: typeof name === 'string' ? name : null,
    },
  });
}

/**
 * Run the SHARED secret detector over one fetched public file and return its
 * SECRET_LEAK_PUBLIC events, tagged with GitHub provenance in meta. We do NOT
 * reinvent secret detection — we reuse shared/detectors/secret-leak-detector.js
 * so there is one honest, entropy-gated, redacting implementation.
 *
 * @param {object} p
 * @param {string} p.text       the file's raw text (already fetched by the actor)
 * @param {string} p.fileUrl    public html/raw URL of the file
 * @param {string} [p.handle]   owner login (for clustering)
 * @param {string} [p.repoName] owner/name for display
 * @returns {object[]} module_event[] (possibly empty — empty means no leak)
 */
function scanFileForSecrets({ text, fileUrl, handle, repoName }) {
  const events = detectSecrets({
    text: typeof text === 'string' ? text : '',
    url: typeof fileUrl === 'string' ? fileUrl : null,
    // A file committed to a public repo is search-indexable.
    visibility: VISIBILITY.INDEXED,
  });
  const bare = typeof handle === 'string' ? handle.trim().replace(/^@+/, '') : '';
  // Annotate provenance without mutating the detector's redaction contract.
  for (const ev of events) {
    ev.meta = Object.assign({}, ev.meta, {
      handle: bare || (ev.meta && ev.meta.handle) || null,
      platform: 'github',
      repo: typeof repoName === 'string' ? repoName : null,
    });
  }
  return events;
}

/**
 * EXPOSURE_SUMMARY event summarising one scan run. Counts are real (derived from
 * the events actually produced); this never asserts a leak by itself.
 *
 * @param {object} p
 * @param {string} p.handle
 * @param {object} p.counts  { repos_scanned, files_scanned, secrets_found }
 * @returns {object} module_event
 */
function makeSummaryEvent({ handle, counts }) {
  const bare = typeof handle === 'string' ? handle.trim().replace(/^@+/, '') : '';
  const c = counts && typeof counts === 'object' ? counts : {};
  const secrets = Number.isFinite(c.secrets_found) ? c.secrets_found : 0;
  return makeEvent({
    event_type: EVENT_TYPES.EXPOSURE_SUMMARY,
    source_module: MODULE,
    data: {
      platform: 'github',
      handle: bare || null,
      repos_scanned: Number.isFinite(c.repos_scanned) ? c.repos_scanned : 0,
      files_scanned: Number.isFinite(c.files_scanned) ? c.files_scanned : 0,
      secrets_found: secrets,
    },
    confidence: 1,
    visibility: VISIBILITY.INDEXED,
    // A summary's risk tracks whether anything was actually found.
    risk: secrets > 0 ? RISK.HIGH : RISK.INFO,
    source_url: bare ? `https://github.com/${bare}` : null,
    meta: { handle: bare, platform: 'github' },
  });
}

module.exports = {
  MODULE,
  makeUsernameEvent,
  makeRepoSurfaceEvent,
  scanFileForSecrets,
  makeSummaryEvent,
};
