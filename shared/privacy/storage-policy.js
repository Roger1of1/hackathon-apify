/**
 * shared/privacy/storage-policy.js
 *
 * BROWSER-ONLY / ZERO-SERVER-STORAGE contract for MirrorTrace's self-exposure
 * report (the "Part 2" exposure map / correlation dossier).
 *
 * WHY THIS MODULE EXISTS — THE NO-HONEYPOT RATIONALE
 * ─────────────────────────────────────────────────────────────────────────────
 * MirrorTrace audits a user's OWN public footprint and then CORRELATES it into a
 * single picture (center = you, surrounding nodes = each site that exposes you,
 * cross-edges where two sites share the same email/handle). That correlated view
 * is, by construction, the single most sensitive artifact in the product: a
 * pre-assembled dossier on a real person. If we ever stored it on a server, our
 * backend would become EXACTLY the centralized "second data-leak site" the
 * product is meant to fight — a honeypot whose breach would re-expose every user
 * we tried to protect. The privacy-preserving move is therefore to NOT hold it
 * at all: the correlated report lives ONLY transiently in the user's own browser,
 * is never persisted to a server, and is purged when the tab closes.
 *
 * This mirrors two proven patterns we cite throughout the codebase:
 *   - HIBP k-anonymity (Troy Hunt, "Understanding HIBP's Use of SHA-1 and
 *     k-Anonymity"): the most sensitive matching happens CLIENT-SIDE; the secret
 *     (or here, the assembled dossier) never has to leave the user's device for
 *     the feature to work. We extend that principle from "don't send the secret"
 *     to "don't STORE the assembled exposure picture server-side at all."
 *   - The Markup's Blacklight: a privacy INSPECTOR shows you what others can see;
 *     it must not itself become a new collector of what it inspected.
 *
 * WHAT THIS MODULE IS
 * ─────────────────────────────────────────────────────────────────────────────
 * Pure policy: the constants describing the ONLY places exposure data may live,
 * an explicit purge contract, and `assertNoServerPersistence(plan)` — a guard
 * the web/front-end (and any reviewer) can run over a data-handling plan to flag
 * any attempt to localStorage-persist findings or POST/upload them off-device.
 * It performs NO storage itself and touches NO browser globals, so it is unit-
 * testable under plain Node. The front-end calls these to PROVE its plan is clean
 * before it ever touches the assembled report.
 *
 * RED LINE: this is about where the SELF subject's OWN footprint may live. It
 * carries no person/romance/intimacy/location semantics — only a storage tier.
 *
 * Pure functions, no network, no mutation of inputs. Safe to require at load.
 */

'use strict';

/**
 * The ONLY storage locations exposure/correlation data may inhabit, plus the
 * forbidden ones. `ephemeral: true` means "must not survive tab close".
 */
const STORAGE_LOCATIONS = Object.freeze({
  /** Held only in JS variables / component state. Gone on navigation/close. */
  IN_MEMORY: 'in_memory',
  /** Browser sessionStorage — scoped to the tab, cleared on tab close. */
  SESSION_STORAGE: 'session_storage',
  /** Browser localStorage — PERSISTS across sessions. FORBIDDEN for findings. */
  LOCAL_STORAGE: 'local_storage',
  /** IndexedDB — persists across sessions. FORBIDDEN for findings. */
  INDEXED_DB: 'indexed_db',
  /** Any server: POST/PUT/upload, DB row, log line, analytics. FORBIDDEN. */
  SERVER: 'server',
});

/** Locations exposure findings are ALLOWED to live in (both ephemeral). */
const ALLOWED_LOCATIONS = Object.freeze([
  STORAGE_LOCATIONS.IN_MEMORY,
  STORAGE_LOCATIONS.SESSION_STORAGE,
]);

/**
 * Locations that PERSIST exposure data beyond the session or move it off the
 * user's device. Any of these in a plan is a hard violation.
 */
const PERSISTENT_OR_SERVER_LOCATIONS = Object.freeze([
  STORAGE_LOCATIONS.LOCAL_STORAGE,
  STORAGE_LOCATIONS.INDEXED_DB,
  STORAGE_LOCATIONS.SERVER,
]);

/**
 * Network actions that would move findings off-device. The plan validator flags
 * any `transmit` of findings using one of these verbs.
 */
const OFF_DEVICE_TRANSPORTS = Object.freeze(['POST', 'PUT', 'PATCH', 'upload', 'beacon']);

/**
 * Human-readable per-location rationale, so a reviewer (or the UI's "why is my
 * data safe?" affordance) can explain every verdict honestly.
 */
const LOCATION_RATIONALE = Object.freeze({
  [STORAGE_LOCATIONS.IN_MEMORY]:
    'Held only in page memory; vanishes on navigation/close. No persistence, no server copy.',
  [STORAGE_LOCATIONS.SESSION_STORAGE]:
    'Tab-scoped sessionStorage; the browser clears it on tab close. Ephemeral by design.',
  [STORAGE_LOCATIONS.LOCAL_STORAGE]:
    'FORBIDDEN: localStorage survives tab close and browser restart — it would persist a ' +
    'standing dossier on disk. Use sessionStorage or memory instead.',
  [STORAGE_LOCATIONS.INDEXED_DB]:
    'FORBIDDEN: IndexedDB is durable client storage; an assembled exposure report must not ' +
    'be retained across sessions.',
  [STORAGE_LOCATIONS.SERVER]:
    'FORBIDDEN: sending findings to any server creates a centralized honeypot — the exact ' +
    '"second data-leak site" this product exists to avoid.',
});

/**
 * The PURGE contract the front-end must honor. These are the triggers on which
 * the in-browser report MUST be destroyed; describing them as data lets the UI
 * and the tests assert the contract without this module touching the DOM.
 */
const PURGE_CONTRACT = Object.freeze({
  /** Events that MUST clear every in-memory + sessionStorage finding. */
  triggers: Object.freeze([
    'tab_close',        // pagehide / beforeunload
    'session_end',      // sessionStorage auto-clears; we also null memory refs
    'explicit_purge',   // user taps "清除 / Purge now"
    'new_subject',      // switching audited subject discards the prior dossier
  ]),
  /** sessionStorage clears itself on tab close; we still must null in-memory refs. */
  mustNullInMemoryRefs: true,
  /** Nothing may be written anywhere that would survive `tab_close`. */
  survivesTabClose: false,
});

function isExposureLocationAllowed(location) {
  return ALLOWED_LOCATIONS.includes(location);
}

/**
 * Guard a data-handling PLAN for the exposure report.
 *
 * A `plan` describes what the front-end intends to do with findings:
 *   {
 *     storage:  [ '<location>' , ... ],           // where findings will be kept
 *     transmits: [ { kind, method, includesFindings } , ... ]  // network calls
 *     persistsExposureFindings?: boolean,         // optional explicit flag
 *   }
 *
 * Returns { ok, violations: [{ code, location?, detail }] }. It NEVER throws on a
 * bad plan — it REPORTS — so a reviewer can see every problem at once; callers
 * that want fail-fast can check `ok`. (Despite the name, we collect rather than
 * throw, matching the repo's validator style; the `assert` prefix marks it as the
 * authoritative gate the UI must pass before handling the dossier.)
 *
 * @param {object} plan
 * @returns {{ ok: boolean, violations: Array<{code:string, location?:string, detail:string}> }}
 */
function assertNoServerPersistence(plan) {
  const violations = [];

  if (!plan || typeof plan !== 'object') {
    return {
      ok: false,
      violations: [{ code: 'invalid_plan', detail: 'plan must be a non-null object' }],
    };
  }

  // 1) Storage locations: only the two ephemeral ones are allowed.
  const storage = Array.isArray(plan.storage) ? plan.storage : [];
  for (const loc of storage) {
    if (!isExposureLocationAllowed(loc)) {
      const known = Object.values(STORAGE_LOCATIONS).includes(loc);
      violations.push({
        code: PERSISTENT_OR_SERVER_LOCATIONS.includes(loc)
          ? (loc === STORAGE_LOCATIONS.SERVER ? 'server_storage' : 'persistent_client_storage')
          : 'unknown_storage_location',
        location: loc,
        detail: known
          ? (LOCATION_RATIONALE[loc] || 'forbidden storage location')
          : `unrecognized storage location "${loc}" — not on the allow-list`,
      });
    }
  }

  // 2) Transmissions: no network call may carry findings off-device.
  const transmits = Array.isArray(plan.transmits) ? plan.transmits : [];
  for (const tx of transmits) {
    if (!tx || typeof tx !== 'object') continue;
    if (tx.includesFindings) {
      const method = typeof tx.method === 'string' ? tx.method : '';
      violations.push({
        code: 'off_device_transmission',
        detail:
          `network "${tx.kind || method || 'request'}" would carry exposure findings off-device` +
          (OFF_DEVICE_TRANSPORTS.includes(method) ? ` (${method})` : '') +
          ' — findings must never leave the browser. ' + LOCATION_RATIONALE[STORAGE_LOCATIONS.SERVER],
      });
    }
  }

  // 3) Explicit self-declared persistence flag, if present.
  if (plan.persistsExposureFindings === true) {
    violations.push({
      code: 'declared_persistence',
      detail: 'plan declares persistsExposureFindings:true — the report must be ephemeral',
    });
  }

  return { ok: violations.length === 0, violations };
}

module.exports = {
  STORAGE_LOCATIONS,
  ALLOWED_LOCATIONS,
  PERSISTENT_OR_SERVER_LOCATIONS,
  OFF_DEVICE_TRANSPORTS,
  LOCATION_RATIONALE,
  PURGE_CONTRACT,
  isExposureLocationAllowed,
  assertNoServerPersistence,
};
