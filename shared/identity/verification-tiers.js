/**
 * shared/identity/verification-tiers.js
 *
 * TIERED identity-verification POLICY for MirrorTrace.
 *
 * THE PROBLEM THIS SOLVES
 * ─────────────────────────────────────────────────────────────────────────────
 * MirrorTrace audits your OWN footprint — the opposite of a people-search engine.
 * The risk is that a "look up your name" tool can be abused to look up SOMEONE
 * ELSE. We mitigate that by gating actions on identity verification IN PROPORTION
 * to how sensitive the action is — not a blanket login wall (which would block
 * harmless self-proving use), and not an open door (which would let it become a
 * lookup engine for strangers).
 *
 * TWO TIERS:
 *   'none'    — self-proving / low-sensitivity. The action either reveals only
 *               already-public, name-scoped results, or REQUIRES the user to
 *               already possess the secret (so it proves self-ownership by
 *               construction). No sign-in needed.
 *   'sign_in' — sensitive. The action PULLS the subject's PII together, CORRELATES
 *               it into the dossier/graph, confirms broker listings, or sets up
 *               ongoing monitoring. These require ONE-CLICK OAuth sign-in
 *               (Google/GitHub) that returns a verified email/handle, so the
 *               correlated identifiers are PROVABLY the signed-in user's own.
 *
 * WHY SELF-PROVING ACTIONS NEED NO SIGN-IN — k-ANONYMITY MODEL (HIBP)
 * ─────────────────────────────────────────────────────────────────────────────
 * Have I Been Pwned's breach/password check is the canonical "self-proving"
 * action: you submit a hash prefix of a secret you ALREADY KNOW (Troy Hunt,
 * "Understanding HIBP's Use of SHA-1 and k-Anonymity"). The check is meaningful
 * only to someone who holds the secret, so it cannot be weaponized to profile a
 * stranger — and therefore needs no account. 'kanon_breach_check' inherits that
 * property exactly. 'public_search' is 'none' for a different reason: it returns
 * only name-scoped PUBLIC results (already gated by shared/scope.js's self/
 * public_figure rules), revealing nothing a plain search engine wouldn't.
 *
 * WHY THE SIGN-IN IS BROWSER-ONLY OAuth 2.0 PKCE (no server secret)
 * ─────────────────────────────────────────────────────────────────────────────
 * The sensitive tier needs to verify "this email/handle is really yours" WITHOUT
 * us running a confidential backend (which would also reintroduce a server that
 * could store the dossier — see shared/privacy/storage-policy.js). OAuth 2.0
 * Authorization Code flow with PKCE (RFC 7636) is the public-client pattern built
 * for exactly this: a browser app proves possession of a one-time code_verifier
 * instead of a client_secret, so there is NO secret to host and no server to
 * trust with the user's tokens. The verified email/handle returned by the
 * provider becomes the trusted identifier we correlate against — entirely client
 * side, consistent with the zero-server-storage model.
 *
 * SCOPE — POLICY ONLY:
 * This module decides WHETHER an action needs sign-in and WHY. It performs NO
 * OAuth, mints no tokens, and asserts no one is signed in. Real OAuth wiring is
 * the LAST integration step (like the Apify account) and is explicitly
 * NOT-YET-WIRED here. The front-end MUST NOT fabricate a successful sign-in;
 * `isVerificationSatisfied` only ever returns true for the 'none' tier or when a
 * REAL verified identity object is supplied by a future live integration.
 *
 * RED LINE: tiers gate ONLY actions on the SELF subject's own footprint. There is
 * no tier, key, or branch here that profiles another person, relationship,
 * gender, or location.
 *
 * Pure functions, no network, no mutation of inputs. Safe to require at load.
 */

'use strict';

/** The two verification tiers. */
const VERIFICATION = Object.freeze({
  NONE: 'none',
  SIGN_IN: 'sign_in',
});

/**
 * The canonical action keys the front-end passes to `requiredVerification`,
 * each with its tier and an honest rationale. This is the single source of truth
 * for the gate UX.
 */
const ACTION_POLICY = Object.freeze({
  // ── Self-proving / low-sensitivity → 'none' ────────────────────────────────
  public_search: Object.freeze({
    tier: VERIFICATION.NONE,
    sensitive: false,
    rationale:
      'Returns only name-scoped PUBLIC results already permitted by shared/scope.js ' +
      '(self/public_figure). Reveals nothing a plain web search would not; no account needed.',
  }),
  kanon_breach_check: Object.freeze({
    tier: VERIFICATION.NONE,
    sensitive: false,
    rationale:
      'HIBP-style k-anonymity self-proving check: meaningful only to someone who ALREADY ' +
      'holds the secret, so it cannot profile a stranger. No sign-in required (RFC: HIBP ' +
      'SHA-1 + k-anonymity range model).',
  }),

  // ── Sensitive → 'sign_in' (OAuth 2.0 PKCE, browser-only) ───────────────────
  pull_pii: Object.freeze({
    tier: VERIFICATION.SIGN_IN,
    sensitive: true,
    rationale:
      'Pulling the subject\'s PII together is high-sensitivity. A verified email/handle ' +
      '(via OAuth 2.0 PKCE) proves the PII being assembled is the signed-in user\'s own, ' +
      'preventing use against a third party.',
  }),
  build_correlation_graph: Object.freeze({
    tier: VERIFICATION.SIGN_IN,
    sensitive: true,
    rationale:
      'Cross-source correlation produces a pre-assembled dossier — the product\'s most ' +
      'sensitive artifact. Requires verified ownership of the correlated identifiers via ' +
      'one-click OAuth sign-in before any linking happens.',
  }),
  confirm_broker_listing: Object.freeze({
    tier: VERIFICATION.SIGN_IN,
    sensitive: true,
    rationale:
      'Confirming a data-broker listing as yours ties a real-world record to the subject; ' +
      'gated behind a verified identity so it cannot confirm listings for someone else.',
  }),
  enable_monitoring: Object.freeze({
    tier: VERIFICATION.SIGN_IN,
    sensitive: true,
    rationale:
      'Ongoing monitoring is a standing capability over a subject\'s footprint; it must be ' +
      'bound to a verified account so only the verified self subject can be monitored.',
  }),
});

/** All recognized action keys (handy for the UI and tests). */
const ACTIONS = Object.freeze(Object.keys(ACTION_POLICY));

/**
 * Fallback for an UNKNOWN action: fail CLOSED to the stricter tier. An action we
 * have not classified must not slip through as 'none'.
 */
const UNKNOWN_ACTION_POLICY = Object.freeze({
  tier: VERIFICATION.SIGN_IN,
  sensitive: true,
  rationale:
    'Unrecognized action — failing closed to sign_in. Add an explicit entry to ACTION_POLICY ' +
    'before exposing this action; never default sensitive flows to "none".',
});

/**
 * THE primary API: which verification tier does this action require?
 * @param {string} action  one of ACTIONS
 * @returns {'none'|'sign_in'}
 */
function requiredVerification(action) {
  const policy = ACTION_POLICY[action];
  return policy ? policy.tier : UNKNOWN_ACTION_POLICY.tier;
}

/**
 * Full policy entry (tier + sensitive + rationale) for an action, for the gate UX
 * to explain WHY a sign-in is (or isn't) needed. Unknown → fail-closed entry.
 * @param {string} action
 * @returns {{tier:string, sensitive:boolean, rationale:string, known:boolean}}
 */
function verificationPolicyFor(action) {
  const policy = ACTION_POLICY[action];
  if (policy) return Object.freeze({ ...policy, known: true });
  return Object.freeze({ ...UNKNOWN_ACTION_POLICY, known: false });
}

/**
 * Is the verification requirement for `action` satisfied by `identity`?
 *
 * - 'none'   tier → always satisfied (no account needed).
 * - 'sign_in' tier → satisfied ONLY by a REAL verified identity object:
 *      { verified: true, email?: string, handle?: string, provider: 'google'|'github' }
 *   with at least one of email/handle present. This NEVER fabricates a sign-in:
 *   absent a real verified identity it returns false. The live OAuth integration
 *   that produces this object is NOT-YET-WIRED (last step).
 *
 * @param {string} action
 * @param {object|null} identity
 * @returns {{ ok:boolean, tier:string, reason:string }}
 */
function isVerificationSatisfied(action, identity) {
  const tier = requiredVerification(action);
  if (tier === VERIFICATION.NONE) {
    return { ok: true, tier, reason: 'self-proving / low-sensitivity action requires no sign-in' };
  }
  const hasId =
    identity &&
    typeof identity === 'object' &&
    identity.verified === true &&
    (typeof identity.email === 'string' && identity.email.length > 0 ||
      typeof identity.handle === 'string' && identity.handle.length > 0);
  if (hasId) {
    return { ok: true, tier, reason: 'verified identity present (OAuth-provided email/handle)' };
  }
  return {
    ok: false,
    tier,
    reason:
      'sensitive action requires sign_in; no real verified identity supplied. ' +
      'Live OAuth 2.0 PKCE sign-in is NOT-YET-WIRED — do not fabricate a sign-in.',
  };
}

module.exports = {
  VERIFICATION,
  ACTION_POLICY,
  ACTIONS,
  UNKNOWN_ACTION_POLICY,
  requiredVerification,
  verificationPolicyFor,
  isVerificationSatisfied,
};
