/**
 * integrations/schedules/cadence-policy.js
 *
 * Pure, dependency-free policy engine that turns a requested re-audit *cadence*
 * into a validated Apify schedule (a 5-field cron expression) — or refuses it.
 *
 * WHY THIS EXISTS (product framing)
 * ---------------------------------
 * Ex-Ditector's "Closure Mode" exists to REDUCE compulsive checking. A scheduled
 * re-audit is the healthy alternative to a human refreshing a page 40x/day: the
 * platform does one paced, low-frequency sweep and the person gets a single
 * digest. So the scheduler's job is not "run as often as possible" — it is to
 * ENFORCE A FLOOR on how often a footprint may be re-audited. The more distress
 * a person is in (higher distress_risk), the SLOWER we schedule, never faster.
 * This is the opposite of a stalking tool, encoded in cron.
 *
 * REFERENCE ARCHITECTURE #1 — Scrapy/Crawlee pipeline + middleware ordering.
 * Scrapy runs every item through an ordered chain of components and lets any
 * stage DROP the item (raise DropItem) so it never reaches persistence; spider-
 * /downloader-middleware are sorted by a numeric `order` and run as a fixed,
 * declarative chain (https://docs.scrapy.org/en/latest/topics/architecture.html,
 * https://docs.scrapy.org/en/latest/topics/spider-middleware.html). We mirror
 * that: `evaluateCadence()` is an ordered pipeline of guard stages
 * (scope-gate -> known-cadence -> distress floor -> compliance floor -> cron
 * build); the FIRST stage that objects DROPS the schedule (returns {allowed:false})
 * and nothing downstream — not even cron generation — runs. Fail-closed, like a
 * middleware short-circuit.
 *
 * REFERENCE ARCHITECTURE #2 — Have I Been Pwned k-anonymity range query.
 * HIBP never accepts a full secret: the client sends only the first 5 chars of a
 * SHA-1 hash and matching is finished locally, so the service learns the minimum
 * (https://www.troyhunt.com/understanding-have-i-been-pwneds-use-of-sha-1-and-k-anonymity/).
 * We borrow the "carry the minimum identifying token, never the identity" stance
 * for schedule NAMING: a schedule is named after the run's k-anonymous
 * `subject_token` (e.g. a 5-char hash prefix the operator supplies) — never an
 * email, handle, or person's name. A schedule should not be a dossier label.
 *
 * SCOPE — this file is pure logic only. It does NOT import shared/scope.js
 * (owned elsewhere); it re-states the SAME allow-list as a fail-closed local
 * constant and expects the operator's run input to ALSO pass the real
 * validateScope gate at execution time. Two doors, both must open.
 */

'use strict';

/**
 * The only scope_type values for which an AUTOMATED, recurring re-audit may be
 * scheduled. Recurring monitoring is a dual-use capability, so we restrict it to
 * the same chokepoint the rest of the product uses for dual-use techniques:
 * scope=self (your own footprint) and scope=public_figure (a genuine public
 * figure). consented/brand/safety_evidence are deliberately EXCLUDED here:
 *  - consented & brand: a one-shot or human-initiated run is appropriate; we do
 *    not auto-loop on third parties from a config file.
 *  - safety_evidence: evidence preservation is event-driven and human-reviewed,
 *    never a cron that quietly re-watches a person.
 * Mirror of shared/scope.js ALLOWED_SCOPES, narrowed for *scheduling*.
 */
const SCHEDULABLE_SCOPES = Object.freeze(['self', 'public_figure']);

/**
 * Named cadences -> minimum spacing in MINUTES. "Closure" is the slowest by
 * design; "compulsive" is intentionally absent (there is no such option).
 * Apify's own minimum schedule interval is 1 minute, but the PRODUCT minimum is
 * far slower — anti-compulsion is the whole point.
 */
const CADENCE_FLOOR_MINUTES = Object.freeze({
  closure: 7 * 24 * 60, // weekly — the recommended healthy default
  weekly: 7 * 24 * 60,
  daily: 24 * 60,
  business_daily: 24 * 60,
});

/**
 * Anti-compulsion FLOOR keyed by distress risk. The more distress, the more we
 * SLOW DOWN automated re-checking. Values are minimum minutes between runs.
 * (distress_risk_score is one of the compliant scores in shared/scoring.js.)
 */
function distressFloorMinutes(distressRiskScore) {
  const d = Number(distressRiskScore);
  if (!Number.isFinite(d)) return CADENCE_FLOOR_MINUTES.daily; // unknown -> cautious
  if (d >= 0.66) return 14 * 24 * 60; // high distress -> at most every 2 weeks
  if (d >= 0.33) return 7 * 24 * 60; // medium -> at most weekly
  return 24 * 60; // low -> at most daily
}

/** Hard platform floor: Apify schedules cannot fire more often than 1/min. */
const APIFY_MIN_INTERVAL_MINUTES = 1;

/**
 * Build a 5-field cron for a given spacing. We never generate sub-daily-noise
 * crons here; cadences are daily-or-slower so the expression is deterministic
 * and auditable (no surprise "every minute"). `anchorHourUtc`/`anchorWeekday`
 * let the operator pin WHEN within the allowed window.
 */
function buildCron(floorMinutes, opts = {}) {
  const hour = clampInt(opts.anchorHourUtc, 0, 23, 9); // default 09:00 UTC
  const minute = clampInt(opts.anchorMinuteUtc, 0, 59, 0);
  const weekday = clampInt(opts.anchorWeekday, 0, 6, 1); // default Monday

  if (floorMinutes >= 7 * 24 * 60) {
    // weekly-or-slower -> run once on the anchor weekday
    return `${minute} ${hour} * * ${weekday}`;
  }
  // daily
  return `${minute} ${hour} * * *`;
}

function clampInt(v, min, max, dflt) {
  const n = Number.parseInt(v, 10);
  if (!Number.isFinite(n)) return dflt;
  return Math.min(max, Math.max(min, n));
}

/**
 * The ordered guard pipeline. Returns:
 *   { allowed:false, reasons:[...] }                       (dropped)
 *   { allowed:true, cron, effectiveFloorMinutes, reasons } (built)
 *
 * @param {object} req
 * @param {string} req.scope_type            run scope (must be schedulable)
 * @param {string} req.cadence               one of CADENCE_FLOOR_MINUTES keys
 * @param {number} [req.distress_risk_score] 0..1 (from shared/scoring.js)
 * @param {object} [req.anchor]              { anchorHourUtc, anchorMinuteUtc, anchorWeekday }
 */
function evaluateCadence(req = {}) {
  const reasons = [];

  // STAGE 1 (scope gate / fail closed) — like a Scrapy middleware that drops.
  const scope = typeof req.scope_type === 'string' ? req.scope_type.trim() : '';
  if (!SCHEDULABLE_SCOPES.includes(scope)) {
    reasons.push(
      `scope_type "${scope || '(none)'}" may not be auto-scheduled. ` +
        `Recurring re-audit is allowed only for: ${SCHEDULABLE_SCOPES.join(', ')}.`,
    );
    return { allowed: false, reasons };
  }

  // STAGE 2 — cadence must be a known, daily-or-slower option.
  const cadence = typeof req.cadence === 'string' ? req.cadence.trim() : '';
  if (!Object.prototype.hasOwnProperty.call(CADENCE_FLOOR_MINUTES, cadence)) {
    reasons.push(
      `Unknown cadence "${cadence || '(none)'}". Allowed: ` +
        `${Object.keys(CADENCE_FLOOR_MINUTES).join(', ')}. ` +
        'There is no high-frequency option by design (Closure Mode).',
    );
    return { allowed: false, reasons };
  }
  const requestedFloor = CADENCE_FLOOR_MINUTES[cadence];

  // STAGE 3 — distress floor: take the SLOWER of requested vs distress floor.
  const distressFloor = distressFloorMinutes(req.distress_risk_score);
  let effectiveFloor = Math.max(requestedFloor, distressFloor);
  if (effectiveFloor > requestedFloor) {
    reasons.push(
      `Cadence slowed from requested ${requestedFloor} min to ${effectiveFloor} min ` +
        'because distress_risk_score is elevated (anti-compulsion floor).',
    );
  }

  // STAGE 4 — platform floor (defensive; our floors are already far above it).
  if (effectiveFloor < APIFY_MIN_INTERVAL_MINUTES) {
    effectiveFloor = APIFY_MIN_INTERVAL_MINUTES;
  }

  // STAGE 5 — build the deterministic cron (only reached if all guards passed).
  const cron = buildCron(effectiveFloor, req.anchor || {});

  return {
    allowed: true,
    cron,
    effectiveFloorMinutes: effectiveFloor,
    reasons: reasons.length ? reasons : ['cadence accepted'],
  };
}

/**
 * Derive a k-anonymous schedule NAME (HIBP stance: carry the minimum token, not
 * an identity). `subjectToken` MUST already be a non-identifying token the
 * operator chose (e.g. a 5-char hash prefix). We refuse anything that looks like
 * a raw email or a long handle, failing closed.
 */
function safeScheduleName(scope, subjectToken) {
  const t = typeof subjectToken === 'string' ? subjectToken.trim() : '';
  // Reject obvious PII: emails, or overly long tokens that could be a handle/name.
  if (!t || /@/.test(t) || t.length > 16 || !/^[A-Za-z0-9_-]+$/.test(t)) {
    throw new Error(
      'safeScheduleName: subjectToken must be a short non-identifying token ' +
        '(e.g. a 5-char hash prefix), not an email/handle/name.',
    );
  }
  if (!SCHEDULABLE_SCOPES.includes(scope)) {
    throw new Error(`safeScheduleName: scope "${scope}" is not schedulable.`);
  }
  return `ex-ditector-reaudit-${scope}-${t.toLowerCase()}`;
}

module.exports = {
  SCHEDULABLE_SCOPES,
  CADENCE_FLOOR_MINUTES,
  APIFY_MIN_INTERVAL_MINUTES,
  distressFloorMinutes,
  buildCron,
  evaluateCadence,
  safeScheduleName,
};
