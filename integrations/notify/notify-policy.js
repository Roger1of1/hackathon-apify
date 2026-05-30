/**
 * integrations/notify/notify-policy.js
 *
 * COMPLIANT NOTIFICATION DISPATCH for Slack / Make / n8n / Zapier.
 *
 * ── WHAT APIFY CAPABILITY THIS WIRES IN ─────────────────────────────────────
 * Apify's "Integrations" tab lets any actor/task fan a run event
 * (ACTOR.RUN.SUCCEEDED / FAILED / TIMED_OUT / ABORTED) out to Slack, Make.com,
 * n8n, Zapier, or a generic HTTP webhook, with a Handlebars message template
 * over the run document
 * (https://docs.apify.com/platform/integrations/slack,
 *  https://docs.apify.com/platform/integrations/zapier,
 *  https://docs.apify.com/platform/integrations/n8n,
 *  https://docs.apify.com/platform/integrations/make).
 * That is the "last mile": how an audit result LEAVES Apify and reaches a human.
 *
 * For a normal scraper you'd template `{{resource.defaultDatasetId}}` straight
 * into a Slack message with a clickable Apify Console link. For THIS product that
 * would be actively harmful in two ways:
 *
 *   1. LEAK. The run document + dataset carry raw locators (public URLs,
 *      screenshot/html storage keys, subject labels). Piping them verbatim into
 *      a Slack channel / a Zapier "email this to a friend" zap leaks more than
 *      the subject consented to.
 *
 *   2. COMPULSION. The product's core identity is CLOSURE MODE: reduce
 *      compulsive checking. A real-time "🔴 new change detected, click here"
 *      ping is a slot-machine notification — the exact dopamine loop we exist to
 *      break. A footprint notification must REASSURE ("nothing changed" / "one
 *      thing changed, it is handled"), never BAIT a click.
 *
 * So this module is the chokepoint that turns a raw Apify run event into a SAFE,
 * PACED, LINKLESS notification payload. It does this WITHOUT re-implementing any
 * policy: it REUSES (read-only require)
 *   - integrations/exports/redaction-policy.js  (TLP marking → field allow-list;
 *     raw locators are TLP:RED-only and physically cannot enter a shared band),
 *   - integrations/webhooks/output-health.js     (success != valid output; we
 *     only ever notify "ready" when the run produced real, healthy output),
 *   - integrations/schedules/cadence-policy.js   (anti-compulsion cadence floor;
 *     a higher distress_risk_score yields a SLOWER minimum gap between pings,
 *     never faster — the same floor that governs re-audit scheduling).
 *
 * REFERENCE ARCHITECTURES (assigned for this product):
 *
 *   A. Mozilla HTTP Observatory / SecurityHeaders grade reporting.
 *      Observatory does not ping you on every header change; it reports a single
 *      stable LETTER you act on, and the report SHOWS ITS WORK (named
 *      deductions) rather than nagging
 *      (https://developer.mozilla.org/en-US/observatory/docs/tests_and_scoring,
 *       https://securityheaders.com/). We mirror that: a notification carries the
 *      Self-Exposure GRADE LETTER and a count of what changed — a calm digest,
 *      not a stream of per-event alarms. The grade is the headline; the dataset
 *      stays behind the login the subject already controls.
 *
 *   B. GOV.UK Design System — notification banner & confirmation patterns.
 *      GOV.UK uses the GREEN success/notification banner to confirm "the thing
 *      you were expecting has happened" and explicitly warns to use notifications
 *      SPARINGLY because people miss (and tire of) frequent ones; reassurance and
 *      "what happens next" beat raw alerts
 *      (https://design-system.service.gov.uk/components/notification-banner/,
 *       https://design-system.service.gov.uk/patterns/confirmation-pages/).
 *      We adopt that voice: the default and most common notification this product
 *      sends is a calm "no change — nothing to do" reassurance; a change
 *      notification states plainly WHAT and WHAT-NEXT, with no clickable target.
 *
 * PURITY + NO-FAKE-DATA: this module performs NO network I/O and ships NO
 * credentials. It only SHAPES a payload from REAL inputs the caller passes
 * (a real output-health verdict + real redacted summary rows). Given nothing, it
 * returns a "dispatch:false / no real result to announce" decision — it will
 * NEVER fabricate a "your audit is ready" message for a run that did not produce
 * healthy output. The transport (actually POSTing to Slack/Make/n8n/Zapier) is a
 * thin separate client an operator wires at deploy time; it is the LAST step.
 * ─────────────────────────────────────────────────────────────────────────────
 */

'use strict';

const path = require('path');

// REUSE, never reimplement. All three are pure modules already in the repo.
const {
  redactRecord,
  isMarking,
  MARKINGS,
} = require(path.join(__dirname, '..', 'exports', 'redaction-policy.js'));
const {
  evaluateOutputHealth,
  HEALTH,
} = require(path.join(__dirname, '..', 'webhooks', 'output-health.js'));
const {
  evaluateCadence,
} = require(path.join(__dirname, '..', 'schedules', 'cadence-policy.js'));

/**
 * Destination channels this product is willing to dispatch to. These are all
 * "generic webhook / automation" sinks Apify supports natively. We do NOT model
 * SMS/push intentionally — a phone-buzz on a footprint change is the most
 * compulsion-inducing channel; a digest in a workspace/automation tool is calmer.
 */
const CHANNELS = Object.freeze(['slack', 'make', 'n8n', 'zapier', 'generic_webhook']);

/**
 * The ONLY notification kinds this product emits. Note there is no
 * "instant per-event alert" kind — by construction. Every notification is a
 * paced DIGEST whose voice is reassurance-first (GOV.UK banner pattern).
 */
const NOTIFY_KIND = Object.freeze({
  NO_CHANGE: 'no_change', // the common, calming case — "nothing changed"
  DIGEST: 'digest', // "N things changed since last check" + grade + what-next
  COMPLIANCE_STOP: 'compliance_stop', // a source asked us to stop — human review
  NOT_READY: 'not_ready', // run finished but output not healthy — do NOT announce
});

/**
 * Decision a caller can refuse on: should we dispatch at all, and if so what.
 * A `dispatch:false` decision ALWAYS carries a `reason` so refusals are auditable.
 */
function decision(fields) {
  return Object.freeze({
    dispatch: false,
    kind: null,
    channel: null,
    marking: null,
    suppressed_until: null,
    payload: null,
    reasons: [],
    ...fields,
  });
}

function isChannel(c) {
  return typeof c === 'string' && CHANNELS.includes(c);
}

/**
 * Map a run's output-health verdict + change summary onto a notification KIND.
 * This is the "what kind of message, if any" decision, separate from "are we
 * allowed to send it now" (cadence) and "what may the message contain" (marking).
 */
function classifyKind(health, changeCount) {
  if (!health) return NOTIFY_KIND.NOT_READY;
  switch (health.health) {
    case HEALTH.HEALTHY:
      // Healthy output: did anything actually change?
      return Number(changeCount) > 0 ? NOTIFY_KIND.DIGEST : NOTIFY_KIND.NO_CHANGE;
    case HEALTH.COMPLIANCE_STOP:
      return NOTIFY_KIND.COMPLIANCE_STOP;
    case HEALTH.EMPTY:
    case HEALTH.MALFORMED:
    case HEALTH.FAILED:
    case HEALTH.UNKNOWN:
    default:
      // Run did not produce a trustworthy result — we must NOT announce "ready".
      return NOTIFY_KIND.NOT_READY;
  }
}

/**
 * Anti-compulsion suppression: even when there IS something to say, we will not
 * say it more often than the distress-aware cadence floor allows. We REUSE the
 * exact same floor that governs re-audit scheduling, so notifications and
 * re-audits breathe at the same calm rhythm. Returns { allowed, suppressed_until,
 * floor_minutes, reason }.
 *
 * @param {object} opts
 * @param {string} [opts.scope_type]            for the cadence policy's own gate
 * @param {string} [opts.cadence]               named cadence (default 'closure' = weekly)
 * @param {number} [opts.distress_risk_score]   0..1 (from shared/scoring.js)
 * @param {string} [opts.last_notified_at]      ISO timestamp of the previous send
 * @param {Date}   [opts.now]                   injectable clock (default Date.now)
 */
function suppressionGate(opts = {}) {
  const now = opts.now instanceof Date ? opts.now : new Date();
  const cadence = evaluateCadence({
    scope_type: opts.scope_type,
    // Default to the SLOWEST healthy cadence ('closure' = weekly). A caller may
    // pass a faster named cadence, but the distress floor below can only SLOW it.
    cadence: typeof opts.cadence === 'string' && opts.cadence.trim() ? opts.cadence.trim() : 'closure',
    distress_risk_score: opts.distress_risk_score,
  });

  // If the cadence policy refused (e.g. non-schedulable scope, bad input), we do
  // NOT invent a floor. Fail closed: no allowed cadence => do not dispatch.
  const floorMinutes = cadence && cadence.allowed ? cadence.effectiveFloorMinutes : null;
  const cadenceReason = cadence && Array.isArray(cadence.reasons) ? cadence.reasons.join(' ') : null;
  if (!floorMinutes || !Number.isFinite(floorMinutes)) {
    return {
      allowed: false,
      suppressed_until: null,
      floor_minutes: null,
      reason: cadenceReason
        ? `No notification cadence floor: ${cadenceReason}`
        : 'No notification cadence floor available — failing closed (no dispatch).',
    };
  }

  if (!opts.last_notified_at) {
    // First-ever notification for this subject: allowed, future sends paced.
    const next = new Date(now.getTime() + floorMinutes * 60 * 1000);
    return {
      allowed: true,
      suppressed_until: next.toISOString(),
      floor_minutes: floorMinutes,
      reason: 'First notification — subsequent sends paced by the anti-compulsion floor.',
    };
  }

  const last = new Date(opts.last_notified_at);
  if (Number.isNaN(last.getTime())) {
    return {
      allowed: false,
      suppressed_until: null,
      floor_minutes: floorMinutes,
      reason: 'last_notified_at is unparseable — failing closed (no dispatch).',
    };
  }
  const elapsedMin = (now.getTime() - last.getTime()) / 60000;
  const nextAllowed = new Date(last.getTime() + floorMinutes * 60 * 1000);
  if (elapsedMin < floorMinutes) {
    return {
      allowed: false,
      suppressed_until: nextAllowed.toISOString(),
      floor_minutes: floorMinutes,
      reason:
        `Suppressed by anti-compulsion floor: only ${Math.floor(elapsedMin)} min since last ` +
        `notification, floor is ${floorMinutes} min. Closure Mode paces this — not a missed alert.`,
    };
  }
  return {
    allowed: true,
    suppressed_until: new Date(now.getTime() + floorMinutes * 60 * 1000).toISOString(),
    floor_minutes: floorMinutes,
    reason: 'Floor satisfied — paced dispatch allowed.',
  };
}

/**
 * Compose the human-facing message body for a kind. Reassurance-first voice
 * (GOV.UK), grade-as-headline (Observatory). NO clickable targets, NO raw
 * locators — by construction the only data here is the grade letter, a count,
 * and a what-next line. The body is plain text + Slack-mrkdwn-safe.
 */
function composeBody(kind, ctx = {}) {
  const grade = ctx.grade ? String(ctx.grade) : null;
  const gradeLine = grade
    ? `Your current public-exposure grade: ${grade}.`
    : 'No grade yet — run a full self-audit to get one.';

  switch (kind) {
    case NOTIFY_KIND.NO_CHANGE:
      return {
        title: 'Self-audit complete — nothing changed',
        body:
          `Good news: your public footprint looks the same as last time. ${gradeLine} ` +
          'There is nothing for you to do right now. You do not need to keep checking — ' +
          'the next scheduled audit will let you know if anything moves.',
        what_next: 'No action needed.',
      };
    case NOTIFY_KIND.DIGEST: {
      const n = Number(ctx.change_count) || 0;
      return {
        title: `Self-audit complete — ${n} change${n === 1 ? '' : 's'} to review`,
        body:
          `${n} item${n === 1 ? '' : 's'} in your own public footprint changed since the last audit. ` +
          `${gradeLine} Open your audit dashboard when you have a quiet moment to review and, if you ` +
          'want, start the opt-out/takedown workflow for each one.',
        what_next:
          'Review the changed items in your dashboard and decide which to act on. No rush — they will ' +
          'still be there. This is a digest, not an emergency.',
      };
    }
    case NOTIFY_KIND.COMPLIANCE_STOP:
      return {
        title: 'Self-audit paused for review',
        body:
          'One of the sources asked automated clients to stop (rate-limit or block). We paused rather ' +
          'than push past it — that is by design. A person should review this source manually.',
        what_next: 'A human reviewer will check the paused source. No automated retry will hammer it.',
      };
    case NOTIFY_KIND.NOT_READY:
    default:
      return {
        title: 'No new audit result to report',
        body:
          'The last run did not produce a complete, trustworthy result, so there is nothing to announce. ' +
          'We will not tell you an audit is "ready" when it is not.',
        what_next: 'No action needed; the next scheduled run will try again.',
      };
  }
}

/**
 * Build the redacted, marking-bound DATA block that may accompany the message.
 * Every change row is run through the EXISTING redaction-policy first, so a
 * sub-RED marking physically cannot carry url/storage-key/subject_label. We also
 * hard-default the marking for any EXTERNAL channel to TLP:GREEN (the widest /
 * least-trusting band) unless the caller explicitly asserts a narrower one — a
 * Slack channel or a Zapier zap is "outside", so it gets the thin shareable
 * shape, never raw locators.
 */
function redactRows(rows, marking) {
  if (!Array.isArray(rows)) return [];
  const out = [];
  for (const r of rows) {
    const red = redactRecord(r, marking);
    if (red) out.push(red);
  }
  return out;
}

/**
 * MAIN ENTRY. Decide whether/what to dispatch to an external channel.
 *
 * @param {object} req
 * @param {string} req.channel                 one of CHANNELS
 * @param {object} req.run                     { status, eventType, datasetItems, output }
 *                                             (passed straight to evaluateOutputHealth)
 * @param {Array}  [req.change_rows]           REAL change records (record_type-tagged)
 * @param {string} [req.grade]                 the Self-Exposure grade LETTER (headline)
 * @param {string} [req.marking]               TLP marking; defaults to TLP:GREEN for
 *                                             external channels (widest/least-trusting)
 * @param {string} [req.scope_type]            for the cadence floor's own gate
 * @param {number} [req.distress_risk_score]   0..1
 * @param {string} [req.last_notified_at]      ISO; previous send for pacing
 * @param {Date}   [req.now]                   injectable clock
 * @returns frozen decision object
 */
function decideNotification(req = {}) {
  const reasons = [];

  // 0) Channel gate — fail closed on an unknown sink.
  if (!isChannel(req.channel)) {
    return decision({
      reasons: [`Unknown or missing channel "${req.channel}". Allowed: ${CHANNELS.join(', ')}.`],
    });
  }

  // 1) Marking: external sinks default to the WIDEST band (TLP:GREEN => fewest
  //    fields). Never silently widen below an explicit caller marking; never
  //    accept an unknown marking.
  let marking = req.marking;
  if (marking === undefined || marking === null) {
    marking = 'TLP:GREEN';
  } else if (!isMarking(marking)) {
    return decision({
      channel: req.channel,
      reasons: [`Unknown distribution marking "${req.marking}". Allowed: ${MARKINGS.join(', ')}.`],
    });
  }
  // A raw (TLP:RED) export to an EXTERNAL automation sink is forbidden outright —
  // Slack/Make/n8n/Zapier are "outside", and RED carries raw locators. Refuse.
  if (marking === 'TLP:RED') {
    return decision({
      channel: req.channel,
      marking,
      reasons: [
        'Refusing TLP:RED to an external channel: raw locators (urls/keys/labels) may not leave ' +
        'the platform via Slack/Make/n8n/Zapier. Use TLP:AMBER or TLP:GREEN for external dispatch.',
      ],
    });
  }

  // 2) Output health — success != valid output. Reuse the webhook evaluator.
  const health = evaluateOutputHealth(req.run || {});
  const kind = classifyKind(health, Array.isArray(req.change_rows) ? req.change_rows.length : 0);

  // NOT_READY is a real, honest outcome but it is NOT an external announcement.
  // We surface it so an operator/log knows, but we do NOT dispatch a "ready"
  // message — that would be fake-data-by-implication.
  if (kind === NOTIFY_KIND.NOT_READY) {
    return decision({
      channel: req.channel,
      marking,
      kind,
      reasons: [
        `Run output health is "${health ? health.health : 'unknown'}" — nothing trustworthy to announce.`,
        ...(health && health.reasons ? health.reasons : []),
      ],
    });
  }

  // 3) Anti-compulsion suppression — reuse the cadence floor.
  const gate = suppressionGate({
    scope_type: req.scope_type,
    cadence: req.cadence,
    distress_risk_score: req.distress_risk_score,
    last_notified_at: req.last_notified_at,
    now: req.now,
  });
  if (!gate.allowed) {
    return decision({
      channel: req.channel,
      marking,
      kind,
      suppressed_until: gate.suppressed_until,
      reasons: [gate.reason],
    });
  }

  // 4) Compose the safe, linkless, reassurance-first payload.
  const body = composeBody(kind, { grade: req.grade, change_count: (req.change_rows || []).length });
  const data = redactRows(req.change_rows, marking);

  return Object.freeze({
    dispatch: true,
    kind,
    channel: req.channel,
    marking,
    suppressed_until: gate.suppressed_until,
    reasons: [gate.reason, ...(reasons)],
    payload: Object.freeze({
      // A normalized, channel-agnostic shape. A thin transport client maps this
      // onto Slack mrkdwn / Make / n8n / Zapier at deploy time. NO clickable
      // target field exists here on purpose (Closure Mode).
      kind,
      title: body.title,
      text: body.body,
      what_next: body.what_next,
      grade: req.grade || null,
      change_count: data.length,
      // Only the marking-redacted, thin rows — never raw locators.
      changes: Object.freeze(data),
      marking,
      // Provenance so a downstream automation can trust the shape without the
      // platform link being clickable bait.
      health: health ? health.health : null,
      generated_at: (req.now instanceof Date ? req.now : new Date()).toISOString(),
      // Explicitly assert there is no destination URL — a contract a reviewer
      // (or a downstream zap) can check to prove this product does not bait clicks.
      clickable_target: null,
    }),
  });
}

module.exports = {
  CHANNELS,
  NOTIFY_KIND,
  isChannel,
  classifyKind,
  suppressionGate,
  composeBody,
  redactRows,
  decideNotification,
};
