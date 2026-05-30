/**
 * shared/aux/erasure-ledger.js
 *
 * AUX — Erasure-Request LEDGER (the "did it actually get removed?" tracker).
 *
 * WHAT THIS ADDS (and why it is genuinely missing)
 * ─────────────────────────────────────────────────────────────────────────────
 * The repo already turns the SELF subject's REAL findings into removal *requests*
 * (shared/aux/takedown-letter.js drafts GDPR Art.17 / CCPA delete / de-index
 * letters; shared/aux/broker-optout.js turns confirmed broker listings into
 * opt-out routes). What it does NOT have is the piece that makes those requests
 * *actionable over time*: a single LEDGER that, for each drafted request,
 *   (1) records the statutory response clock the controller is legally on, and
 *   (2) tells the subject the ONE date to check back — so they verify removal on
 *       the deadline instead of compulsively re-checking (Closure Mode).
 *
 * This is exactly the value of a DeleteMe-style consolidated removal dashboard:
 * not "send a letter", but "track every request, its deadline, and its status in
 * one place". It serves the core job (act on YOUR OWN exposure + stop the
 * compulsive re-checking loop) and adds NO new intelligence about anyone.
 *
 * REFERENCE PATTERNS APPLIED (both required refs, borrowed concretely)
 * ─────────────────────────────────────────────────────────────────────────────
 *  - DeleteMe / Aura data-broker opt-out workflow → the consolidated REMOVAL
 *    LEDGER model. DeleteMe/Aura don't just file an opt-out; they maintain a
 *    per-subject list of every removal request with a status column
 *    (in_progress / removed / re-appeared) and a scheduled re-scan cadence so the
 *    subject doesn't have to keep manually checking each broker. We mirror that:
 *    one ledger row per request, an explicit `status` lifecycle, and a single
 *    `recheck_on` date that drives a scheduled verification rather than constant
 *    manual checking.
 *  - GDPR Article 17 (Right to be Forgotten) erasure-request automation → the
 *    STATUTORY DEADLINE CLOCK. Art.12(3) requires the controller to act "without
 *    undue delay and in any event within one month of receipt of the request",
 *    extendable by two further months for complex requests (so up to 3 months
 *    total), and Art.12(4) requires a reason if they refuse. CCPA/CPRA (Cal. Civ.
 *    Code §1798.130) gives a verifiable-delete response window of 45 days,
 *    extendable by a further 45. RTBF-automation tools (e.g. Mine, Osano,
 *    DataGrail) compute that deadline when a request is logged and surface the
 *    "respond-by" date. We compute the SAME deadline windows here from the
 *    request's statute, deterministically, so the subject knows exactly when the
 *    controller is overdue and what their escalation is.
 *
 * NO FAKE DATA (the hard rule)
 *  - This module invents NO removal outcome. Every ledger row starts at status
 *    "drafted" (or "submitted" only if the caller asserts a real sent_at date).
 *    It never reports "removed" on its own — removal is confirmed only by a later
 *    re-scan finding the exposure gone, which is OUTSIDE this module. Deadlines
 *    are computed by deterministic date arithmetic from a real `submitted_at`
 *    (or, if absent, are clearly marked `clock_started: false` / pending).
 *  - The whole ledger is `is_template: true` and carries a review banner. Nothing
 *    is sent and nothing is removed by this code.
 *
 * COMPLIANCE-BY-CONSTRUCTION
 *  - The actor that drives this module routes the subject through the canonical
 *    shared/scope.js validateScope() FIRST (self / public_figure only); this pure
 *    module only formats requests the subject already drafted from their OWN
 *    findings. There is no third-party pathway and no
 *    romance/gender/sexuality/intimacy/live-location field anywhere.
 *  - It REUSES shared/aux/takedown-letter.js (buildTakedownPlan) — it does not
 *    re-implement letter drafting, statute selection, or clustering.
 *
 * Zero dependencies beyond the existing planner. Pure + deterministic.
 */

'use strict';

const { buildTakedownPlan, REQUEST_KINDS } = require('./takedown-letter.js');

const SOURCE_MODULE = 'erasure_ledger';

/**
 * Ledger row status lifecycle (DeleteMe-style). We only ever SET the first two
 * from inputs we can verify; "removed" / "reappeared" are set by a later re-scan
 * (outside this module) — never invented here.
 */
const LEDGER_STATUS = Object.freeze({
  DRAFTED: 'drafted', // letter generated, not yet sent (default — no clock yet)
  SUBMITTED: 'submitted', // subject asserts a real sent date → statutory clock runs
  AWAITING: 'awaiting_response', // within the statutory window
  OVERDUE: 'overdue', // past the statutory deadline with no confirmed removal
  REMOVED: 'removed', // confirmed gone by a later re-scan (set elsewhere)
  REAPPEARED: 'reappeared', // came back after removal (set elsewhere)
});

/**
 * Statutory response clocks, keyed by the request_kind that takedown-letter.js
 * already emits. Days are the *controller's* legal response window. `extend_days`
 * is the further extension the statute allows for complex requests. These are
 * the real legal windows, not guesses:
 *   - GDPR Art.12(3): 1 month, +2 months extension  → 30 (+60)
 *   - CCPA/CPRA §1798.130: 45 days, +45 days         → 45 (+45)
 *   - Google "Results about you" is a policy process, not a statute → no clock.
 */
const STATUTE_CLOCK = Object.freeze({
  [REQUEST_KINDS.GDPR_ERASURE]: {
    label: 'GDPR Art. 17 erasure',
    respond_days: 30,
    extend_days: 60,
    basis: 'GDPR Art. 12(3): without undue delay, within one month; extendable by two further months.',
    overdue_escalation:
      'If overdue with no substantive reply, you may lodge a complaint with your supervisory '
      + 'authority (GDPR Art. 77) or seek a judicial remedy (Art. 79).',
  },
  [REQUEST_KINDS.CCPA_DELETE]: {
    label: 'CCPA/CPRA right to delete',
    respond_days: 45,
    extend_days: 45,
    basis: 'Cal. Civ. Code §1798.130: respond within 45 days; extendable by a further 45 days.',
    overdue_escalation:
      'If overdue, you may notify the California Privacy Protection Agency (CPPA) or the '
      + 'Attorney General.',
  },
});

const REVIEW_BANNER =
  'TRACKING TEMPLATE — review before relying on any date. Deadlines are computed '
  + 'from the date YOU say you submitted the request; nothing here was sent, and no '
  + 'removal is reported until a later re-scan confirms the exposure is gone.';

/** Add whole days to an ISO date, returning an ISO date (UTC, date-stable). */
function addDays(iso, days) {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return null;
  d.setUTCDate(d.getUTCDate() + days);
  return d.toISOString();
}

/** Parse a caller-supplied submitted_at; only accept a real, valid date. */
function validSubmittedAt(value) {
  if (typeof value !== 'string' || !value.trim()) return null;
  const d = new Date(value.trim());
  return Number.isNaN(d.getTime()) ? null : d.toISOString();
}

/**
 * Compute the deadline block for one request_kind, given an optional real
 * submitted_at. If no real submission date, the clock has NOT started — we say so
 * honestly instead of inventing a deadline.
 */
function deadlineFor(requestKind, submittedAt, now) {
  const clock = STATUTE_CLOCK[requestKind];
  if (!clock) {
    return {
      clock_started: false,
      has_statutory_clock: false,
      note:
        'This request kind follows a provider policy process, not a statutory '
        + 'deadline, so there is no legal response clock to track.',
    };
  }
  if (!submittedAt) {
    return {
      clock_started: false,
      has_statutory_clock: true,
      statute_basis: clock.basis,
      respond_days: clock.respond_days,
      extend_days: clock.extend_days,
      note:
        'Clock not started: set submitted_at to the real date you sent this '
        + 'request and the respond-by date will be computed.',
    };
  }
  const respondBy = addDays(submittedAt, clock.respond_days);
  const maxBy = addDays(submittedAt, clock.respond_days + clock.extend_days);
  const overdue = now ? new Date(now) > new Date(respondBy) : false;
  return {
    clock_started: true,
    has_statutory_clock: true,
    statute_basis: clock.basis,
    submitted_at: submittedAt,
    respond_by: respondBy, // controller's legal deadline
    extended_max_by: maxBy, // if they invoke the complex-request extension
    is_overdue: overdue,
    overdue_escalation: clock.overdue_escalation,
  };
}

/**
 * Closure-Mode recheck date: ONE scheduled verification, not constant checking.
 * Rule (deterministic): check back the day AFTER the statutory respond-by date
 * (so the controller has had their full legal window). If there is no statutory
 * clock, default to a calm 30-day cadence from submission/draft so the subject
 * still has a single, finite check-back instead of an open compulsive loop.
 */
function recheckDateFor(deadline, anchorIso) {
  if (deadline.clock_started && deadline.respond_by) {
    return addDays(deadline.respond_by, 1);
  }
  return addDays(anchorIso, 30);
}

/**
 * Build ledger rows from a takedown plan's packets. One row per (host, request
 * kind) — the same grain the letters are drafted at — so each legal request the
 * subject can actually send has its own trackable clock.
 *
 * @param {object} plan         output of buildTakedownPlan (REUSED, not rebuilt)
 * @param {object} [opts]
 * @param {string} [opts.now]   ISO "now" (for overdue calc / testing)
 * @param {object} [opts.submitted_at]  map of { [`${host}|${request_kind}`]: ISO }
 *                                       real submission dates the subject asserts
 */
function ledgerRowsFromTakedownPlan(plan, opts = {}) {
  const now = typeof opts.now === 'string' ? opts.now : new Date().toISOString();
  const submittedMap = opts.submitted_at && typeof opts.submitted_at === 'object' ? opts.submitted_at : {};
  const rows = [];

  const packets = Array.isArray(plan && plan.packets) ? plan.packets : [];
  for (const packet of packets) {
    const host = packet.host || null;
    const letters = Array.isArray(packet.letters) ? packet.letters : [];
    for (const letter of letters) {
      const requestKind = letter.request_kind;
      const key = `${host || ''}|${requestKind}`;
      const submittedAt = validSubmittedAt(submittedMap[key]);
      const deadline = deadlineFor(requestKind, submittedAt, now);
      const anchor = submittedAt || now;
      const recheckOn = recheckDateFor(deadline, anchor);

      let status = LEDGER_STATUS.DRAFTED;
      if (submittedAt) {
        status = deadline.is_overdue ? LEDGER_STATUS.OVERDUE : LEDGER_STATUS.AWAITING;
      }

      rows.push({
        record_type: 'erasure_ledger_row',
        source_module: SOURCE_MODULE,
        ledger_key: key,
        host,
        target_urls: packet.target_urls || [],
        request_kind: requestKind,
        statute_refs: letter.statute_refs || [],
        exposure_summary: packet.why_it_matters || '',
        top_risk: packet.top_risk || 'info',
        finding_count: packet.finding_count || 0,
        status,
        deadline,
        recheck_on: recheckOn, // the ONE date to check back (Closure Mode)
        subject_line: letter.subject_line || '',
        is_template: true,
        review_banner: REVIEW_BANNER,
      });
    }
  }
  // Deterministic order: by host then request kind.
  rows.sort((a, b) =>
    (a.ledger_key < b.ledger_key ? -1 : a.ledger_key > b.ledger_key ? 1 : 0),
  );
  return rows;
}

/**
 * Build the full erasure ledger. REUSES buildTakedownPlan to derive the requests
 * from the subject's REAL events; optionally folds in an existing broker opt-out
 * plan's erasure_plan packets (also produced by takedown-letter, so same shape).
 *
 * @param {object} p
 * @param {object[]} p.events                module_event records (the subject's own findings)
 * @param {string[]} [p.ownedHosts]          hosts the subject controls
 * @param {string}   [p.subjectName]         the subject's name (for the letters)
 * @param {object}   [p.brokerOptOutPlan]    optional broker_optout_plan to fold in
 * @param {object}   [p.submitted_at]        { [ledger_key]: ISO } real submission dates
 * @param {string}   [p.now]                 ISO now (testing / overdue calc)
 * @returns {object} erasure_ledger record (is_template:true, no fabricated outcomes)
 */
function buildErasureLedger(p = {}) {
  const now = typeof p.now === 'string' ? p.now : new Date().toISOString();

  // REUSE the existing planner — do NOT re-implement letter/statute/cluster logic.
  const takedownPlan = buildTakedownPlan({
    events: Array.isArray(p.events) ? p.events : [],
    ownedHosts: Array.isArray(p.ownedHosts) ? p.ownedHosts : [],
    subjectName: typeof p.subjectName === 'string' ? p.subjectName : undefined,
  });

  let rows = ledgerRowsFromTakedownPlan(takedownPlan, { now, submitted_at: p.submitted_at });

  // Optionally fold in a broker opt-out plan's erasure letters (same packet shape,
  // because broker-optout.js itself reuses takedown-letter.js). We tag origin so
  // the UI can show "data broker" vs "general web exposure".
  if (p.brokerOptOutPlan && p.brokerOptOutPlan.erasure_plan) {
    const brokerRows = ledgerRowsFromTakedownPlan(p.brokerOptOutPlan.erasure_plan, {
      now,
      submitted_at: p.submitted_at,
    }).map((r) => ({ ...r, origin: 'data_broker' }));
    rows = rows.map((r) => ({ ...r, origin: r.origin || 'web_exposure' })).concat(brokerRows);
  }

  // Closure-Mode summary: the SINGLE next check-back date across the whole ledger,
  // plus the count of currently-overdue requests (so the user sees a finite,
  // bounded to-do, not an endless feed).
  const pendingRecheckDates = rows
    .filter((r) => r.status !== LEDGER_STATUS.REMOVED)
    .map((r) => r.recheck_on)
    .filter(Boolean)
    .sort();
  const overdueCount = rows.filter((r) => r.status === LEDGER_STATUS.OVERDUE).length;

  return {
    record_type: 'erasure_ledger',
    source_module: SOURCE_MODULE,
    generated_at: now,
    request_count: rows.length,
    overdue_count: overdueCount,
    next_recheck_on: pendingRecheckDates.length ? pendingRecheckDates[0] : null,
    rows,
    is_template: true,
    review_banner: REVIEW_BANNER,
    closure_mode_note:
      'Closure Mode: check back on next_recheck_on — not before. Each request has '
      + 'one scheduled verification tied to the controller\'s legal deadline, so you '
      + 'can stop manually re-checking in the meantime.',
    disclaimer:
      'Generated from your OWN audit findings only. No data about third parties was '
      + 'created; nothing was sent or removed. Deadlines are computed from dates you '
      + 'supply and are informational, not legal advice.',
  };
}

module.exports = {
  SOURCE_MODULE,
  LEDGER_STATUS,
  STATUTE_CLOCK,
  REVIEW_BANNER,
  addDays,
  validSubmittedAt,
  deadlineFor,
  recheckDateFor,
  ledgerRowsFromTakedownPlan,
  buildErasureLedger,
};
