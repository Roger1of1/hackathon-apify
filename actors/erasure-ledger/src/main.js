/**
 * AUX — Erasure-Request Ledger / Removal Tracker
 *
 * The piece that makes removal requests actionable over TIME. The other aux
 * actors draft the requests (takedown-generator → GDPR Art.17 / CCPA letters;
 * broker-optout → opt-out routes). This actor turns those drafted requests into a
 * single trackable LEDGER: per request it records the controller's statutory
 * response deadline and the ONE date to check back, so the subject verifies
 * removal on the deadline instead of compulsively re-checking (Closure Mode).
 *
 * It reads the SELF subject's REAL typed module_events (the same records every
 * other detector emits) and REUSES shared/aux/erasure-ledger.js, which in turn
 * REUSES shared/aux/takedown-letter.js — there is no re-implementation of letter,
 * statute-selection, or clustering logic here. It produces NO new intelligence
 * about anyone and fetches nothing.
 *
 * ───────────────────────── COMPLIANCE BOUNDARY ─────────────────────────
 * 1. Scope gate FIRST: every run is routed through shared/scope.js validateScope
 *    and additionally restricted to scope_type ∈ {self, public_figure}. Tracking
 *    your OWN removal requests is inherently first-person; we fail CLOSED for any
 *    other scope, and the gate's free-text laundering scan runs over subject_label
 *    so a laundered intent ("track my ex's removals") is rejected exactly as the
 *    web and other actor paths reject it.
 * 2. SELF only: this actor never fetches anything and never analyses a third
 *    party. It only schedules check-backs for the subject's OWN drafted requests.
 *    There is no romance/gender/sexuality/intimacy/live-location field anywhere.
 * 3. NO FAKE DATA: every deadline is computed by deterministic date arithmetic
 *    from a real submitted_at the SUBJECT supplies; with no submission date the
 *    clock is honestly marked "not started". No removal outcome is ever invented —
 *    a row is "removed" only when a later re-scan (outside this actor) confirms
 *    the exposure is gone. No findings in → empty ledger out. is_template:true.
 * ─────────────────────────────────────────────────────────────────────────
 *
 * REFERENCE PATTERNS APPLIED (both required refs, borrowed concretely):
 *  - DeleteMe / Aura data-broker opt-out workflow → the CONSOLIDATED removal
 *    dashboard: one row per request with a status lifecycle and a scheduled
 *    re-check cadence, so the subject tracks every removal in one place instead
 *    of manually re-checking each site — the same model DeleteMe/Aura use to keep
 *    a subject's broker removals visible and re-scanned over time.
 *  - GDPR Article 17 (Right to be Forgotten) erasure-request automation → the
 *    STATUTORY DEADLINE CLOCK: Art.12(3) requires the controller to respond
 *    "without undue delay and within one month" (extendable by two months), and
 *    CCPA/CPRA §1798.130 gives 45 days (+45). RTBF-automation tools surface that
 *    respond-by date when a request is logged; we compute the same deadline and
 *    the Art.77/79 escalation when it is overdue.
 */

'use strict';

const { Actor, log } = require('apify');

const { validateScope, ALLOWED_SCOPES } = require('../../../shared/scope.js');
const { isModuleEvent } = require('../../../shared/detectors/event-types.js');
const { buildErasureLedger, SOURCE_MODULE } = require('../../../shared/aux/erasure-ledger.js');

// Tracking your OWN removals acts on your OWN footprint: self + public_figure.
const LEDGER_SCOPES = new Set(['self', 'public_figure']);

/**
 * Collect the real module_events the ledger acts on. Precedence:
 *  1. input.events (inline) — for offline/composed runs and tests.
 *  2. the shared case dataset named by input.findings_dataset_name.
 * Only records that pass isModuleEvent() are kept (no fabrication, no coercion).
 */
async function collectEvents(input) {
  const out = [];

  if (Array.isArray(input.events)) {
    for (const e of input.events) if (isModuleEvent(e)) out.push(e);
  }

  const datasetName =
    typeof input.findings_dataset_name === 'string' && input.findings_dataset_name.trim()
      ? input.findings_dataset_name.trim()
      : null;
  if (datasetName) {
    try {
      const ds = await Actor.openDataset(datasetName);
      const { items } = await ds.getData();
      for (const e of items || []) if (isModuleEvent(e)) out.push(e);
    } catch (err) {
      log.warning(`Could not open findings dataset "${datasetName}": ${err.message}`);
    }
  }

  return out;
}

/**
 * Optionally load a previously-produced broker_optout_plan from a KV store so its
 * erasure letters fold into the same ledger. We only accept a record that really
 * is a broker_optout_plan with an erasure_plan; anything else is ignored.
 */
async function loadBrokerPlan(input) {
  const storeName =
    typeof input.broker_plan_store_name === 'string' && input.broker_plan_store_name.trim()
      ? input.broker_plan_store_name.trim()
      : null;
  if (!storeName) return null;
  const key = (typeof input.broker_plan_key === 'string' && input.broker_plan_key.trim())
    ? input.broker_plan_key.trim()
    : 'BROKER_OPTOUT_PLAN';
  try {
    const store = await Actor.openKeyValueStore(storeName);
    const rec = await store.getValue(key);
    if (rec && rec.record_type === 'broker_optout_plan' && rec.erasure_plan) return rec;
    if (rec) log.warning('broker_plan_store record is not a broker_optout_plan; ignoring.');
  } catch (err) {
    log.debug(`No broker plan store available (${err.message}).`);
  }
  return null;
}

Actor.main(async () => {
  const input = (await Actor.getInput()) || {};
  const scopeType = typeof input.scope_type === 'string' ? input.scope_type.trim() : '';

  // ── Gate 1: canonical scope gate (the chokepoint the whole product shares). ──
  // This actor fetches nothing, so we hand the gate a harmless self placeholder
  // ONLY to satisfy its target check, while still getting its prohibited-scope /
  // prohibited-intent rejection and free-text laundering scan over subject_label.
  const gateDecision = validateScope({
    scope_type: scopeType,
    target_urls: ['https://example.invalid/self-erasure-ledger'],
    subject_label: input.subject_label,
    description: input.subject_label,
    subject_name: input.subject_name,
  });

  if (!gateDecision.allowed) {
    log.error('Erasure-ledger refused by scope gate.', {
      reasons: gateDecision.reasons,
      violated: gateDecision.violated_red_lines,
    });
    await Actor.pushData({
      record_type: 'erasure_ledger',
      source_module: SOURCE_MODULE,
      refused: true,
      reasons: gateDecision.reasons,
      violated_red_lines: gateDecision.violated_red_lines,
      alternatives: gateDecision.alternatives,
    });
    await Actor.fail('Erasure-ledger rejected by compliance gate.');
    return;
  }

  // ── Gate 2: scope restriction. Tracking removals is self/public_figure only. ──
  if (!ALLOWED_SCOPES.includes(scopeType) || !LEDGER_SCOPES.has(scopeType)) {
    log.error('Erasure-ledger refused: tracking is restricted to self/public_figure.', {
      scope_type: scopeType,
    });
    await Actor.fail('Erasure-ledger is allowed only for scope_type=self or public_figure.');
    return;
  }

  // Resolve case id from the shared case store, like the other actors.
  const caseStoreName = input.case_store_name || 'ex-ditector-case';
  let caseId = input.case_id || null;
  try {
    const caseStore = await Actor.openKeyValueStore(caseStoreName);
    const caseRecord = await caseStore.getValue('CASE');
    if (caseRecord && caseRecord.case_id) caseId = caseRecord.case_id;
  } catch (err) {
    log.debug(`No case store available (${err.message}); running standalone.`);
  }
  if (!caseId) caseId = 'standalone_erasure_ledger';

  // Gather the subject's REAL findings. No findings → empty ledger (NO FAKE DATA).
  const events = await collectEvents(input);
  if (events.length === 0) {
    log.warning('No actionable module_events found; producing an empty ledger (no fake data).');
  }

  const brokerOptOutPlan = await loadBrokerPlan(input);

  const ownedHosts = Array.isArray(input.owned_hosts)
    ? input.owned_hosts.filter((h) => typeof h === 'string')
    : [];
  const subjectName =
    typeof input.subject_name === 'string' && input.subject_name.trim()
      ? input.subject_name.trim()
      : '';
  const submittedAt =
    input.submitted_at && typeof input.submitted_at === 'object' ? input.submitted_at : {};

  // ── Build the ledger: REUSE buildErasureLedger (which reuses buildTakedownPlan). ──
  const ledger = buildErasureLedger({
    events,
    ownedHosts,
    subjectName,
    brokerOptOutPlan,
    submitted_at: submittedAt,
  });

  // Push one dataset record per ledger row so the report builder / web UI can
  // render them as trackable cards with their deadline + recheck date.
  for (const row of ledger.rows) {
    await Actor.pushData({ ...row, case_id: caseId });
  }

  // And a single ledger summary record + KV snapshot for the case + a re-check
  // SCHEDULE PROPOSAL (template only — we never auto-schedule or auto-send).
  const summary = {
    record_type: 'erasure_ledger_summary',
    source_module: SOURCE_MODULE,
    case_id: caseId,
    scope_type: scopeType,
    subject_label: typeof input.subject_label === 'string' ? input.subject_label : '',
    events_considered: events.length,
    request_count: ledger.request_count,
    overdue_count: ledger.overdue_count,
    next_recheck_on: ledger.next_recheck_on,
    is_template: true,
    generated_at: ledger.generated_at,
    closure_mode_note: ledger.closure_mode_note,
    recheck_schedule_proposal: ledger.next_recheck_on
      ? {
          // Apify Schedule shape the operator can wire to a re-scan run. Template
          // only: this actor proposes it, it does not create the schedule.
          is_template: true,
          run_on_or_after: ledger.next_recheck_on,
          note:
            'Propose a one-shot re-scan on/after this date to verify removal. '
            + 'Closure Mode: do not re-check before then. Nothing is scheduled automatically.',
        }
      : null,
  };
  await Actor.pushData(summary);
  await Actor.setValue('ERASURE_LEDGER', { ...ledger, case_id: caseId });

  log.info('Erasure-ledger complete.', {
    events_considered: events.length,
    requests: ledger.request_count,
    overdue: ledger.overdue_count,
    next_recheck_on: ledger.next_recheck_on,
  });
});
