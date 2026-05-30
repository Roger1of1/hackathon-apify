/**
 * AUX — Takedown / Removal-Letter Generator
 *
 * An auxiliary actor that orbits the core Ex-Ditector pipeline and closes the
 * loop: the audit actors tell the SELF subject WHAT is exposed; this actor turns
 * those real findings into structured, ready-to-review removal requests so the
 * subject can actually ACT — a GDPR Art.17 erasure letter, a CCPA/CPRA delete
 * request, a Google "Results about you" de-index request, a self-remediation
 * checklist for surfaces they control, or credential-rotation guidance for a
 * breach/secret leak. It reads the same typed module_events every other detector
 * emits; it produces NO new intelligence about anyone.
 *
 * ───────────────────────── COMPLIANCE BOUNDARY ─────────────────────────
 * 1. Scope gate: every run is routed through shared/scope.js validateScope and
 *    additionally restricted to scope_type ∈ {self, public_figure}. A takedown
 *    request is inherently first-person ("remove information about ME"); we still
 *    fail CLOSED for any other scope, and the gate's free-text laundering scan
 *    runs over subject_label so a laundered intent is rejected.
 * 2. SELF only: this actor never fetches anything and never analyses a third
 *    party. It only reformats the subject's OWN existing findings into the
 *    standard legal request shapes. There is no romance/gender/sexuality/
 *    intimacy/live-location pathway — it reads the FROZEN EVENT_TYPES enum and
 *    ignores anything outside it.
 * 3. NO FAKE DATA: every letter is a DETERMINISTIC template filled ONLY from
 *    fields that exist in the real events, with explicit [[ FILL IN ]] blanks for
 *    anything we don't have. Each draft is marked is_template:true with a visible
 *    review banner. Nothing is sent; nothing is removed automatically; no finding
 *    is invented. No findings in → empty plan out.
 * ─────────────────────────────────────────────────────────────────────────
 *
 * REFERENCE PATTERNS APPLIED:
 *  - SpiderFoot correlation engine: rather than one letter per raw event, events
 *    are CLUSTERED by co-occurrence key (host / email-prefix / handle) via the
 *    shared/enrich/cluster-keys.js index — the same correlation the report
 *    builder uses — so one request can cover every leak on one host, exactly as
 *    SpiderFoot's correlation engine groups related events into one finding.
 *  - The Markup "Blacklight" self-exposure inspector: each packet carries a
 *    plain-language "why this matters to YOU" line in the subject's own voice,
 *    matching Blacklight's self-audit framing rather than bare legalese.
 */

'use strict';

const { Actor, log } = require('apify');

const { validateScope, ALLOWED_SCOPES } = require('../../../shared/scope.js');
const { isModuleEvent } = require('../../../shared/detectors/event-types.js');
const { buildTakedownPlan, SOURCE_MODULE } = require('../../../shared/aux/takedown-letter.js');

// Takedown drafting acts on the subject's OWN footprint: self + public_figure.
const TAKEDOWN_SCOPES = new Set(['self', 'public_figure']);

/**
 * Collect the real module_events to act on. Precedence:
 *  1. input.events (inline) — for offline/composed runs and tests.
 *  2. the shared case dataset named by input.findings_dataset_name — the real
 *     output the other actors pushed.
 * We only ever keep records that pass isModuleEvent(); anything else is dropped
 * (no fabrication, no coercion).
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

Actor.main(async () => {
  const input = (await Actor.getInput()) || {};
  const scopeType = typeof input.scope_type === 'string' ? input.scope_type.trim() : '';

  // ── Gate 1: canonical scope gate (the chokepoint the whole product shares). ──
  // This actor fetches nothing, so we hand the gate a harmless self placeholder
  // ONLY to satisfy its target check, while still getting its prohibited-scope /
  // prohibited-intent rejection and its free-text laundering scan over the
  // subject's label/name (so "draft a letter to find my ex" is rejected).
  const gateDecision = validateScope({
    scope_type: scopeType,
    target_urls: ['https://example.invalid/self-takedown-draft'],
    subject_label: input.subject_label,
    description: input.subject_label,
    subject_name: input.subject_name,
  });

  if (!gateDecision.allowed) {
    log.error('Takedown-generator refused by scope gate.', {
      reasons: gateDecision.reasons,
      violated: gateDecision.violated_red_lines,
    });
    await Actor.pushData({
      record_type: 'takedown_plan',
      source_module: SOURCE_MODULE,
      refused: true,
      reasons: gateDecision.reasons,
      violated_red_lines: gateDecision.violated_red_lines,
      alternatives: gateDecision.alternatives,
    });
    await Actor.fail('Takedown-generator rejected by compliance gate.');
    return;
  }

  // ── Gate 2: scope restriction. Takedown drafting is self/public_figure only. ──
  if (!ALLOWED_SCOPES.includes(scopeType) || !TAKEDOWN_SCOPES.has(scopeType)) {
    log.error('Takedown-generator refused: drafting is restricted to self/public_figure.', {
      scope_type: scopeType,
    });
    await Actor.fail('Takedown drafting is allowed only for scope_type=self or public_figure.');
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
  if (!caseId) caseId = 'standalone_takedown';

  // Gather the subject's REAL findings. No findings → empty plan (NO FAKE DATA).
  const events = await collectEvents(input);
  if (events.length === 0) {
    log.warning('No actionable module_events found; producing an empty plan (no fake data).');
  }

  const ownedHosts = Array.isArray(input.owned_hosts)
    ? input.owned_hosts.filter((h) => typeof h === 'string')
    : [];
  const subjectName =
    typeof input.subject_name === 'string' && input.subject_name.trim()
      ? input.subject_name.trim()
      : '';

  // ── Build the plan: cluster events (SpiderFoot correlation keys) → packets. ──
  const plan = buildTakedownPlan({ events, ownedHosts, subjectName });

  // Push one dataset record per packet so the report builder / web UI can render
  // them as grouped action cards.
  for (const packet of plan.packets) {
    await Actor.pushData({ ...packet, case_id: caseId });
  }

  // And a single plan summary record + KV snapshot for the case.
  const summary = {
    record_type: 'takedown_plan_summary',
    source_module: SOURCE_MODULE,
    case_id: caseId,
    scope_type: scopeType,
    subject_label: typeof input.subject_label === 'string' ? input.subject_label : '',
    events_considered: events.length,
    packet_count: plan.packet_count,
    letter_count: plan.letter_count,
    is_template: true,
    generated_at: new Date().toISOString(),
    note: plan.generated_note,
  };
  await Actor.pushData(summary);
  await Actor.setValue('TAKEDOWN_PLAN', { ...plan, case_id: caseId, generated_at: summary.generated_at });

  log.info('Takedown-generator complete.', {
    events_considered: events.length,
    packets: plan.packet_count,
    letters: plan.letter_count,
  });
});
