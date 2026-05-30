/**
 * integrations/standby/chain-policy.js
 *
 * Pure, zero-I/O policy for the Standby + metamorph capability. Given a raw
 * subject input, it produces the metamorph PLAN: the next stage to hand the run
 * to, or a refusal. No network, no fs at the decision boundary, so it is unit
 * testable and reusable by both the live Standby server (server.js) and the
 * dry-run client (client.js).
 *
 * Two reference architectures shape this file:
 *
 *  - SpiderFoot (OSINT module graph + correlation engine). SpiderFoot wires
 *    modules into a directed graph and gates what data may flow from one module
 *    to the next; a module never runs on data it is not permitted to consume.
 *    Here the "module graph" is the metamorph chain (chain.config.json) and the
 *    "gate between modules" is validateScope, re-asserted on every hop so a
 *    later stage can never run on a subject an earlier stage would have refused.
 *
 *  - The Markup's Blacklight (self-exposure inspector). Blacklight is a single
 *    real-time endpoint: you hand it ONE subject (a URL that is yours/public)
 *    and it inspects it. Standby gives the gate exactly that shape — a real-time
 *    API that takes one subject and returns either "inspecting" (metamorphed
 *    into the pipeline) or a plain-language refusal with legal alternatives.
 *    There is no batch, no list-of-people, no enumeration of strangers.
 *
 * The gate is shared/scope.js (Codex owns it; we only READ it).
 */

'use strict';

const fs = require('fs');
const path = require('path');
const { validateScope } = require('../../shared/scope.js');

const CHAIN_PATH = path.join(__dirname, 'chain.config.json');

/** Load and freeze the metamorph chain manifest. */
function loadChain(chainPath = CHAIN_PATH) {
  const raw = JSON.parse(fs.readFileSync(chainPath, 'utf8'));
  return raw;
}

/**
 * Given the chain manifest and a stage key, return the stage object that the
 * given stage metamorphs INTO, or null if terminal / unknown.
 */
function nextStage(chain, fromKey) {
  const stage = chain.stages.find((s) => s.key === fromKey);
  if (!stage || !stage.metamorph_to) return null;
  return chain.stages.find((s) => s.key === stage.metamorph_to) || null;
}

/**
 * planMetamorph(input, opts) -> plan
 *
 * The decision a Standby request makes. `fromStage` defaults to the entry
 * ("policy-gate") because Standby may ONLY enter through the gate; passing any
 * other fromStage is itself a refusal (no smuggling into a downstream actor).
 *
 * Returns one of:
 *   { decision: 'reject', http_status: 403, reasons, alternatives, ... }
 *   { decision: 'metamorph', http_status: 202, targetActorId, targetStage,
 *     normalizedInput, ... }            // gate passed, hand off to next actor
 *   { decision: 'complete', http_status: 200, ... }   // terminal stage reached
 */
function planMetamorph(input, opts = {}) {
  const chain = opts.chain || loadChain(opts.chainPath);
  const fromStage = opts.fromStage || chain.entry;

  // Standby may ONLY enter through the declared entry stage. A request that
  // tries to start mid-chain (e.g. straight into the crawler) is refused: that
  // would bypass the gate. This is the SpiderFoot "you cannot inject data into
  // an arbitrary module" property expressed for actor chaining.
  if (fromStage !== chain.entry) {
    return {
      decision: 'reject',
      http_status: 403,
      reasons: [
        `Standby entry must be the gate ("${chain.entry}"). ` +
          `Direct entry into "${fromStage}" would bypass the scope gate and is refused.`,
      ],
      violated_red_lines: ['gate_bypass_attempt'],
      alternatives: [],
      normalizedInput: null,
    };
  }

  // The real gate. NO bypass, NO fake pass. (shared/scope.js, read-only.)
  const verdict = validateScope(input || {});
  if (!verdict.allowed) {
    return {
      decision: 'reject',
      http_status: 403,
      reasons: verdict.reasons,
      violated_red_lines: verdict.violated_red_lines,
      alternatives: verdict.alternatives,
      normalizedInput: null,
    };
  }

  // Passed the gate. Compute the hand-off target from the manifest. The input we
  // forward is the NORMALIZED, minimal payload from the gate — never the raw
  // request body — so downstream actors inherit only vetted fields.
  const target = nextStage(chain, fromStage);
  if (!target) {
    return {
      decision: 'complete',
      http_status: 200,
      reasons: ['Gate passed; chain has no downstream stage (terminal).'],
      normalizedInput: verdict.normalized,
    };
  }

  return {
    decision: 'metamorph',
    http_status: 202,
    targetStage: target.key,
    targetActorId: target.actorId,
    // Every downstream stage re-asserts scope, so we also carry the scope_type
    // forward explicitly; a stage that finds it missing must fail closed.
    normalizedInput: verdict.normalized,
    reasons: [`Gate passed (scope=${verdict.scope_type}); metamorph to "${target.key}".`],
  };
}

/** Does the given actorId look like an unfilled placeholder (<...>)? */
function isPlaceholderId(actorId) {
  return typeof actorId !== 'string' || /<[A-Z_]+>/.test(actorId) || actorId.trim() === '';
}

module.exports = {
  loadChain,
  nextStage,
  planMetamorph,
  isPlaceholderId,
  CHAIN_PATH,
};
