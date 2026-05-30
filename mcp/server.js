'use strict';

/**
 * mcp/server.js
 *
 * MirrorTrace (合规版) — APIFY MCP TOOL-SERVER
 * ─────────────────────────────────────────────────────────────────────────────
 * A small, runnable Model-Context-Protocol tool layer that exposes the product's
 * EXISTING, already-tested compliance planners as MCP tools an AI agent can call.
 *
 * The single design rule of this file: an AI-agent caller MUST NOT be able to
 * bypass the red lines. Every tool handler routes its subject through the REAL
 * canonical gate (shared/scope.js → validateScope) FIRST, before it touches any
 * planner. If the gate refuses (prohibited scope_type, or laundered / stalking
 * freeText, or a private-social host), the tool fails CLOSED and returns the
 * gate's own refusal — never a result. This is the same gate the web path
 * (window.MirrorTrace.runPolicyGate) and every actor uses, so the MCP surface is
 * NOT a weaker side-door: it is the same wall.
 *
 * ZERO DUPLICATION. This file re-uses, never re-implements:
 *   - shared/scope.js              → validateScope (read-only require; NOT rewritten)
 *   - shared/aux/broker-optout.js  → buildBrokerOptOutPlan  (self-only erasure plan)
 *   - shared/aux/takedown-letter.js→ buildTakedownPlan      (Art.17 RTBF letters)
 *   - shared/enrich/stix-evidence.js→ toBundle              (STIX 2.1 evidence)
 * ZERO NETWORK FETCH. ZERO FABRICATED DATA. Planners are pure functions over the
 * user's OWN confirmed inputs; nothing here scrapes, sends, or invents a result.
 *
 * REFERENCE ARCHITECTURES (how a mature system wires this) — cited, borrowed:
 *
 *  1) DeleteMe / Aura data-broker opt-out workflow.
 *     Both gate every removal on EXPLICIT AUTHORIZATION ("you authorize us to act
 *     on your behalf") and only ever remove the SUBSCRIBER'S OWN record — you
 *     cannot opt a third party out of a broker. We mirror that exactly: the
 *     plan_broker_optout tool is self-only (scope_type self, or consented WITH
 *     authorization_evidence_url — the DeleteMe "authorization" step), and it acts
 *     only on listings the user CONFIRMED are about them (the DeleteMe "scan then
 *     confirm" step) — we never scrape brokers to discover listings.
 *     Refs: aura.com/data-removal-service ; security.org/data-removal/deleteme-vs-aura
 *
 *  2) GDPR Article 17 — Right to be Forgotten (RTBF) erasure-request automation.
 *     A first-person erasure is a DATA-SUBJECT request sent to the third-party
 *     controller (the broker / host) under Art.17. build_takedown_letter and the
 *     erasure_plan inside plan_broker_optout reuse takedown-letter.js, which routes
 *     a third-party host (ownedHosts left empty) to the Art.17 + CCPA-delete +
 *     de-index channel — the correct RTBF erasure path, drafted as a TEMPLATE the
 *     user verifies and sends; this server sends nothing.
 *     Ref: GDPR Art.17 (Regulation (EU) 2016/679).
 *
 *  3) Apify MCP server (how the platform exposes tools to AI agents).
 *     The Apify MCP server loads each Actor's input schema and turns it into one
 *     MCP tool, so the agent knows the exact arguments and return shape; transport
 *     moved SSE → Streamable HTTP on 2026-04-01. We follow the same contract: each
 *     tool declares an inputSchema; the whitelist (?tools=…) is the compliance
 *     control that keeps private-scraping actors physically uncallable. This file
 *     is the LOCAL, gate-enforcing counterpart of that remote whitelist.
 *     Refs: docs.apify.com/platform/integrations/mcp ; github.com/apify/apify-mcp-server
 *
 * The transport (stdio / Streamable HTTP plumbing) is intentionally NOT bundled
 * here so the module stays dependency-free and unit-testable: this file exports a
 * pure, synchronous tool REGISTRY + dispatcher. A thin transport adapter (or the
 * Apify MCP runtime) wires `listTools()` / `callTool()` to the wire. server_selftest.js
 * exercises the registry directly and proves the gate cannot be bypassed.
 *
 * No claim of being deployed. Wiring a live transport + Apify token is the
 * operator's last step.
 */

const { validateScope } = require('../shared/scope.js');
const { buildBrokerOptOutPlan } = require('../shared/aux/broker-optout.js');
const { buildTakedownPlan } = require('../shared/aux/takedown-letter.js');
const { toBundle } = require('../shared/enrich/stix-evidence.js');

const SERVER_NAME = 'mirrortrace-mcp';
const SERVER_VERSION = '1.0.0';

/**
 * ─────────────────────────────────────────────────────────────────────────────
 * THE WHITELIST IS THE RED LINE AT THE PROTOCOL LAYER.
 *
 * Apify's MCP server turns each whitelisted Actor's input schema into ONE MCP
 * tool an AI agent can call (--actors flag locally, or the hosted scope chooser).
 * A tool that is NOT in the list is not merely "discouraged" — it is ABSENT from
 * tools/list, so an agent literally has no tool to call. We make that the
 * enforcement point: prohibited capabilities (private-social scraping, follower
 * enumeration, people-search of strangers, live-location tracking) are NOT
 * present in TOOLS, by construction. There is no handler to reach.
 *
 * To make "absent by construction" a TESTABLE GUARANTEE rather than a hope, we
 * keep an explicit DENYLIST of capability names a non-compliant build might be
 * tempted to expose, and `assertWhitelistClean()` proves at load/test time that
 * NONE of them appear in the exposed tool set. The denylist documents the red
 * line; the freeze on TOOLS keeps the surface immutable at runtime.
 *
 * Refs (verified May 2026):
 *   docs.apify.com/platform/integrations/mcp  (Actor input schema -> MCP tool;
 *     the whitelist/scope chooser controls which Actors become tools)
 *   github.com/apify/apify-mcp-server          (--actors whitelist; aim for a
 *     small core tool set, ~10-15 tools)
 *   The MCP server moved SSE -> Streamable HTTP on 2026-04-01 (mcp.apify.com).
 * ───────────────────────────────────────────────────────────────────────────── */

/**
 * Capabilities that MUST NEVER be exposed as a tool. Each entry is a prohibited
 * actor/capability identity (and common aliases an agent or a careless operator
 * might reach for). The presence test below matches a denylisted name against a
 * tool name OR its description, so a tool cannot smuggle a prohibited capability
 * under an innocuous name either.
 */
const DENYLISTED_ACTORS = Object.freeze([
  'instagram-followers-scraper',
  'instagram-private-profile-scraper',
  'facebook-friends-scraper',
  'tiktok-follower-scraper',
  'people-search',
  'person-locator',
  'reverse-phone-lookup',
  'romantic-interest-finder',
  'live-location-tracker',
  'private-social-scraper',
  'stalkerware',
]);

/** Substrings that, in a tool name/description, indicate a prohibited capability. */
const PROHIBITED_CAPABILITY_PATTERNS = Object.freeze([
  /private[\s_-]?social/i,
  /follower[\s_-]?(scrap|enum)/i,
  /people[\s_-]?search/i,
  /reverse[\s_-]?phone/i,
  /(track|locate)[\s_-]?(a\s+)?(private\s+)?person/i,
  /live[\s_-]?location/i,
  /romanc|intima|girlfriend|boyfriend|dating[\s_-]?profile/i,
  /stalk/i,
]);

/**
 * Shared gate front-door for EVERY tool. We pass the agent's structured args AND
 * any free text straight into the canonical validateScope so the natural-language
 * intent scan (PROHIBITED_TEXT_PATTERNS) and the scope_type allow-list both run.
 * Returns the gate decision verbatim — handlers must check `.allowed`.
 *
 * Note we forward `freeText` (a field collectIntentText scans) so a laundered
 * stalking prompt smuggled into a tool call is rejected exactly as on the web path.
 */
function gateFor(args) {
  const a = args && typeof args === 'object' ? args : {};
  return validateScope({
    scope_type: a.scope_type,
    subject_label: a.subject_label,
    authorization_evidence_url: a.authorization_evidence_url,
    // Surface every URL bucket the gate knows so private-social hosts are blocked.
    target_urls: a.target_urls,
    start_urls: a.start_urls,
    targets: a.targets,
    // Intent-scan fields (collectIntentText): catch laundered stalking freeText.
    freeText: a.freeText,
    prompt: a.prompt,
    goal: a.goal,
    description: a.description,
    // Prohibited-analysis buckets.
    analysis: a.analysis,
    tasks: a.tasks,
  });
}

/** Uniform fail-closed refusal envelope returned to the agent when the gate rejects. */
function gateRefusal(toolName, gate) {
  return {
    ok: false,
    refused: true,
    tool: toolName,
    refused_by: 'shared/scope.js::validateScope',
    reasons: gate.reasons,
    violated_red_lines: gate.violated_red_lines,
    alternatives: gate.alternatives,
    note:
      'This MCP tool fails closed. The same canonical scope gate used by the web ' +
      'and actor paths rejected this request; no planner was invoked and no data ' +
      'was produced. The red lines cannot be bypassed via the tool layer.',
  };
}

/**
 * TOOL: audit_scope_check
 * Pre-flight: tell an agent whether a subject/intent is in-scope BEFORE it tries
 * anything else. This is the gate, surfaced as a callable tool. It NEVER produces
 * footprint data — it only returns the gate's allow/deny decision, so an agent
 * can self-check and pick a compliant path.
 */
function audit_scope_check(args) {
  const gate = gateFor(args);
  if (!gate.allowed) return gateRefusal('audit_scope_check', gate);
  return {
    ok: true,
    tool: 'audit_scope_check',
    allowed: true,
    scope_type: gate.scope_type,
    normalized: gate.normalized,
    note:
      'In scope. This tool only validates scope; it does not fetch, scrape, or ' +
      'produce any footprint data. Proceed via a compliant Apify audit actor.',
  };
}

/**
 * TOOL: plan_broker_optout
 * Self-only data-broker erasure plan (DeleteMe/Aura pattern), drafted from
 * listings the USER confirmed are about them. Gate runs here AND again inside
 * buildBrokerOptOutPlan (defence in depth); both must pass. Returns the planner's
 * own refusal envelope on any refusal (scope gate OR self-only rule).
 */
function plan_broker_optout(args) {
  const a = args && typeof args === 'object' ? args : {};
  // Front-door gate (fail closed before the planner even runs). The generic gate
  // requires ≥1 target; a broker opt-out's targets ARE the confirmed listing URLs,
  // so we synthesize them exactly as buildBrokerOptOutPlan does internally — this
  // keeps the front-door check meaningful (it still scans freeText / private-social
  // hosts) without spuriously failing on `no_targets`. The planner re-gates anyway.
  const listingUrls = Array.isArray(a.confirmed_listings)
    ? a.confirmed_listings
        .map((l) => (l && typeof l.listing_url === 'string' ? l.listing_url.trim() : ''))
        .filter(Boolean)
    : [];
  const gate = gateFor({
    ...a,
    target_urls: []
      .concat(a.target_urls || [])
      .concat(listingUrls.length ? listingUrls : ['https://example.invalid/self-broker-optout']),
  });
  if (!gate.allowed) return gateRefusal('plan_broker_optout', gate);

  // Reuse the existing planner. It re-gates internally and enforces SELF-ONLY,
  // so a public_figure/brand (which passes the generic gate) is still refused.
  const plan = buildBrokerOptOutPlan(
    {
      scope_type: a.scope_type,
      subject_label: a.subject_label,
      authorization_evidence_url: a.authorization_evidence_url,
      confirmed_listings: a.confirmed_listings,
    },
    a.now ? { now: a.now } : {},
  );

  if (plan && plan.allowed === false) {
    return {
      ok: false,
      refused: true,
      tool: 'plan_broker_optout',
      refused_by: 'shared/aux/broker-optout.js::buildBrokerOptOutPlan',
      refusal: plan.refusal,
      reasons: plan.reasons,
      violated_red_lines: plan.violated_red_lines,
      alternatives: plan.alternatives,
    };
  }
  return { ok: true, tool: 'plan_broker_optout', result: plan };
}

/**
 * TOOL: build_takedown_letter
 * Draft GDPR Art.17 RTBF / CCPA-delete erasure letters from the user's OWN audit
 * findings (module_events). Gate runs first; then reuse takedown-letter.js. Output
 * is an explicit TEMPLATE — nothing is sent. We also attach a STIX 2.1 evidence
 * bundle (reused toBundle) so the letter carries verifiable provenance.
 */
function build_takedown_letter(args) {
  const a = args && typeof args === 'object' ? args : {};
  const events = Array.isArray(a.events) ? a.events : [];
  // The targets of a takedown are the hosts in the user's own findings; the gate
  // requires ≥1 target, so we surface each event's source_url (and any explicit
  // target_urls) for the front-door scan. The intent scan still runs on freeText.
  const eventUrls = events
    .map((e) => (e && typeof e.source_url === 'string' ? e.source_url.trim() : ''))
    .filter(Boolean);
  const gate = gateFor({
    ...a,
    target_urls: []
      .concat(a.target_urls || [])
      .concat(eventUrls.length ? eventUrls : ['https://example.invalid/self-takedown']),
  });
  if (!gate.allowed) return gateRefusal('build_takedown_letter', gate);

  const plan = buildTakedownPlan({
    events,
    ownedHosts: Array.isArray(a.owned_hosts) ? a.owned_hosts : [],
    subjectName: typeof a.subject_label === 'string' ? a.subject_label : undefined,
  });
  const evidence_bundle = toBundle(events, a.now ? { now: a.now } : {});

  return {
    ok: true,
    tool: 'build_takedown_letter',
    scope_type: gate.scope_type,
    takedown_plan: plan,        // is_template:true inside; nothing sent
    evidence_bundle,            // STIX 2.1 (Art.17 provenance)
    note:
      'Erasure letters are a TEMPLATE drafted from your own findings under GDPR ' +
      'Art.17 / CCPA-delete. Verify and send them yourself; this tool sends nothing.',
  };
}

/**
 * TOOL: compliance_docs
 * A read-only, no-side-effect tool that returns the product's compliance posture:
 * the allowed scope enum, the red lines, the browser-only data-flow model, and
 * the identity-verification tiering. An agent can call this to understand WHY a
 * prohibited request will be refused before it makes one. Produces NO footprint
 * data and reaches no planner. (Whitelisted "docs" tool from the round directive.)
 */
function compliance_docs() {
  return {
    ok: true,
    tool: 'compliance_docs',
    server: { name: SERVER_NAME, version: SERVER_VERSION },
    allowed_scopes: ['self', 'consented', 'public_figure', 'brand', 'safety_evidence'],
    red_lines: [
      'No tracking of private individuals.',
      'No romance/gender/sexuality/intimacy inference.',
      'No private-social scraping (login-walled hosts blocked).',
      'No bypassing logins / captcha / rate-limits.',
      'Dual-use discovery only for self / public_figure, via the scope gate.',
    ],
    whitelist_is_the_red_line:
      'This MCP server exposes ONLY compliant tools. Prohibited capabilities ' +
      '(private-social scraping, follower enumeration, people-search of strangers, ' +
      'live-location) are ABSENT from the tool list, so an agent has no tool to call. ' +
      `Denylisted capabilities (proven absent by the self-test): ${DENYLISTED_ACTORS.join(', ')}.`,
    browser_only_data_flow:
      'The exposure report/graph (Part 2) is built TRANSIENTLY in the user\'s browser ' +
      'from their own findings and is NEVER persisted to a MirrorTrace server — no ' +
      'central honeypot. See docs/apify/exposure-map.md and docs/apify/mcp-whitelist-redline.md.',
    identity_verification_tiering: {
      low_sensitivity_no_verification: ['view scope-gated public name-search results', 'k-anonymity breach check'],
      sensitive_requires_one_click_oauth: ['pull + correlate PII into the dossier/graph', 'confirm data-broker listings', 'monitoring'],
      live_oauth_wired: false,
    },
    docs: [
      'docs/apify/mcp.md',
      'docs/apify/mcp-whitelist-redline.md',
      'docs/apify/exposure-map.md',
      'docs/apify/ingest.md',
      'docs/apify/standby.md',
    ],
    note: 'Read-only compliance descriptor. No scrape, no fetch, no footprint data produced.',
  };
}

/**
 * The MCP tool registry. Each entry mirrors the Apify-MCP contract: a name,
 * description, JSON-Schema inputSchema (so the agent knows the args), and a pure
 * handler. NO handler reaches its planner without `gateFor` passing first.
 */
const TOOLS = Object.freeze({
  compliance_docs: {
    name: 'compliance_docs',
    description:
      'Read-only compliance descriptor: the allowed scope enum, the red lines, the ' +
      'browser-only data-flow model, the identity-verification tiering, and the list ' +
      'of denylisted (physically absent) capabilities. Produces NO footprint data.',
    inputSchema: { type: 'object', additionalProperties: false, properties: {} },
    handler: compliance_docs,
  },
  audit_scope_check: {
    name: 'audit_scope_check',
    description:
      'Pre-flight compliance check: is this subject/intent in scope for a SELF / ' +
      'consented / public_figure / brand / safety_evidence audit? Returns the ' +
      'canonical scope-gate decision only — never any footprint data. Call this ' +
      'first; it rejects private-person tracking and laundered stalking prompts.',
    inputSchema: {
      type: 'object',
      additionalProperties: true,
      required: ['scope_type'],
      properties: {
        scope_type: {
          type: 'string',
          enum: ['self', 'consented', 'public_figure', 'brand', 'safety_evidence'],
          description: 'The ONLY permitted scope types. Anything else is refused.',
        },
        subject_label: { type: 'string', description: 'Plain label for the audit subject (e.g. your name).' },
        authorization_evidence_url: {
          type: 'string',
          description: 'Required when scope_type="consented": URL to written consent.',
        },
        target_urls: { type: 'array', items: { type: 'string' }, description: 'Public URLs to audit.' },
        freeText: { type: 'string', description: 'Free-text goal; scanned for prohibited intent.' },
      },
    },
    handler: audit_scope_check,
  },
  plan_broker_optout: {
    name: 'plan_broker_optout',
    description:
      'SELF-ONLY data-broker opt-out plan (DeleteMe/Aura pattern). Drafts GDPR ' +
      'Art.17 erasure routes for people-search listings the USER CONFIRMED are ' +
      'about them. Refused for public_figure/brand/other and never scrapes brokers.',
    inputSchema: {
      type: 'object',
      additionalProperties: true,
      required: ['scope_type'],
      properties: {
        scope_type: {
          type: 'string',
          enum: ['self', 'consented'],
          description: 'Broker opt-out is first-person erasure: self only (or consented w/ authorization).',
        },
        subject_label: { type: 'string', description: 'Your name, for the erasure letter.' },
        authorization_evidence_url: {
          type: 'string',
          description: 'Required when scope_type="consented" (the DeleteMe "authorization" step).',
        },
        confirmed_listings: {
          type: 'array',
          description: 'Listings YOU confirmed are about you: [{broker_id, listing_url, confirmed_self:true}].',
          items: {
            type: 'object',
            properties: {
              broker_id: { type: 'string' },
              listing_url: { type: 'string' },
              confirmed_self: { type: 'boolean' },
            },
          },
        },
      },
    },
    handler: plan_broker_optout,
  },
  build_takedown_letter: {
    name: 'build_takedown_letter',
    description:
      'Draft GDPR Art.17 RTBF / CCPA-delete erasure letters (a TEMPLATE) from YOUR ' +
      'OWN audit findings, with a STIX 2.1 evidence bundle for provenance. Sends ' +
      'nothing. Gate-checked: refused for prohibited scope or laundered intent.',
    inputSchema: {
      type: 'object',
      additionalProperties: true,
      required: ['scope_type'],
      properties: {
        scope_type: {
          type: 'string',
          enum: ['self', 'consented', 'public_figure', 'brand', 'safety_evidence'],
        },
        subject_label: { type: 'string', description: 'Your name, for the letter.' },
        events: {
          type: 'array',
          description: 'module_event objects from YOUR audit (shared/detectors shape).',
          items: { type: 'object' },
        },
        owned_hosts: {
          type: 'array',
          items: { type: 'string' },
          description: 'Hosts you control (routed to self-remediation, not a third-party letter).',
        },
      },
    },
    handler: build_takedown_letter,
  },
});

/** MCP `tools/list`: the agent-visible catalogue (name/description/inputSchema). */
function listTools() {
  return Object.values(TOOLS).map(({ name, description, inputSchema }) => ({
    name,
    description,
    inputSchema,
  }));
}

/**
 * MCP `tools/call` dispatcher. Unknown tool → fail closed. Any handler throw is
 * caught and returned as a structured error (the gate itself never throws, but a
 * malformed planner input must not crash the server).
 */
function callTool(name, args) {
  const tool = TOOLS[name];
  if (!tool) {
    return {
      ok: false,
      refused: true,
      tool: String(name),
      refused_by: 'mcp/server.js::callTool',
      reasons: [`Unknown MCP tool "${name}". This server exposes only: ${Object.keys(TOOLS).join(', ')}.`],
      note: 'Fail-closed: an unrecognized tool is never silently allowed.',
    };
  }
  try {
    return tool.handler(args);
  } catch (err) {
    return {
      ok: false,
      tool: name,
      error: 'handler_threw',
      message: err && err.message ? err.message : String(err),
      note: 'The tool errored on malformed input; no data was produced.',
    };
  }
}

/**
 * PROVE THE WHITELIST IS CLEAN. Scans the EXPOSED tool surface (names +
 * descriptions) and asserts that NO denylisted capability is present. Returns
 * { clean:true, exposed:[...] } or throws with the offending tool — so a future
 * edit that tries to add a private-scraping tool fails at load/test time, not in
 * production. This is the runtime counterpart of Apify's --actors whitelist:
 * the red line is enforced at the protocol layer, by ABSENCE.
 *
 * @param {object} [tools] tool registry to check (defaults to the real TOOLS)
 * @returns {{ clean: true, exposed: string[], denylisted: string[] }}
 */
function assertWhitelistClean(tools = TOOLS) {
  const exposed = Object.values(tools);
  for (const t of exposed) {
    const name = String(t.name || '');
    const lname = name.toLowerCase();
    // The enforcement target is the tool's IDENTITY (its name) — that is what an
    // agent calls. A compliant tool's DESCRIPTION may legitimately reference a
    // prohibited capability in order to REFUSE or REMEDIATE it (e.g. broker
    // opt-out removes "people-search listings"; compliance_docs names the red
    // lines). So we flag on the NAME, not on prose inside the description.
    // (a) exact denylisted capability identity as the tool name (or a segment of it)
    for (const deny of DENYLISTED_ACTORS) {
      const d = deny.toLowerCase();
      if (lname === d || lname.includes(d)) {
        throw new Error(
          `whitelist violation: tool "${name}" exposes denylisted capability "${deny}". ` +
            'Prohibited capabilities must be ABSENT from the MCP tool surface.',
        );
      }
    }
    // (b) prohibited-capability language in the tool NAME (smuggling under an
    //     innocuous-looking-but-not name).
    for (const re of PROHIBITED_CAPABILITY_PATTERNS) {
      if (re.test(name)) {
        throw new Error(
          `whitelist violation: tool name "${name}" matches a prohibited-capability pattern ${re}.`,
        );
      }
    }
  }
  return {
    clean: true,
    exposed: exposed.map((t) => t.name),
    denylisted: DENYLISTED_ACTORS.slice(),
  };
}

/**
 * Is a given (hypothetical) actor/capability name on the denylist? Helper for an
 * operator wiring the real Apify MCP server's --actors flag: never pass a name
 * this returns true for.
 */
function isDenylistedActor(name) {
  if (typeof name !== 'string') return false;
  const n = name.toLowerCase();
  if (DENYLISTED_ACTORS.some((d) => n.includes(d.toLowerCase()))) return true;
  return PROHIBITED_CAPABILITY_PATTERNS.some((re) => re.test(name));
}

// FAIL-CLOSED AT LOAD: if the registry ever ships a prohibited tool, requiring
// this module throws — the server cannot start with a dirty whitelist.
assertWhitelistClean();

module.exports = {
  SERVER_NAME,
  SERVER_VERSION,
  TOOLS,
  listTools,
  callTool,
  // The red line at the protocol layer: prohibited capabilities are ABSENT.
  DENYLISTED_ACTORS,
  PROHIBITED_CAPABILITY_PATTERNS,
  assertWhitelistClean,
  isDenylistedActor,
  // Exposed for the self-test to prove handlers reuse (not re-implement) the gate/planners.
  _internals: { gateFor, audit_scope_check, plan_broker_optout, build_takedown_letter, compliance_docs },
};
