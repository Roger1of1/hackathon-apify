/**
 * integrations/exposure-map/exposure-graph.js
 *
 * THE #1 DELIVERABLE'S DATA LAYER — the pure function that turns REAL detector
 * module_events (the output of the Apify ingest pipeline) into the EXPOSURE MAP
 * graph the browser renders in "Part 2": a radial node graph where the CENTER is
 * "you" and every surrounding node is ONE source/site that exposes information
 * about you. This file produces ONLY the graph data shape; rendering (SVG,
 * layout, colours, motion) lives in the web/ subtree (Codex/UI agent owns it).
 * We hand the front-end an honest, already-computed structure so the UI never
 * has to re-derive severity or correlation — those come from the SAME canonical
 * modules every other surface uses.
 *
 * ── WHAT EACH PART OF THE GRAPH MEANS (locked product spec) ──────────────────
 *   center node     : "you" (the self subject). id = "self".
 *   source node     : one host/site that exposes info about you. id = "src:<host>".
 *   node.color_tier : green | yellow | red  — derived from the finding severity
 *                     band (shared/enrich/severity.js), NEVER a new scoring axis:
 *                       red    = critical|high   (email+phone+address / breach-grade)
 *                       yellow = medium
 *                       green  = low|info        (only public trivia)
 *                     A source node's tier is its WORST finding's tier (one red
 *                     finding makes the whole source red — that is the honest,
 *                     scary truth a first-time visitor must grasp in seconds).
 *   node.size       : how much info that source holds about you = the count of
 *                     DISTINCT findings at that source (radius is a UI concern;
 *                     we emit the raw count + a normalized 0..1 weight).
 *   edge (radial)   : center -> each source node. kind = "exposes".
 *   edge (correlate): source <-> source when they SHARE THE SAME IDENTIFIER
 *                     (same email / handle / leaked secret), reusing the canonical
 *                     shared/enrich/cluster-keys.js. kind = "correlates". These
 *                     cross-source edges are the SpiderFoot/Maltego "this is all
 *                     the same person" picture — the most important insight Part 2
 *                     delivers, and the reason a calm static radial layout beats a
 *                     bouncy physics sim (the edges, not motion, carry the meaning).
 *
 * ── ZERO DUPLICATION — reuse, never re-implement ─────────────────────────────
 *   - shared/enrich/severity.js     → rankBySeverity / bandFor (the ONE severity model)
 *   - shared/enrich/cluster-keys.js → buildKeyIndex / clusterKeysFor (correlation keys)
 *   - shared/detectors/event-types.js → isModuleEvent (frozen-vocabulary guard)
 * There is NO severity math and NO correlation math in this file; we only fold
 * already-computed signals into nodes + edges.
 *
 * ── REFERENCE ARCHITECTURES (cited, borrowed — not reinvented) ───────────────
 *  1) Maltego / SpiderFoot entity-link graphs. Both visualise OSINT as ENTITIES
 *     (hosts, accounts, emails) linked by SHARED-IDENTITY edges; a node's "weight"
 *     reflects how many observations attach to it. We mirror that exactly: source
 *     nodes are entities keyed by host, correlation edges are shared-identifier
 *     links, node size = observation count. We do NOT borrow their free-form
 *     person-pivoting — every node here is a public SURFACE about the SELF subject,
 *     never a third party (the red line lives one layer up in the gate, but this
 *     layer also refuses to mint a node for anything that is not a self finding).
 *     Refs: docs.maltego.com (entity/link model) ; github.com/smicallef/spiderfoot
 *           (correlation engine: events sharing an entity are linked).
 *  2) The Markup's Blacklight (privacy inspector report). Blacklight turns a scan
 *     into a small, plain, ranked list a non-expert grasps immediately. We keep
 *     that "clarity first" stance: every node carries a one-line `why` and a
 *     `suggested_action`, and the graph degrades to the SAME ranked list (the UI
 *     "切换查看" fallback) because the list IS the accessible primary view.
 *     Ref: themarkup.org/blacklight.
 *
 * ── BROWSER-ONLY DATA FLOW (locked privacy decision) ─────────────────────────
 * This module is loadable in TWO ways and is otherwise IDENTICAL:
 *   - Node:   const { buildExposureGraph } = require('./exposure-graph.js')
 *   - Browser <script>: sets window.MirrorTrace.buildExposureGraph (file://-safe,
 *     no bundler, no framework, no CDN). The graph is therefore built TRANSIENTLY
 *     IN THE BROWSER from the user's own findings and is NEVER persisted to a
 *     server. This file performs ZERO I/O and ZERO network — it is a pure
 *     transform, which is exactly what makes "build the dossier in the browser and
 *     purge it on tab close" enforceable: there is no code path here that could
 *     write the graph anywhere. (See docs/apify/exposure-map.md.)
 *
 * NO FAKE DATA: every node/edge is derived from a REAL module_event passed in. If
 * given zero events, it returns an empty-but-honest graph (just the center node),
 * never a demo dossier.
 */

'use strict';

/* ──────────────────────────────────────────────────────────────────────────
 * Dependency resolution that works in BOTH Node (require) and the browser.
 * In the browser, the UI agent loads the three shared modules first (as
 * window.MirrorTrace.{severity,clusterKeys,eventTypes} or equivalent globals);
 * here we resolve from require() when available, else from the global. We never
 * re-implement the math — if a dep is missing we fail loudly rather than guess.
 * ────────────────────────────────────────────────────────────────────────── */
function resolveDeps() {
  if (typeof require === 'function') {
    try {
      return {
        rankBySeverity: require('../../shared/enrich/severity.js').rankBySeverity,
        bandFor: require('../../shared/enrich/severity.js').bandFor,
        clusterKeysFor: require('../../shared/enrich/cluster-keys.js').clusterKeysFor,
        isModuleEvent: require('../../shared/detectors/event-types.js').isModuleEvent,
      };
    } catch (_) {
      /* fall through to global resolution (browser file://) */
    }
  }
  const g = (typeof window !== 'undefined' && window.MirrorTrace) || {};
  const sev = g.severity || {};
  const ck = g.clusterKeys || {};
  const et = g.eventTypes || {};
  return {
    rankBySeverity: sev.rankBySeverity,
    bandFor: sev.bandFor,
    clusterKeysFor: ck.clusterKeysFor,
    isModuleEvent: et.isModuleEvent || ((e) => !!(e && typeof e === 'object' && typeof e.event_type === 'string')),
  };
}

/** Map a severity BAND (critical|high|medium|low|info) to the 3 node colour tiers. */
function bandToTier(band) {
  switch (band) {
    case 'critical':
    case 'high':
      return 'red'; // sensitive: email+phone+address / breach-grade
    case 'medium':
      return 'yellow';
    case 'low':
    case 'info':
    default:
      return 'green'; // only low/public trivia
  }
}

/** Rank order so a source node can take its WORST finding's tier. */
const TIER_RANK = Object.freeze({ green: 0, yellow: 1, red: 2 });

/** Lower-cased hostname of a URL, or a stable fallback label. Never throws. */
function hostOf(url) {
  if (typeof url !== 'string' || !url) return null;
  try {
    const h = new URL(url).hostname.toLowerCase();
    return h || null;
  } catch {
    return null;
  }
}

/**
 * A short, non-PII "why it matters" line for a finding, from frozen vocabulary
 * only (event_type / risk / visibility). We do NOT echo the raw leaked value.
 */
function whyForEvent(ev) {
  const risk = String(ev.risk || '').toLowerCase();
  const vis = String(ev.visibility || '').toLowerCase();
  const indexed = vis === 'indexed' ? 'search-engine indexed' : vis === 'linked' ? 'publicly linked' : 'public';
  const type = String(ev.event_type || 'exposure').replace(/_/g, ' ').toLowerCase();
  return `${type} — ${risk || 'public'} risk, ${indexed}`;
}

/**
 * buildExposureGraph(events, opts) -> { nodes, edges, summary }
 *
 * @param {object[]} events  REAL module_events (e.g. from the Apify ingest pipeline)
 * @param {object} [opts]
 * @param {string} [opts.subjectLabel]  label for the center "you" node (no PII required)
 * @param {object} [opts.integrityByUrl] forwarded to severity for evidence quality
 * @param {object} [opts.deps]  test-injectable {rankBySeverity,bandFor,clusterKeysFor,isModuleEvent}
 * @returns {{
 *   center: object,
 *   nodes: object[],        // includes the center node first
 *   edges: object[],        // "exposes" (center->source) + "correlates" (source<->source)
 *   summary: object,        // headline counts the UI shows above the map
 *   __privacy: string,      // the browser-only banner the UI must surface
 * }}
 *
 * Pure. No I/O. Deterministic for a given event set.
 */
function buildExposureGraph(events, opts = {}) {
  const deps = opts.deps || resolveDeps();
  const { rankBySeverity, bandFor, clusterKeysFor, isModuleEvent } = deps;
  if (typeof rankBySeverity !== 'function' || typeof clusterKeysFor !== 'function') {
    throw new Error(
      'exposure-graph: canonical deps (shared/enrich/severity.js, cluster-keys.js) not resolvable. ' +
        'Load them before this module in the browser, or require() in Node.',
    );
  }

  const subjectLabel = typeof opts.subjectLabel === 'string' && opts.subjectLabel.trim()
    ? opts.subjectLabel.trim()
    : 'You';

  const center = {
    id: 'self',
    role: 'center',
    label: subjectLabel,
    color_tier: 'green',
    is_subject: true,
  };

  const valid = (Array.isArray(events) ? events : []).filter(isModuleEvent);

  // Empty-but-honest graph: just the center, no fabricated sources.
  if (valid.length === 0) {
    return {
      center,
      nodes: [center],
      edges: [],
      summary: { source_count: 0, finding_count: 0, red: 0, yellow: 0, green: 0, correlated_sources: 0 },
      __privacy:
        'Built in your browser from your own findings. Nothing here is sent to or stored on a server; ' +
        'it is purged when you close this tab.',
    };
  }

  // ── 1) Rank with the canonical severity model (gives each event a band) ─────
  const ranked = rankBySeverity(valid, { integrityByUrl: opts.integrityByUrl || {} });

  // ── 2) Group findings by SOURCE host -> one node per source ─────────────────
  // We keep a stable index per event so cluster-key correlation can map an event
  // back to its source node.
  const sourceByHost = new Map(); // host -> node accumulator
  const hostByEventIndex = [];     // ranked index -> host (or null)

  ranked.forEach((ev, i) => {
    const host = hostOf(ev.source_url) || 'unknown-source';
    hostByEventIndex[i] = host;
    if (!sourceByHost.has(host)) {
      sourceByHost.set(host, {
        id: `src:${host}`,
        role: 'source',
        host,
        label: host,
        findings: [],
        worst_tier: 'green',
        worst_band: 'info',
      });
    }
    const node = sourceByHost.get(host);
    const sev = ev._severity || { band: 'info' };
    const tier = bandToTier(sev.band);
    if (TIER_RANK[tier] > TIER_RANK[node.worst_tier]) {
      node.worst_tier = tier;
      node.worst_band = sev.band;
    }
    node.findings.push({
      event_type: ev.event_type,
      source_module: ev.source_module || null,
      risk: ev.risk || null,
      visibility: ev.visibility || null,
      confidence: Number.isFinite(ev.confidence) ? ev.confidence : null,
      source_url: ev.source_url || null,
      severity_band: sev.band,
      severity: sev.severity != null ? sev.severity : null,
      tier,
      why: whyForEvent(ev),
    });
  });

  // ── 3) Finalize source nodes: size = distinct finding count, normalized 0..1 ─
  const sourceNodes = Array.from(sourceByHost.values());
  const maxFindings = sourceNodes.reduce((m, n) => Math.max(m, n.findings.length), 1);
  for (const n of sourceNodes) {
    n.color_tier = n.worst_tier;
    n.finding_count = n.findings.length;
    n.size_weight = n.finding_count / maxFindings; // 0..1; UI maps to radius
    // Suggested action follows tier (Blacklight-style plain remediation hint).
    n.suggested_action =
      n.worst_tier === 'red'
        ? 'High-sensitivity exposure here — prioritize a takedown / data-broker opt-out for this source.'
        : n.worst_tier === 'yellow'
          ? 'Medium exposure — review what this source publishes and tighten or request removal.'
          : 'Low/public trivia — usually fine, but confirm it is information you intend to be public.';
  }
  // Stable, meaningful order: worst tier first, then most findings — so the UI's
  // radial rings (severity rings) and the list fallback agree, calm and deterministic.
  sourceNodes.sort((a, b) => {
    const t = TIER_RANK[b.color_tier] - TIER_RANK[a.color_tier];
    if (t !== 0) return t;
    if (b.finding_count !== a.finding_count) return b.finding_count - a.finding_count;
    return a.host < b.host ? -1 : a.host > b.host ? 1 : 0;
  });

  // ── 4) Radial edges: center -> each source ──────────────────────────────────
  const edges = sourceNodes.map((n) => ({
    id: `exposes:self->${n.id}`,
    source: 'self',
    target: n.id,
    kind: 'exposes',
    tier: n.color_tier,
  }));

  // ── 5) Correlation edges: source <-> source sharing the SAME identifier ──────
  // Reuse cluster-keys: for each event, its keys (host:/handle:/email_prefix:/
  // secret_fp:) tell us which identifiers it carries. We IGNORE host: keys for
  // correlation (every event trivially shares its own host); the SCARY signal is
  // two DIFFERENT sources sharing the SAME email/handle/secret.
  const sharedKeyToHosts = new Map(); // identifier-key -> Set(host)
  ranked.forEach((ev, i) => {
    const host = hostByEventIndex[i];
    const keys = clusterKeysFor(ev) || [];
    for (const k of keys) {
      if (k.indexOf('host:') === 0) continue; // skip the self-host key
      if (!sharedKeyToHosts.has(k)) sharedKeyToHosts.set(k, new Set());
      sharedKeyToHosts.get(k).add(host);
    }
  });

  const correlationEdges = [];
  const seenPair = new Set();
  for (const [key, hosts] of sharedKeyToHosts.entries()) {
    if (hosts.size < 2) continue; // a shared identifier needs >=2 distinct sources
    const list = Array.from(hosts).sort();
    const keyKind = key.split(':')[0]; // handle | email_prefix | secret_fp
    for (let a = 0; a < list.length; a += 1) {
      for (let b = a + 1; b < list.length; b += 1) {
        const ha = list[a];
        const hb = list[b];
        const pairId = `${ha}|${hb}|${keyKind}`;
        if (seenPair.has(pairId)) continue;
        seenPair.add(pairId);
        correlationEdges.push({
          id: `correlates:${pairId}`,
          source: `src:${ha}`,
          target: `src:${hb}`,
          kind: 'correlates',
          shared: keyKind, // what kind of identifier is shared (never the value)
        });
      }
    }
  }

  const allEdges = edges.concat(correlationEdges);

  // Headline counts for the calm summary line above the map.
  let red = 0;
  let yellow = 0;
  let green = 0;
  for (const n of sourceNodes) {
    if (n.color_tier === 'red') red += 1;
    else if (n.color_tier === 'yellow') yellow += 1;
    else green += 1;
  }
  const correlatedSources = new Set();
  for (const e of correlationEdges) {
    correlatedSources.add(e.source);
    correlatedSources.add(e.target);
  }

  return {
    center,
    nodes: [center].concat(sourceNodes),
    edges: allEdges,
    summary: {
      source_count: sourceNodes.length,
      finding_count: valid.length,
      red,
      yellow,
      green,
      correlation_edges: correlationEdges.length,
      correlated_sources: correlatedSources.size,
    },
    __privacy:
      'Built in your browser from your own findings. Nothing here is sent to or stored on a server; ' +
      'it is purged when you close this tab.',
  };
}

/* ── Dual export: Node require() AND browser window.MirrorTrace ─────────────── */
const api = { buildExposureGraph, bandToTier, hostOf };

if (typeof module !== 'undefined' && module.exports) {
  module.exports = api;
}
if (typeof window !== 'undefined') {
  window.MirrorTrace = window.MirrorTrace || {};
  window.MirrorTrace.buildExposureGraph = buildExposureGraph;
  window.MirrorTrace.exposureGraph = api;
}
