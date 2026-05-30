/**
 * shared/graph/build-exposure-graph.js
 *
 * PURE, DETERMINISTIC builder that turns a produced self-audit REPORT (the shape
 * in web/data/example-report.json) into the EXPOSURE MAP model the web "Part 2"
 * radial node graph renders: a center "you" node, one node per distinct source
 * host, center->source `exposes` edges, and cross-source `shared-identifier`
 * edges wherever two hosts expose the SAME identifier (same email/handle).
 *
 * WHY A SEPARATE BUILDER (not just the existing report grouping):
 *   The grouped-findings LIST (shared/enrich/report-groups.js) buckets by KIND of
 *   exposure. The Exposure Map buckets by SOURCE (where you are exposed) and adds
 *   the scary cross-source correlation picture. This is the entity-link view, not
 *   the category view. Both are second lenses on the SAME real findings.
 *
 * REFERENCE ARCHITECTURES (borrowed patterns, cited honestly):
 *   - Maltego entity-link graphs: a central ENTITY ("you") radiating to the
 *     SURFACES/transforms that hold data about it; clicking an entity reveals its
 *     details. We mirror that center+spokes topology and per-node detail refs.
 *       https://docs.maltego.com/support/solutions/articles/15000019166
 *   - SpiderFoot 4.0 correlation engine: events that reference the SAME entity are
 *     LINKED. Our `shared-identifier` edges are exactly that link, computed by
 *     REUSING shared/enrich/cluster-keys.js (the same honest key extractor the
 *     correlation pass uses) — we never invent a new identity join.
 *       https://github.com/smicallef/spiderfoot
 *   - The Markup's Blacklight report framing: severity is shown plainly so a
 *     first-time visitor grasps "how bad / how findable" at a glance; node COLOR =
 *     severity tier, node SIZE = how much that source holds.
 *       https://themarkup.org/blacklight
 *
 * HONESTY / RED LINES:
 *   - No network, no fake data. Operates ONLY on the findings handed in. An empty
 *     report yields the center node only (no fabricated spokes).
 *   - Cross-source links are ENTITY/SURFACE links (email_prefix / handle), never a
 *     person/relationship/intimacy/location inference. The only join keys are the
 *     ones cluster-keys.js can emit, by construction.
 *   - Severity tiers map from the report's own severity_band/risk — we do not
 *     invent a parallel scoring axis.
 *
 * Pure functions, no mutation of inputs. Safe to require at load (used in-browser
 * via the web layer and in node via the self-test).
 */

'use strict';

const { hostOf, clusterKeysFor, normalizeHandle } = require('../enrich/cluster-keys.js');
const { eventSeverity, bandFor } = require('../enrich/severity.js');
const { isModuleEvent } = require('../detectors/event-types.js');
const { emailHashKey } = require('../aux/kanon.js');

/**
 * Map a report's severity_band (or, as a fallback, a finding risk) onto the three
 * visual tiers the map uses. critical/high -> red, medium -> yellow,
 * low/info -> green. This is a pure presentation projection of the SAME band the
 * grade/severity pipeline already produced — not a new scoring axis.
 */
const BAND_TO_TIER = Object.freeze({
  critical: 'red',
  high: 'red',
  medium: 'yellow',
  low: 'green',
  info: 'green',
});

const RISK_TO_BAND = Object.freeze({
  high: 'high',
  medium: 'medium',
  low: 'low',
  info: 'info',
});

// Numeric rank so a node's tier = the WORST tier among its findings, and so we
// can order nodes deterministically by severity.
const TIER_RANK = Object.freeze({ green: 0, yellow: 1, red: 2 });

function tierForBand(band) {
  return BAND_TO_TIER[band] || 'green';
}

/**
 * Normalize a raw REPORT finding (which lacks record_type/meta — see
 * web/data/example-report.json) into the canonical module_event shape so we can
 * REUSE the shared severity + cluster-key extractors honestly instead of forking
 * their logic. We only fill fields that are genuinely present on the finding; we
 * never invent data.
 *
 * @param {object} f a report finding
 * @returns {object|null} a module_event-shaped object, or null if unusable
 */
function findingToEvent(f) {
  if (!f || typeof f !== 'object' || typeof f.event_type !== 'string') return null;
  // Already a full module_event? pass it through untouched.
  if (isModuleEvent(f)) return f;
  return {
    record_type: 'module_event',
    event_type: f.event_type,
    source_module: typeof f.source_module === 'string' ? f.source_module : 'report',
    data: f.data === undefined ? null : f.data,
    confidence: Number.isFinite(f.confidence) ? f.confidence : 0.5,
    visibility: typeof f.visibility === 'string' ? f.visibility : 'linked',
    risk: typeof f.risk === 'string' ? f.risk : 'low',
    source_url: typeof f.source_url === 'string' ? f.source_url : null,
    meta: f.meta && typeof f.meta === 'object' ? f.meta : {},
  };
}

/**
 * The stable node id ("source key") a finding belongs to. Findings with a real
 * URL group by HOST (the public surface they live on). Hostless findings — e.g. a
 * BREACH_RANGE_HIT, which by design has no source_url because it is a k-anonymity
 * range hit, not a page — get a stable synthetic source keyed by their detector
 * module, so the exposure still appears as its own node instead of vanishing.
 *
 * @returns {{ id:string, host:string|null, label:string, kind:'host'|'origin' }}
 */
function sourceOf(ev) {
  const host = hostOf(ev.source_url);
  if (host) {
    return { id: `host:${host}`, host, label: host, kind: 'host' };
  }
  const mod = ev.source_module || 'origin';
  // A hostless origin (breach range, etc.). Labelled plainly so a first-time
  // viewer understands it's a source even without a web address.
  return { id: `origin:${mod}`, host: null, label: ORIGIN_LABELS[mod] || mod, kind: 'origin' };
}

const ORIGIN_LABELS = Object.freeze({
  breach_range_detector: 'Breach database (k-anonymity)',
  breach_detector: 'Breach database',
});

/**
 * Identifier keys a finding contributes that can LINK two sources together. We
 * deliberately keep only the cross-surface identity keys — email_prefix and
 * handle — and DROP host/secret keys for the linking step: host is the node
 * itself (linking by host would just be the same node), and a secret fingerprint
 * is a credential artifact rather than an identity that ties your accounts
 * together. The keys come straight from the canonical cluster-keys extractor.
 *
 * As a graceful fallback, when a PII_EMAIL_PUBLIC finding carries the plaintext
 * email in `data` (and no meta prefix), we derive the SAME k-anonymity prefix via
 * the shared kanon helper, so two sources publishing the same address still link
 * without us ever storing the address.
 */
function identifierKeysOf(ev) {
  const keys = clusterKeysFor(ev).filter((k) => k.startsWith('email_prefix:') || k.startsWith('handle:'));
  // Fallback: plaintext email in data but no prefix surfaced by cluster-keys.
  if (ev.event_type === 'PII_EMAIL_PUBLIC'
      && typeof ev.data === 'string'
      && ev.data.includes('@')
      && !keys.some((k) => k.startsWith('email_prefix:'))) {
    const p = emailHashKey(ev.data).email_hash_prefix;
    if (p) keys.push(`email_prefix:${p}`);
  }
  // De-dup, stable order.
  return Array.from(new Set(keys)).sort();
}

/**
 * Build the Exposure Map model from a produced report.
 *
 * @param {object} report a self-audit report (see web/data/example-report.json)
 * @param {object} [opts]
 * @param {string} [opts.selfLabel='You'] center node label
 * @returns {{
 *   center: { id:'self', label:string },
 *   nodes: Array<{
 *     id:string, host:string|null, label:string,
 *     severityTier:'green'|'yellow'|'red', severityScore:number,
 *     infoCount:number, eventTypes:string[], findingRefs:number[]
 *   }>,
 *   edges: Array<{ from:string, to:string, kind:'exposes'|'shared-identifier', via?:string }>,
 *   legend: object,
 *   meta: object
 * }}
 */
function buildExposureGraph(report, opts = {}) {
  const selfLabel = (opts && typeof opts.selfLabel === 'string' && opts.selfLabel) || 'You';
  const center = { id: 'self', label: selfLabel };

  const findings = report && Array.isArray(report.findings) ? report.findings : [];

  // Group findings by source. We keep the ORIGINAL finding index (position in
  // report.findings) as findingRefs so the web detail panel can render the exact
  // real finding back from report.findings[ref] — no duplication of finding data
  // into the graph model.
  const bySource = new Map(); // sourceId -> aggregate
  // identifier key -> Set(sourceId) for the cross-source link step.
  const keyToSources = new Map();

  findings.forEach((f, idx) => {
    const ev = findingToEvent(f);
    if (!ev) return;
    const src = sourceOf(ev);

    let agg = bySource.get(src.id);
    if (!agg) {
      agg = {
        id: src.id,
        host: src.host,
        label: src.label,
        kind: src.kind,
        findingRefs: [],
        eventTypes: new Set(),
        worstBandRank: -1,
        worstBand: 'info',
        maxSeverity: 0,
      };
      bySource.set(src.id, agg);
    }

    agg.findingRefs.push(idx);
    agg.eventTypes.add(ev.event_type);

    // Worst severity_band on this source decides its tier (a source is as scary
    // as its scariest finding). Prefer the report's own band; fall back to risk.
    const band = bandOf(f, ev);
    const r = TIER_RANK[tierForBand(band)];
    if (r > agg.worstBandRank) {
      agg.worstBandRank = r;
      agg.worstBand = band;
    }

    // severityScore: reuse the canonical per-event severity model so the map and
    // the list rank exposures the SAME way. Node score = its worst finding.
    const sev = eventSeverity(ev).severity;
    if (sev > agg.maxSeverity) agg.maxSeverity = sev;

    // Record which identifier keys this source touches, for cross-links.
    for (const k of identifierKeysOf(ev)) {
      if (!keyToSources.has(k)) keyToSources.set(k, new Set());
      keyToSources.get(k).add(src.id);
    }
  });

  // Materialize nodes. infoCount = distinct findings at that source.
  const nodes = [];
  for (const agg of bySource.values()) {
    nodes.push({
      id: agg.id,
      host: agg.host,
      label: agg.label,
      kind: agg.kind,
      severityTier: tierForBand(agg.worstBand),
      severityScore: Math.round(agg.maxSeverity),
      infoCount: agg.findingRefs.length,
      eventTypes: Array.from(agg.eventTypes).sort(),
      findingRefs: agg.findingRefs.slice().sort((a, b) => a - b),
    });
  }

  // Deterministic ordering: severityScore desc, then host/label asc.
  nodes.sort((a, b) =>
    (b.severityScore - a.severityScore)
    || String(a.host || a.label).localeCompare(String(b.host || b.label))
    || a.id.localeCompare(b.id));

  // Edges. Center -> each source (exposes).
  const edges = nodes.map((n) => ({ from: 'self', to: n.id, kind: 'exposes' }));

  // Cross-source shared-identifier edges: any identifier key touched by >=2
  // distinct sources links those sources pairwise. Deterministic, de-duplicated,
  // undirected (stored from<to by id). `via` names the shared key kind for the
  // detail panel ("same email" / "same handle") without leaking the value.
  const seenPair = new Set();
  const sharedEdges = [];
  const sortedKeys = Array.from(keyToSources.keys()).sort();
  for (const key of sortedKeys) {
    const srcIds = Array.from(keyToSources.get(key)).sort();
    if (srcIds.length < 2) continue;
    const viaKind = key.startsWith('email_prefix:') ? 'email' : 'handle';
    for (let i = 0; i < srcIds.length; i += 1) {
      for (let j = i + 1; j < srcIds.length; j += 1) {
        const a = srcIds[i];
        const b = srcIds[j];
        const pairId = `${a}|${b}|${viaKind}`;
        if (seenPair.has(pairId)) continue;
        seenPair.add(pairId);
        sharedEdges.push({ from: a, to: b, kind: 'shared-identifier', via: viaKind });
      }
    }
  }
  // Stable order for shared edges.
  sharedEdges.sort((x, y) =>
    x.from.localeCompare(y.from) || x.to.localeCompare(y.to) || x.via.localeCompare(y.via));
  edges.push(...sharedEdges);

  const legend = buildLegend(nodes);

  return {
    center,
    nodes,
    edges,
    legend,
    meta: {
      generated_at: report && report.generated_at ? report.generated_at : null,
      source_count: nodes.length,
      finding_count: findings.length,
      shared_identifier_links: sharedEdges.length,
      // honest provenance so the UI can show "this map is built from N real findings"
      built_by: 'shared/graph/build-exposure-graph.js',
      reference_patterns: ['maltego-entity-link', 'spiderfoot-correlation', 'blacklight-report'],
    },
  };
}

/** The severity_band for a finding: trust the report's own band, else derive
 * from risk (so the builder still works on findings produced before banding). */
function bandOf(finding, ev) {
  if (finding && typeof finding.severity_band === 'string' && BAND_TO_TIER[finding.severity_band]) {
    return finding.severity_band;
  }
  // Derive a coarse band from per-event severity if no band is present.
  const sev = eventSeverity(ev).severity;
  return bandFor(sev);
}

/** A self-describing legend so the map explains itself with no external doc. */
function buildLegend(nodes) {
  const tally = { red: 0, yellow: 0, green: 0 };
  for (const n of nodes) tally[n.severityTier] += 1;
  return {
    color: [
      { tier: 'red', meaning: 'Sensitive exposure (breach-grade, or email/phone/address)', count: tally.red },
      { tier: 'yellow', meaning: 'Medium exposure', count: tally.yellow },
      { tier: 'green', meaning: 'Low / public trivia only', count: tally.green },
    ],
    size: 'Bigger node = more distinct findings at that source',
    edges: [
      { kind: 'exposes', meaning: 'This source holds information about you' },
      { kind: 'shared-identifier', meaning: 'Two sources expose the SAME identifier (same email/handle) — they can be correlated' },
    ],
    center: 'You — the self subject this audit is about',
  };
}

module.exports = {
  buildExposureGraph,
  // exported for the self-test + the web layer's optional reuse; not the main API.
  BAND_TO_TIER,
  tierForBand,
  findingToEvent,
  sourceOf,
  identifierKeysOf,
};
