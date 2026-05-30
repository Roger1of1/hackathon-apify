/**
 * shared/enrich/clusters.js
 *
 * The SpiderFoot-style CORRELATION pass, kept inside the enrich subtree so the
 * web report can render a "these findings are the same exposure" cluster view
 * without depending on a separate correlation actor. It does ONE honest job:
 * assemble connected components over the co-occurrence keys that
 * shared/enrich/cluster-keys.js already extracts.
 *
 * How it works (and why it's safe):
 *   - cluster-keys.js gives us, per event, a set of ENTITY/SURFACE keys
 *     (host:<h>, handle:<u>, email_prefix:<5hex>, secret_fp:<12hex>) — never a
 *     person/relationship/location key, by construction.
 *   - We union-find events that share ANY key into clusters. This is exactly
 *     SpiderFoot's correlation idea ("events that share an entity are linked"),
 *     expressed as connected components.
 *   - We then summarize each cluster for display: which surfaces/handles/email
 *     prefixes it spans, its worst severity (reusing severity.js), and the
 *     shared keys that bound it together (the "why these are linked" evidence).
 *
 * This module REUSES, never forks:
 *   - shared/enrich/cluster-keys.js   buildKeyIndex / clusterKeysFor
 *   - shared/enrich/severity.js       rankBySeverity / bandFor
 * and the frozen vocabulary in shared/detectors/event-types.js.
 *
 * Reference patterns applied:
 *   - SpiderFoot 4.0 CORRELATION ENGINE — link OSINT events that reference the
 *     same entity into a single finding; we implement the linking step as
 *     connected components over shared keys and surface the binding keys as the
 *     correlation rationale. Ref: https://github.com/smicallef/spiderfoot ;
 *     https://deepwiki.com/smicallef/spiderfoot
 *   - HIBP k-anonymity — clusters join on a hash PREFIX / one-way fingerprint
 *     (email_prefix / secret_fp), never the plaintext value, so "the same email
 *     across two sites" can cluster while the address itself is never stored.
 *     Ref: Troy Hunt, "Understanding HIBP's Use of SHA-1 and k-Anonymity".
 *
 * RED LINE: a cluster is a set of public exposures that share a public surface
 * or a one-way artifact key. It is NOT a profile of a person and carries no
 * relationship/intimacy/identity inference. The only join keys possible are the
 * ones cluster-keys.js emits, which are surface/artifact keys only.
 *
 * Pure functions, no network, no mutation of inputs. Safe to require at load.
 */

'use strict';

const { isModuleEvent } = require('../detectors/event-types.js');
const { buildKeyIndex } = require('./cluster-keys.js');
const { rankBySeverity, bandFor } = require('./severity.js');

/**
 * Disjoint-set (union-find) with path compression + union by size.
 * Tiny, dependency-free, deterministic.
 */
function makeDSU(n) {
  const parent = new Array(n);
  const size = new Array(n).fill(1);
  for (let i = 0; i < n; i += 1) parent[i] = i;

  function find(x) {
    let root = x;
    while (parent[root] !== root) root = parent[root];
    // path compression
    while (parent[x] !== root) { const nxt = parent[x]; parent[x] = root; x = nxt; }
    return root;
  }
  function union(a, b) {
    let ra = find(a);
    let rb = find(b);
    if (ra === rb) return;
    if (size[ra] < size[rb]) { const t = ra; ra = rb; rb = t; }
    parent[rb] = ra;
    size[ra] += size[rb];
  }
  return { find, union };
}

/**
 * Build correlation clusters from a flat module_event[].
 *
 * @param {object[]} events
 * @param {object} [opts]
 * @param {object} [opts.integrityByUrl] passed to severity ranking for evidence quality
 * @param {boolean} [opts.includeSingletons=true] keep clusters of size 1
 * @returns {{
 *   clusters: Array<{
 *     id:string,
 *     size:number,
 *     band:string,
 *     top_severity:number,
 *     keys:string[],          // the shared co-occurrence keys binding this cluster
 *     hosts:string[],
 *     handles:string[],
 *     email_prefixes:string[],
 *     secret_fingerprints:string[],
 *     event_types:string[],
 *     event_indexes:number[], // indexes into the returned `ranked` array
 *   }>,
 *   ranked: object[],         // the severity-ranked events the indexes refer to
 *   linked_count:number,      // events that share a key with >=1 other event
 * }}
 */
function buildClusters(events = [], opts = {}) {
  const integrityByUrl = (opts && opts.integrityByUrl) || {};
  const includeSingletons = opts.includeSingletons !== false;

  // Rank first so cluster ordering & per-cluster severity reuse the canonical
  // model, and the indexes we return point into a stable, sorted array.
  const ranked = rankBySeverity(events, { integrityByUrl });
  const n = ranked.length;
  if (n === 0) {
    return { clusters: [], ranked, linked_count: 0 };
  }

  // Inverted index key -> [eventIdx...] from the canonical key extractor.
  const { index, keysByEvent } = buildKeyIndex(ranked);

  // Union events that share any key.
  const dsu = makeDSU(n);
  let linkedCount = 0;
  const linkedFlags = new Array(n).fill(false);
  for (const idxs of index.values()) {
    if (idxs.length < 2) continue;
    const first = idxs[0];
    for (let i = 1; i < idxs.length; i += 1) {
      dsu.union(first, idxs[i]);
    }
    for (const i of idxs) {
      if (!linkedFlags[i]) { linkedFlags[i] = true; linkedCount += 1; }
    }
  }

  // Gather members per root.
  const members = new Map();
  for (let i = 0; i < n; i += 1) {
    const root = dsu.find(i);
    if (!members.has(root)) members.set(root, []);
    members.get(root).push(i);
  }

  const clusters = [];
  for (const [root, idxs] of members) {
    if (idxs.length < 2 && !includeSingletons) continue;

    // Aggregate the binding keys + entity facets across the cluster's events.
    const keySet = new Set();
    const hosts = new Set();
    const handles = new Set();
    const emailPrefixes = new Set();
    const secretFps = new Set();
    const eventTypes = new Set();
    let topSeverity = 0;

    for (const i of idxs) {
      const ev = ranked[i];
      eventTypes.add(ev.event_type);
      const sev = ev._severity && typeof ev._severity.severity === 'number'
        ? ev._severity.severity : 0;
      if (sev > topSeverity) topSeverity = sev;
      for (const k of keysByEvent[i]) {
        keySet.add(k);
        const sep = k.indexOf(':');
        const kind = k.slice(0, sep);
        const val = k.slice(sep + 1);
        if (kind === 'host') hosts.add(val);
        else if (kind === 'handle') handles.add(val);
        else if (kind === 'email_prefix') emailPrefixes.add(val);
        else if (kind === 'secret_fp') secretFps.add(val);
      }
    }

    clusters.push({
      id: `cluster--${root}`,
      size: idxs.length,
      band: bandFor(topSeverity),
      top_severity: topSeverity,
      keys: Array.from(keySet).sort(),
      hosts: Array.from(hosts).sort(),
      handles: Array.from(handles).sort(),
      email_prefixes: Array.from(emailPrefixes).sort(),
      secret_fingerprints: Array.from(secretFps).sort(),
      event_types: Array.from(eventTypes).sort(),
      event_indexes: idxs.slice().sort((a, b) => a - b),
    });
  }

  // Most significant clusters first: by top severity, then by size.
  clusters.sort((a, b) => (b.top_severity - a.top_severity) || (b.size - a.size));

  return { clusters, ranked, linked_count: linkedCount };
}

/**
 * Convenience: clusters that actually CORRELATE (>=2 events sharing a key).
 * These are the rows worth showing in a "linked exposures" view; singletons are
 * just standalone findings already shown in the grouped report.
 *
 * @param {object[]} events
 * @param {object} [opts]
 * @returns {object[]} correlated clusters only
 */
function correlatedClusters(events = [], opts = {}) {
  const { clusters } = buildClusters(events, opts);
  return clusters.filter((c) => c.size >= 2);
}

module.exports = {
  buildClusters,
  correlatedClusters,
  // exported for the self-test only; not part of the public surface
  _makeDSU: makeDSU,
};
