/**
 * integrations/ingest/ingest-policy.js
 *
 * The SELF-AUDIT INGESTION layer: how a vetted subject's OWN public footprint is
 * fetched via two Apify FIRST-PARTY actors and mapped into the product's typed
 * evidence pipeline. Pure + zero-I/O at the decision boundary, so the dry-run
 * client (ingest-client.js) and the tests share one truth. No network, no fs
 * except loading the policy config (callers can inject it).
 *
 * WHAT THIS WIRES (the round's assigned Apify capability)
 * ------------------------------------------------------
 * Apify Website Content Crawler (apify/website-content-crawler) is the REAL
 * self-audit ingestion source: given the subject's OWN start URLs it crawls and
 * returns clean per-page `text` / `markdown`, plus `htmlUrl` / `screenshotUrl`
 * evidence handles and an `error` field on failed pages
 * (https://apify.com/apify/website-content-crawler,
 *  .../website-content-crawler/input-schema). Apify RAG Web Browser
 * (apify/rag-web-browser) is the CONTEXT source: it runs a public Google
 * search (or fetches a single URL) and returns the top-N pages as markdown for
 * an LLM/RAG step (https://apify.com/apify/rag-web-browser). Both can run in
 * Apify Standby for low-latency real-time use, matching our standby gate.
 *
 * REFERENCE ARCHITECTURE #1 — Apify Website Content Crawler + RAG Web Browser.
 * We borrow their concrete input contracts (WCC: startUrls, crawlerType,
 * include/excludeUrlGlobs, maxCrawlDepth, maxCrawlPages, saveMarkdown,
 * saveHtmlAsFile, saveScreenshots, respectRobotsTxtFile, proxyConfiguration;
 * RAG: query, maxResults, outputFormats) and their per-row OUTPUT shape (WCC:
 * url, crawl.loadedUrl, text, markdown, metadata.title/canonicalUrl, htmlUrl,
 * screenshotUrl, error; RAG: searchResult/metadata + markdown/text). We map
 * those rows onto the EXISTING detector artifact kinds
 * (shared/detectors index ARTIFACT_KINDS.PAGE_TEXT / PAGE_RESOURCES) so the real
 * detector modules run on real crawl output — no parallel detection logic.
 *
 * REFERENCE ARCHITECTURE #2 — OpenCTI / MISP + STIX 2.1.
 * An exposure finding is a STIX 2.1 *Observed Data* SDO: "the raw data was
 * observed at a particular time" (OASIS STIX 2.1, §Observed Data). OpenCTI/MISP
 * connectors round-trip such SDOs as bundles (MISP-STIX: a to_ids attribute now
 * exports BOTH an Indicator and an Observed Data, linked by a Relationship;
 * OpenCTI ingests STIX 2.1 bundles via its workers —
 * docs.opencti.io, github.com/OpenCTI-Platform/connectors misp). So the terminal
 * stage of this pipeline emits, per detected event, the Observed Data object the
 * existing shared/enrich/stix-evidence.js already produces — making each finding
 * portable into a takedown request or a SIEM. We reuse that module verbatim; we
 * do not re-encode STIX here.
 *
 * SCOPE — fail-closed. This module READS shared/scope.js (Codex owns it; we
 * never write it). buildIngestPlan() calls validateScope() FIRST and refuses to
 * build ANY actor input for a rejected subject. A private-individual / stalking
 * query is therefore dropped BEFORE a single fetch input exists. Two doors,
 * both must open: validateScope AND this ingestion policy. This is the Scrapy
 * downloader-middleware "IgnoreRequest at the first gate" pattern (mirrored from
 * shared/middleware/pipeline.js) applied to ingestion.
 *
 * NO FAKE DATA: this file NEVER fabricates a crawl row. The input-builder builds
 * the exact actor input an operator WOULD submit; the row-mapper only transforms
 * REAL rows passed to it (e.g. by the dataset reader). Off-platform / without a
 * token the client dry-runs and returns the plan, started:false.
 */

'use strict';

const fs = require('fs');
const path = require('path');
const { validateScope } = require('../../shared/scope.js');
const { ARTIFACT_KINDS, runDetectors } = require('../../shared/detectors/index.js');
const { toObservedData, toBundle } = require('../../shared/enrich/stix-evidence.js');
const { buildItemPipeline, DropItem } = require('../../shared/middleware/pipeline.js');

const CONFIG_PATH = path.join(__dirname, 'ingest.config.json');

/** Load the ingestion policy config (only fs touch; injectable for tests). */
function loadIngestConfig(configPath = CONFIG_PATH) {
  return JSON.parse(fs.readFileSync(configPath, 'utf8'));
}

/** Refusal codes so callers/tests can assert the EXACT reason, fail-closed. */
const REFUSAL = Object.freeze({
  SCOPE_REJECTED: 'scope_rejected',
  SOURCE_NOT_ALLOWED: 'ingest_source_not_allowed',
  NAME_SEARCH_NOT_ALLOWED_FOR_SCOPE: 'name_search_not_allowed_for_scope',
  NO_TARGETS: 'no_ingest_targets',
  RAG_QUERY_REQUIRED: 'rag_query_required',
});

/** The two ingestion sources we wire. */
const SOURCE = Object.freeze({
  WCC: 'website_content_crawler',
  RAG: 'rag_web_browser',
});

/** Clamp a requested numeric DOWN to a ceiling (anti-dragnet, never up). */
function clampDown(requested, ceiling, fallback) {
  const r = Number(requested);
  if (!Number.isFinite(r) || r <= 0) return fallback;
  return Math.min(r, ceiling);
}

/** A free-text RAG query that is NOT a single URL is a NAME/PHRASE search. */
function isUrlQuery(query) {
  if (typeof query !== 'string') return false;
  try { new URL(query.trim()); return true; } catch { return false; }
}

/**
 * buildIngestPlan(input, opts) -> plan | refusal
 *
 * The ordered guard pipeline (Scrapy middleware ordering). The FIRST guard that
 * objects DROPS the request and NO actor input is built:
 *   1. scope gate     — real shared/scope.js must accept the subject (fail-closed)
 *   2. source gate    — requested source must be a known, scope-allowed source
 *   3. name-search gate — a RAG phrase (non-URL) search is restricted to
 *                         scope=self|public_figure (dual-use discovery chokepoint)
 *   4. target gate    — WCC needs >=1 vetted URL; RAG needs a query
 *   5. build          — emit the EXACT apify actor input (robots forced on)
 *
 * Returns one of:
 *   { allowed:true, source, actorId, deployed:false, scope, input, caps }
 *   { allowed:false, refusal, detail, scope }
 * NEVER throws on a bad request; refusals are values, not exceptions.
 */
function buildIngestPlan(input, opts = {}) {
  const cfg = opts.config || loadIngestConfig();
  const safe = input && typeof input === 'object' ? input : {};

  // ---- Guard 1: the REAL scope gate (read-only use of Coda private person's module) -------
  const scopeResult = validateScope(safe);
  if (!scopeResult.allowed) {
    return drop(REFUSAL.SCOPE_REJECTED, {
      detail: 'The audit subject was refused by the scope gate; no ingestion input is built.',
      scope_reasons: scopeResult.reasons,
      violated_red_lines: scopeResult.violated_red_lines,
      scope: safe.scope_type || null,
    });
  }
  const scope = scopeResult.scope_type;
  const targets = scopeResult.normalized.target_urls; // already host-vetted by the gate

  // ---- Guard 2: source must be known + allowed for this scope ---------------
  const source = (safe.ingest_source || SOURCE.WCC);
  if (source !== SOURCE.WCC && source !== SOURCE.RAG) {
    return drop(REFUSAL.SOURCE_NOT_ALLOWED, {
      detail: `Unknown ingest_source "${source}". Allowed: ${SOURCE.WCC}, ${SOURCE.RAG}.`,
      scope,
    });
  }
  const scopesAllowed = cfg.scopes_allowed_to_ingest || [];
  if (!scopesAllowed.includes(scope)) {
    return drop(REFUSAL.SOURCE_NOT_ALLOWED, {
      detail: `scope=${scope} may not run ingestion source ${source}.`,
      scope,
    });
  }

  // ---- Build per source -----------------------------------------------------
  if (source === SOURCE.RAG) {
    const query = typeof safe.query === 'string' ? safe.query.trim() : '';
    if (!query) {
      return drop(REFUSAL.RAG_QUERY_REQUIRED, {
        detail: 'rag_web_browser requires a `query` (a search phrase OR a single URL).',
        scope,
      });
    }
    // ---- Guard 3: a NAME/PHRASE search is dual-use discovery ----------------
    if (!isUrlQuery(query)) {
      const nameOk = cfg.scopes_allowed_name_search || [];
      if (!nameOk.includes(scope)) {
        return drop(REFUSAL.NAME_SEARCH_NOT_ALLOWED_FOR_SCOPE, {
          detail:
            'A free-text/name web search is a dual-use discovery technique, ' +
            `restricted to scope=${nameOk.join('|')}. For scope=${scope}, the ` +
            'query must be a concrete URL you already hold, not a name search.',
          scope,
        });
      }
    }
    return buildRagPlan({ cfg, scope, query, safe });
  }

  // source === WCC
  // ---- Guard 4: WCC needs at least one vetted target URL --------------------
  if (!Array.isArray(targets) || targets.length === 0) {
    return drop(REFUSAL.NO_TARGETS, {
      detail: 'website_content_crawler requires at least one vetted target_url.',
      scope,
    });
  }
  return buildWccPlan({ cfg, scope, targets, safe });
}

/** Build the apify/website-content-crawler input from vetted self URLs. */
function buildWccPlan({ cfg, scope, targets, safe }) {
  const d = cfg.wcc_defaults || {};
  const caps = cfg.caps || {};
  const actor = (cfg.actors && cfg.actors.website_content_crawler) || {};

  const wccInput = {
    startUrls: targets.map((url) => ({ url })),
    crawlerType: d.crawlerType || 'playwright:adaptive',
    maxCrawlDepth: clampDown(safe.maxCrawlDepth, caps.max_crawl_depth || 2, d.maxCrawlDepth || 1),
    maxCrawlPages: clampDown(safe.maxCrawlPages, caps.max_crawl_pages || 50, d.maxCrawlPages || 25),
    saveMarkdown: d.saveMarkdown !== false,
    saveHtmlAsFile: d.saveHtmlAsFile !== false, // tamper-evident evidence handle for STIX x_integrity
    saveScreenshots: d.saveScreenshots !== false,
    removeCookieWarnings: d.removeCookieWarnings !== false,
    requestTimeoutSecs: d.requestTimeoutSecs || 60,
    // ANTI-EVASION FLOOR: robots compliance is forced on and CANNOT be disabled.
    respectRobotsTxtFile: true,
  };
  // Stay on the subject's own surface: confine the crawl to the start hosts.
  wccInput.includeUrlGlobs = targets
    .map((u) => globForHost(u))
    .filter(Boolean);

  // Optional availability-only proxy spec (the proxy policy is the source of
  // truth; if the caller already decided a proxy, we PASS IT THROUGH untouched).
  if (safe.proxyConfiguration && typeof safe.proxyConfiguration === 'object') {
    wccInput.proxyConfiguration = safe.proxyConfiguration;
  }

  return {
    allowed: true,
    source: SOURCE.WCC,
    actorId: actor.actorId || '<PLACEHOLDER>',
    deployed: false,
    scope,
    input: wccInput,
    caps: { max_crawl_pages: caps.max_crawl_pages, max_crawl_depth: caps.max_crawl_depth },
    note:
      'Self-audit crawl plan built (apify/website-content-crawler). robots forced ' +
      'ON; pages/depth clamped to caps; crawl confined to the subject\'s own hosts. ' +
      'NOT deployed — actorId is a placeholder until the operator wires a live token.',
  };
}

/** Build the apify/rag-web-browser input for the public CONTEXT pass. */
function buildRagPlan({ cfg, scope, query, safe }) {
  const d = cfg.rag_defaults || {};
  const caps = cfg.caps || {};
  const actor = (cfg.actors && cfg.actors.rag_web_browser) || {};

  const ragInput = {
    query,
    maxResults: clampDown(safe.maxResults, caps.max_rag_results || 5, d.maxResults || 3),
    outputFormats: Array.isArray(d.outputFormats) ? d.outputFormats.slice() : ['markdown'],
    requestTimeoutSecs: d.requestTimeoutSecs || 40,
  };

  return {
    allowed: true,
    source: SOURCE.RAG,
    actorId: actor.actorId || '<PLACEHOLDER>',
    deployed: false,
    scope,
    input: ragInput,
    is_name_search: !isUrlQuery(query),
    caps: { max_rag_results: caps.max_rag_results },
    note:
      'Public context plan built (apify/rag-web-browser). maxResults clamped to ' +
      'caps. A name search was permitted only because scope is self|public_figure. ' +
      'NOT deployed — actorId is a placeholder until the operator wires a live token.',
  };
}

/** Build an include-glob that confines crawling to the start URL's host. */
function globForHost(urlString) {
  try {
    const u = new URL(urlString);
    return `${u.protocol}//${u.hostname}/**`;
  } catch {
    return null;
  }
}

/** Internal: shape a refusal value. */
function drop(refusal, extra) {
  return Object.assign({ allowed: false, refusal }, extra);
}

// ---------------------------------------------------------------------------
// MAPPING: real Apify actor OUTPUT rows -> detector artifacts -> module_events
//          -> STIX 2.1 Observed Data (the OpenCTI/MISP-portable evidence).
// ---------------------------------------------------------------------------

/**
 * Map ONE real Website Content Crawler output row to detector artifacts.
 * WCC row fields used: url, crawl.loadedUrl, text, markdown,
 * metadata.title/canonicalUrl, htmlUrl, screenshotUrl, error.
 *
 * Produces up to two artifacts, tagged with the EXISTING ARTIFACT_KINDS the
 * detector registry already dispatches on:
 *   - PAGE_TEXT      : { kind, text, source_url } for PII + secret-leak modules
 *   - PAGE_RESOURCES : { kind, source_url, ... } for the tracker module (only
 *                      populated when the row carried resource fields; WCC's
 *                      markdown mode usually does not, so this is conditional)
 *
 * @param {object} row a REAL WCC dataset row
 * @returns {{ artifacts: object[], integrity: object, page_error: string|null }}
 */
function wccRowToArtifacts(row) {
  if (!row || typeof row !== 'object') return { artifacts: [], integrity: {}, page_error: null };
  const sourceUrl =
    (row.crawl && typeof row.crawl.loadedUrl === 'string' && row.crawl.loadedUrl) ||
    (typeof row.url === 'string' && row.url) ||
    (row.metadata && row.metadata.canonicalUrl) ||
    null;

  // A failed WCC page carries `error` and null content — surface it, detect nothing.
  if (row.error) {
    return { artifacts: [], integrity: {}, page_error: String(row.error), source_url: sourceUrl };
  }

  const text =
    (typeof row.text === 'string' && row.text) ||
    (typeof row.markdown === 'string' && row.markdown) ||
    '';

  const artifacts = [];
  if (text) {
    artifacts.push({ kind: ARTIFACT_KINDS.PAGE_TEXT, text, source_url: sourceUrl });
  }
  // If the row carried resource arrays (some WCC configs add scripts/cookies),
  // hand them to the tracker module. We DO NOT fabricate empty resources.
  const res = row.resources || row.pageResources;
  if (res && typeof res === 'object') {
    artifacts.push(Object.assign({ kind: ARTIFACT_KINDS.PAGE_RESOURCES, source_url: sourceUrl }, res));
  }

  // Tamper-evident evidence handles -> STIX x_integrity (content/html/screenshot).
  const integrity = {
    html_key: typeof row.htmlUrl === 'string' ? row.htmlUrl : null,
    screenshot_key: typeof row.screenshotUrl === 'string' ? row.screenshotUrl : null,
    content_sha256: (row.metadata && row.metadata.contentSha256) || null,
    html_sha256: (row.metadata && row.metadata.htmlSha256) || null,
  };

  return { artifacts, integrity, page_error: null, source_url: sourceUrl };
}

/**
 * Build the ordered ITEM PIPELINE that turns REAL crawler rows into preserved,
 * STIX-portable evidence. Mirrors Scrapy's Item Pipeline (shared/middleware):
 *   stage 10 scope-reassert : a row whose source_url is NOT a vetted target is
 *                             DROPPED (a metamorph/link cannot smuggle a host the
 *                             gate refused). Fail-closed.
 *   stage 20 to-artifacts   : map the WCC row -> detector artifacts (+ integrity)
 *   stage 30 detect         : run the REAL detector modules over the artifacts
 *   stage 40 to-stix        : wrap each module_event as a STIX 2.1 Observed Data
 *
 * @param {object} plan the accepted plan from buildIngestPlan (carries scope)
 * @param {object} [opts] { now } injectable clock for deterministic STIX ids
 * @returns {{ pipeline, runRow:function }}
 */
function buildIngestItemPipeline(plan, opts = {}) {
  const now = typeof opts.now === 'string' ? opts.now : undefined;
  const allowedHosts = new Set(
    ((plan && plan.input && plan.input.startUrls) || [])
      .map((s) => { try { return new URL(s.url).hostname.toLowerCase(); } catch { return null; } })
      .filter(Boolean),
  );

  const stages = [
    {
      name: 'scope-reassert',
      order: 10,
      processItem(row) {
        const { source_url: src } = wccRowToArtifacts(row);
        // RAG context rows (no startUrls confinement) skip host-confinement; WCC
        // rows must stay on a vetted host. If we have a host allow-list, enforce.
        if (allowedHosts.size > 0 && src) {
          let h = null;
          try { h = new URL(src).hostname.toLowerCase(); } catch { h = null; }
          if (h && !allowedHosts.has(h)) {
            throw new DropItem('row source host is not a vetted target host', { source_url: src });
          }
        }
        return row;
      },
    },
    {
      name: 'to-artifacts',
      order: 20,
      processItem(row, ctx) {
        const mapped = wccRowToArtifacts(row);
        ctx.integrity = mapped.integrity;
        ctx.source_url = mapped.source_url;
        ctx.page_error = mapped.page_error;
        return { __row: row, artifacts: mapped.artifacts };
      },
    },
    {
      name: 'detect',
      order: 30,
      processItem(item) {
        const { events } = runDetectors(item.artifacts || []);
        return Object.assign({}, item, { events });
      },
    },
    {
      name: 'to-stix',
      order: 40,
      processItem(item, ctx) {
        const integrityByUrl = {};
        if (ctx.source_url) integrityByUrl[ctx.source_url] = ctx.integrity || {};
        const observed = (item.events || [])
          .map((ev) => toObservedData(ev, { now, integrity: ctx.integrity || {} }))
          .filter(Boolean);
        return Object.assign({}, item, {
          observed_data: observed,
          page_error: ctx.page_error || null,
        });
      },
    },
  ];

  const pipeline = buildItemPipeline(stages);

  /**
   * Run a single REAL crawler row through the pipeline.
   * @returns the pipeline result; on success result.item carries
   *          { events, observed_data, page_error }.
   */
  function runRow(row) {
    return pipeline.run(row, {});
  }

  return { pipeline, runRow };
}

/**
 * Convenience: map a whole batch of REAL crawler rows to a single STIX bundle
 * (the report's evidence package). Drops any row that fails host re-assertion.
 *
 * @param {object} plan accepted plan from buildIngestPlan
 * @param {object[]} rows REAL crawler output rows
 * @param {object} [opts] { now }
 * @returns {{ events: object[], bundle: object, dropped: object[], page_errors: object[] }}
 */
function ingestRowsToBundle(plan, rows = [], opts = {}) {
  const { runRow } = buildIngestItemPipeline(plan, opts);
  const events = [];
  const dropped = [];
  const page_errors = [];
  for (const row of Array.isArray(rows) ? rows : []) {
    const res = runRow(row);
    if (res.status === 'dropped') {
      dropped.push({ reason: res.reason, source: res.item });
      continue;
    }
    const item = res.item || {};
    if (item.page_error) page_errors.push({ error: item.page_error });
    for (const ev of item.events || []) events.push(ev);
  }
  const integrityByUrl = {};
  // Re-derive integrity per source_url for the bundle pass.
  for (const row of Array.isArray(rows) ? rows : []) {
    const m = wccRowToArtifacts(row);
    if (m.source_url) integrityByUrl[m.source_url] = m.integrity || {};
  }
  const bundle = toBundle(events, { now: opts.now, integrityByUrl });
  return { events, bundle, dropped, page_errors };
}

module.exports = {
  loadIngestConfig,
  buildIngestPlan,
  buildWccPlan,
  buildRagPlan,
  wccRowToArtifacts,
  buildIngestItemPipeline,
  ingestRowsToBundle,
  isUrlQuery,
  clampDown,
  globForHost,
  SOURCE,
  REFUSAL,
};
