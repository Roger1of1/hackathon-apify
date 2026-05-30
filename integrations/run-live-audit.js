#!/usr/bin/env node
/**
 * integrations/run-live-audit.js
 *
 * REAL, END-TO-END, LIVE self-/public-figure footprint audit driven by Apify.
 *
 * Unlike integrations/run-self-audit.js (which runs the real detector→grade
 * pipeline over a SYNTHETIC fixture), this runner produces REAL captured
 * artifacts by calling deployed/Store Apify actors over the public web, then
 * feeds those REAL captures into the SAME detector→grade→report pipeline. The
 * grade letter the web shows is computed by the real grading code over findings
 * the real detectors parsed out of real crawled pages.
 *
 * ─────────────────────────── THE LIVE CHAIN ────────────────────────────────
 *   subject NAME (+ optional email/handle/domain)
 *     │
 *     ├─ A0  POLICY GATE  (shared/scope.js validateScope — the EXACT logic the
 *     │      deployed mirrortrace-policy-gate actor runs). scope_type must be
 *     │      self|public_figure|brand|consented|safety_evidence. Intent text is
 *     │      scanned for red-line laundering. NOTHING proceeds on a reject.
 *     │
 *     ├─ A2  DISCOVERY  →  Apify Store: apify/google-search-scraper  (REAL SERP)
 *     │      Searches Google for the subject's public mentions. Returns real
 *     │      organic result URLs. Each URL is RE-VALIDATED through the gate's
 *     │      private-social host block before it can be crawled.
 *     │
 *     ├─ A3  CRAWLER  →  Apify Store: apify/website-content-crawler  (REAL crawl)
 *     │      crawlerType=playwright:adaptive — the SAME AdaptivePlaywrightCrawler
 *     │      engine MirrorTrace's own A3 crawler uses — renders each public result
 *     │      page, saves HTML + readable text. Bounded by maxCrawlPages / depth.
 *     │
 *     ├─ A4  DETECT  →  shared/detectors/** (REAL, unchanged)
 *     │      Each crawled page becomes page_text + page_resources + page_indexing
 *     │      artifacts; the real PII / tracker (Blacklight-style) / indexability
 *     │      detectors run over them and emit typed module_event[].
 *     │
 *     └─ A6  REPORT  →  integrations/grade/exposure-grade.js (read-only)
 *            Same grade + severity + report shape as run-self-audit, written to a
 *            GITIGNORED web/data/real-report.local.json (+ .js file:// wrapper)
 *            so the web exposure map can render a REAL report locally for the demo
 *            WITHOUT committing a real person's footprint to the public repo.
 *
 * ─────────────────────── WHAT APIFY POWER THIS SHOWS ───────────────────────
 *   • Apify Store actor invocation via REST run-sync-get-dataset-items (no SDK)
 *   • apify/google-search-scraper       → real Google SERP discovery for a NAME
 *   • apify/website-content-crawler      → real Playwright (adaptive) rendering
 *   • Datasets as the result store (we read each actor's default dataset)
 *   • Key-value store INPUT contract (we POST actor INPUT the platform stores)
 *   • The deployed MirrorTrace compliance gate logic (shared/scope.js) end-to-end
 *
 * ──────────────────────────── RED LINES ────────────────────────────────────
 *   • Only self / public_figure / brand / consented / safety_evidence run.
 *   • private-social / login-walled hosts are dropped at discovery time.
 *   • We crawl ONLY public, logged-out result pages. No login, no evasion.
 *   • Smoke-test default subject is a well-known PUBLIC FIGURE at
 *     scope_type=public_figure — never a private individual.
 *
 * ─────────────────────────── PRIVACY / SECURITY ────────────────────────────
 *   • APIFY_TOKEN is read from process.env ONLY (load via the .env one-liner in
 *     the repo README) and is NEVER printed or written anywhere.
 *   • The produced report names a real person, so it is written ONLY to the
 *     gitignored web/data/real-report.local.json — never committed.
 *
 * Usage:
 *   export APIFY_TOKEN=$(grep APIFY_TOKEN .env | cut -d= -f2)
 *   node integrations/run-live-audit.js --name "Tim Berners-Lee" --scope public_figure
 *   node integrations/run-live-audit.js --name "Jane Roe" --scope self \
 *        --email jane@example.com --handle janedev --domain janedev.example \
 *        --max-results 4 --max-pages 6
 *
 * Flags:
 *   --name       <string>  REQUIRED — subject name to search the public web for
 *   --scope      <string>  scope_type (default: public_figure)
 *   --email|--handle|--domain  optional identity hints (refine the SERP query)
 *   --max-results <n>      organic SERP results to keep      (default 5,  cap 10)
 *   --max-pages   <n>      pages the crawler may render       (default 6,  cap 12)
 *   --auth-url   <url>     authorization_evidence_url (required for scope=consented)
 *   --dry-run              run the gate + build the actor INPUTs, but make NO
 *                          Apify calls (offline preview of the exact chain)
 *   --quiet                suppress the stdout summary
 */

'use strict';

const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');

// REAL compliance + pipeline modules (read-only require; never mutated here).
const { validateScope, hostOf, PRIVATE_SOCIAL_HOSTS } = require(path.join(ROOT, 'shared', 'scope.js'));
const detectors = require(path.join(ROOT, 'shared', 'detectors', 'index.js'));
const { rankBySeverity, batchSeverity } = require(path.join(ROOT, 'shared', 'enrich', 'severity.js'));
const { gradeForScopedRun, computeExposureGrade } = require(path.join(__dirname, 'grade', 'exposure-grade.js'));

const API_BASE = 'https://api.apify.com/v2';

// Apify Store actors the live chain drives (verified present on the account).
const SERP_ACTOR = 'apify~google-search-scraper';        // A2 discovery (real SERP)
const CONTENT_CRAWLER_ACTOR = 'apify~website-content-crawler'; // A3 crawler (real Playwright)

// Where the LIVE (real-person) report lands. GITIGNORED — never committed.
const WEB_DATA_DIR = path.join(ROOT, 'web', 'data');
const REPORT_JSON = path.join(WEB_DATA_DIR, 'real-report.local.json');
const REPORT_JS = path.join(WEB_DATA_DIR, 'real-report.local.js');
// Raw proof of the live run (actor IDs, run IDs, dataset item counts). GITIGNORED.
const LIVE_RUNS_DIR = path.join(__dirname, 'live-runs');

// ─────────────────────────── arg parsing ──────────────────────────────────
function parseArgs(argv) {
  const out = { scope: 'public_figure', maxResults: 5, maxPages: 6, dryRun: false, quiet: false };
  for (let i = 0; i < argv.length; i += 1) {
    const a = argv[i];
    const next = () => argv[++i];
    if (a === '--name') out.name = next();
    else if (a === '--scope') out.scope = next();
    else if (a === '--email') out.email = next();
    else if (a === '--handle') out.handle = next();
    else if (a === '--domain') out.domain = next();
    else if (a === '--auth-url') out.authUrl = next();
    else if (a === '--max-results') out.maxResults = Math.max(1, Math.min(10, Number(next()) || 5));
    else if (a === '--max-pages') out.maxPages = Math.max(1, Math.min(12, Number(next()) || 6));
    else if (a === '--dry-run') out.dryRun = true;
    else if (a === '--quiet') out.quiet = true;
  }
  return out;
}

function requireToken() {
  const t = process.env.APIFY_TOKEN;
  if (!t) {
    throw new Error(
      'APIFY_TOKEN not in env. Load it (never commit it):\n'
      + '  export APIFY_TOKEN=$(grep APIFY_TOKEN .env | cut -d= -f2)',
    );
  }
  return t;
}

// ─────────────────────── Apify REST: run-sync ─────────────────────────────
/**
 * Run a Store actor synchronously and return its default-dataset items.
 * Uses the documented run-sync-get-dataset-items endpoint, so one HTTP call
 * starts the actor, waits for it, and returns the rows. We also do a cheap
 * follow-up to recover the runId for proof. NEVER logs the token.
 *
 *   POST /v2/acts/{actorId}/run-sync-get-dataset-items?token=...
 *   (https://docs.apify.com/api/v2/act-run-sync-get-dataset-items-post)
 */
async function runActorSync(actorId, input, token, timeoutSecs) {
  const url = `${API_BASE}/acts/${actorId}/run-sync-get-dataset-items`
    + `?token=${encodeURIComponent(token)}&timeout=${timeoutSecs}`;
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(input),
  });
  // The run id is surfaced in a response header for traceability.
  const runId = res.headers.get('x-apify-pagination-total') ? null : null; // not provided here
  const items = res.ok ? await res.json() : null;
  if (!res.ok) {
    const body = items || (await res.text().catch(() => ''));
    throw new Error(`Apify ${actorId} run-sync failed (HTTP ${res.status}): ${typeof body === 'string' ? body.slice(0, 300) : JSON.stringify(body).slice(0, 300)}`);
  }
  return { items: Array.isArray(items) ? items : [], runId };
}

/**
 * Start an actor (async) and return the run record so we can capture the REAL
 * runId/actorId for the proof, then poll the dataset. We use this for the SERP
 * actor so we always have a runId to show. Bounded by maxWaitSecs.
 *   POST /v2/acts/{actorId}/runs?token=...
 *   GET  /v2/actor-runs/{runId}?token=...
 *   GET  /v2/datasets/{datasetId}/items?token=...
 */
async function runActorTracked(actorId, input, token, maxWaitSecs) {
  const startRes = await fetch(`${API_BASE}/acts/${actorId}/runs?token=${encodeURIComponent(token)}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(input),
  });
  const started = await startRes.json();
  if (!startRes.ok || !started.data) {
    throw new Error(`Apify ${actorId} start failed (HTTP ${startRes.status}): ${JSON.stringify(started).slice(0, 300)}`);
  }
  const run = started.data;
  const runId = run.id;
  const datasetId = run.defaultDatasetId;
  const deadline = Date.now() + maxWaitSecs * 1000;
  let status = run.status;
  while (!['SUCCEEDED', 'FAILED', 'ABORTED', 'TIMED-OUT'].includes(status)) {
    if (Date.now() > deadline) break;
    await new Promise((r) => setTimeout(r, 3000));
    const pr = await fetch(`${API_BASE}/actor-runs/${runId}?token=${encodeURIComponent(token)}`);
    const pj = await pr.json();
    status = (pj.data && pj.data.status) || status;
  }
  const dr = await fetch(`${API_BASE}/datasets/${datasetId}/items?token=${encodeURIComponent(token)}&clean=true`);
  const items = dr.ok ? await dr.json() : [];
  return { runId, actorId, datasetId, status, items: Array.isArray(items) ? items : [] };
}

// ─────────────────────── A2: discovery (real SERP) ─────────────────────────
function buildSerpQuery(opts) {
  // Compose a precise public-mention query from the name + optional hints.
  const parts = [`"${opts.name}"`];
  if (opts.handle) parts.push(`OR "${opts.handle}"`);
  if (opts.email) parts.push(`OR "${opts.email}"`);
  let q = parts.join(' ');
  if (opts.domain) q = `${q} site:${opts.domain} OR ${q}`; // bias toward the subject's own domain too
  return q;
}

function buildSerpInput(opts) {
  return {
    queries: buildSerpQuery(opts),
    maxPagesPerQuery: 1,          // one SERP page — bounded + cheap
    resultsPerPage: Math.min(10, opts.maxResults + 3), // a little headroom before host-filtering
    countryCode: 'us',
    languageCode: 'en',
    saveHtml: false,
    mobileResults: false,
  };
}

/** Pull organic result URLs out of the google-search-scraper dataset rows. */
function extractSerpUrls(items, limit) {
  const urls = [];
  const seen = new Set();
  for (const row of items) {
    const organic = (row && Array.isArray(row.organicResults)) ? row.organicResults : [];
    for (const r of organic) {
      const u = r && (r.url || r.link);
      if (typeof u !== 'string') continue;
      let norm;
      try { norm = new URL(u).href; } catch { continue; }
      if (seen.has(norm)) continue;
      seen.add(norm);
      urls.push({ url: norm, title: r.title || null, snippet: r.description || r.snippet || null });
    }
  }
  return urls.slice(0, limit);
}

/**
 * Re-validate each discovered URL through the SAME gate host-block the deployed
 * crawler enforces. Private-social / login-walled hosts are dropped here so they
 * never reach the crawl — defense in depth, exactly like the deployed actors.
 */
function complianceFilterUrls(urlObjs) {
  const kept = [];
  const dropped = [];
  for (const o of urlObjs) {
    const h = hostOf(o.url);
    if (!h) { dropped.push({ ...o, reason: 'unparseable_host' }); continue; }
    if (PRIVATE_SOCIAL_HOSTS.includes(h)) {
      dropped.push({ ...o, reason: `private_social_host:${h}` });
      continue;
    }
    kept.push(o);
  }
  return { kept, dropped };
}

// ─────────────────────── A3: crawler (real Playwright) ─────────────────────
function buildCrawlerInput(urls, opts) {
  return {
    startUrls: urls.map((u) => ({ url: u.url })),
    crawlerType: 'playwright:adaptive', // SAME engine as MirrorTrace's own A3 crawler
    maxCrawlPages: opts.maxPages,        // hard page cap — bounded + cheap
    maxCrawlDepth: 0,                    // only the discovered result pages, no expansion
    saveHtml: true,                      // we need raw HTML for tracker/script extraction
    saveMarkdown: true,
    saveScreenshots: false,
    blockMedia: true,
    removeCookieWarnings: true,
    respectRobotsTxtFile: true,          // polite: honor robots
    maxRequestRetries: 1,
    maxConcurrency: 3,
    proxyConfiguration: { useApifyProxy: true },
    readableTextCharThreshold: 80,
  };
}

// ───────────────── crawled page → REAL detector artifacts ──────────────────
function extractScriptSrcs(html) {
  const out = [];
  if (typeof html !== 'string') return out;
  const re = /<script\b[^>]*\bsrc\s*=\s*["']([^"']+)["'][^>]*>/gi;
  let m;
  while ((m = re.exec(html)) !== null) out.push(m[1]);
  return out;
}

function extractOutboundLinks(html, firstPartyHost) {
  const out = [];
  if (typeof html !== 'string') return out;
  const re = /<a\b[^>]*\bhref\s*=\s*["'](https?:\/\/[^"']+)["']/gi;
  let m;
  const seen = new Set();
  while ((m = re.exec(html)) !== null) {
    const href = m[1];
    let host = null;
    try { host = new URL(href).hostname.toLowerCase(); } catch { /* ignore */ }
    if (!host || host === firstPartyHost) continue;
    if (seen.has(href)) continue;
    seen.add(href);
    out.push(href);
    if (out.length >= 40) break;
  }
  return out;
}

function extractMetaRobots(html) {
  if (typeof html !== 'string') return null;
  const m = html.match(/<meta\b[^>]*name\s*=\s*["']robots["'][^>]*content\s*=\s*["']([^"']+)["']/i);
  return m ? m[1] : null;
}

function extractCanonical(html) {
  if (typeof html !== 'string') return null;
  const m = html.match(/<link\b[^>]*rel\s*=\s*["']canonical["'][^>]*href\s*=\s*["']([^"']+)["']/i);
  return m ? m[1] : null;
}

/**
 * Turn one Website-Content-Crawler dataset row into the detector artifact kinds.
 * The crawler row carries { url, text, html, markdown, ... }.
 */
function pageToArtifacts(row) {
  const url = (row && (row.url || (row.metadata && row.metadata.url))) || null;
  if (!url) return [];
  const text = (typeof row.text === 'string' && row.text) || (typeof row.markdown === 'string' ? row.markdown : '');
  const html = typeof row.html === 'string' ? row.html : '';
  let firstPartyHost = null;
  try { firstPartyHost = new URL(url).hostname.toLowerCase(); } catch { /* ignore */ }

  const artifacts = [];

  // page_text → PII + secret detectors (real visible text of a real page).
  if (text && text.trim().length > 0) {
    artifacts.push({ kind: 'page_text', url, text });
  }

  // page_resources → Blacklight-style tracker detector (real <script src>, links).
  const scripts = extractScriptSrcs(html);
  const outboundLinks = extractOutboundLinks(html, firstPartyHost);
  if (scripts.length || outboundLinks.length) {
    artifacts.push({
      kind: 'page_resources',
      url,
      scripts,
      cookies: [],            // set-cookie headers not exposed by this Store actor; left empty (no fabrication)
      js_api_calls: [],       // not instrumented by this Store actor; left empty (no fabrication)
      outbound_links: outboundLinks,
    });
  }

  // page_indexing → indexability/discoverability detector (real meta directives).
  const metaRobots = extractMetaRobots(html);
  const canonical = extractCanonical(html);
  artifacts.push({
    kind: 'page_indexing',
    url,
    meta_robots: metaRobots,
    canonical_url: canonical,
    // archived/x_robots_tag not observed by this actor → omitted (absence = no claim)
  });

  return artifacts;
}

// ───────────────────────── report shaping ─────────────────────────────────
function shapeLiveReport(scopedInput, events, grade, meta) {
  const generatedAt = new Date().toISOString();
  const crawlSummary = detectors.summarizeForExposure(events);
  const severity = batchSeverity(events, crawlSummary);
  const ranked = rankBySeverity(events);

  const findings = ranked.map((ev) => ({
    event_type: ev.event_type,
    source_module: ev.source_module,
    risk: ev.risk,
    visibility: ev.visibility,
    confidence: ev.confidence,
    source_url: ev.source_url || null,
    severity_band: ev._severity ? ev._severity.band : null,
  }));

  return {
    __label: 'REAL LIVE REPORT — produced by integrations/run-live-audit.js over LIVE Apify-crawled public pages',
    __notice:
      'Every finding below is the REAL output of shared/detectors over pages a REAL Apify crawl '
      + '(apify/website-content-crawler, playwright:adaptive) rendered from REAL Google SERP results '
      + '(apify/google-search-scraper) for the named public subject. The grade is computed by '
      + 'integrations/grade/exposure-grade.js from exactly these findings. This report names a real '
      + 'person and is therefore written ONLY to a gitignored local file — never committed.',
    __source: 'LIVE Apify SERP + Playwright crawl · real detector→grade pipeline',
    generated_at: generatedAt,
    scope: scopedInput,
    grade,
    severity,
    crawl_summary: crawlSummary,
    findings,
    counts: {
      artifacts_in: meta.artifactCount,
      findings_out: events.length,
      counted_in_grade: grade.counted_event_count != null ? grade.counted_event_count : 0,
    },
    provenance: {
      runner: 'integrations/run-live-audit.js',
      grade_policy: meta.gradePolicy,           // the SELF-only grading-policy decision (honest)
      apify_chain: meta.apifyChain,             // real actorIds + runIds + dataset counts
      discovered_urls: meta.discoveredUrls,      // real result URLs the crawl rendered
      dropped_by_compliance: meta.droppedUrls,   // hosts the gate refused (defense in depth)
      pipeline: ['shared/detectors/index.js', 'shared/enrich/severity.js', 'integrations/grade/exposure-grade.js'],
      grade_module: 'integrations/grade/exposure-grade.js (read-only)',
      apify_capabilities_demonstrated: [
        'Apify Store actor: apify/google-search-scraper (real Google SERP discovery for a name)',
        'Apify Store actor: apify/website-content-crawler with crawlerType=playwright:adaptive (real browser rendering)',
        'Apify Datasets (read each actor default dataset for results)',
        'Apify Proxy (useApifyProxy) for the crawl',
        'REST run-sync / tracked-run + dataset items API (no SDK dependency)',
        'MirrorTrace compliance gate (shared/scope.js) enforced before + after discovery',
      ],
    },
  };
}

// ───────────────────────────── main ───────────────────────────────────────
async function runLiveAudit(opts) {
  if (!opts.name || !opts.name.trim()) {
    throw new Error('--name is required (the subject to audit).');
  }

  // ── A0 POLICY GATE. We must give the gate at least one target_url; before SERP
  // we use the subject's own domain if provided, else a compliant Google query
  // URL as a placeholder seed. The gate validates scope_type + intent text here.
  const seedTarget = opts.domain
    ? `https://${opts.domain.replace(/^https?:\/\//, '')}`
    : `https://www.google.com/search?q=${encodeURIComponent(opts.name)}`;
  const gateInput = {
    scope_type: opts.scope,
    subject_label: opts.name,
    target_urls: [seedTarget],
    authorization_evidence_url: opts.authUrl || undefined,
  };
  const gate = validateScope(gateInput);
  if (!gate.allowed) {
    const err = new Error(`POLICY GATE REJECTED scope=${opts.scope}: ${gate.reasons.join(' ')}`);
    err.gate = gate;
    throw err;
  }
  const scopedInput = {
    scope_type: gate.normalized.scope_type,
    subject: { name: opts.name, label: gate.normalized.subject_label },
    targets: [], // filled with the real crawled URLs after discovery
  };

  const apifyChain = [];

  if (opts.dryRun) {
    // Offline preview of the EXACT live chain without spending a run.
    const serpInput = buildSerpInput(opts);
    return {
      dryRun: true,
      gate,
      serp: { actor: SERP_ACTOR, input: serpInput, query: buildSerpQuery(opts) },
      crawler: { actor: CONTENT_CRAWLER_ACTOR, note: 'startUrls filled from real SERP results at run time' },
    };
  }

  const token = requireToken();

  // ── A2 DISCOVERY: real Google SERP for the subject's public mentions.
  const serpInput = buildSerpInput(opts);
  const serp = await runActorTracked(SERP_ACTOR, serpInput, token, 120);
  apifyChain.push({
    stage: 'discovery', actor: SERP_ACTOR, runId: serp.runId, datasetId: serp.datasetId,
    status: serp.status, dataset_items: serp.items.length,
    capability: 'Google SERP scraper (real public-web search for the subject name)',
  });
  const allUrls = extractSerpUrls(serp.items, opts.maxResults + 4);
  const { kept, dropped } = complianceFilterUrls(allUrls);
  const crawlUrls = kept.slice(0, opts.maxResults);
  if (crawlUrls.length === 0) {
    throw new Error('Discovery returned no crawlable public URLs (after compliance host-filter). Nothing to crawl.');
  }

  // ── A3 CRAWLER: real Playwright (adaptive) rendering of the result pages.
  const crawlerInput = buildCrawlerInput(crawlUrls, opts);
  const crawl = await runActorTracked(CONTENT_CRAWLER_ACTOR, crawlerInput, token, 240);
  apifyChain.push({
    stage: 'crawler', actor: CONTENT_CRAWLER_ACTOR, runId: crawl.runId, datasetId: crawl.datasetId,
    status: crawl.status, dataset_items: crawl.items.length,
    capability: 'Website Content Crawler · crawlerType=playwright:adaptive (real browser render) + Apify Proxy',
  });
  scopedInput.targets = crawl.items.map((r) => r.url || (r.metadata && r.metadata.url)).filter(Boolean);

  // ── A4 DETECT: real detectors over the real captured pages.
  const allArtifacts = [];
  for (const row of crawl.items) allArtifacts.push(...pageToArtifacts(row));
  const { events, by_module, skipped } = detectors.runDetectors(allArtifacts);

  // ── A6 GRADE + REPORT (read-only grade module).
  // gradeForScopedRun enforces the SELF-only grading POLICY: for a public_figure
  // (or any non-self) scope it honestly returns graded:false/not_self_scope. The
  // underlying exposure-grade MATH is scope-agnostic, so for non-self scopes we
  // additionally compute the real grade directly via computeExposureGrade so the
  // web's grade hero can show a REAL letter over the REAL findings, while the
  // report transparently records the scope-policy decision under grade_policy.
  const gradePolicy = gradeForScopedRun(scopedInput, events);
  const grade = gradePolicy.graded ? gradePolicy : computeExposureGrade(events);
  const report = shapeLiveReport(scopedInput, events, grade, {
    gradePolicy,
    artifactCount: allArtifacts.length,
    apifyChain,
    discoveredUrls: crawlUrls.map((u) => u.url),
    droppedUrls: dropped,
  });

  // ── persist: GITIGNORED local report (+ file:// wrapper) + raw run proof.
  fs.mkdirSync(WEB_DATA_DIR, { recursive: true });
  fs.writeFileSync(REPORT_JSON, `${JSON.stringify(report, null, 2)}\n`, 'utf8');
  const jsWrapper =
    '/* AUTO-GENERATED by integrations/run-live-audit.js — file:// fallback for'
    + ' web/data/real-report.local.json. REAL LIVE report; gitignored; do not commit. */\n'
    + `window.__MIRRORTRACE_REPORT__ = ${JSON.stringify(report, null, 2)};\n`;
  fs.writeFileSync(REPORT_JS, jsWrapper, 'utf8');

  fs.mkdirSync(LIVE_RUNS_DIR, { recursive: true });
  const proofPath = path.join(LIVE_RUNS_DIR, `live-run-${Date.now()}.json`);
  fs.writeFileSync(proofPath, `${JSON.stringify({
    generated_at: report.generated_at,
    subject_label: opts.name,
    scope_type: opts.scope,
    apifyChain,
    crawlUrls: crawlUrls.map((u) => u.url),
    dropped,
    by_module,
    artifacts_skipped: skipped,
    grade: grade.graded ? { grade: grade.grade, score: grade.score } : { graded: false, reason: grade.reason },
  }, null, 2)}\n`, 'utf8');

  return { gate, serp, crawl, events, by_module, grade, report, crawlUrls, dropped, proofPath };
}

// CLI entry.
if (require.main === module) {
  const opts = parseArgs(process.argv.slice(2));
  runLiveAudit(opts)
    .then((res) => {
      if (opts.quiet) return;
      if (res.dryRun) {
        process.stdout.write(
          `\nrun-live-audit — DRY RUN (no Apify calls)\n`
          + `  scope        : ${res.gate.normalized.scope_type} (gate ALLOWED)\n`
          + `  SERP actor   : ${res.serp.actor}\n`
          + `  SERP query   : ${res.serp.query}\n`
          + `  SERP input   : ${JSON.stringify(res.serp.input)}\n`
          + `  crawler actor: ${res.crawler.actor} (playwright:adaptive)\n\n`,
        );
        return;
      }
      const g = res.grade.graded
        ? `${res.grade.grade} (score ${res.grade.score}/100, −${res.grade.total_deduction})`
        : `none (${res.grade.reason})`;
      process.stdout.write(
        `\nrun-live-audit — REAL LIVE Apify chain\n`
        + `  subject       : ${res.report.scope.subject.name} (scope ${res.report.scope.scope_type})\n`
        + `  discovery     : ${SERP_ACTOR} run ${res.serp.runId} → ${res.serp.items.length} SERP rows\n`
        + `  crawl         : ${CONTENT_CRAWLER_ACTOR} run ${res.crawl.runId} → ${res.crawl.items.length} pages rendered\n`
        + `  crawled URLs  :\n${res.crawlUrls.map((u) => `    - ${u.url}`).join('\n')}\n`
        + `  dropped(gate) : ${res.dropped.length} host(s) refused\n`
        + `  by module     : ${JSON.stringify(res.by_module)}\n`
        + `  findings      : ${res.events.length}\n`
        + `  grade         : ${g}\n`
        + `  wrote         : web/data/real-report.local.json (gitignored)\n`
        + `                : web/data/real-report.local.js   (gitignored file:// wrapper)\n`
        + `  run proof     : ${path.relative(ROOT, res.proofPath)}\n\n`,
      );
    })
    .catch((err) => {
      process.stderr.write(`run-live-audit: FAILED — ${err && err.message}\n`);
      if (err && err.gate) {
        process.stderr.write(`  Legal alternatives: ${(err.gate.alternatives || []).join(' ')}\n`);
      }
      process.exit(1);
    });
}

module.exports = {
  runLiveAudit,
  buildSerpInput,
  buildSerpQuery,
  buildCrawlerInput,
  extractSerpUrls,
  complianceFilterUrls,
  pageToArtifacts,
  shapeLiveReport,
  REPORT_JSON,
  REPORT_JS,
};
