/**
 * shared/detectors/html-artifacts.js
 *
 * THE MISSING SEAM: turn ONE captured HTML document into the precise tagged
 * artifacts that `shared/detectors/index.js#runDetectors` consumes.
 *
 * WHY THIS EXISTS
 * ─────────────────────────────────────────────────────────────────────────────
 * Every detector in this folder consumes a PRE-NORMALIZED artifact — PII/secret
 * read `{kind:'page_text', text, url}`, the tracker module reads
 * `{kind:'page_resources', scripts, cookies, outbound_links, js_api_calls}`, and
 * the indexability module reads `{kind:'page_indexing', meta_robots, ...}`.
 * Nothing in the repo produced those artifacts from a real captured page, so an
 * end-to-end run on the demo fixture (demo/sample-evidence.html) had no honest
 * path from HTML → detector inputs. This module is that path, and ONLY that:
 * it parses, it does not invent. Fields absent from the HTML are emitted as
 * `null`/empty so a downstream detector honestly produces nothing for them.
 *
 * REFERENCE ARCHITECTURES BORROWED (concrete patterns, not vibes)
 * ─────────────────────────────────────────────────────────────────────────────
 *  (1) Crawlee `CheerioCrawler` / server-side parsing of a captured response.
 *      Crawlee's non-browser crawler hands the handler a parsed body and you
 *      pull structured data out of it (text, `script[src]`, `a[href]`,
 *      `meta`, `link[rel=canonical]`) WITHOUT a live browser or network. We do
 *      the same extraction step with dependency-free regex/text scanning so the
 *      module is import-safe and works on a local fixture exactly like a Crawlee
 *      run against the local dataset. Ref: Crawlee CheerioCrawler + local
 *      Dataset — crawlee.dev/docs/guides/cheerio-crawler-guide and
 *      crawlee.dev/docs/guides/result-storage#dataset.
 *      Analogous to Apify CLI `apify run` reading INPUT.json from local storage:
 *      input (the captured HTML) comes from a local file, not the network.
 *  (2) Blacklight / EFF inspector's three-way split of a page into
 *      (a) the human-visible content, (b) the third-party RESOURCES & tracking
 *      surface, and (c) the search-discoverability posture. The registry already
 *      splits artifacts on exactly those three kinds; this extractor fills them.
 *      Ref: The Markup Blacklight methodology (scripts, cookies, fingerprinting,
 *      session-recording) — themarkup.org/blacklight.
 *
 * RED LINES
 * ─────────────────────────────────────────────────────────────────────────────
 *  - Pure function, ZERO network, no DOM/library deps, safe to require at load.
 *  - It NEVER fabricates: no synthesized cookies, no guessed trackers, no
 *    defaulted indexing posture. Only signals literally present in the HTML.
 *  - scope_type is passed THROUGH untouched onto each artifact (so the gate's
 *    decision rides along); this module makes no scope decision and gates
 *    nothing — dual-use detectors self-refuse downstream as they already do.
 *  - HTML cookies cannot be observed from static markup, so `cookies` is always
 *    [] here; only an instrumented crawl (a different track) can fill it. We do
 *    NOT invent cookies to make the tracker module "look" productive.
 *
 * @module shared/detectors/html-artifacts
 */

'use strict';

const { ARTIFACT_KINDS } = require('./index.js');

// ── tiny, dependency-free HTML helpers ──────────────────────────────────────
// We intentionally avoid a full HTML parser: the inputs are captured static
// documents and we only need a handful of well-defined extractions. Each helper
// is conservative — when it cannot confidently extract a signal it returns the
// empty/neutral value, never a guess.

/** Decode the handful of HTML entities that matter for readable text. */
function decodeEntities(s) {
  if (typeof s !== 'string' || s.indexOf('&') === -1) return s || '';
  return s
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#0*39;|&apos;/g, "'")
    .replace(/&nbsp;/g, ' ')
    .replace(/&#x([0-9a-fA-F]+);/g, (_, h) => safeCodePoint(parseInt(h, 16)))
    .replace(/&#(\d+);/g, (_, d) => safeCodePoint(parseInt(d, 10)));
}

function safeCodePoint(n) {
  if (!Number.isFinite(n) || n < 0 || n > 0x10ffff) return '';
  try { return String.fromCodePoint(n); } catch { return ''; }
}

/**
 * Strip <script>/<style> blocks and all tags, returning the human-visible text
 * with collapsed whitespace. This mirrors Cheerio's `$('body').text()` after
 * removing script/style — the "what a reader sees" projection the PII/secret
 * detectors expect. NOTE: script/style CONTENT is removed from page_text so the
 * PII detector doesn't read tracker code as "published text"; secret-in-source
 * leaks are handled separately below via `sourceText`.
 */
function visibleText(html) {
  if (typeof html !== 'string') return '';
  let s = html;
  s = s.replace(/<!--[\s\S]*?-->/g, ' ');
  s = s.replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi, ' ');
  s = s.replace(/<style\b[^>]*>[\s\S]*?<\/style>/gi, ' ');
  s = s.replace(/<\/(p|div|section|article|li|tr|h[1-6]|br|blockquote|footer|header|main)\s*>/gi, '\n');
  s = s.replace(/<br\s*\/?>/gi, '\n');
  s = s.replace(/<[^>]+>/g, ' ');
  s = decodeEntities(s);
  // collapse runs of spaces but keep newlines as soft separators
  s = s.replace(/[ \t\f\v]+/g, ' ').replace(/ *\n */g, '\n').replace(/\n{3,}/g, '\n\n');
  return s.trim();
}

/**
 * The source-side text the SECRET scanner should see: visible text PLUS the
 * literal content of inline <script> blocks (where an accidentally-committed
 * API key/token most often hides on a self-controlled page). We deliberately do
 * NOT feed inline-script content to the PII detector (that would mis-read code
 * as published contact info), but a secret-scan must see it — exactly how
 * gitleaks/TruffleHog scan raw source, not rendered text.
 */
function sourceText(html) {
  if (typeof html !== 'string') return '';
  const vis = visibleText(html);
  const inlineScripts = [];
  const re = /<script\b([^>]*)>([\s\S]*?)<\/script>/gi;
  let m;
  while ((m = re.exec(html)) !== null) {
    // only INLINE scripts (no src=) carry literal secrets in the markup
    if (/\bsrc\s*=/.test(m[1])) continue;
    const body = (m[2] || '').trim();
    if (body) inlineScripts.push(body);
  }
  return inlineScripts.length ? `${vis}\n${inlineScripts.join('\n')}` : vis;
}

/** Extract every <script src="..."> URL (the tracker surface). */
function scriptSrcs(html, baseUrl) {
  const out = [];
  if (typeof html !== 'string') return out;
  const re = /<script\b[^>]*\bsrc\s*=\s*("([^"]*)"|'([^']*)'|([^\s>]+))/gi;
  let m;
  while ((m = re.exec(html)) !== null) {
    const raw = (m[2] || m[3] || m[4] || '').trim();
    const abs = resolveUrl(raw, baseUrl);
    if (abs && !out.includes(abs)) out.push(abs);
  }
  return out;
}

/** Extract every outbound <a href="..."> (referrer/identity-leak surface). */
function anchorHrefs(html, baseUrl) {
  const out = [];
  if (typeof html !== 'string') return out;
  const re = /<a\b[^>]*\bhref\s*=\s*("([^"]*)"|'([^']*)'|([^\s>]+))/gi;
  let m;
  while ((m = re.exec(html)) !== null) {
    const raw = (m[2] || m[3] || m[4] || '').trim();
    if (!raw || raw.startsWith('#') || /^(mailto|tel|javascript):/i.test(raw)) continue;
    const abs = resolveUrl(raw, baseUrl);
    if (abs && !out.includes(abs)) out.push(abs);
  }
  return out;
}

/** Resolve a possibly-relative URL against the page's URL; conservative. */
function resolveUrl(raw, baseUrl) {
  if (!raw) return null;
  try {
    if (/^https?:\/\//i.test(raw)) return new URL(raw).href;
    if (/^\/\//.test(raw)) {
      // protocol-relative: only resolvable if we know the base scheme
      if (!baseUrl) return null;
      return new URL(`${new URL(baseUrl).protocol}${raw}`).href;
    }
    if (baseUrl) return new URL(raw, baseUrl).href;
    return null; // relative ref with no base → unknown, don't guess a host
  } catch {
    return null;
  }
}

/** Read the content of the FIRST matching meta name (case-insensitive). */
function metaContent(html, name) {
  if (typeof html !== 'string') return null;
  // <meta name="robots" content="..."> in either attribute order
  const tags = html.match(/<meta\b[^>]*>/gi) || [];
  const wantName = name.toLowerCase();
  for (const tag of tags) {
    const nm = attr(tag, 'name');
    if (nm && nm.toLowerCase() === wantName) {
      const c = attr(tag, 'content');
      if (c != null) return decodeEntities(c).trim();
    }
  }
  return null;
}

/** Read <link rel="canonical" href="...">. */
function canonicalHref(html, baseUrl) {
  if (typeof html !== 'string') return null;
  const tags = html.match(/<link\b[^>]*>/gi) || [];
  for (const tag of tags) {
    const rel = attr(tag, 'rel');
    if (rel && rel.toLowerCase().split(/\s+/).includes('canonical')) {
      const href = attr(tag, 'href');
      if (href) return resolveUrl(decodeEntities(href).trim(), baseUrl) || decodeEntities(href).trim();
    }
  }
  return null;
}

/** Pull one attribute value from a single tag string. */
function attr(tag, name) {
  const re = new RegExp(`\\b${name}\\s*=\\s*("([^"]*)"|'([^']*)'|([^\\s>]+))`, 'i');
  const m = tag.match(re);
  if (!m) return null;
  return (m[2] != null ? m[2] : m[3] != null ? m[3] : m[4] != null ? m[4] : '');
}

// ── public API ──────────────────────────────────────────────────────────────

/**
 * Extract the three artifact kinds from a single captured HTML document.
 *
 * NETWORK-FREE: `html` is the ALREADY-CAPTURED body (as `apify run` would read
 * INPUT.json / a stored page from local storage, or a Crawlee handler would
 * receive the parsed body). This function performs NO fetch.
 *
 * @param {object} input
 * @param {string} input.html                 captured page HTML (required)
 * @param {string} [input.url]                 the public URL it was captured from
 * @param {string} [input.scope_type]          gate-approved scope, passed through
 * @param {string} [input.visibility]          VISIBILITY for PII/secret surfaces
 * @param {string} [input.x_robots_tag]        OPTIONAL response-header value (not in HTML)
 * @param {boolean} [input.robots_txt_disallow] OPTIONAL robots.txt fact (not in HTML)
 * @param {boolean} [input.archived]           OPTIONAL durable-archive observation
 * @returns {{page_text:object, page_resources:object, page_indexing:object, artifacts:object[]}}
 *          The three artifacts (each tagged with its `kind`) PLUS a flat
 *          `artifacts` array ready to hand straight to `runDetectors`.
 */
function extractArtifacts(input = {}) {
  const html = typeof input.html === 'string' ? input.html : '';
  const url = typeof input.url === 'string' ? input.url : undefined;
  const scope_type = input.scope_type;
  const visibility = input.visibility;

  // (a) human-visible text → PII; source text (visible + inline scripts) → secrets.
  // The registry routes BOTH the PII and secret modules at kind=page_text, and
  // each reads `page.text`. They need different text projections (rendered vs
  // source), so we expose both and let the caller pass the right one. To keep a
  // single artifact while honoring both, page_text.text is the SOURCE text
  // (a superset): PII patterns (email/phone/handle) do not false-positive on
  // inline JS, and the secret scanner needs the script bodies. We also surface
  // `visible_text` separately for callers that want the rendered-only view.
  const visText = visibleText(html);
  const srcText = sourceText(html);

  const page_text = {
    kind: ARTIFACT_KINDS.PAGE_TEXT,
    text: srcText,
    visible_text: visText,
    url,
    scope_type,
    visibility,
  };

  // (b) third-party RESOURCE/tracking surface (Blacklight split). Cookies cannot
  // be read from static markup, so they are honestly [] — an instrumented crawl
  // (separate track) fills them. js_api_calls likewise require runtime hooks; []
  // here. We DO surface real <script src> and outbound <a href>.
  const page_resources = {
    kind: ARTIFACT_KINDS.PAGE_RESOURCES,
    url,
    scope_type,
    scripts: scriptSrcs(html, url),
    cookies: [],
    js_api_calls: [],
    outbound_links: anchorHrefs(html, url),
  };

  // (c) search-discoverability posture (indexability module). Carriers present
  // in the HTML are <meta name="robots"> and <link rel="canonical">. The
  // HTTP-header carrier (X-Robots-Tag), robots.txt, and durable-archive facts
  // live OUTSIDE the document, so we only pass them through if the caller
  // observed them — never fabricated.
  const meta_robots = metaContent(html, 'robots');
  const canonical_url = canonicalHref(html, url);
  const page_indexing = {
    kind: ARTIFACT_KINDS.PAGE_INDEXING,
    url,
    scope_type,
    meta_robots: meta_robots != null ? meta_robots : null,
    canonical_url: canonical_url != null ? canonical_url : null,
    // pass-through, default null/undefined when the caller didn't observe them
    x_robots_tag: input.x_robots_tag != null ? input.x_robots_tag : null,
    robots_txt_disallow: input.robots_txt_disallow != null ? input.robots_txt_disallow : null,
    archived: input.archived != null ? input.archived : null,
  };

  return {
    page_text,
    page_resources,
    page_indexing,
    artifacts: [page_text, page_resources, page_indexing],
  };
}

module.exports = {
  extractArtifacts,
  // exported for unit tests + reuse by an enrich/correlation pass:
  visibleText,
  sourceText,
  scriptSrcs,
  anchorHrefs,
  metaContent,
  canonicalHref,
  resolveUrl,
  decodeEntities,
};
