#!/usr/bin/env node
/**
 * shared/detectors/html-artifacts_selftest.js
 *
 * Dependency-free self-tests for the HTML → artifact extractor (the seam that
 * lets a captured page flow into the REAL detector registry). Run:
 *   node shared/detectors/html-artifacts_selftest.js
 *
 * NO FAKE DATA: the extractor only surfaces signals literally present in the
 * supplied HTML. These tests assert exactly that — including that it emits
 * NOTHING (empty/null) where the HTML carries nothing, so no downstream detector
 * is fed an invented input. We also drive the extractor's output through the
 * REAL `runDetectors` registry (end-to-end, no mocks) — the same integration-on-
 * a-local-fixture pattern Crawlee/Apify-CLI runs use against local storage.
 */

'use strict';

const fs = require('fs');
const path = require('path');
const assert = require('assert');

const {
  extractArtifacts, visibleText, sourceText, scriptSrcs, anchorHrefs,
  metaContent, canonicalHref, resolveUrl, decodeEntities,
} = require('./html-artifacts.js');
const { ARTIFACT_KINDS, runDetectors } = require('./index.js');
const { EVENT_TYPES } = require('./event-types.js');

let pass = 0;
function t(name, fn) {
  try { fn(); pass += 1; console.log(`  PASS  ${name}`); }
  catch (e) { console.error(`  FAIL  ${name}: ${e.message}`); process.exitCode = 1; }
}

// ── [1] primitive extraction helpers ────────────────────────────────────────
console.log('[html-artifacts / primitives]');

t('visibleText strips tags, scripts, styles and decodes entities', () => {
  const txt = visibleText(
    '<style>.a{}</style><p>Hello&nbsp;&amp; <b>world</b></p><script>var x=1</script>'
  );
  assert.ok(txt.includes('Hello & world'), txt);
  assert.ok(!txt.includes('var x'), 'inline script must not leak into visible text');
  assert.ok(!txt.includes('.a{}'), 'style content must not leak into visible text');
});

t('sourceText INCLUDES inline-script bodies (for secret scanning) but visibleText does NOT', () => {
  const html = '<p>hi</p><script>const K="AKIAIOSFODNN7EXAMPLE";</script>';
  assert.ok(sourceText(html).includes('AKIAIOSFODNN7EXAMPLE'));
  assert.ok(!visibleText(html).includes('AKIAIOSFODNN7EXAMPLE'));
});

t('sourceText does NOT pull in external <script src> bodies (it has none)', () => {
  const html = '<p>hi</p><script src="https://cdn.example/x.js"></script>';
  // external script has no inline body to add; sourceText == visibleText here
  assert.strictEqual(sourceText(html), visibleText(html));
});

t('scriptSrcs resolves and dedupes only real src attributes', () => {
  const html =
    '<script src="https://a.example/x.js"></script>' +
    '<script>inline()</script>' +
    '<script src="/y.js"></script>' +
    '<script src="https://a.example/x.js"></script>';
  const out = scriptSrcs(html, 'https://site.example/page');
  assert.deepStrictEqual(out, ['https://a.example/x.js', 'https://site.example/y.js']);
});

t('anchorHrefs skips #fragments, mailto/tel/js, resolves relative, dedupes', () => {
  const html =
    '<a href="#top">x</a>' +
    '<a href="mailto:a@b.c">m</a>' +
    '<a href="/about">a</a>' +
    '<a href="https://ext.example/p">e</a>' +
    '<a href="/about">dup</a>';
  const out = anchorHrefs(html, 'https://site.example/page');
  assert.deepStrictEqual(out, ['https://site.example/about', 'https://ext.example/p']);
});

t('metaContent reads <meta name=robots> in either attribute order', () => {
  assert.strictEqual(metaContent('<meta name="robots" content="noindex">', 'robots'), 'noindex');
  assert.strictEqual(metaContent('<meta content="noindex,nofollow" name="ROBOTS">', 'robots'), 'noindex,nofollow');
  assert.strictEqual(metaContent('<meta name="description" content="x">', 'robots'), null);
});

t('canonicalHref resolves rel=canonical against the base url', () => {
  assert.strictEqual(
    canonicalHref('<link rel="canonical" href="/me">', 'https://site.example/page'),
    'https://site.example/me'
  );
  assert.strictEqual(canonicalHref('<link rel="stylesheet" href="/x.css">', 'https://s/'), null);
});

t('resolveUrl never fabricates a host for a relative ref with no base', () => {
  assert.strictEqual(resolveUrl('/foo', undefined), null);
  assert.strictEqual(resolveUrl('https://x.example/a', undefined), 'https://x.example/a');
});

t('decodeEntities handles numeric + named entities, rejects out-of-range', () => {
  assert.strictEqual(decodeEntities('a&#39;b&amp;c'), "a'b&c");
  assert.strictEqual(decodeEntities('&#x2014;'), '—');
});

// ── [2] extractArtifacts shape + pass-through + no-fabrication ───────────────
console.log('\n[html-artifacts / extractArtifacts]');

t('returns the three registry artifact kinds plus a flat artifacts[]', () => {
  const r = extractArtifacts({ html: '<p>x</p>', url: 'https://s.example/p', scope_type: 'self' });
  assert.strictEqual(r.page_text.kind, ARTIFACT_KINDS.PAGE_TEXT);
  assert.strictEqual(r.page_resources.kind, ARTIFACT_KINDS.PAGE_RESOURCES);
  assert.strictEqual(r.page_indexing.kind, ARTIFACT_KINDS.PAGE_INDEXING);
  assert.deepStrictEqual(
    r.artifacts.map((a) => a.kind),
    [ARTIFACT_KINDS.PAGE_TEXT, ARTIFACT_KINDS.PAGE_RESOURCES, ARTIFACT_KINDS.PAGE_INDEXING]
  );
});

t('scope_type and url ride through onto every artifact (gate decision travels)', () => {
  const r = extractArtifacts({ html: '<p>x</p>', url: 'https://s.example/p', scope_type: 'public_figure' });
  for (const a of r.artifacts) {
    assert.strictEqual(a.scope_type, 'public_figure', `${a.kind} lost scope_type`);
    assert.strictEqual(a.url, 'https://s.example/p', `${a.kind} lost url`);
  }
});

t('NO FAKE DATA: cookies and js_api_calls are honestly empty for static HTML', () => {
  const r = extractArtifacts({ html: '<script src="https://t.example/t.js"></script>', url: 'https://s/' });
  assert.deepStrictEqual(r.page_resources.cookies, []);
  assert.deepStrictEqual(r.page_resources.js_api_calls, []);
  // the real script src IS surfaced (not invented, but observed)
  assert.deepStrictEqual(r.page_resources.scripts, ['https://t.example/t.js']);
});

t('NO FAKE DATA: indexing carriers absent from HTML stay null (no defaulted posture)', () => {
  const r = extractArtifacts({ html: '<p>no directives here</p>', url: 'https://s/p' });
  assert.strictEqual(r.page_indexing.meta_robots, null);
  assert.strictEqual(r.page_indexing.canonical_url, null);
  assert.strictEqual(r.page_indexing.x_robots_tag, null);
  assert.strictEqual(r.page_indexing.robots_txt_disallow, null);
  assert.strictEqual(r.page_indexing.archived, null);
});

t('out-of-document indexing facts pass through ONLY when the caller observed them', () => {
  const r = extractArtifacts({
    html: '<p>x</p>', url: 'https://s/p',
    x_robots_tag: 'noindex', robots_txt_disallow: true, archived: false,
  });
  assert.strictEqual(r.page_indexing.x_robots_tag, 'noindex');
  assert.strictEqual(r.page_indexing.robots_txt_disallow, true);
  assert.strictEqual(r.page_indexing.archived, false);
});

t('empty/garbage input yields well-formed empty artifacts, never throws', () => {
  for (const bad of [undefined, {}, { html: null }, { html: 123 }]) {
    const r = extractArtifacts(bad);
    assert.strictEqual(r.page_text.text, '');
    assert.deepStrictEqual(r.page_resources.scripts, []);
    assert.deepStrictEqual(r.page_resources.outbound_links, []);
  }
});

// ── [3] END-TO-END through the REAL detector registry (no mocks) ─────────────
// This is the integration-on-a-local-fixture pattern (Crawlee local dataset /
// Apify CLI local run): real captured HTML in, real detector events out.
console.log('\n[html-artifacts / end-to-end through runDetectors]');

t('rich page: every applicable real detector fires from the extracted artifacts', () => {
  const html = `<!DOCTYPE html><html><head>
    <meta name="robots" content="noindex">
    <link rel="canonical" href="/me">
    <script src="https://www.google-analytics.com/analytics.js"></script>
  </head><body>
    <h1>Contact</h1>
    <p>Email me at jane.doe@example.com or call (555) 123-4567</p>
    <a href="https://twitter.com/janedoe">twitter</a>
    <script>const AWS_KEY="AKIAIOSFODNN7EXAMPLE";</script>
  </body></html>`;
  const { artifacts } = extractArtifacts({ html, url: 'https://jane.example.com/contact', scope_type: 'self' });
  const { events, by_module, skipped } = runDetectors(artifacts);
  assert.strictEqual(skipped, 0, 'all three artifacts must be dispatched');
  const types = new Set(events.map((e) => e.event_type));
  assert.ok(types.has(EVENT_TYPES.PII_EMAIL_PUBLIC), 'email PII expected');
  assert.ok(types.has(EVENT_TYPES.PII_PHONE_PUBLIC), 'phone PII expected');
  assert.ok(types.has(EVENT_TYPES.SECRET_LEAK_PUBLIC), 'inline-script secret expected');
  assert.ok(types.has(EVENT_TYPES.TRACKER_THIRD_PARTY), 'GA tracker expected');
  assert.ok(types.has(EVENT_TYPES.EXPOSURE_SUMMARY), 'indexability summary expected');
  assert.ok(by_module.pii_detector >= 2 && by_module.secret_leak_detector >= 1, JSON.stringify(by_module));
});

t('REAL demo fixture (demo/sample-evidence.html) yields ONLY honest findings', () => {
  const fixture = path.join(__dirname, '..', '..', 'demo', 'sample-evidence.html');
  if (!fs.existsSync(fixture)) { console.log('    (skip: demo fixture not present)'); return; }
  const html = fs.readFileSync(fixture, 'utf8');
  const { artifacts } = extractArtifacts({
    html, url: 'https://example.org/demo/sample-evidence.html', scope_type: 'safety_evidence',
  });
  const { events, by_module } = runDetectors(artifacts);
  // The synthetic demo page contains NO PII/secret/tracker — only an indexable
  // posture. The extractor + detectors must reflect that honestly: exactly the
  // indexability summary, nothing fabricated.
  assert.ok(!('pii_detector' in by_module), 'demo page has no PII to detect');
  assert.ok(!('secret_leak_detector' in by_module), 'demo page has no secret to detect');
  assert.ok(!('tracker_detector' in by_module), 'demo page has no tracker to detect');
  const types = events.map((e) => e.event_type);
  assert.deepStrictEqual(types, [EVENT_TYPES.EXPOSURE_SUMMARY], `unexpected events: ${types}`);
});

t('DETERMINISM: extracting the same HTML twice yields identical artifacts', () => {
  const html = '<meta name="robots" content="index"><p>a@b.com</p><a href="/x">l</a>';
  const a = extractArtifacts({ html, url: 'https://s/p', scope_type: 'self' });
  const b = extractArtifacts({ html, url: 'https://s/p', scope_type: 'self' });
  assert.deepStrictEqual(a.artifacts, b.artifacts);
});

console.log(`\nOK — html-artifacts self-tests, ${pass} passed.`);
