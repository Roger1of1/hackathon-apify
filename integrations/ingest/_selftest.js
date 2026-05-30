/**
 * integrations/ingest/_selftest.js
 *
 * Self-contained, zero-dependency tests for the SELF-AUDIT INGESTION layer
 * (Apify Website Content Crawler + RAG Web Browser, scope-gated, mapped to
 * STIX 2.1 Observed Data). Lives in integrations/ (my subtree) — NOT in test/.
 * Run: `node integrations/ingest/_selftest.js`
 *
 * Properties asserted (all inside the red lines):
 *  - the REAL shared/scope.js gate runs FIRST: a private-individual / stalking
 *    query is DROPPED before any actor input exists (no fetch can be built);
 *  - a disallowed scope_type, a romance/dating-laundered self request, and a
 *    login-walled private-social host are all refused upstream of input-build;
 *  - a NAME/PHRASE web search (RAG) is a dual-use discovery chokepoint:
 *    refused for consented|brand|safety_evidence, allowed for self|public_figure;
 *  - the WCC input-builder forces respectRobotsTxtFile:true even when the caller
 *    passes false, and clamps maxCrawlPages/Depth DOWN to caps (anti-dragnet);
 *  - the item-pipeline maps a REAL WCC row -> detector module_events -> STIX 2.1
 *    Observed Data with first_observed/last_observed/content-hash/observable
 *    category, and a row on a NON-vetted host is DROPPED (host re-assertion);
 *  - a failed WCC page (error field) surfaces as page_error and yields no events;
 *  - the client dry-runs without a token: started:false, no network, no fake rows.
 */

'use strict';

const assert = require('assert');
const {
  buildIngestPlan,
  buildIngestItemPipeline,
  ingestRowsToBundle,
  wccRowToArtifacts,
  isUrlQuery,
  clampDown,
  SOURCE,
  REFUSAL,
} = require('./ingest-policy.js');
const { planAndDescribe } = require('./ingest-client.js');

let pass = 0;
let fail = 0;
function check(name, fn) {
  try {
    fn();
    pass += 1;
    console.log(`  PASS  ${name}`);
  } catch (err) {
    fail += 1;
    console.log(`  FAIL  ${name}: ${err.message}`);
  }
}

// A minimal valid "self" subject the scope gate accepts.
const SELF = {
  scope_type: 'self',
  subject_label: 'me',
  target_urls: ['https://my-own-site.example/me'],
  ingest_source: SOURCE.WCC,
};

console.log('\n[1] scope gate runs FIRST — stalking / private query dropped before any input is built');
check('disallowed scope (private_person_tracking) => no actor input', () => {
  const p = buildIngestPlan({ scope_type: 'private_person_tracking', ingest_source: SOURCE.WCC });
  assert.strictEqual(p.allowed, false);
  assert.strictEqual(p.refusal, REFUSAL.SCOPE_REJECTED);
  assert.ok(!p.input, 'no actor input may be built for a rejected subject');
});
check('romance laundering under self => dropped by gate (no input)', () => {
  const p = buildIngestPlan(Object.assign({}, SELF, { prohibited_analysis: ['romance_inference'] }));
  assert.strictEqual(p.allowed, false);
  assert.strictEqual(p.refusal, REFUSAL.SCOPE_REJECTED);
  assert.ok(!p.input);
});
check('stalking freeText under self => dropped by gate (no input)', () => {
  const p = buildIngestPlan(Object.assign({}, SELF, {
    freeText: 'track a private person and watch their account for me',
  }));
  assert.strictEqual(p.allowed, false);
  assert.strictEqual(p.refusal, REFUSAL.SCOPE_REJECTED);
  assert.ok(!p.input);
});
check('login-walled private-social host => dropped by gate (no input)', () => {
  const p = buildIngestPlan({
    scope_type: 'self',
    subject_label: 'me',
    target_urls: ['https://www.instagram.com/someones-followers'],
    ingest_source: SOURCE.WCC,
  });
  assert.strictEqual(p.allowed, false);
  assert.strictEqual(p.refusal, REFUSAL.SCOPE_REJECTED);
  assert.ok(!p.input);
});

console.log('\n[2] RAG name search is a dual-use chokepoint (self|public_figure only)');
check('RAG NAME search refused for scope=brand', () => {
  const p = buildIngestPlan({
    scope_type: 'brand',
    subject_label: 'acme',
    target_urls: ['https://acme.example/product'],
    ingest_source: SOURCE.RAG,
    query: 'acme product reviews', // a phrase, not a URL
  });
  assert.strictEqual(p.allowed, false);
  assert.strictEqual(p.refusal, REFUSAL.NAME_SEARCH_NOT_ALLOWED_FOR_SCOPE);
});
check('RAG URL query ALLOWED for scope=brand (concrete URL, not a name search)', () => {
  const p = buildIngestPlan({
    scope_type: 'brand',
    subject_label: 'acme',
    target_urls: ['https://acme.example/product'],
    ingest_source: SOURCE.RAG,
    query: 'https://news.example/acme-coverage',
  });
  assert.strictEqual(p.allowed, true);
  assert.strictEqual(p.source, SOURCE.RAG);
  assert.strictEqual(p.is_name_search, false);
  assert.strictEqual(p.deployed, false);
});
check('RAG NAME search ALLOWED for scope=self', () => {
  const p = buildIngestPlan(Object.assign({}, SELF, {
    ingest_source: SOURCE.RAG,
    query: 'my own name where am i mentioned',
  }));
  assert.strictEqual(p.allowed, true);
  assert.strictEqual(p.is_name_search, true);
});
check('isUrlQuery distinguishes a URL from a phrase', () => {
  assert.strictEqual(isUrlQuery('https://x.example/p'), true);
  assert.strictEqual(isUrlQuery('find me everywhere'), false);
});

console.log('\n[3] WCC input-builder — robots forced ON, caps clamp DOWN (anti-dragnet)');
check('respectRobotsTxtFile forced true even when caller passes false', () => {
  const p = buildIngestPlan(Object.assign({}, SELF, { respectRobotsTxtFile: false, maxCrawlPages: 99999 }));
  assert.strictEqual(p.allowed, true);
  assert.strictEqual(p.input.respectRobotsTxtFile, true);
});
check('maxCrawlPages clamped DOWN to the cap, never up', () => {
  const p = buildIngestPlan(Object.assign({}, SELF, { maxCrawlPages: 100000 }));
  assert.ok(p.input.maxCrawlPages <= p.caps.max_crawl_pages);
});
check('startUrls + host-confining includeUrlGlobs built from vetted targets', () => {
  const p = buildIngestPlan(SELF);
  assert.deepStrictEqual(p.input.startUrls, [{ url: 'https://my-own-site.example/me' }]);
  assert.ok(p.input.includeUrlGlobs.some((g) => g.includes('my-own-site.example')));
  assert.strictEqual(p.actorId.includes('PLACEHOLDER') || p.actorId.includes('website-content-crawler'), true);
  assert.strictEqual(p.deployed, false);
});
check('clampDown helper clamps down and floors invalid to fallback', () => {
  assert.strictEqual(clampDown(1000, 50, 25), 50);
  assert.strictEqual(clampDown(10, 50, 25), 10);
  assert.strictEqual(clampDown(-3, 50, 25), 25);
  assert.strictEqual(clampDown('nope', 50, 25), 25);
});

console.log('\n[4] item-pipeline maps a REAL WCC row -> module_events -> STIX 2.1 Observed Data');
const plan = buildIngestPlan(SELF);
const REAL_ROW = {
  url: 'https://my-own-site.example/me',
  crawl: { loadedUrl: 'https://my-own-site.example/me' },
  // A real self-published contact email in the page text -> PII_EMAIL_PUBLIC.
  text: 'Contact me: hello.self.audit@my-own-site.example  Based in Berlin.',
  markdown: '# Me\nContact me: hello.self.audit@my-own-site.example',
  metadata: { title: 'About me', canonicalUrl: 'https://my-own-site.example/me', contentSha256: 'abc123' },
  htmlUrl: 'https://kvs.apify.example/html/me.html',
  screenshotUrl: 'https://kvs.apify.example/shot/me.png',
};
check('wccRowToArtifacts builds a PAGE_TEXT artifact + integrity handles', () => {
  const m = wccRowToArtifacts(REAL_ROW);
  assert.ok(m.artifacts.length >= 1);
  assert.strictEqual(m.artifacts[0].kind, 'page_text');
  assert.strictEqual(m.integrity.html_key, 'https://kvs.apify.example/html/me.html');
  assert.strictEqual(m.integrity.screenshot_key, 'https://kvs.apify.example/shot/me.png');
  assert.strictEqual(m.integrity.content_sha256, 'abc123');
});
check('pipeline produces module_events AND STIX Observed Data with the right shape', () => {
  const { runRow } = buildIngestItemPipeline(plan, { now: '2026-05-30T00:00:00.000Z' });
  const res = runRow(REAL_ROW);
  assert.strictEqual(res.status, 'ok');
  const item = res.item;
  assert.ok(Array.isArray(item.events) && item.events.length >= 1, 'expected >=1 detected event');
  assert.ok(item.events.some((e) => e.event_type === 'PII_EMAIL_PUBLIC'), 'expected a public email event');
  assert.ok(Array.isArray(item.observed_data) && item.observed_data.length >= 1, 'expected STIX Observed Data');
  const od = item.observed_data[0];
  assert.strictEqual(od.type, 'observed-data');
  assert.strictEqual(od.spec_version, '2.1');
  assert.strictEqual(od.first_observed, '2026-05-30T00:00:00.000Z');
  assert.strictEqual(od.last_observed, '2026-05-30T00:00:00.000Z');
  assert.strictEqual(od.number_observed, 1);
  assert.strictEqual(od.x_integrity.html_key, 'https://kvs.apify.example/html/me.html');
  assert.strictEqual(od.x_integrity.content_sha256, 'abc123');
  assert.ok(od.objects && od.objects['0'], 'STIX objects bag present');
});

console.log('\n[5] host re-assertion — a row on a NON-vetted host is DROPPED (no smuggling)');
check('row whose source host is not a vetted target is dropped', () => {
  const { runRow } = buildIngestItemPipeline(plan, { now: '2026-05-30T00:00:00.000Z' });
  const evil = {
    url: 'https://not-my-site.example/someone-else',
    crawl: { loadedUrl: 'https://not-my-site.example/someone-else' },
    text: 'someone.else@elsewhere.example',
  };
  const res = runRow(evil);
  assert.strictEqual(res.status, 'dropped');
  assert.strictEqual(res.droppedBy, 'scope-reassert');
});

console.log('\n[6] failed WCC page surfaces as page_error and yields no events');
check('row with error field -> page_error, zero events', () => {
  const { runRow } = buildIngestItemPipeline(plan, { now: '2026-05-30T00:00:00.000Z' });
  const failed = {
    url: 'https://my-own-site.example/me',
    crawl: { loadedUrl: 'https://my-own-site.example/me' },
    error: 'Navigation timeout of 60000 ms exceeded',
    text: null,
  };
  const res = runRow(failed);
  assert.strictEqual(res.status, 'ok');
  assert.strictEqual(res.item.page_error, 'Navigation timeout of 60000 ms exceeded');
  assert.strictEqual((res.item.events || []).length, 0);
});

console.log('\n[7] batch -> STIX bundle; dropped rows excluded');
check('ingestRowsToBundle bundles real rows + drops the foreign-host row', () => {
  const out = ingestRowsToBundle(
    plan,
    [REAL_ROW, { url: 'https://not-my-site.example/x', crawl: { loadedUrl: 'https://not-my-site.example/x' }, text: 'a@b.example' }],
    { now: '2026-05-30T00:00:00.000Z' },
  );
  assert.strictEqual(out.bundle.type, 'bundle');
  assert.strictEqual(out.bundle.spec_version, '2.1');
  assert.ok(out.events.length >= 1);
  assert.strictEqual(out.dropped.length, 1, 'the foreign-host row must be dropped from the bundle');
});

console.log('\n[8] client dry-run honesty — no token => started:false, no network, no fake rows');
check('dry-run without token returns the exact request, started:false', () => {
  const r = planAndDescribe(SELF, { token: null });
  assert.strictEqual(r.started, false);
  assert.strictEqual(r.mode, 'dry_run_no_token');
  assert.ok(r.request.url.includes('run-sync-get-dataset-items'));
  assert.ok(r.request.url.includes('<MISSING_APIFY_TOKEN>'));
  assert.strictEqual(r.request.deployed, false);
  assert.deepStrictEqual(r.request.body.startUrls, [{ url: 'https://my-own-site.example/me' }]);
});
check('refused subject => client reports refused, no request', () => {
  const r = planAndDescribe({ scope_type: 'private_person_tracking', ingest_source: SOURCE.WCC }, { token: 'x' });
  assert.strictEqual(r.started, false);
  assert.strictEqual(r.mode, 'refused');
  assert.strictEqual(r.refusal, REFUSAL.SCOPE_REJECTED);
  assert.ok(!r.request, 'no run request for a refused subject');
});
check('with token => live request BUILT but NOT sent, still deployed:false', () => {
  const r = planAndDescribe(SELF, { token: 'tok_placeholder' });
  assert.strictEqual(r.started, false);
  assert.strictEqual(r.mode, 'live_request_built_not_sent');
  assert.ok(r.request.url.includes('<APIFY_TOKEN>'));
  assert.strictEqual(r.request.deployed, false);
});

console.log(
  `\nOK — ingestion: scope-gate-first + name-search chokepoint + robots-forced + ` +
    `caps-clamp + WCC-row->STIX + host-reassert + dry-run honesty. ${pass} pass, ${fail} fail.\n`,
);
if (fail > 0) process.exit(1);
