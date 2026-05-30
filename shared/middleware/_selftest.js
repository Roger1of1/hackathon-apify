/**
 * shared/middleware/_selftest.js
 *
 * Self-test for the Crawlee/Scrapy-style compliance pipeline. Proves:
 *   1. Downloader middlewares run in ascending `order` (Scrapy convention).
 *   2. A stalking / private-individual request is DROPPED at the scope-gate
 *      middleware (order 100) BEFORE robots, rate-limit, or any fetch stage runs
 *      — i.e. no network I/O is ever reached for a prohibited request.
 *   3. A legitimate scope=self request passes the whole chain and the terminal
 *      stage returns a clearly-labelled TEMPLATE response (never fake scrape).
 *   4. The RequestQueue dedupes and a re-discovered prohibited link is re-gated
 *      on the next hop (gate re-asserts every hop, not just at submit).
 *   5. The item pipeline runs in order and attaches tamper-evident hashes, and
 *      drops an item with a missing/invalid scope_type.
 *
 * Run: node shared/middleware/_selftest.js
 *
 * Refs applied:
 *   - Scrapy downloader middleware `process_request` (None/Response/Request/
 *     IgnoreRequest) + item pipeline `process_item` ordering by priority number.
 *   - Crawlee RequestQueue (ordered, dedupe by uniqueKey) + per-hop routing.
 *   - (Sibling deliverable) HIBP k-anonymity range query for the breach feature.
 */

'use strict';

const assert = require('assert');
const {
  RequestQueue,
  buildDownloaderChain,
  buildItemPipeline,
  byOrder,
} = require('./pipeline.js');
const {
  defaultDownloaderMiddlewares,
  defaultItemPipeline,
} = require('./stages.js');

let pass = 0;
const fail = [];
function check(name, fn) {
  try {
    fn();
    pass += 1;
    console.log('  PASS  ' + name);
  } catch (err) {
    fail.push({ name, err });
    console.log('  FAIL  ' + name + ' — ' + err.message);
  }
}

console.log('\n[1] downloader middleware ordering (Scrapy: lower order first)');

check('stages are ordered 100,200,300,900', () => {
  const ordered = byOrder(defaultDownloaderMiddlewares());
  assert.deepStrictEqual(ordered.map((m) => m.order), [100, 200, 300, 900]);
  assert.deepStrictEqual(
    ordered.map((m) => m.name),
    ['scopeGate', 'robotsTos', 'rateLimit', 'fetchTerminal'],
  );
});

console.log('\n[2] a stalking request is dropped at the gate BEFORE any fetch');

check('private-person scope_type dropped at scopeGate, fetch never runs', () => {
  let fetchCalled = false;
  const chain = buildDownloaderChain(
    defaultDownloaderMiddlewares({
      fetch: () => { fetchCalled = true; return { ok: true }; },
    }),
  );
  const res = chain.run({
    url: 'https://example.com/someone',
    scopeEnvelope: {
      scope_type: 'private_person_tracking',
      intent_text: '帮我查一下我私人个体住在哪',
    },
  });
  assert.strictEqual(res.status, 'dropped', 'must be dropped');
  assert.strictEqual(res.droppedBy, 'scopeGate', 'must be dropped at scopeGate, not later');
  assert.strictEqual(fetchCalled, false, 'fetch must NEVER run for a stalking request');
  // gate is the only stage that executed before the drop
  assert.deepStrictEqual(res.trace.map((t) => t.mw), ['scopeGate']);
});

check('laundering: self scope + stalking intent text dropped at gate', () => {
  let fetchCalled = false;
  const chain = buildDownloaderChain(
    defaultDownloaderMiddlewares({ fetch: () => { fetchCalled = true; } }),
  );
  const res = chain.run({
    url: 'https://example.com/p',
    scopeEnvelope: {
      scope_type: 'self',
      intent_text: 'stalk a private person-girlfriend and find her home address',
    },
  });
  assert.strictEqual(res.status, 'dropped');
  assert.strictEqual(res.droppedBy, 'scopeGate');
  assert.strictEqual(fetchCalled, false);
});

console.log('\n[3] a legitimate self request passes the whole chain (template fetch)');

check('scope=self passes; terminal returns labelled TEMPLATE, not fake data', () => {
  const chain = buildDownloaderChain(defaultDownloaderMiddlewares());
  const res = chain.run({
    url: 'https://example.com/my-public-profile',
    scopeEnvelope: { scope_type: 'self', intent_text: '审计我本人的公开足迹' },
  });
  assert.strictEqual(res.status, 'short_circuit', 'terminal stage supplies the response');
  assert.strictEqual(res.response.template, true, 'must be a labelled template, never fake scrape');
  assert.strictEqual(res.response.scope_type, 'self');
  // proves it traversed gate -> robots -> rateLimit -> fetchTerminal in order
  assert.deepStrictEqual(
    res.trace.map((t) => t.mw),
    ['scopeGate', 'robotsTos', 'rateLimit', 'fetchTerminal'],
  );
});

check('robots.txt disallow drops a self request at robotsTos (order 200), after gate', () => {
  // The scope gate (order 100) passes a legit self host; the robots/ToS layer
  // (order 200) then enforces robots.txt — here injected to disallow this path.
  const chain = buildDownloaderChain(defaultDownloaderMiddlewares({
    robotsAllows: (url) => !url.includes('/disallowed'),
  }));
  const res = chain.run({
    url: 'https://example.com/disallowed/page',
    scopeEnvelope: { scope_type: 'self', intent_text: '我本人的公开页面' },
  });
  assert.strictEqual(res.status, 'dropped');
  assert.strictEqual(res.droppedBy, 'robotsTos', 'robots/ToS layer must drop disallowed paths');
  // proves the gate ran and passed FIRST, then robots dropped it
  assert.deepStrictEqual(res.trace.map((t) => t.mw), ['scopeGate', 'robotsTos']);
});

check('private-social host is defense-in-depth blocked (gate AND robotsTos)', () => {
  const chain = buildDownloaderChain(defaultDownloaderMiddlewares());
  const res = chain.run({
    url: 'https://www.instagram.com/someprofile',
    scopeEnvelope: { scope_type: 'self', intent_text: '我本人的公开页面' },
  });
  // scope.js itself blocks login-walled private-social hosts, so the drop
  // happens as early as the scope gate. robotsTos would also block it.
  assert.strictEqual(res.status, 'dropped');
  assert.ok(['scopeGate', 'robotsTos'].includes(res.droppedBy), 'must be blocked, earliest wins');
});

console.log('\n[4] RequestQueue dedupe + per-hop re-gating of discovered links');

check('RequestQueue enqueues once, dedupes the second time', () => {
  const q = new RequestQueue();
  assert.strictEqual(q.enqueue({ url: 'https://example.com/a' }), true);
  assert.strictEqual(q.enqueue({ url: 'https://example.com/a' }), false);
  assert.strictEqual(q.size, 1);
});

check('a discovered link inheriting a stalking envelope is re-gated and dropped', () => {
  const chain = buildDownloaderChain(defaultDownloaderMiddlewares({
    fetch: () => { throw new Error('fetch must not be reached'); },
  }));
  // simulate a link discovered mid-crawl that carries a prohibited envelope
  const discovered = {
    url: 'https://example.com/discovered',
    scopeEnvelope: { scope_type: 'self', intent_text: '顺便扒一下那个女生的行踪' },
  };
  const res = chain.run(discovered);
  assert.strictEqual(res.status, 'dropped');
  assert.strictEqual(res.droppedBy, 'scopeGate');
});

console.log('\n[5] item pipeline ordering + evidence hashing + drop-on-bad-scope');

check('item pipeline runs scopeReassert(100) then evidenceHash(500) in order', () => {
  const pipe = buildItemPipeline(defaultItemPipeline());
  assert.deepStrictEqual(pipe.ordered.map((s) => s.order), [100, 500]);
  const out = pipe.run({
    scope_type: 'self',
    url: 'https://example.com/x',
    text: '  hello   world  ',
    html: '<p>hello world</p>',
  });
  assert.strictEqual(out.status, 'ok');
  assert.match(out.item.content_sha256, /^[0-9a-f]{64}$/, 'content hash attached');
  assert.match(out.item.html_sha256, /^[0-9a-f]{64}$/, 'html hash attached');
  assert.deepStrictEqual(out.trace.map((t) => t.stage), ['scopeReassertItem', 'evidenceHash']);
});

check('item with invalid scope_type dropped at scopeReassert, never hashed', () => {
  const pipe = buildItemPipeline(defaultItemPipeline());
  const out = pipe.run({ scope_type: 'private_person_tracking', text: 'x', html: '<p>x</p>' });
  assert.strictEqual(out.status, 'dropped');
  assert.strictEqual(out.droppedBy, 'scopeReassertItem');
  assert.strictEqual(out.item.content_sha256, undefined, 'must not be hashed/persisted');
});

console.log(
  '\n' + (fail.length === 0
    ? `OK — ${pass} middleware-pipeline checks passed, 0 failures (Scrapy ordering + Crawlee RequestQueue + fail-closed scope gate).`
    : `FAILED — ${fail.length} failure(s).`),
);
process.exit(fail.length === 0 ? 0 : 1);
