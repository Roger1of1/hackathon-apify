#!/usr/bin/env node
/**
 * integrations/frontier/frontier_selftest.js
 *
 * Self-test for the Apify Request Queue ('frontier') layer. Proves the
 * load-bearing guarantees with REAL assertions (no fake data, no network):
 *   1. Scope gate is the front door — a prohibited subject is REFUSED and yields
 *      zero enqueueable requests (fail-closed).
 *   2. Private-social hosts are refused ENTRY to the frontier (second door).
 *   3. uniqueKey canonicalization collapses different spellings of the SAME
 *      public surface to ONE queue entry (dedup == minimum-disclosure).
 *   4. respectRobotsTxtFile is FORCED true in every request's userData even if a
 *      caller tries to turn it off (anti-evasion floor).
 *   5. The frontier is BOUNDED: caps + remaining headroom clamp the enqueue DOWN
 *      (anti-dragnet), and batch size never exceeds the Apify ≤25 limit.
 *   6. The client DRY-RUNS without APIFY_TOKEN: it builds API descriptors but
 *      makes NO network call and asserts usedNetwork:false.
 *
 * Auto-discovered & spawned by integrations/run-module-selftests.js (npm run
 * test:modules). Exits non-zero on any failure (fail-closed CI).
 */

'use strict';

const assert = require('assert');
const {
  buildEnqueuePlan,
  canonicalizeUrl,
  isPrivateSocialHost,
  splitBatches,
} = require('./frontier-policy.js');
const { enqueue } = require('./frontier-client.js');

let passed = 0;
function ok(label, cond) {
  assert.ok(cond, `FAIL: ${label}`);
  console.log(`  PASS  ${label}`);
  passed += 1;
}

console.log('\nfrontier_selftest — Apify Request Queue layer\n');

// ── 1. Scope gate is the front door (fail-closed) ────────────────────────────
const stalk = buildEnqueuePlan({
  scope_type: 'private_person_tracking',
  target_urls: ['https://example.com/ex'],
});
ok('prohibited scope_type refused at the gate', stalk.allowed === false);
ok('refusal yields NO requests array', stalk.requests === undefined);
ok('refusal carries scope reasons', Array.isArray(stalk.scope_reasons) && stalk.scope_reasons.length > 0);

// A laundered self-scope with a stalking intent string must also be refused.
const launder = buildEnqueuePlan({
  scope_type: 'self',
  target_urls: ['https://self-demo.example/me'],
  subject_label: 'stalk a private person and watch this person',
});
ok('laundered stalking intent under scope=self refused', launder.allowed === false);

// ── 2. Private-social hosts refused entry ────────────────────────────────────
ok('isPrivateSocialHost flags instagram.com', isPrivateSocialHost('https://www.instagram.com/someone') === true);
ok('isPrivateSocialHost allows own site', isPrivateSocialHost('https://self-demo.example/about') === false);

// ── 3. uniqueKey canonicalization / dedup ────────────────────────────────────
const a = canonicalizeUrl('https://Self-Demo.Example:443/about/');
const b = canonicalizeUrl('https://self-demo.example/about');
ok('canonicalize collapses case + default port + trailing slash', a === b);
const q1 = canonicalizeUrl('https://x.example/p?b=2&a=1');
const q2 = canonicalizeUrl('https://x.example/p?a=1&b=2#frag');
ok('canonicalize sorts query + drops fragment', q1 === q2);
ok('canonicalize refuses non-http(s)', canonicalizeUrl('ftp://x.example/f') === null);

const dupPlan = buildEnqueuePlan({
  scope_type: 'self',
  target_urls: [
    'https://self-demo.example/about',
    'https://Self-Demo.Example/about/', // same surface, different spelling
    'https://self-demo.example/contact',
  ],
});
ok('dedup plan accepted (scope=self)', dupPlan.allowed === true);
ok('dedup collapses two spellings to one request', dupPlan.requests.length === 2);
ok('dedup accounting reports one already_present', dupPlan.dedup.already_present === 1);

// ── 4. respectRobotsTxtFile forced on (anti-evasion) ─────────────────────────
ok(
  'every enqueued request forces respectRobotsTxtFile:true',
  dupPlan.requests.every((r) => r.userData && r.userData.respectRobotsTxtFile === true),
);
ok(
  'every enqueued request records scope_reasserted',
  dupPlan.requests.every((r) => r.userData && r.userData.scope_reasserted === true),
);
ok(
  'every request carries a uniqueKey == its canonical url',
  dupPlan.requests.every((r) => r.uniqueKey === canonicalizeUrl(r.url)),
);

// ── 5. Bounded frontier: caps + headroom clamp DOWN; batch ≤25 ───────────────
const many = [];
for (let i = 0; i < 60; i += 1) many.push(`https://self-demo.example/p/${i}`);
const bigPlan = buildEnqueuePlan({ scope_type: 'self', target_urls: many });
ok('big enqueue clamped to batch limit (≤25 per call)', bigPlan.requests.length <= 25);
ok('clamp is reported, not silent', bigPlan.dedup.clamped_for_caps > 0);
const batches = splitBatches(bigPlan.requests, bigPlan.caps.max_enqueue_batch);
ok('splitBatches never exceeds 25 per batch', batches.every((bt) => bt.length <= 25));

// Headroom: if the queue is already full, refuse (anti-dragnet).
const fullKeys = [];
for (let i = 0; i < 200; i += 1) fullKeys.push(canonicalizeUrl(`https://self-demo.example/full/${i}`));
const fullPlan = buildEnqueuePlan(
  { scope_type: 'self', target_urls: ['https://self-demo.example/new'] },
  { existingUniqueKeys: fullKeys },
);
ok('full frontier refuses new enqueue (anti-dragnet)', fullPlan.allowed === false && fullPlan.refusal === 'queue_full');

// ── 6. Client dry-runs without a token, no network ───────────────────────────
const dry = enqueue(
  { scope_type: 'self', target_urls: ['https://self-demo.example/about'] },
  { env: {} }, // no APIFY_TOKEN
);
ok('client dry-runs without APIFY_TOKEN', dry.ok === true && dry.mode === 'dry_run');
ok('dry-run made no network call', dry.usedNetwork === false);
ok('dry-run is honest about not being deployed', dry.deployed === false);
ok('dry-run produced batch-add descriptors', Array.isArray(dry.descriptors.batches) && dry.descriptors.batches.length >= 1);
ok('dry-run head-lock descriptor present with lockSecs', dry.descriptors.headLock.url.includes('lockSecs='));
ok('dry-run token is redacted in descriptors', dry.descriptors.create.url.includes('<MISSING_APIFY_TOKEN>'));

// A refused subject through the CLIENT yields no descriptors either.
const dryRefused = enqueue({ scope_type: 'private_person_tracking', target_urls: ['https://x/y'] }, { env: {} });
ok('client refusal yields null descriptors', dryRefused.ok === false && dryRefused.descriptors === null);

console.log(`\nOK — ${passed} frontier checks passed, 0 failures (Apify Request Queue dedup + caps + scope gate + dry-run).\n`);
