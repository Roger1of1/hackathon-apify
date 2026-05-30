/**
 * integrations/proxy/_selftest.js
 *
 * Self-contained, zero-dependency tests for the compliant Apify Proxy policy.
 * Lives in integrations/ (my subtree) — NOT in test/ (Codex owns that).
 * Run: `node integrations/proxy/_selftest.js`
 *
 * Properties asserted (all inside the red lines):
 *  - the REAL shared/scope.js gate runs FIRST: a stalking / private-individual
 *    subject is DROPPED before any proxy is built (ordered-pipeline / DropItem);
 *  - EVASION intent (bypass ban/captcha/rate-limit, "rotate until it passes",
 *    "avoid getting banned", "look more human") is a hard refusal;
 *  - RESIDENTIAL is dual-use: refused for consented/brand/safety_evidence,
 *    and refused for self/public_figure WITHOUT a geo_justification;
 *  - geo is coarse: unknown country refused, US-subdivision targeting disabled;
 *  - a BLOCK status (403/429) is classified as COMPLIANCE STOP, never a
 *    retire-and-rotate-to-fresh-IP loop (the Crawlee inversion);
 *  - a transport fault with no block signal => at most ONE retry;
 *  - dry-run honesty: no credential => no proxy URL with a secret, no network,
 *    redacted URL only (HIBP minimum-disclosure stance);
 *  - the redacted URL NEVER contains a real password.
 */

'use strict';

const assert = require('assert');
const {
  decideProxy,
  classifyResponse,
  buildRedactedProxyUrl,
  hasEvasionIntent,
  REFUSAL,
} = require('./proxy-policy.js');
const { prepareProxy } = require('./proxy-client.js');

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
const SELF = { scope_type: 'self', subject_label: 'me', target_urls: ['https://example.com/me'] };

console.log('\n[1] scope gate runs FIRST — stalking subject dropped before any proxy');
check('private_person_tracking scope dropped (no proxy)', () => {
  const d = decideProxy({ scope_type: 'private_person_tracking', proxy_group: 'DATACENTER' });
  assert.strictEqual(d.allowed, false);
  assert.strictEqual(d.refusal, REFUSAL.SCOPE_REJECTED);
  assert.ok(!d.proxySpec, 'no proxy spec must be built for a rejected scope');
});
check('romance/intimacy laundering under self => still dropped by gate', () => {
  const d = decideProxy({
    scope_type: 'self',
    target_urls: ['https://example.com/me'],
    prohibited_analysis: ['romance_inference'],
    proxy_group: 'DATACENTER',
  });
  assert.strictEqual(d.allowed, false);
  assert.strictEqual(d.refusal, REFUSAL.SCOPE_REJECTED);
});

console.log('\n[2] evasion intent is a hard refusal (availability-only)');
[
  { proxy_intent_flags: ['bypass_ban'] },
  { proxy_intent_flags: ['rotate_until_pass'] },
  { tasks: ['solve_captcha'] },
  { proxy_note: 'rotate proxies until it stops blocking me' },
  { justification: 'I need to avoid getting banned from the site' },
  { note: 'use residential so I look more human and get past the block' },
].forEach((extra, i) => {
  check(`evasion variant #${i + 1} refused`, () => {
    const d = decideProxy(Object.assign({}, SELF, extra));
    assert.strictEqual(d.allowed, false, 'must be refused');
    assert.strictEqual(d.refusal, REFUSAL.EVASION_INTENT);
    assert.ok(!d.proxySpec);
  });
});
check('hasEvasionIntent is false for a plain availability request', () => {
  assert.strictEqual(hasEvasionIntent(SELF), false);
});

console.log('\n[3] residential is dual-use — scope + justification gated');
check('residential refused for scope=brand', () => {
  const d = decideProxy({
    scope_type: 'brand',
    subject_label: 'acme',
    target_urls: ['https://acme.example.com'],
    proxy_group: 'RESIDENTIAL',
    geo_justification: 'per-country storefront rendering',
  });
  assert.strictEqual(d.allowed, false);
  assert.strictEqual(d.refusal, REFUSAL.RESIDENTIAL_NOT_ALLOWED_FOR_SCOPE);
});
check('residential refused for scope=self WITHOUT justification', () => {
  const d = decideProxy(Object.assign({}, SELF, { proxy_group: 'RESIDENTIAL' }));
  assert.strictEqual(d.allowed, false);
  assert.strictEqual(d.refusal, REFUSAL.RESIDENTIAL_WITHOUT_JUSTIFICATION);
});
check('residential ALLOWED for scope=self WITH geo_justification + country', () => {
  const d = decideProxy(
    Object.assign({}, SELF, {
      proxy_group: 'RESIDENTIAL',
      geo_justification: 'my own page renders differently per country',
      country_code: 'DE',
    }),
  );
  assert.strictEqual(d.allowed, true);
  assert.deepStrictEqual(d.proxySpec.apifyProxyGroups, ['RESIDENTIAL']);
  assert.strictEqual(d.proxySpec.apifyProxyCountry, 'DE');
});

console.log('\n[4] geo is coarse — allow-list + subdivision disabled');
check('unknown country refused', () => {
  const d = decideProxy(Object.assign({}, SELF, { country_code: 'XX' }));
  assert.strictEqual(d.allowed, false);
  assert.strictEqual(d.refusal, REFUSAL.COUNTRY_NOT_ALLOWED);
});
check('US-subdivision targeting refused (anti-profiling)', () => {
  const d = decideProxy(Object.assign({}, SELF, { country_code: 'US', subdivision_code: 'NY' }));
  assert.strictEqual(d.allowed, false);
  assert.strictEqual(d.refusal, REFUSAL.SUBDIVISION_TARGETING_DISABLED);
});
check('GOOGLE_SERP group denied', () => {
  const d = decideProxy(Object.assign({}, SELF, { proxy_group: 'GOOGLE_SERP' }));
  assert.strictEqual(d.allowed, false);
  assert.strictEqual(d.refusal, REFUSAL.GROUP_DENIED);
});

console.log('\n[5] datacenter availability path works for every allowed scope');
check('datacenter allowed for plain self request', () => {
  const d = decideProxy(SELF);
  assert.strictEqual(d.allowed, true);
  assert.deepStrictEqual(d.proxySpec, { useApifyProxy: true, apifyProxyGroups: ['DATACENTER'] });
  assert.strictEqual(d.intent, 'availability_only');
  assert.ok(d.complianceFloor.retire_on_block === true);
});

console.log('\n[6] Crawlee INVERSION — block = compliance stop, not retire-and-rotate');
[401, 403, 407, 429, 451, 503].forEach((status) => {
  check(`status ${status} => compliance_stop (no fresh-IP retry loop)`, () => {
    const c = classifyResponse(status, null, { complianceFloor: { max_proxy_retries: 1 } });
    assert.strictEqual(c.action, 'compliance_stop');
  });
});
check('transport fault (ECONNRESET) with no block => retry_once', () => {
  const c = classifyResponse(null, 'ECONNRESET', { complianceFloor: { max_proxy_retries: 1 } });
  assert.strictEqual(c.action, 'retry_once');
});
check('transport fault but retries disabled => compliance_stop', () => {
  const c = classifyResponse(null, 'ETIMEDOUT', { complianceFloor: { max_proxy_retries: 0 } });
  assert.strictEqual(c.action, 'compliance_stop');
});
check('clean 200 => proceed', () => {
  const c = classifyResponse(200, null);
  assert.strictEqual(c.action, 'proceed');
});

console.log('\n[7] dry-run honesty + redaction (HIBP minimum-disclosure stance)');
check('no credential => dry_run, no network, no secret in URL', () => {
  const r = prepareProxy(SELF, { env: {} });
  assert.strictEqual(r.ok, true);
  assert.strictEqual(r.mode, 'dry_run');
  assert.strictEqual(r.usedNetwork, false);
  assert.ok(r.redactedProxyUrl.includes('<APIFY_PROXY_PASSWORD>'));
  assert.ok(!r.proxyUrl, 'dry run must not produce a usable proxy URL');
});
check('refused request => no proxy URL at all', () => {
  const r = prepareProxy({ scope_type: 'private_person_tracking' }, { env: {} });
  assert.strictEqual(r.ok, false);
  assert.strictEqual(r.mode, 'refused');
  assert.strictEqual(r.proxyUrl, null);
  assert.strictEqual(r.usedNetwork, false);
});
check('live mode builds real URL in memory but redacted form hides password', () => {
  const r = prepareProxy(SELF, { env: { APIFY_PROXY_PASSWORD: 'super-secret-123' } });
  assert.strictEqual(r.mode, 'live');
  assert.ok(r.proxyUrl.includes('super-secret-123'), 'live URL has the credential for the fetch layer');
  assert.ok(!r.redactedProxyUrl.includes('super-secret-123'), 'redacted/loggable URL must NOT leak the secret');
  assert.strictEqual(r.usedNetwork, false);
});
check('buildRedactedProxyUrl never contains a raw password', () => {
  const url = buildRedactedProxyUrl({ useApifyProxy: true, apifyProxyGroups: ['DATACENTER'], apifyProxyCountry: 'US' });
  assert.ok(url.includes('groups-DATACENTER'));
  assert.ok(url.includes('country-US'));
  assert.ok(url.includes('<APIFY_PROXY_PASSWORD>'));
});

console.log(
  `\nOK — proxy policy: scope-gate-first + evasion-refusal + dual-use residential + ` +
    `block-is-stop + dry-run honesty. ${pass} pass, ${fail} fail.\n`,
);
if (fail > 0) process.exit(1);
