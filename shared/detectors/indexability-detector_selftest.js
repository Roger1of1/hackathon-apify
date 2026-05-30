#!/usr/bin/env node
/**
 * shared/detectors/indexability-detector_selftest.js
 *
 * Dependency-free self-tests for the indexability/discoverability detector. Run:
 *   node shared/detectors/indexability-detector_selftest.js
 *
 * NO FAKE DATA: every assertion drives the REAL detector with concrete, observed
 * indexing directives; the detector emits nothing when no directive is present.
 */

'use strict';

const assert = require('assert');
const { EVENT_TYPES, VISIBILITY, RISK, isModuleEvent } = require('./event-types.js');
const {
  detectIndexability, classifyPage, tokenize, MODULE,
} = require('./indexability-detector.js');

let pass = 0;
function t(name, fn) {
  try { fn(); pass += 1; console.log(`  PASS  ${name}`); }
  catch (e) { console.error(`  FAIL  ${name}: ${e.message}`); process.exitCode = 1; }
}

console.log('[indexability / tokenize]');
t('tokenize splits and lowercases robots directive tokens', () => {
  const s = tokenize('NoIndex, nofollow, max-snippet:-1');
  assert.ok(s.has('noindex'));
  assert.ok(s.has('nofollow'));
  assert.ok(s.has('max-snippet')); // colon arg stripped
});
t('tokenize on non-string returns empty set', () => {
  assert.strictEqual(tokenize(null).size, 0);
  assert.strictEqual(tokenize(123).size, 0);
});

console.log('[indexability / classifyPage precedence (Google indexing-control model)]');
t('meta noindex => LINKED (deindexed, reachable only via URL)', () => {
  const c = classifyPage({ url: 'https://me.example/contact', meta_robots: 'noindex,follow' });
  assert.strictEqual(c.visibility, VISIBILITY.LINKED);
  assert.ok(c.removable);
  assert.ok(c.signals.includes('meta:noindex'));
});
t('X-Robots-Tag noindex header also deindexes', () => {
  const c = classifyPage({ url: 'https://me.example/p', x_robots_tag: 'noindex' });
  assert.strictEqual(c.visibility, VISIBILITY.LINKED);
  assert.ok(c.signals.includes('x-robots:noindex'));
});
t('"none" token == noindex,nofollow => LINKED', () => {
  const c = classifyPage({ url: 'https://me.example/p', meta_robots: 'none' });
  assert.strictEqual(c.visibility, VISIBILITY.LINKED);
});
t('canonical pointing elsewhere demotes duplicate => LINKED', () => {
  const c = classifyPage({ url: 'https://me.example/dupe', canonical_url: 'https://me.example/main' });
  assert.strictEqual(c.visibility, VISIBILITY.LINKED);
  assert.ok(c.signals.includes('canonical:elsewhere'));
});
t('canonical to SELF does not demote => stays INDEXED', () => {
  const c = classifyPage({ url: 'https://me.example/main', canonical_url: 'https://me.example/main' });
  assert.strictEqual(c.visibility, VISIBILITY.INDEXED);
});
t('robots.txt Disallow ONLY still INDEXED (Google caveat: blocks crawl, not index)', () => {
  const c = classifyPage({ url: 'https://me.example/p', robots_txt_disallow: true });
  assert.strictEqual(c.visibility, VISIBILITY.INDEXED);
  assert.ok(c.signals.includes('robots-txt:disallow'));
  assert.ok(/does NOT prevent indexing/i.test(c.reason));
});
t('noindex BEATS robots.txt disallow (precedence)', () => {
  const c = classifyPage({ url: 'https://me.example/p', meta_robots: 'noindex', robots_txt_disallow: true });
  assert.strictEqual(c.visibility, VISIBILITY.LINKED);
});
t('plain indexable page => INDEXED, removable', () => {
  const c = classifyPage({ url: 'https://me.example/p' });
  assert.strictEqual(c.visibility, VISIBILITY.INDEXED);
  assert.ok(c.removable);
  assert.strictEqual(c.durable, false);
});

console.log('[indexability / durability (archive copies)]');
t('archived indexable page => INDEXED, durable, NOT trivially removable', () => {
  const c = classifyPage({ url: 'https://me.example/p', archived: true });
  assert.strictEqual(c.visibility, VISIBILITY.INDEXED);
  assert.strictEqual(c.durable, true);
  assert.strictEqual(c.removable, false);
  assert.ok(c.signals.includes('archived'));
});
t('noarchive directive suppresses the archived/durable signal', () => {
  const c = classifyPage({ url: 'https://me.example/p', archived: true, x_robots_tag: 'noarchive' });
  assert.strictEqual(c.durable, false);
});
t('deindexed BUT archived => LINKED yet still durable (archive survives deindex)', () => {
  const c = classifyPage({ url: 'https://me.example/p', meta_robots: 'noindex', archived: true });
  assert.strictEqual(c.visibility, VISIBILITY.LINKED);
  assert.strictEqual(c.durable, true);
});

console.log('[indexability / detectIndexability event emission]');
t('emits exactly one valid EXPOSURE_SUMMARY module_event for a page', () => {
  const evs = detectIndexability({ url: 'https://me.example/p', meta_robots: 'noindex' });
  assert.strictEqual(evs.length, 1);
  assert.ok(isModuleEvent(evs[0]));
  assert.strictEqual(evs[0].event_type, EVENT_TYPES.EXPOSURE_SUMMARY);
  assert.strictEqual(evs[0].source_module, MODULE);
  assert.strictEqual(evs[0].visibility, VISIBILITY.LINKED);
});
t('NO FAKE DATA: no url and no directives => emits NOTHING', () => {
  assert.deepStrictEqual(detectIndexability({}), []);
});
t('directive-driven findings carry higher confidence than inferred-indexed', () => {
  const [deindexed] = detectIndexability({ url: 'https://me.example/p', meta_robots: 'noindex' });
  const [inferred] = detectIndexability({ url: 'https://me.example/q' });
  assert.ok(deindexed.confidence > inferred.confidence, 'noindex directive is a stronger signal than absence-of-restriction');
});
t('indexed page bearing real exposures => MEDIUM risk; deindexed clean page => INFO', () => {
  const [withExposures] = detectIndexability({
    url: 'https://me.example/p',
    exposed_events: [{ event_type: 'PII_EMAIL_PUBLIC' }, { event_type: 'PII_PHONE_PUBLIC' }],
  });
  assert.strictEqual(withExposures.risk, RISK.MEDIUM);
  assert.strictEqual(withExposures.meta.governs_exposures, 2);

  const [clean] = detectIndexability({ url: 'https://me.example/q', meta_robots: 'noindex' });
  assert.strictEqual(clean.risk, RISK.INFO);
});
t('remediation guidance is posture-specific and actionable', () => {
  const [archived] = detectIndexability({ url: 'https://me.example/p', archived: true });
  assert.ok(/archived|cached copy/i.test(archived.meta.remediation));
  const [disallow] = detectIndexability({ url: 'https://me.example/p', robots_txt_disallow: true });
  assert.ok(/noindex/i.test(disallow.meta.remediation));
});

console.log(`\nOK — indexability detector self-test: ${pass} checks passed, ${process.exitCode ? 'with failures' : '0 failures'}.`);
if (process.exitCode) process.exit(process.exitCode);
