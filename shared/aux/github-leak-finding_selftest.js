/**
 * shared/aux/github-leak-finding_selftest.js
 *
 * Standalone self-test for the AUX GitHub-leak finding shapers. Lives in
 * shared/aux (NOT under test/, which another track owns). Pure + offline: it
 * never touches the network — it only asserts that the shapers emit valid,
 * frozen-vocabulary module_events, reuse the shared redacting secret detector,
 * carry the correlation keys the engine needs, and NEVER fabricate output for
 * empty input.
 *
 * Run: node shared/aux/github-leak-finding_selftest.js
 */

'use strict';

const assert = require('assert');
const {
  makeUsernameEvent,
  makeRepoSurfaceEvent,
  scanFileForSecrets,
  makeSummaryEvent,
  MODULE,
} = require('./github-leak-finding.js');
const { isModuleEvent, EVENT_TYPES } = require('../detectors/event-types.js');
const { clusterKeysFor } = require('../enrich/cluster-keys.js');

let pass = 0;
const ok = (name) => { pass += 1; console.log(`  PASS  ${name}`); };

// 1) SELF_USERNAME is a valid frozen-vocabulary event with a clusterable handle.
{
  const ev = makeUsernameEvent({ handle: '@Jane', profileUrl: 'https://github.com/Jane' });
  assert(isModuleEvent(ev), 'username event must be a valid module_event');
  assert.strictEqual(ev.event_type, EVENT_TYPES.SELF_USERNAME);
  assert.strictEqual(ev.source_module, MODULE);
  assert.strictEqual(ev.data, '@Jane');
  const keys = clusterKeysFor(ev);
  assert(keys.includes('handle:jane'), 'must yield a handle: cluster key (lowercased)');
  assert(keys.includes('host:github.com'), 'must yield a host: cluster key');
  ok('SELF_USERNAME is a valid event and yields handle + host cluster keys');
}

// 2) SELF_PROFILE_URL for a repo surface, with surface_kind in meta.
{
  const ev = makeRepoSurfaceEvent({ handle: 'jane', repoUrl: 'https://github.com/jane/app', name: 'jane/app', kind: 'repo' });
  assert(isModuleEvent(ev));
  assert.strictEqual(ev.event_type, EVENT_TYPES.SELF_PROFILE_URL);
  assert.strictEqual(ev.meta.surface_kind, 'repo');
  assert.strictEqual(ev.source_url, 'https://github.com/jane/app');
  ok('SELF_PROFILE_URL repo surface event is valid with provenance');
}

// 3) scanFileForSecrets REUSES the shared detector: a real AWS key shape is
//    found, emitted as SECRET_LEAK_PUBLIC, and REDACTED (no plaintext value).
{
  const text = 'AWS_SECRET=AKIAIOSFODNN7EXAMPLE\nharmless = "config"';
  const events = scanFileForSecrets({
    text,
    fileUrl: 'https://github.com/jane/app/blob/main/.env',
    handle: 'jane',
    repoName: 'jane/app',
  });
  assert(events.length >= 1, 'a vendor-shaped key must be detected');
  const leak = events[0];
  assert(isModuleEvent(leak));
  assert.strictEqual(leak.event_type, EVENT_TYPES.SECRET_LEAK_PUBLIC);
  // Redaction contract: a fingerprint exists and the raw secret is never present.
  assert(typeof leak.data.fingerprint === 'string' && leak.data.fingerprint.length > 0, 'must carry a fingerprint');
  assert(!('value' in leak.data) && !('secret' in leak.data), 'must NOT echo the secret value');
  assert(!JSON.stringify(leak).includes('AKIAIOSFODNN7EXAMPLE'), 'plaintext secret must never appear in the event');
  // GitHub provenance annotated without breaking redaction.
  assert.strictEqual(leak.meta.platform, 'github');
  assert.strictEqual(leak.meta.repo, 'jane/app');
  assert.strictEqual(leak.meta.handle, 'jane');
  // A secret fingerprint must be a cluster key so the SAME key elsewhere co-occurs.
  const keys = clusterKeysFor(leak);
  assert(keys.some((k) => k.startsWith('secret_fp:')), 'leak must yield a secret_fp cluster key');
  ok('scanFileForSecrets reuses the shared detector, redacts, and is clusterable');
}

// 4) NO FAKE DATA: empty / no-secret input => zero events (never a fabricated leak).
{
  assert.strictEqual(scanFileForSecrets({ text: '', fileUrl: null }).length, 0, 'empty text => no events');
  const clean = scanFileForSecrets({ text: 'just some prose with no credentials', fileUrl: 'https://github.com/jane/app/blob/main/README.md', handle: 'jane' });
  assert.strictEqual(clean.length, 0, 'clean text => no fabricated leak');
  ok('empty / clean input yields no events (no fake data)');
}

// 5) EXPOSURE_SUMMARY reflects REAL counts and escalates risk only on a real find.
{
  const found = makeSummaryEvent({ handle: 'jane', counts: { repos_scanned: 3, files_scanned: 9, secrets_found: 2 } });
  assert(isModuleEvent(found));
  assert.strictEqual(found.event_type, EVENT_TYPES.EXPOSURE_SUMMARY);
  assert.strictEqual(found.data.secrets_found, 2);
  assert.strictEqual(found.risk, 'high', 'summary risk must be high when secrets were found');
  const none = makeSummaryEvent({ handle: 'jane', counts: { repos_scanned: 3, files_scanned: 9, secrets_found: 0 } });
  assert.strictEqual(none.risk, 'info', 'summary risk must be info when nothing was found');
  ok('EXPOSURE_SUMMARY carries real counts and risk-bands honestly');
}

console.log(`\nOK — github-leak-finding self-test: ${pass} checks, 0 failures.`);
