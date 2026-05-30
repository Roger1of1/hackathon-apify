#!/usr/bin/env node
/**
 * shared/privacy/storage-policy_selftest.js
 *
 * Dependency-free self-tests for the browser-only / zero-server-storage policy.
 * Run:  node shared/privacy/storage-policy_selftest.js
 *
 * NO FAKE DATA: every assertion exercises the REAL guard against REAL plan
 * shapes. The module stores nothing; these tests verify it correctly FLAGS any
 * plan that would persist or off-load findings.
 */

'use strict';

const assert = require('assert');
const {
  STORAGE_LOCATIONS,
  ALLOWED_LOCATIONS,
  PERSISTENT_OR_SERVER_LOCATIONS,
  PURGE_CONTRACT,
  isExposureLocationAllowed,
  assertNoServerPersistence,
} = require('./storage-policy.js');

let pass = 0;
function t(name, fn) {
  try { fn(); pass += 1; console.log(`  PASS  ${name}`); }
  catch (e) { console.error(`  FAIL  ${name}: ${e.message}`); process.exitCode = 1; }
}

console.log('[storage-policy / allowed locations]');
t('in_memory and session_storage are the only allowed locations', () => {
  assert.deepStrictEqual(
    [...ALLOWED_LOCATIONS].sort(),
    [STORAGE_LOCATIONS.IN_MEMORY, STORAGE_LOCATIONS.SESSION_STORAGE].sort(),
  );
  assert.ok(isExposureLocationAllowed(STORAGE_LOCATIONS.IN_MEMORY));
  assert.ok(isExposureLocationAllowed(STORAGE_LOCATIONS.SESSION_STORAGE));
});
t('localStorage / indexedDB / server are NOT allowed', () => {
  for (const loc of PERSISTENT_OR_SERVER_LOCATIONS) {
    assert.ok(!isExposureLocationAllowed(loc), `${loc} must be disallowed`);
  }
});

console.log('[storage-policy / assertNoServerPersistence — clean plans]');
t('memory + sessionStorage plan with no transmits passes', () => {
  const r = assertNoServerPersistence({
    storage: [STORAGE_LOCATIONS.IN_MEMORY, STORAGE_LOCATIONS.SESSION_STORAGE],
    transmits: [],
  });
  assert.strictEqual(r.ok, true);
  assert.strictEqual(r.violations.length, 0);
});
t('a network call that does NOT include findings is fine', () => {
  const r = assertNoServerPersistence({
    storage: [STORAGE_LOCATIONS.IN_MEMORY],
    transmits: [{ kind: 'kanon_range_prefix', method: 'GET', includesFindings: false }],
  });
  assert.strictEqual(r.ok, true);
});

console.log('[storage-policy / assertNoServerPersistence — violations]');
t('localStorage of findings is flagged as persistent_client_storage', () => {
  const r = assertNoServerPersistence({ storage: [STORAGE_LOCATIONS.LOCAL_STORAGE] });
  assert.strictEqual(r.ok, false);
  assert.ok(r.violations.some(v => v.code === 'persistent_client_storage'
    && v.location === STORAGE_LOCATIONS.LOCAL_STORAGE));
});
t('indexedDB is flagged persistent too', () => {
  const r = assertNoServerPersistence({ storage: [STORAGE_LOCATIONS.INDEXED_DB] });
  assert.ok(r.violations.some(v => v.code === 'persistent_client_storage'));
});
t('server storage is flagged as server_storage', () => {
  const r = assertNoServerPersistence({ storage: [STORAGE_LOCATIONS.SERVER] });
  assert.strictEqual(r.ok, false);
  assert.ok(r.violations.some(v => v.code === 'server_storage'));
});
t('POSTing findings off-device is flagged off_device_transmission', () => {
  const r = assertNoServerPersistence({
    storage: [STORAGE_LOCATIONS.IN_MEMORY],
    transmits: [{ kind: 'save_report', method: 'POST', includesFindings: true }],
  });
  assert.strictEqual(r.ok, false);
  assert.ok(r.violations.some(v => v.code === 'off_device_transmission'));
});
t('beacon/upload carrying findings is flagged', () => {
  const r = assertNoServerPersistence({
    transmits: [{ kind: 'analytics', method: 'beacon', includesFindings: true }],
  });
  assert.ok(r.violations.some(v => v.code === 'off_device_transmission'));
});
t('declared persistsExposureFindings:true is flagged', () => {
  const r = assertNoServerPersistence({ storage: [], persistsExposureFindings: true });
  assert.ok(r.violations.some(v => v.code === 'declared_persistence'));
});
t('unknown storage location is flagged, not silently passed', () => {
  const r = assertNoServerPersistence({ storage: ['cloud_bucket'] });
  assert.strictEqual(r.ok, false);
  assert.ok(r.violations.some(v => v.code === 'unknown_storage_location'));
});
t('a non-object plan fails closed', () => {
  for (const bad of [null, undefined, 42, 'plan']) {
    const r = assertNoServerPersistence(bad);
    assert.strictEqual(r.ok, false);
    assert.ok(r.violations.some(v => v.code === 'invalid_plan'));
  }
});
t('multiple violations are collected, not short-circuited', () => {
  const r = assertNoServerPersistence({
    storage: [STORAGE_LOCATIONS.LOCAL_STORAGE, STORAGE_LOCATIONS.SERVER],
    transmits: [{ kind: 'sync', method: 'PUT', includesFindings: true }],
  });
  assert.ok(r.violations.length >= 3);
});

console.log('[storage-policy / purge contract]');
t('purge contract forbids surviving tab close and lists real triggers', () => {
  assert.strictEqual(PURGE_CONTRACT.survivesTabClose, false);
  assert.strictEqual(PURGE_CONTRACT.mustNullInMemoryRefs, true);
  assert.ok(PURGE_CONTRACT.triggers.includes('tab_close'));
  assert.ok(PURGE_CONTRACT.triggers.includes('explicit_purge'));
});

console.log(`\nstorage-policy self-test: ${pass} checks passed`);
