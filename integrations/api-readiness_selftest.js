#!/usr/bin/env node
/**
 * Self-test for the API readiness audit. It verifies the audit is honest in this
 * repository state: code may be green, but missing credentials/placeholders mean
 * live Apify/OAuth readiness must not be reported.
 */

'use strict';

const assert = require('assert');
const path = require('path');
const { assessApiReadiness } = require('./api-readiness.js');

const r = assessApiReadiness({
  env: {},
  apifyCli: { ok: false, version: null },
  apifyAuthFile: path.join(__dirname, '__missing_apify_auth__.json'),
  actorConfigEnv: {},
});

assert.strictEqual(r.overall, 'code_ready_credentials_pending');
assert.strictEqual(r.checks.apify_credentials.status, 'missing');
assert.strictEqual(r.checks.core_metamorph_env.status, 'missing');
assert.strictEqual(r.checks.oauth.status, 'not_wired');
assert.strictEqual(r.checks.old_branding_globals.status, 'clear');
assert.strictEqual(r.checks.dependency_audit.status, 'known_upstream_tail');
assert.strictEqual(r.checks.dependency_audit.file_type_version, '20.5.0');
assert.ok(r.known_dependency_tails.length > 0);
assert.ok(Array.isArray(r.remaining_non_ui_to_go_live));
assert.ok(r.remaining_non_ui_to_go_live.length > 0);

console.log('\napi-readiness self-test: OK (honest non-live state detected)');
