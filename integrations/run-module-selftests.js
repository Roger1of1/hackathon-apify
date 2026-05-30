#!/usr/bin/env node
/**
 * integrations/run-module-selftests.js
 *
 * AGGREGATING CI RUNNER for the repo's module self-tests.
 *
 * WHY THIS EXISTS
 * ─────────────────────────────────────────────────────────────────────────────
 * The repo has ~a dozen real `*_selftest.js` modules (shared/**, integrations/**)
 * that each prove a load-bearing guarantee, but the default `npm test`
 * (test/run-compliance-tests.js) only exercises the scope-rejection fixtures —
 * it does NOT run those module self-tests, so their green status was UNVERIFIED
 * by CI. This runner closes that gap: it DISCOVERS every `*_selftest.js` in the
 * repo and SPAWNS each in its own `node` process (so one module's process.exit
 * cannot mask another's), then reports a single aggregate pass/fail.
 *
 * COLLISION-SAFE (concurrency with Codex)
 *  - Codex owns test/. This runner lives in integrations/ (this agent's subtree)
 *    and does NOT modify test/run-compliance-tests.js or its fixtures.
 *  - It is purely ADDITIVE: it spawns the existing self-tests as-is and changes
 *    none of them. Wire it as a NEW npm script without touching the existing
 *    `test` script:
 *        "test:modules": "node integrations/run-module-selftests.js"
 *    (Adding that one line to package.json is the operator/Codex step — this file
 *     never edits package.json, to avoid a merge collision on a shared file.)
 *  - You can ALSO run it directly:  node integrations/run-module-selftests.js
 *
 * NO FAKE DATA: it runs the REAL self-tests and reports their REAL exit codes. A
 * non-zero child exit (or a crash) fails the aggregate; nothing is assumed green.
 *
 * Zero dependencies. Node >=18. Discovery is a plain recursive fs walk so it does
 * not depend on a glob library and finds new self-tests automatically.
 */

'use strict';

const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');

const ROOT = path.join(__dirname, '..');

// Directories we never descend into (no source self-tests live here).
const SKIP_DIRS = new Set(['node_modules', '.git', 'web', 'demo', 'docs']);

/** Recursively collect every file whose name ends with `_selftest.js`. */
function findSelfTests(dir, acc = []) {
  let entries;
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch {
    return acc;
  }
  for (const ent of entries) {
    if (ent.name.startsWith('.') && ent.name !== '.') continue;
    const full = path.join(dir, ent.name);
    if (ent.isDirectory()) {
      if (SKIP_DIRS.has(ent.name)) continue;
      findSelfTests(full, acc);
    } else if (ent.isFile() && ent.name.endsWith('_selftest.js')) {
      acc.push(full);
    }
  }
  return acc;
}

function main() {
  const tests = findSelfTests(ROOT).sort();

  if (tests.length === 0) {
    console.error('run-module-selftests: no *_selftest.js modules found — nothing to verify.');
    // Treat "found nothing" as a failure: a CI guard that silently passes when it
    // discovers no tests is worse than useless (fail-closed).
    process.exit(1);
  }

  console.log(`\nrun-module-selftests — discovering & spawning ${tests.length} module self-test(s)\n`);

  let failed = 0;
  const failedNames = [];

  for (const file of tests) {
    const rel = path.relative(ROOT, file);
    const res = spawnSync(process.execPath, [file], {
      cwd: ROOT,
      stdio: 'inherit', // surface each module's own PASS/FAIL lines
      env: process.env,
    });
    const ok = res.status === 0 && !res.error;
    if (!ok) {
      failed += 1;
      failedNames.push(rel);
      if (res.error) {
        console.error(`  !! ${rel} failed to spawn: ${res.error.message}`);
      }
    }
    console.log(`${ok ? 'OK  ' : 'FAIL'}  ${rel}\n`);
  }

  const total = tests.length;
  console.log('─'.repeat(60));
  if (failed === 0) {
    console.log(`run-module-selftests: OK — all ${total} module self-test(s) passed\n`);
    process.exit(0);
  }
  console.log(`run-module-selftests: FAILED — ${failed}/${total} module self-test(s) failed:`);
  for (const n of failedNames) console.log(`   - ${n}`);
  console.log('');
  process.exit(1);
}

main();
