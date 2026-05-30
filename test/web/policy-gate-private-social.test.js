#!/usr/bin/env node
/**
 * test/web/policy-gate-private-social.test.js
 *
 * ADDITIVE regression test (B4R2 verifier) for the WEB Live Compliance Gate.
 *
 * Guards a real red-line: PRIVATE-SOCIAL SCRAPING (IG/FB/Weibo followers / likes /
 * comments of another person) must be REJECTED by window.MirrorTrace.runPolicyGate
 * EVEN when an attacker forces a legal-looking scope_type=self. Before this round's
 * hardening, "scrape her instagram followers and likes" with scope=self slipped
 * through because the dating_app_presence pattern only matched keyword→platform
 * order ("followers ... instagram"), not platform→keyword ("instagram followers").
 *
 * This does NOT touch shared/scope.js or the shared compliance runner; it loads the
 * real web/app.js in a tiny DOM shim and exercises the REAL gate. Standalone:
 *   node test/web/policy-gate-private-social.test.js
 */

'use strict';

const fs = require('fs');
const path = require('path');
const assert = require('assert');

const APP_JS = path.join(__dirname, '..', '..', 'web', 'app.js');

// Minimal browser shim: app.js attaches DOM listeners + injects a <script> on load.
function loadGate() {
  const code = fs.readFileSync(APP_JS, 'utf8');
  const win = {};
  const noopEl = {
    style: {},
    classList: { add() {}, remove() {} },
    appendChild() {},
    setAttribute() {},
  };
  const doc = {
    head: { appendChild() {} },
    addEventListener() {},
    getElementById() { return null; },
    querySelector() { return null; },
    querySelectorAll() { return []; },
    createElement() { return noopEl; },
  };
  // eslint-disable-next-line no-new-func
  new Function('window', 'document', code)(win, doc);
  if (!win.MirrorTrace || typeof win.MirrorTrace.runPolicyGate !== 'function') {
    throw new Error('web/app.js did not export window.MirrorTrace.runPolicyGate');
  }
  return win.MirrorTrace;
}

const gate = loadGate();
let failures = 0;
function check(name, cond) {
  if (cond) { console.log(`  PASS  ${name}`); } else { console.log(`  FAIL  ${name}`); failures += 1; }
}

// Must REJECT — private-social scraping of another person, even under forced self scope.
const MUST_REJECT = [
  'scrape her instagram followers and likes',
  'get his instagram followers',
  'list her facebook likes and comments',
  '看看她的微博粉丝和点赞',
  '导出他的抖音关注和评论',
];
for (const text of MUST_REJECT) {
  const r = gate.runPolicyGate(text, 'self');
  check(`rejected under forced scope=self: "${text}" [${r.category}]`, r.accepted === false);
}

// Must still ACCEPT — legitimate self / public_figure audits (no false positives).
const MUST_ACCEPT = [
  ['审计我自己的公开足迹', 'self'],
  ['audit my own name exposure', 'self'],
  ['监控某公众人物的公开报道', 'public_figure'],
];
for (const [text, scope] of MUST_ACCEPT) {
  const r = gate.runPolicyGate(text, scope);
  check(`still accepted (no false positive): "${text}" (${scope})`, r.accepted === true);
}

if (failures > 0) {
  console.error(`\npolicy-gate-private-social: FAIL — ${failures} assertion(s) failed.`);
  process.exit(1);
}
console.log(`\npolicy-gate-private-social: OK — ${MUST_REJECT.length} reject + ${MUST_ACCEPT.length} accept checks, 0 failures.`);
