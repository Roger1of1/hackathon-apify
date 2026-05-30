#!/usr/bin/env node
/**
 * Ensures web/app.js extends window.MirrorTrace instead of overwriting modules
 * loaded before it.
 */

'use strict';

const fs = require('fs');
const path = require('path');
const assert = require('assert');

const APP_JS = path.join(__dirname, '..', '..', 'web', 'app.js');
const sentinel = function sentinelBuildExposureGraph() {};

function loadApp() {
  const code = fs.readFileSync(APP_JS, 'utf8');
  const win = {
    MirrorTrace: {
      buildExposureGraph: sentinel,
      exposureGraph: { source: 'preloaded-module' },
    },
    sessionStorage: { getItem() { return null; }, setItem() {}, removeItem() {} },
    addEventListener() {},
    innerHeight: 900,
  };
  const noopEl = {
    style: {},
    dataset: {},
    classList: { add() {}, remove() {}, contains() { return false; }, toggle() {} },
    appendChild() {},
    removeChild() {},
    setAttribute() {},
    addEventListener() {},
    scrollIntoView() {},
    querySelector() { return null; },
    querySelectorAll() { return []; },
  };
  const doc = {
    documentElement: { style: { setProperty() {} }, clientHeight: 900 },
    body: noopEl,
    head: { appendChild() {} },
    addEventListener() {},
    execCommand() { return false; },
    getElementById() { return null; },
    querySelector() { return null; },
    querySelectorAll() { return []; },
    createElement() { return Object.assign({}, noopEl); },
    createElementNS() { return Object.assign({}, noopEl); },
  };

  // eslint-disable-next-line no-new-func
  new Function('window', 'document', code)(win, doc);
  return win.MirrorTrace;
}

const mt = loadApp();
assert.strictEqual(mt.buildExposureGraph, sentinel, 'preloaded graph API must survive app.js');
assert.strictEqual(mt.exposureGraph.source, 'preloaded-module', 'preloaded namespace must survive app.js');
assert.strictEqual(typeof mt.runPolicyGate, 'function', 'app.js still exports policy gate');
assert.strictEqual(typeof mt.buildExposureGraphFromReport, 'function', 'app.js exposes its report graph adapter');

console.log('\nweb MirrorTrace global merge self-test: OK (4 checks passed)');
