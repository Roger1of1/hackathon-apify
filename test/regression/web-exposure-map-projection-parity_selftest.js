#!/usr/bin/env node
/**
 * Locks the file:// browser graph mirror to the canonical shared builder's
 * UI-relevant topology projection. The shared builder remains the full source
 * of truth for enriched metadata and severity scoring.
 */

'use strict';

const fs = require('fs');
const path = require('path');
const assert = require('assert');
const { buildExposureGraph: buildSharedGraph } = require('../../shared/graph/build-exposure-graph.js');

const APP_JS = path.join(__dirname, '..', '..', 'web', 'app.js');

function loadBrowserGraphBuilder() {
  const code = fs.readFileSync(APP_JS, 'utf8');
  const win = {
    MirrorTrace: {},
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
  return win.MirrorTrace.buildExposureGraphFromReport;
}

function project(graph) {
  return {
    center: graph.center,
    nodes: graph.nodes.map((n) => ({
      id: n.id,
      host: n.host,
      label: n.label,
      kind: n.kind,
      severityTier: n.severityTier,
      infoCount: n.infoCount,
      eventTypes: n.eventTypes,
      findingRefs: n.findingRefs,
    })).sort((a, b) => a.id.localeCompare(b.id)),
    edges: graph.edges.map((e) => ({
      from: e.from,
      to: e.to,
      kind: e.kind,
      via: e.via || null,
    })).sort((a, b) => a.from.localeCompare(b.from)
      || a.to.localeCompare(b.to)
      || a.kind.localeCompare(b.kind)
      || String(a.via).localeCompare(String(b.via))),
    meta: {
      source_count: graph.meta.source_count,
      finding_count: graph.meta.finding_count,
      shared_identifier_links: graph.meta.shared_identifier_links,
    },
  };
}

const report = {
  findings: [
    {
      event_type: 'PII_EMAIL_PUBLIC',
      source_module: 'pii_detector',
      risk: 'high',
      visibility: 'indexed',
      confidence: 0.95,
      source_url: 'https://broker.example/p/1',
      severity_band: 'critical',
      data: 'casey@example.com',
      meta: { email_hash_prefix: 'A1B2C' },
    },
    {
      event_type: 'PII_EMAIL_PUBLIC',
      source_module: 'pii_detector',
      risk: 'medium',
      visibility: 'linked',
      confidence: 0.82,
      source_url: 'https://forum.example/u/casey',
      severity_band: 'high',
      data: 'casey@example.com',
      meta: { email_hash_prefix: 'A1B2C' },
    },
    {
      event_type: 'PII_HANDLE_PUBLIC',
      source_module: 'pii_detector',
      risk: 'medium',
      visibility: 'linked',
      confidence: 0.8,
      source_url: 'https://forum.example/u/casey',
      severity_band: 'medium',
      data: '@casey',
      meta: { handle: '@casey' },
    },
    {
      event_type: 'PII_HANDLE_PUBLIC',
      source_module: 'pii_detector',
      risk: 'low',
      visibility: 'linked',
      confidence: 0.7,
      source_url: 'https://profile.example/casey',
      severity_band: 'low',
      data: '@casey',
      meta: { handle: '@casey' },
    },
    {
      event_type: 'BREACH_RANGE_HIT',
      source_module: 'breach_range_detector',
      risk: 'medium',
      visibility: 'private',
      confidence: 0.99,
      source_url: null,
      severity_band: 'medium',
      data: null,
      meta: { hash_prefix: 'ABCDE' },
    },
  ],
};

const buildBrowserGraph = loadBrowserGraphBuilder();
assert.strictEqual(typeof buildBrowserGraph, 'function');
assert.deepStrictEqual(
  project(buildBrowserGraph(report, { selfLabel: 'Casey' })),
  project(buildSharedGraph(report, { selfLabel: 'Casey' })),
);

console.log('\nweb exposure-map projection parity self-test: OK');
