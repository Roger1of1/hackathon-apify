#!/usr/bin/env node
/**
 * Locks ExposureGraphV1 parity across shared/ and integrations/.
 *
 * The integration layer accepts module_event[] from Apify ingest, but it must not
 * emit a second graph dialect. This test proves it is a thin adapter over the
 * canonical shared builder.
 */

'use strict';

const assert = require('assert');
const { makeEvent } = require('../../shared/detectors/event-types.js');
const { buildExposureGraph: buildSharedGraph } = require('../../shared/graph/build-exposure-graph.js');
const { buildExposureGraph: buildIntegrationGraph } = require('../../integrations/exposure-map/exposure-graph.js');

const EVENTS = [
  makeEvent({
    event_type: 'PII_EMAIL_PUBLIC',
    source_module: 'pii_detector',
    risk: 'high',
    visibility: 'indexed',
    confidence: 0.95,
    source_url: 'https://broker.example/p/1',
    data: 'casey@example.com',
    meta: { email_hash_prefix: 'A1B2C' },
  }),
  makeEvent({
    event_type: 'PII_EMAIL_PUBLIC',
    source_module: 'pii_detector',
    risk: 'medium',
    visibility: 'linked',
    confidence: 0.82,
    source_url: 'https://forum.example/u/casey',
    data: 'casey@example.com',
    meta: { email_hash_prefix: 'A1B2C' },
  }),
  makeEvent({
    event_type: 'BREACH_RANGE_HIT',
    source_module: 'breach_range_detector',
    risk: 'high',
    visibility: 'private',
    confidence: 0.99,
    source_url: null,
    data: null,
    meta: { hash_prefix: 'ABCDE', breach_count: 4 },
  }),
];

function withoutAdapterOnlyFields(graph) {
  const copy = JSON.parse(JSON.stringify(graph));
  delete copy.__privacy;
  return copy;
}

let passed = 0;
function ok(label, condition) {
  assert.ok(condition, label);
  passed += 1;
  console.log('  ok  ' + label);
}

const shared = buildSharedGraph({ generated_at: null, findings: EVENTS }, { selfLabel: 'Casey' });
const integration = buildIntegrationGraph(EVENTS, { subjectLabel: 'Casey' });

assert.deepStrictEqual(withoutAdapterOnlyFields(integration), shared);
ok('integration graph is byte-for-byte canonical ExposureGraphV1 (+ privacy banner only)', true);

ok('center is separate from source nodes',
  integration.center.id === 'self' && !integration.nodes.some((n) => n.id === 'self'));

ok('source ids use canonical host:/origin: prefixes',
  integration.nodes.every((n) => /^(host|origin):/.test(n.id)));

ok('edges use canonical from/to fields',
  integration.edges.every((e) => Object.prototype.hasOwnProperty.call(e, 'from')
    && Object.prototype.hasOwnProperty.call(e, 'to')));

ok('correlation edges use shared-identifier + via',
  integration.edges.some((e) => e.kind === 'shared-identifier' && e.via === 'email'));

ok('old integration dialect is absent',
  integration.nodes.every((n) => !Object.prototype.hasOwnProperty.call(n, 'color_tier')
    && !Object.prototype.hasOwnProperty.call(n, 'finding_count')
    && !String(n.id).startsWith('src:'))
  && integration.edges.every((e) => e.kind !== 'correlates'
    && !Object.prototype.hasOwnProperty.call(e, 'source')
    && !Object.prototype.hasOwnProperty.call(e, 'target')));

console.log('\nexposure-map contract parity self-test: OK (' + passed + ' checks passed)');
