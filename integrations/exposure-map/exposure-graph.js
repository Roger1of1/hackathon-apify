/**
 * integrations/exposure-map/exposure-graph.js
 *
 * Thin adapter for Apify ingest rows -> the canonical ExposureGraphV1 contract.
 *
 * The source of truth is shared/graph/build-exposure-graph.js. This module keeps
 * the integration-facing API that takes module_event[] but deliberately returns
 * the SAME shape the web/report builder use:
 *
 *   { center, nodes, edges, legend, meta }
 *
 * No src:/color_tier/correlates fork, no separate severity model, no separate
 * correlation semantics. The adapter only wraps event arrays as a report-shaped
 * object and adds the browser-only privacy banner used by the feed UI.
 */

'use strict';

const {
  buildExposureGraph: buildExposureGraphFromReport,
  tierForBand,
} = require('../../shared/graph/build-exposure-graph.js');
const { isModuleEvent } = require('../../shared/detectors/event-types.js');

const PRIVACY_BANNER =
  'Built in your browser from your own findings. Nothing here is sent to or stored on a server; ' +
  'it is purged when you close this tab.';

function bandToTier(band) {
  return tierForBand(band);
}

/**
 * buildExposureGraph(events, opts) -> ExposureGraphV1
 *
 * @param {object[]} events REAL module_event records from Apify ingest.
 * @param {object} [opts]
 * @param {string} [opts.subjectLabel] label for the center node.
 * @param {string} [opts.selfLabel] alias for subjectLabel.
 * @param {string} [opts.generatedAt] optional provenance timestamp.
 */
function buildExposureGraph(events, opts = {}) {
  const findings = (Array.isArray(events) ? events : []).filter(isModuleEvent);
  const report = {
    generated_at: opts.generatedAt || null,
    findings,
  };
  const graph = buildExposureGraphFromReport(report, {
    selfLabel: opts.subjectLabel || opts.selfLabel || 'You',
  });
  return Object.assign({}, graph, {
    __privacy: PRIVACY_BANNER,
  });
}

const api = {
  buildExposureGraph,
  buildExposureGraphFromEvents: buildExposureGraph,
  bandToTier,
  PRIVACY_BANNER,
};

if (typeof module !== 'undefined' && module.exports) {
  module.exports = api;
}
if (typeof window !== 'undefined') {
  window.MirrorTrace = Object.assign(window.MirrorTrace || {}, {
    buildExposureGraph,
    buildExposureGraphFromEvents: buildExposureGraph,
    exposureGraph: api,
  });
}
