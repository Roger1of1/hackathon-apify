/**
 * integrations/exports/export-client.js
 *
 * REAL Apify DATASET EXPORT client, INERT without credentials.
 *
 * Wraps GET /v2/datasets/{datasetId}/items, the canonical Apify export endpoint
 * that supports format=json|jsonl|csv|xlsx|xml|rss|html and the
 * fields/omit/clean/flatten query params
 * (https://docs.apify.com/api/v2/dataset-items-get). The whole point of this
 * wrapper is that the export SHAPE is NOT chosen by the caller: it is DERIVED
 * from integrations/exports/redaction-policy.exportQueryFor(marking), so a
 * "shareable" export physically cannot request raw url / storage-key columns.
 *
 * Behaviour:
 *   - No APIFY_TOKEN  -> DRY RUN. Returns the exact request URL + headers it
 *                        WOULD send, and never touches the network. (No fake
 *                        data: we return a plan, not a pretend dataset.)
 *   - Token present   -> performs the GET, then runs every returned row back
 *                        through redactRecord() as a client-side backstop
 *                        before handing rows to the caller. Server-side
 *                        fields/omit is the first line; this is the second.
 *   - Unknown marking -> refuses (fail-closed), never falls back to "all fields".
 *
 * Reference architectures (assigned for this product):
 *   - OpenCTI / MISP + STIX: an export is a marking-scoped TAXII-collection-like
 *     pull; data segregation by marking-definition is enforced on the way OUT,
 *     not trusted from the requester
 *     (https://medium.com/@julien.richard/opencti-data-sharing-6da7dc045d14).
 *   - Apify RAG Web Browser / Website Content Crawler: those actors hand
 *     downstream pipelines a thin typed projection rather than raw pages; this
 *     client is the read-side equivalent — consumers pull a pre-redacted view,
 *     never the wide internal record
 *     (https://apify.com/apify/website-content-crawler/input-schema).
 *
 * This file ships NO credentials and makes NO claim of being deployed.
 */

'use strict';

const { exportQueryFor, redactRecord, isMarking } = require('./redaction-policy');

const APIFY_API = process.env.APIFY_API_BASE || 'https://api.apify.com';
const TOKEN = process.env.APIFY_TOKEN || '';

/**
 * Build the fully-qualified export request (url + headers) for a dataset at a
 * given distribution marking. Pure: no I/O. Returns { error } on a refused
 * marking/format so callers can report instead of throw.
 */
function buildExportRequest(datasetId, marking, opts = {}) {
  if (!datasetId || typeof datasetId !== 'string') {
    return { error: 'datasetId is required' };
  }
  if (!isMarking(marking)) {
    return { error: `unknown marking "${marking}"; refusing to export (fail-closed)` };
  }
  const q = exportQueryFor(marking, opts);
  if (q.error) return { error: q.error };

  const search = new URLSearchParams(q.params);
  // Reasonable hard cap so an export can never silently page the whole world.
  if (!search.has('limit')) search.set('limit', String(opts.limit || 5000));

  const url = `${APIFY_API}/v2/datasets/${encodeURIComponent(datasetId)}/items?${search.toString()}`;
  const headers = TOKEN ? { Authorization: `Bearer ${TOKEN}` } : {};
  return { url, headers, marking, format: q.params.format, params: q.params };
}

/**
 * Perform (or dry-run) the export. Always returns a descriptor; NEVER fabricates
 * rows. Shape:
 *   { ok, dryRun, marking, format, url, params, rows?, count?, note?, error? }
 */
async function exportDataset(datasetId, marking, opts = {}) {
  const req = buildExportRequest(datasetId, marking, opts);
  if (req.error) return { ok: false, error: req.error };

  // INERT path: no token => return the plan, do not pretend to have data.
  if (!TOKEN || typeof fetch !== 'function') {
    return {
      ok: true,
      dryRun: true,
      marking: req.marking,
      format: req.format,
      url: req.url,
      params: req.params,
      note: 'DRY RUN: set APIFY_TOKEN to perform this export. No data was fetched and none is fabricated.',
    };
  }

  try {
    const res = await fetch(req.url, { headers: req.headers });
    if (!res.ok) {
      return { ok: false, marking: req.marking, url: req.url, error: `Apify export failed: HTTP ${res.status}` };
    }
    // Only JSON variants are post-redacted client-side; binary/text formats
    // (csv/xlsx/html/xml/rss) are returned as-is because the server already
    // applied fields+omit. We still report which marking shaped them.
    if (req.format === 'json' || req.format === 'jsonl') {
      const body = await res.text();
      let rows;
      try {
        rows = req.format === 'jsonl'
          ? body.split('\n').filter(Boolean).map((l) => JSON.parse(l))
          : JSON.parse(body);
      } catch {
        return { ok: false, marking: req.marking, url: req.url, error: 'export body was not valid JSON' };
      }
      const list = Array.isArray(rows) ? rows : [];
      // Client-side backstop: re-redact every row, drop any the marking forbids.
      const redacted = list.map((r) => redactRecord(r, req.marking)).filter((r) => r !== null);
      return {
        ok: true,
        dryRun: false,
        marking: req.marking,
        format: req.format,
        url: req.url,
        params: req.params,
        rows: redacted,
        count: redacted.length,
        dropped: list.length - redacted.length,
      };
    }
    return {
      ok: true,
      dryRun: false,
      marking: req.marking,
      format: req.format,
      url: req.url,
      params: req.params,
      note: `Returned ${req.format} stream shaped by marking ${req.marking} (server-side fields/omit). Not re-parsed client-side.`,
    };
  } catch (err) {
    return { ok: false, marking: req.marking, url: req.url, error: `export error: ${err.message}` };
  }
}

// CLI: node integrations/exports/export-client.js <datasetId> <marking> [format]
if (require.main === module) {
  const [datasetId, marking, format] = process.argv.slice(2);
  if (!datasetId || !marking) {
    process.stdout.write('usage: node export-client.js <datasetId> <TLP:RED|TLP:AMBER|TLP:GREEN> [format]\n');
    process.exit(2);
  }
  exportDataset(datasetId, marking, format ? { format } : {})
    .then((r) => {
      process.stdout.write(JSON.stringify(r, null, 2) + '\n');
      process.exit(r.ok ? 0 : 1);
    })
    .catch((e) => {
      process.stderr.write(String(e && e.stack ? e.stack : e) + '\n');
      process.exit(1);
    });
}

module.exports = { buildExportRequest, exportDataset };
