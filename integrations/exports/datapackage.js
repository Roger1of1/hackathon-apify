/**
 * integrations/exports/datapackage.js
 *
 * PORTABLE EVIDENCE PACKAGE emitter (Frictionless Data Package / Datasette-ready).
 *
 * The product's promise is that the audit subject OWNS their evidence: they can
 * walk away with a self-contained, citable bundle of WHAT was found about their
 * own public footprint, in an open standard any tool can read — not locked in a
 * vendor dashboard. This module produces exactly that: a Frictionless Data
 * Package (`datapackage.json` + tabular CSV resources with Table Schemas) built
 * from the user's OWN already-collected, ALREADY-REDACTED findings.
 *
 * It is the publish-side bookend to integrations/exports/redaction-policy.js:
 * that module decides WHICH columns may leave at a distribution marking; this
 * module wraps the rows it produces into a portable package and embeds the same
 * marking on the package + every resource, so the bundle is honest about its own
 * shareability. Nothing here widens what redaction-policy allows — it can only
 * package what redaction already permitted.
 *
 * ── Reference architecture #1: Frictionless Data Package ─────────────────────
 * The Frictionless spec defines a self-describing dataset as a top-level
 * `datapackage.json` descriptor carrying package metadata (name, title, licenses,
 * created, sources) plus a `resources` array; each tabular resource names its
 * `path`, `format`/`mediatype`, `profile: "tabular-data-resource"`, and a
 * `schema` with typed `fields` (name + type: string/number/integer/datetime/…).
 * A consumer needs nothing but the package to read, validate and re-derive it.
 *   Refs: https://specs.frictionlessdata.io/data-package/
 *         https://specs.frictionlessdata.io/tabular-data-resource/
 *         https://specs.frictionlessdata.io/table-schema/
 * We emit precisely that shape: one tabular resource per redacted record_type,
 * each with a Table Schema derived from the redaction allow-list for the marking,
 * so the package is valid against the Frictionless profile and self-validating.
 *
 * ── Reference architecture #2: Datasette portable/publishable dataset ────────
 * Datasette's model is "take a directory of data and publish it as an explorable,
 * queryable, CITABLE site"; a Frictionless package is one of its native intake
 * shapes (datasette + the dogsheep/frictionless tooling import datapackage.json
 * straight into SQLite tables). Mirroring Datasette's emphasis on REPRODUCIBLE,
 * SELF-CONTAINED, CITABLE publishing, this emitter:
 *   - emits a relative-path, dependency-free directory (datapackage.json + *.csv)
 *     that opens offline and imports into Datasette/SQLite/pandas unchanged,
 *   - records provenance (created timestamp, marking, source actor/dataset id,
 *     a content fingerprint) so a citation pins an exact bundle, and
 *   - optionally carries the Self-Exposure GRADE LEDGER as its own resource so a
 *     third party can RE-DERIVE the A–F letter from the published rows — the
 *     reproducibility Datasette is built around.
 *   Ref: https://datasette.io/  (publish, citable, queryable open data)
 *
 * ── RED LINES (by construction) ─────────────────────────────────────────────
 *  - WRAPS, NEVER BYPASSES, redaction-policy.js. Every row MUST be run through
 *    redactRecord(row, marking) before it can enter a resource; a row that
 *    redacts to null is DROPPED (never half-emitted). At a non-RED marking the
 *    Table Schema itself cannot contain url/storage-key/note columns, because the
 *    fields come from redaction-policy.allowedFields(type, marking).
 *  - NO FAKE DATA. Zero real rows ⇒ a package with zero resources and a clear
 *    `meta.note: 'no findings — empty evidence package'`; we never inject sample
 *    rows. Any template/example is labelled as such.
 *  - NO raw QI/PII leakage and the reidentification red-line omissions are
 *    inherited wholesale: there is simply no column for url/note/storage keys at
 *    a shareable marking, and no event/field for sex/gender/sexuality/romance/
 *    relationship/live-location exists upstream, so none can appear here.
 *  - PURE + OFFLINE: builds an in-memory package object + file map. No network,
 *    no token, no filesystem write here (a thin writer is provided separately and
 *    only writes when the caller passes an explicit outDir).
 */

'use strict';

const crypto = require('crypto');
const { allowedFields, redactRecord, isMarking, MARKINGS } = require('./redaction-policy');

/**
 * Frictionless Table Schema field TYPES for the columns redaction can emit.
 * Anything not listed defaults to "string" (the safe, lossless Frictionless type).
 * These names are stable across every record_type so a column always has one type.
 */
const FIELD_TYPES = Object.freeze({
  record_type: { type: 'string' },
  case_id: { type: 'string' },
  url: { type: 'string', format: 'uri' },
  content_sha256: { type: 'string' },
  html_sha256: { type: 'string' },
  html_key: { type: 'string' },
  screenshot_key: { type: 'string' },
  status_code: { type: 'integer' },
  captured_at: { type: 'datetime' },
  timestamp: { type: 'datetime' },
  flagged_at: { type: 'datetime' },
  logged_at: { type: 'datetime' },
  change: { type: 'string' },
  immutable: { type: 'boolean' },
  note: { type: 'string' },
  decision: { type: 'string' },
  validation: { type: 'string' },
});

function fieldDescriptor(name) {
  const t = FIELD_TYPES[name] || { type: 'string' };
  return { name, ...t };
}

/**
 * Build the Frictionless Table Schema for one record_type at one marking, by
 * READING the redaction allow-list (never a hand-kept parallel list). If the
 * type has no allowed fields at this marking, returns null (no resource emitted).
 *
 * @param {string} recordType
 * @param {string} marking
 * @returns {{fields: object[]}|null}
 */
function schemaFor(recordType, marking) {
  const fields = allowedFields(recordType, marking);
  if (!fields || fields.length === 0) return null;
  return { fields: fields.map(fieldDescriptor) };
}

/** CSV-escape one cell value per RFC 4180 (used by Frictionless `csv` resources). */
function csvCell(v) {
  if (v === null || v === undefined) return '';
  let s;
  if (typeof v === 'object') {
    try { s = JSON.stringify(v); } catch { s = String(v); }
  } else {
    s = String(v);
  }
  if (/[",\r\n]/.test(s)) return `"${s.replace(/"/g, '""')}"`;
  return s;
}

/**
 * Serialize redacted rows of ONE record_type to CSV text matching its schema's
 * column order exactly (so the resource is valid against its Table Schema).
 *
 * @param {string[]} columns  ordered field names (the schema's field order)
 * @param {object[]} rows      already-redacted rows for this record_type
 * @returns {string} CSV text with a header row
 */
function rowsToCsv(columns, rows) {
  const header = columns.map(csvCell).join(',');
  const body = rows.map((r) => columns.map((c) => csvCell(r[c])).join(',')).join('\n');
  return body ? `${header}\n${body}\n` : `${header}\n`;
}

/**
 * REDACT-THEN-GROUP. Run EVERY raw row through redactRecord(row, marking) and
 * bucket the survivors by record_type. A row that redacts to null is dropped.
 * This is the single chokepoint that guarantees the package can only ever
 * contain marking-permitted columns.
 *
 * @param {object[]} rawRows
 * @param {string} marking
 * @returns {Map<string, object[]>} record_type -> redacted rows
 */
function redactAndGroup(rawRows, marking) {
  const byType = new Map();
  for (const raw of (Array.isArray(rawRows) ? rawRows : [])) {
    const red = redactRecord(raw, marking);
    if (!red) continue; // not exportable at this marking, or invalid → drop
    const rt = red.record_type;
    if (!rt) continue;
    if (!byType.has(rt)) byType.set(rt, []);
    byType.get(rt).push(red);
  }
  return byType;
}

/**
 * buildDataPackage(rawRows, opts) — the emitter.
 *
 * @param {object[]} rawRows  RAW evidence rows (will be redacted here).
 * @param {object} opts
 * @param {string} opts.marking   distribution marking (MARKINGS); fail-closed.
 * @param {string} [opts.name]    package slug (default 'self-footprint-evidence').
 * @param {string} [opts.title]
 * @param {string} [opts.caseId]
 * @param {string} [opts.datasetId]  source Apify dataset id (provenance only).
 * @param {string} [opts.actorId]    source Apify actor id (provenance only).
 * @param {string} [opts.now]        ISO timestamp for `created` (deterministic tests).
 * @param {object} [opts.grade]      a computeExposureGrade() result to embed as a
 *                                   resource (its breakdown ledger), so the grade
 *                                   is re-derivable from the bundle. Optional.
 * @returns {{
 *   error?: string,
 *   datapackage?: object,            // the datapackage.json descriptor object
 *   files?: Record<string,string>,   // relative path -> file contents (csv/json)
 *   resourceCount?: number,
 *   rowCount?: number,
 *   fingerprint?: string,            // sha256 over the package contents (citation pin)
 *   meta?: object
 * }}
 */
function buildDataPackage(rawRows, opts = {}) {
  const marking = opts.marking;
  if (!isMarking(marking)) {
    return { error: `unknown or missing marking; refusing to build a package (fail-closed). Allowed: ${MARKINGS.join(', ')}` };
  }

  const now = typeof opts.now === 'string' && opts.now ? opts.now : new Date().toISOString();
  const name = (opts.name || 'self-footprint-evidence').toString();
  const grouped = redactAndGroup(rawRows, marking);

  const resources = [];
  const files = {};
  let rowCount = 0;

  // One tabular resource per record_type that survived redaction.
  for (const [recordType, rows] of grouped) {
    const schema = schemaFor(recordType, marking);
    if (!schema) continue; // no allowed columns at this marking → skip entirely
    const columns = schema.fields.map((f) => f.name);
    const fileName = `data/${recordType}.csv`;
    files[fileName] = rowsToCsv(columns, rows);
    rowCount += rows.length;
    resources.push({
      name: recordType.replace(/_/g, '-'),
      path: fileName,
      profile: 'tabular-data-resource',
      format: 'csv',
      mediatype: 'text/csv',
      encoding: 'utf-8',
      'x-marking': marking,
      'x-row-count': rows.length,
      dialect: { delimiter: ',', header: true },
      schema,
    });
  }

  // Optional: embed the Self-Exposure Grade LEDGER as its own tabular resource so
  // a consumer can RE-DERIVE the A–F letter from the published rows (Datasette
  // reproducibility). Only embedded when a REAL graded result is supplied.
  if (opts.grade && opts.grade.graded === true && Array.isArray(opts.grade.breakdown)) {
    const gradeCols = ['category', 'instances', 'deduction', 'worst_instance_penalty'];
    const gradeRows = opts.grade.breakdown;
    const fileName = 'data/exposure-grade-ledger.csv';
    files[fileName] = rowsToCsv(gradeCols, gradeRows);
    resources.push({
      name: 'exposure-grade-ledger',
      path: fileName,
      profile: 'tabular-data-resource',
      format: 'csv',
      mediatype: 'text/csv',
      encoding: 'utf-8',
      title: `Self-Exposure Grade ledger (score ${opts.grade.score}, grade ${opts.grade.grade}, baseline ${opts.grade.baseline})`,
      description: 'Per-category weighted deductions. score == round(baseline − Σ deduction). Re-derivable Mozilla-Observatory-style grade.',
      'x-grade': opts.grade.grade,
      'x-score': opts.grade.score,
      'x-baseline': opts.grade.baseline,
      schema: {
        fields: [
          { name: 'category', type: 'string', description: 'event_type the deduction applies to' },
          { name: 'instances', type: 'integer' },
          { name: 'deduction', type: 'number', description: 'points subtracted from baseline (damped+capped)' },
          { name: 'worst_instance_penalty', type: 'number' },
        ],
      },
    });
  }

  // The datapackage.json descriptor (Frictionless Data Package profile).
  const descriptor = {
    profile: 'tabular-data-package',
    name,
    title: opts.title || 'Self Footprint Audit — portable evidence package',
    description:
      'Self-contained, redaction-respecting evidence package of a SELF subject\'s OWN public footprint, '
      + 'emitted in the open Frictionless Data Package format. Every column was permitted by the '
      + `distribution marking "${marking}"; raw locators/PII are absent at non-RED markings. `
      + 'Opens offline; imports into Datasette / SQLite / pandas / OpenRefine unchanged.',
    created: now,
    licenses: [
      {
        name: 'subject-owned',
        title: 'Owned by the audit subject (self-data). Not for re-identifying or targeting any person.',
      },
    ],
    keywords: ['self-audit', 'digital-footprint', 'privacy', 'evidence', 'frictionless', 'redacted'],
    // Provenance so a citation pins an exact run. IDs are references, not secrets.
    sources: [{
      title: 'Apify dataset export (redacted via redaction-policy.js)',
      'x-dataset-id': opts.datasetId || null,
      'x-actor-id': opts.actorId || null,
      'x-case-id': opts.caseId || null,
    }],
    'x-distribution-marking': marking,
    'x-redaction-policy': 'integrations/exports/redaction-policy.js (marking-scoped, fail-closed)',
    resources,
  };

  // Content fingerprint: deterministic sha256 over the descriptor + every file,
  // so a citation can pin THIS exact bundle (Datasette-style citability). The
  // descriptor copy used for the hash omits the not-yet-known fingerprint.
  const fingerprint = fingerprintPackage(descriptor, files);
  descriptor['x-content-sha256'] = fingerprint;

  // Emit datapackage.json LAST so its serialized form includes the fingerprint.
  files['datapackage.json'] = `${JSON.stringify(descriptor, null, 2)}\n`;

  return {
    datapackage: descriptor,
    files,
    resourceCount: resources.length,
    rowCount,
    fingerprint,
    meta: {
      marking,
      created: now,
      note: resources.length === 0 ? 'no findings — empty evidence package' : undefined,
      grade_embedded: !!(opts.grade && opts.grade.graded === true),
    },
  };
}

/**
 * Deterministic sha256 over (descriptor-without-fingerprint || sorted files).
 * Used as a citation pin; pure, no I/O.
 */
function fingerprintPackage(descriptor, files) {
  const h = crypto.createHash('sha256');
  const descForHash = { ...descriptor };
  delete descForHash['x-content-sha256'];
  h.update('descriptor\n');
  h.update(JSON.stringify(descForHash));
  for (const key of Object.keys(files).sort()) {
    h.update(`\nfile:${key}\n`);
    h.update(files[key]);
  }
  return h.digest('hex');
}

/**
 * writeDataPackage(pkg, outDir) — OPTIONAL thin filesystem writer. Only writes
 * when the caller explicitly opts in by passing an outDir; buildDataPackage does
 * NO I/O on its own. Returns the list of written paths. Refuses if pkg has an
 * error. (Kept tiny + side-effect-gated so the emitter stays pure/testable.)
 *
 * @param {object} pkg     a buildDataPackage() result
 * @param {string} outDir  directory to write the package into
 * @returns {{error?:string, written?:string[]}}
 */
function writeDataPackage(pkg, outDir) {
  if (!pkg || pkg.error) return { error: pkg ? pkg.error : 'no package' };
  if (!outDir || typeof outDir !== 'string') return { error: 'outDir is required to write' };
  // eslint-disable-next-line global-require
  const fs = require('fs');
  // eslint-disable-next-line global-require
  const path = require('path');
  const written = [];
  for (const [rel, content] of Object.entries(pkg.files)) {
    const full = path.join(outDir, rel);
    fs.mkdirSync(path.dirname(full), { recursive: true });
    fs.writeFileSync(full, content, 'utf-8');
    written.push(full);
  }
  return { written };
}

module.exports = {
  FIELD_TYPES,
  schemaFor,
  rowsToCsv,
  redactAndGroup,
  buildDataPackage,
  fingerprintPackage,
  writeDataPackage,
};
