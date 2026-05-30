/**
 * shared/hashing.js
 *
 * Deterministic content hashing for evidence integrity.
 *
 * Two hashes per captured page:
 *   - content_sha256 : sha256 of NORMALIZED visible text (stable across
 *                      whitespace / boilerplate noise) — used for change detection.
 *   - html_sha256    : sha256 of the RAW html exactly as fetched — used as a
 *                      tamper-evident fingerprint of the preserved evidence.
 *
 * No network or storage access here so it is trivially testable and reusable.
 */

'use strict';

const crypto = require('crypto');

/**
 * Hash any string with sha256, hex-encoded.
 */
function sha256(input) {
  const buf = typeof input === 'string' ? input : String(input ?? '');
  return crypto.createHash('sha256').update(buf, 'utf8').digest('hex');
}

/**
 * Normalize visible text so that cosmetic changes do not register as content
 * changes. Lowercases is intentionally NOT done — case can be meaningful
 * evidence. We only collapse whitespace and strip zero-width junk.
 */
function normalizeText(text) {
  if (typeof text !== 'string') return '';
  return text
    // strip zero-width / BOM characters often injected by anti-scrape layers
    .replace(/[​-‍﻿]/g, '')
    // normalize all whitespace runs (incl. NBSP) to single spaces
    .replace(/[\s ]+/g, ' ')
    .trim();
}

/**
 * Produce both hashes for a captured page.
 * @param {{ text?: string, html?: string }} page
 * @returns {{ content_sha256: string, html_sha256: string, normalized_length: number }}
 */
function hashPage({ text = '', html = '' }) {
  const normalized = normalizeText(text);
  return {
    content_sha256: sha256(normalized),
    html_sha256: sha256(html),
    normalized_length: normalized.length,
  };
}

module.exports = { sha256, normalizeText, hashPage };
