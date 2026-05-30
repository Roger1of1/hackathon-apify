/**
 * shared/enrich/cluster-keys.js
 *
 * Pure CO-OCCURRENCE KEY extractor for the SpiderFoot-style correlation engine
 * (shared/correlation.js, a sibling track). SpiderFoot's correlation engine
 * links events that share an ENTITY — the same host, the same account/handle,
 * the same email. We centralise that key-extraction here so every detector's
 * events yield clusterable keys through ONE honest, unit-tested function instead
 * of the engine reaching into each event shape ad hoc.
 *
 * The keys we emit are deliberately ENTITY/SURFACE keys, never identity/person
 * inference:
 *   - host:<hostname>             from source_url (the surface the leak lives on)
 *   - handle:<lowercased handle>  a self-published @handle / username
 *   - email_prefix:<5 hex>        the HIBP k-anonymity SHA-1 prefix of an email,
 *                                 NEVER the plaintext address
 *   - secret_fp:<12 hex>          a one-way fingerprint of a leaked secret, so the
 *                                 SAME leaked key on two pages co-occurs without
 *                                 the engine ever seeing the credential
 *
 * RED LINE: there is no key here for a person, a relationship, a gender, or a
 * location track. Clustering is by shared public surface/artifact only — exactly
 * the boundary correlation.js must enforce.
 *
 * Refs:
 *   SpiderFoot correlation engine (entity-shared event linking) —
 *     github.com/smicallef/spiderfoot
 *   HIBP k-anonymity range model (email/secret keyed on a hash prefix, not the
 *     plaintext) — Troy Hunt, "Understanding HIBP's Use of SHA-1 and k-Anonymity".
 *
 * Pure functions, no network, no mutation of inputs. Safe to require at load.
 */

'use strict';

const { isModuleEvent } = require('../detectors/event-types.js');
const { emailHashKey } = require('../aux/kanon.js');

/** Lower-cased hostname of a URL, or null. Never throws. */
function hostOf(url) {
  if (typeof url !== 'string' || !url) return null;
  try { return new URL(url).hostname.toLowerCase() || null; } catch { return null; }
}

/** Normalize a handle/username token to a stable comparable form. */
function normalizeHandle(h) {
  if (typeof h !== 'string') return null;
  const v = h.trim().replace(/^@+/, '').toLowerCase();
  return v.length ? v : null;
}

/**
 * Extract the set of co-occurrence keys for ONE module_event. Returns a
 * de-duplicated string[] (stable order: host, handle, email_prefix, secret_fp).
 * A non-event yields [].
 *
 * @param {object} event a module_event
 * @returns {string[]}
 */
function clusterKeysFor(event) {
  if (!isModuleEvent(event)) return [];
  const keys = [];
  const add = (k) => { if (k && !keys.includes(k)) keys.push(k); };

  // host — the public surface the exposure lives on.
  add(prefixKey('host', hostOf(event.source_url)));

  const meta = event.meta && typeof event.meta === 'object' ? event.meta : {};

  // handle — from a self-published @handle event, or any meta.handle.
  if (event.event_type === 'PII_HANDLE_PUBLIC' || event.event_type === 'SELF_USERNAME') {
    // data is like "@jane"; meta.handle is the bare form.
    add(prefixKey('handle', normalizeHandle(meta.handle != null ? meta.handle : event.data)));
  } else if (meta.handle != null) {
    add(prefixKey('handle', normalizeHandle(meta.handle)));
  }

  // email_prefix — prefer a prefix already carried in meta (e.g. from the PII
  // detector), else derive it from a plaintext email in data via k-anonymity.
  let emailPrefix = typeof meta.email_hash_prefix === 'string' ? meta.email_hash_prefix : null;
  if (!emailPrefix && typeof event.data === 'string' && event.data.includes('@')) {
    emailPrefix = emailHashKey(event.data).email_hash_prefix;
  }
  add(prefixKey('email_prefix', emailPrefix));

  // secret_fp — a leaked secret's one-way fingerprint (from the secret module).
  if (event.data && typeof event.data === 'object' && typeof event.data.fingerprint === 'string') {
    add(prefixKey('secret_fp', event.data.fingerprint));
  }

  return keys;
}

function prefixKey(prefix, value) {
  return value ? `${prefix}:${value}` : null;
}

/**
 * Build a key -> event-index[] inverted index over many events. This is the
 * adjacency the correlation engine walks to form clusters (events sharing any
 * key belong together). We return indices (not events) so the engine stays in
 * control of cluster construction & scoring — we only do honest key extraction.
 *
 * @param {object[]} events
 * @returns {{ index: Map<string, number[]>, keysByEvent: string[][] }}
 */
function buildKeyIndex(events = []) {
  const index = new Map();
  const keysByEvent = [];
  const list = Array.isArray(events) ? events : [];
  for (let i = 0; i < list.length; i += 1) {
    const keys = clusterKeysFor(list[i]);
    keysByEvent.push(keys);
    for (const k of keys) {
      if (!index.has(k)) index.set(k, []);
      index.get(k).push(i);
    }
  }
  return { index, keysByEvent };
}

module.exports = {
  hostOf,
  normalizeHandle,
  clusterKeysFor,
  buildKeyIndex,
};
