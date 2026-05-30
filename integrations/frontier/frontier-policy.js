/**
 * integrations/frontier/frontier-policy.js
 *
 * The APIFY REQUEST QUEUE ('frontier') layer: the deduplicated, lockable,
 * resumable URL frontier that a compliant self-audit crawl pulls from. Pure +
 * zero-I/O at the decision boundary, so the dry-run client (frontier-client.js)
 * and the self-test share one truth. No network, no fs except loading the policy
 * config (callers can inject it).
 *
 * WHAT THIS WIRES (the round's assigned Apify capability)
 * ──────────────────────────────────────────────────────────────────────────────
 * Apify Request Queue (https://docs.apify.com/platform/storage/request-queue,
 * https://docs.apify.com/api/v2/storage-request-queues). It is the platform's
 * server-side, deduplicated URL frontier:
 *   - addRequest / batchAddRequests deduplicate on `uniqueKey`: a second add
 *     with a uniqueKey already present returns the EXISTING request and adds
 *     nothing (wasAlreadyPresent / wasAlreadyHandled) —
 *     https://docs.apify.com/api/v2/request-queue-requests-post,
 *     https://docs.apify.com/api/v2/request-queue-requests-batch-post (≤25/call);
 *   - head-and-lock hands the head request to one client for lockSecs so two
 *     crawl clients never fetch the same surface at once —
 *     https://docs.apify.com/api/client/js/reference/class/RequestQueueClient.
 *
 * WHY A QUEUE IS A COMPLIANCE PRIMITIVE HERE (not a perf trick)
 *   - uniqueKey dedup  → minimum-disclosure: the SAME public surface is fetched
 *     at most once per audit; we never re-pull a page we already hold.
 *   - max_queue_size   → anti-dragnet: the frontier is BOUNDED; once full, new
 *     enqueues are refused (clamped to zero), never grown.
 *   - scope at enqueue → the SAME chokepoint as ingest: every URL is routed
 *     through shared/scope.js validateScope() and any PRIVATE_SOCIAL_HOSTS host
 *     is refused entry. A queue can never widen scope.
 *   - lockSecs         → politeness: one client owns the head, slowing concurrent
 *     pressure on a target host. Slows, never speeds (anti-evasion).
 *
 * REFERENCE ARCHITECTURE #1 — Apify Request Queue (platform + API v2 client).
 * We borrow its concrete contracts verbatim: the `{ url, uniqueKey, method,
 * userData }` request shape, server-side uniqueKey dedup, the ≤25-per-call batch
 * add limit, and head-and-lock with lockSecs. We do NOT re-implement a queue;
 * we build the exact request descriptors that API would receive.
 *
 * REFERENCE ARCHITECTURE #2 — Crawlee / Scrapy frontier + dupefilter. Crawlee's
 * RequestQueue and Scrapy's scheduler both put a DEDUPED, RESUMABLE frontier at
 * the centre of a polite crawl: a canonical request fingerprint (Scrapy's
 * `request_fingerprint`, Crawlee's `uniqueKey`) guarantees each URL is scheduled
 * once, and a bounded scheduler + per-domain politeness throttle the crawl
 * (Crawlee maxRequestsPerCrawl, Scrapy DEPTH/CLOSESPIDER limits, AUTOTHROTTLE).
 * We mirror that essence: canonicalize → fingerprint(uniqueKey) → bounded enqueue
 * → polite head-lock. For self-audit we tighten it to OWN-SURFACE only via the
 * scope gate, which a generic crawler frontier does not have.
 *   refs: https://crawlee.dev/js/api/core/class/RequestQueue
 *         https://docs.scrapy.org/en/latest/topics/settings.html (DUPEFILTER, DEPTH_LIMIT)
 *
 * NO FAKE DATA: this module decides and builds descriptors only. It never claims
 * a request was enqueued, never invents a queue state, and never fabricates a
 * dedup result — the real wasAlreadyPresent flags come from the live API at the
 * operator's last deploy step.
 */

'use strict';

const fs = require('fs');
const path = require('path');

// Read-only require of the scope gate — the front door. We DO NOT re-implement
// host blocking or scope rules here; we reuse validateScope + PRIVATE_SOCIAL_HOSTS.
const { validateScope, PRIVATE_SOCIAL_HOSTS, hostOf } = require('../../shared/scope.js');

const CONFIG_PATH = path.join(__dirname, 'frontier.config.json');

const SOURCE = 'apify/request-queue';

const REFUSAL = Object.freeze({
  SCOPE: 'scope_rejected',
  PRIVATE_HOST: 'private_social_host',
  BAD_URL: 'unusable_url',
  QUEUE_FULL: 'queue_full',
  NO_URLS: 'no_enqueueable_urls',
});

/** Load the frontier policy config (callers can inject an already-parsed object). */
function loadFrontierConfig(configPath = CONFIG_PATH) {
  if (configPath && typeof configPath === 'object') return configPath;
  const raw = fs.readFileSync(configPath, 'utf8');
  return JSON.parse(raw);
}

/** Clamp a requested numeric DOWN to a ceiling (anti-dragnet: never up). */
function clampDown(requested, ceiling, fallback) {
  const c = Number.isFinite(ceiling) ? ceiling : fallback;
  const r = Number.isFinite(requested) ? requested : fallback;
  return Math.max(0, Math.min(r, c));
}

/**
 * Canonicalize a URL into the stable `uniqueKey` Apify dedupes on. We normalize
 * conservatively (lowercase scheme+host, strip default ports, strip a trailing
 * slash on the path, strip the fragment, sort the query) so two spellings of the
 * SAME public surface collapse to one queue entry. Returns null for anything we
 * cannot parse or that is not http(s) — those are refused, not guessed.
 *
 * This is the moral equivalent of Scrapy's request_fingerprint / Crawlee's
 * default uniqueKey derivation: a deterministic identity for "the same request".
 */
function canonicalizeUrl(urlString) {
  if (typeof urlString !== 'string' || !urlString.trim()) return null;
  let u;
  try {
    u = new URL(urlString.trim());
  } catch {
    return null;
  }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') return null;

  const scheme = u.protocol.toLowerCase();
  const host = u.hostname.toLowerCase();
  // Drop default ports so http://x:80 == http://x.
  const isDefaultPort =
    !u.port ||
    (scheme === 'http:' && u.port === '80') ||
    (scheme === 'https:' && u.port === '443');
  const port = isDefaultPort ? '' : `:${u.port}`;

  // Normalize path: collapse a bare/trailing slash to '/'.
  let pathName = u.pathname || '/';
  if (pathName.length > 1 && pathName.endsWith('/')) pathName = pathName.slice(0, -1);

  // Sort query params for a stable key; drop the fragment entirely.
  const params = [...u.searchParams.entries()].sort(([a], [b]) =>
    a < b ? -1 : a > b ? 1 : 0,
  );
  const search = params.length
    ? '?' + params.map(([k, v]) => `${k}=${v}`).join('&')
    : '';

  return `${scheme}//${host}${port}${pathName}${search}`;
}

/** Is this URL's host one of the login-walled private-social hosts we refuse? */
function isPrivateSocialHost(urlString) {
  const host = hostOf(urlString);
  if (!host) return false;
  return PRIVATE_SOCIAL_HOSTS.some(
    (blocked) => host === blocked || host.endsWith(`.${blocked}`),
  );
}

function drop(refusal, extra = {}) {
  return {
    allowed: false,
    source: SOURCE,
    deployed: false,
    refusal,
    ...extra,
  };
}

/**
 * buildEnqueuePlan(input, opts) -> plan | refusal
 *
 * Pure planner. Takes the audit input ({ scope_type, target_urls, subject_token,
 * lockSecs?, existing_unique_keys? }) and returns the EXACT, deduplicated,
 * capped, scope-gated batch of Apify Request Queue requests that WOULD be
 * enqueued — or a fail-closed refusal. NO network.
 *
 * @returns on success:
 *   {
 *     allowed: true, source, deployed:false, scope_type, queueId,
 *     requests: [{ url, uniqueKey, method, userData }],   // ready for batch-add
 *     caps: { max_queue_size, max_enqueue_batch },
 *     dedup: { requested, unique, already_present, refused }, // accounting only
 *     lockSecs, notes
 *   }
 */
function buildEnqueuePlan(input, opts = {}) {
  const cfg = loadFrontierConfig(opts.config);

  // 1) FRONT DOOR — the scope gate. A rejected subject never reaches the queue.
  const scope = validateScope(input || {});
  if (!scope.allowed) {
    return drop(REFUSAL.SCOPE, {
      scope_reasons: scope.reasons,
      violated_red_lines: scope.violated_red_lines,
      alternatives: scope.alternatives,
    });
  }

  const allowedScopes = cfg.scopes_allowed_to_enqueue || [];
  if (!allowedScopes.includes(scope.scope_type)) {
    return drop(REFUSAL.SCOPE, {
      scope_reasons: [`scope_type "${scope.scope_type}" may not enqueue to a frontier.`],
    });
  }

  const caps = cfg.caps || {};
  const maxQueue = Number.isFinite(caps.max_queue_size) ? caps.max_queue_size : 200;
  const maxBatch = Number.isFinite(caps.max_enqueue_batch) ? caps.max_enqueue_batch : 25;
  const maxUrlLen = Number.isFinite(caps.max_url_length) ? caps.max_url_length : 2048;

  // The set already in the queue (dedup is server-side at deploy; we account for
  // it locally when the operator passes the known head). NEVER fabricated.
  const existing = new Set(
    Array.isArray(opts.existingUniqueKeys) ? opts.existingUniqueKeys : [],
  );

  // 2) Build candidate requests from the gate's NORMALIZED targets (never the raw
  //    caller input — the gate already trimmed + vetted them).
  const targets = (scope.normalized && scope.normalized.target_urls) || [];

  const seen = new Set();
  let refused = 0;
  let alreadyPresent = 0;
  const requests = [];

  for (const rawUrl of targets) {
    if (typeof rawUrl !== 'string' || rawUrl.length > maxUrlLen) {
      refused += 1;
      continue;
    }
    // Second door: refuse private-social hosts at enqueue (belt-and-braces with
    // the gate, in case a target slipped through as a bare host).
    if (isPrivateSocialHost(rawUrl)) {
      refused += 1;
      continue;
    }
    const uniqueKey = canonicalizeUrl(rawUrl);
    if (!uniqueKey) {
      refused += 1;
      continue;
    }
    // Local dedup (same batch) + server-side dedup accounting.
    if (seen.has(uniqueKey)) {
      alreadyPresent += 1;
      continue;
    }
    if (existing.has(uniqueKey)) {
      alreadyPresent += 1;
      seen.add(uniqueKey);
      continue;
    }
    seen.add(uniqueKey);
    requests.push(buildRequest(uniqueKey, rawUrl, cfg));
  }

  if (requests.length === 0) {
    return drop(REFUSAL.NO_URLS, {
      scope_type: scope.scope_type,
      dedup: { requested: targets.length, unique: 0, already_present: alreadyPresent, refused },
      notes:
        'Nothing enqueueable: every target was a duplicate, a private-social host, ' +
        'or an unusable URL. Fail-closed — an empty frontier is not an error to mask.',
    });
  }

  // 3) ANTI-DRAGNET cap. Remaining queue headroom = max_queue_size - already-present.
  const headroom = Math.max(0, maxQueue - existing.size);
  if (headroom === 0) {
    return drop(REFUSAL.QUEUE_FULL, {
      scope_type: scope.scope_type,
      caps: { max_queue_size: maxQueue },
      notes: `Frontier already holds ${existing.size}/${maxQueue} surfaces — refused (anti-dragnet).`,
    });
  }
  // Clamp the enqueue to BOTH the batch limit and the remaining headroom.
  const allowedCount = Math.min(requests.length, maxBatch, headroom);
  const clamped = requests.slice(0, allowedCount);
  const clampedOut = requests.length - clamped.length;

  const lockSecs = clampDown(
    opts.lockSecs,
    (cfg.lock && cfg.lock.max_lock_secs) || 300,
    (cfg.lock && cfg.lock.default_lock_secs) || 60,
  );

  return {
    allowed: true,
    source: SOURCE,
    deployed: false,
    scope_type: scope.scope_type,
    queueId: (cfg.queue && cfg.queue.queueId) || '<PLACEHOLDER:REQUEST_QUEUE_ID>',
    requests: clamped,
    caps: { max_queue_size: maxQueue, max_enqueue_batch: maxBatch },
    dedup: {
      requested: targets.length,
      unique: requests.length,
      already_present: alreadyPresent,
      refused,
      clamped_for_caps: clampedOut,
    },
    lockSecs,
    notes:
      `Enqueue plan built (apify/request-queue). ${clamped.length} deduplicated ` +
      `request(s) ready for batch-add (≤${maxBatch}/call). ${alreadyPresent} duplicate(s) ` +
      `and ${refused} unusable/blocked target(s) dropped; ${clampedOut} clamped by caps. ` +
      'respectRobotsTxtFile forced ON in userData; scope re-asserted at enqueue.',
  };
}

/** Build one Apify Request Queue request object with forced-compliant userData. */
function buildRequest(uniqueKey, url, cfg) {
  const defaults = cfg.request_defaults || {};
  const forced = cfg.forced_overrides || {};
  const userData = {
    ...(defaults._userData || {}),
    respectRobotsTxtFile: true, // forced — never trust caller (anti-evasion floor)
    scope_reasserted: true,
  };
  if (forced.respectRobotsTxtFile === true) userData.respectRobotsTxtFile = true;
  return {
    url,
    uniqueKey,
    method: defaults.method || 'GET',
    userData,
  };
}

/**
 * splitBatches(requests, size) -> [[...], ...]
 * Apify batch-add accepts ≤25 requests per call. This splits a plan's requests
 * into API-sized batches so the client can iterate without exceeding the limit.
 */
function splitBatches(requests, size = 25) {
  const cap = Number.isFinite(size) && size > 0 ? Math.min(size, 25) : 25;
  const out = [];
  for (let i = 0; i < requests.length; i += cap) out.push(requests.slice(i, i + cap));
  return out;
}

module.exports = {
  loadFrontierConfig,
  buildEnqueuePlan,
  canonicalizeUrl,
  isPrivateSocialHost,
  splitBatches,
  clampDown,
  buildRequest,
  SOURCE,
  REFUSAL,
};
