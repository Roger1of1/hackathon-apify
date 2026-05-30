/**
 * shared/middleware/stages.js
 *
 * The concrete, ordered crawler stages that enforce our red lines. These are the
 * actual policy "middlewares" plugged into pipeline.js. They mirror the role
 * Scrapy gives its built-in downloader middlewares (each with an order number;
 * lower runs first) and item-pipeline stages, and Crawlee's idea of re-asserting
 * routing/policy on every dequeued request.
 *
 * Request path (downloader middlewares, ascending order):
 *   100  scopeGateMiddleware      — re-run shared/scope.js validateScope on EVERY
 *                                   hop; IgnoreRequest if not self/consented/
 *                                   public_figure/brand/safety_evidence or if the
 *                                   request smells like private-person tracking.
 *                                   This is FIRST and fail-closed: a stalking
 *                                   request dies here, BEFORE robots, rate limit,
 *                                   or any fetch.
 *   200  robotsTosMiddleware      — drop disallowed paths / private-social /
 *                                   login-walled hosts; never bypass robots/ToS.
 *   300  rateLimitMiddleware      — enforce a polite per-host delay; never
 *                                   hammer, never evade bans/captcha/rate limits.
 *   900  fetchTerminalMiddleware  — (real actors only) the last stage that
 *                                   actually fetches. Here it short-circuits with
 *                                   a placeholder so the pure pipeline is testable
 *                                   without network. NO FAKE DATA: the placeholder
 *                                   is clearly marked template:true, not a scrape.
 *
 * Item path (item pipeline, ascending order):
 *   100  scopeReassertItemStage   — defensive re-check that the produced item is
 *                                   tagged with an allowed scope; DropItem else.
 *   500  evidenceHashItemStage    — compute tamper-evident content/html hashes
 *                                   (shared/hashing.js) so every preserved item is
 *                                   citable. Mirrors a Scrapy persistence stage.
 *
 * scope.js is used READ-ONLY (validateScope) and is NEVER rewritten here.
 */

'use strict';

const { validateScope, hostOf, PRIVATE_SOCIAL_HOSTS } = require('../scope.js');
const { hashPage } = require('../hashing.js');
const { IgnoreRequest, DropItem } = require('./pipeline.js');

const ALLOWED_SCOPES = ['self', 'consented', 'public_figure', 'brand', 'safety_evidence'];

/**
 * Build the validateScope input from a request. A request carries the crawl's
 * scope envelope plus the specific URL of this hop. We re-assert the FULL gate
 * (scope_type + intent text + target) every hop so a link discovered mid-crawl
 * cannot smuggle a prohibited target past a gate that only ran once at submit.
 */
function scopeInputForRequest(request) {
  const env = (request && request.scopeEnvelope) || {};
  return {
    scope_type: env.scope_type,
    authorization_evidence_url: env.authorization_evidence_url,
    subject_label: env.subject_label,
    // intent text travels with the request so laundering is caught per-hop.
    // scope.js's collectIntentText() scans freeText/prompt/goal — map onto
    // `freeText` (and `prompt` for redundancy) so the per-hop intent scan fires.
    freeText: env.intent_text || request.intent_text || '',
    prompt: env.intent_text || request.intent_text || '',
    target_urls: [request.url],
  };
}

/**
 * ORDER 100 — Scope gate. FIRST, fail-closed. The single guarantee that a
 * stalking / private-individual request never reaches a fetch.
 */
const scopeGateMiddleware = {
  name: 'scopeGate',
  order: 100,
  processRequest(request) {
    const verdict = validateScope(scopeInputForRequest(request));
    if (!verdict.allowed) {
      throw new IgnoreRequest(
        'scope gate rejected this hop: ' + (verdict.reasons[0] || 'not permitted'),
        { violated_red_lines: verdict.violated_red_lines },
      );
    }
    // Pin the validated scope onto the request for later re-assertion.
    request.validatedScope = verdict.normalized.scope_type;
    return null; // Scrapy "None": continue down the chain.
  },
};

/**
 * ORDER 200 — robots.txt / ToS respect. We never bypass disallow rules, never
 * touch login-walled private-social hosts. A `robotsAllows` predicate is
 * injected (real actors back it with a fetched, cached robots.txt); default is
 * permissive ONLY for non-private hosts so the pure pipeline stays testable.
 */
function makeRobotsTosMiddleware(opts = {}) {
  const robotsAllows = typeof opts.robotsAllows === 'function'
    ? opts.robotsAllows
    : () => true;
  return {
    name: 'robotsTos',
    order: 200,
    processRequest(request) {
      const host = hostOf(request.url);
      if (!host) {
        throw new IgnoreRequest('invalid URL, cannot resolve host', { url: request.url });
      }
      if (PRIVATE_SOCIAL_HOSTS.includes(host)) {
        throw new IgnoreRequest(
          'host is a login-walled / private-social graph; we do not bypass logins',
          { host },
        );
      }
      if (!robotsAllows(request.url, host)) {
        throw new IgnoreRequest('robots.txt / ToS disallows this path', { url: request.url });
      }
      return null;
    },
  };
}

/**
 * ORDER 300 — polite rate limiting. Enforces a minimum per-host gap; if the gap
 * has not elapsed the request is rescheduled (Scrapy: return a Request) with a
 * computed `notBefore` so the queue can defer it — we never circumvent server
 * rate limits or bans, we slow ourselves down. State is injected so it is pure.
 */
function makeRateLimitMiddleware(opts = {}) {
  const minGapMs = Number.isFinite(opts.minGapMs) ? opts.minGapMs : 1000;
  const lastHit = opts.lastHit instanceof Map ? opts.lastHit : new Map();
  const now = typeof opts.now === 'function' ? opts.now : () => Date.now();
  return {
    name: 'rateLimit',
    order: 300,
    lastHit,
    processRequest(request) {
      const host = hostOf(request.url);
      const t = now();
      const prev = lastHit.get(host);
      if (prev !== undefined && t - prev < minGapMs && !request._rateDeferred) {
        // Reschedule politely instead of hammering. Mark so we don't loop.
        return {
          request: Object.assign({}, request, {
            _rateDeferred: true,
            notBefore: prev + minGapMs,
          }),
        };
      }
      lastHit.set(host, t);
      return null;
    },
  };
}

/**
 * ORDER 900 — terminal fetch stage. In a real actor this performs the HTTP
 * fetch. In the pure/testable pipeline it short-circuits with a clearly-labelled
 * TEMPLATE placeholder (template:true) so NO FAKE scrape data is ever produced.
 */
function makeFetchTerminalMiddleware(opts = {}) {
  const fetchImpl = typeof opts.fetch === 'function' ? opts.fetch : null;
  return {
    name: 'fetchTerminal',
    order: 900,
    processRequest(request) {
      if (fetchImpl) {
        return { response: fetchImpl(request) };
      }
      return {
        response: {
          template: true,
          note: 'TEMPLATE placeholder — no real fetch in the pure pipeline. A real '
            + 'Apify actor supplies opts.fetch; this proves ordering, not a scrape.',
          url: request.url,
          scope_type: request.validatedScope || null,
        },
      };
    },
  };
}

/**
 * ITEM ORDER 100 — re-assert scope on the produced item. Defensive: an item must
 * carry an allowed scope_type or it is dropped before persistence.
 */
const scopeReassertItemStage = {
  name: 'scopeReassertItem',
  order: 100,
  processItem(item) {
    const sc = item && item.scope_type;
    if (!ALLOWED_SCOPES.includes(sc)) {
      throw new DropItem('item missing/invalid scope_type', { scope_type: sc });
    }
    return item;
  },
};

/**
 * ITEM ORDER 500 — evidence hashing. Attaches tamper-evident content/html hashes
 * so every preserved item is citable. Mirrors a Scrapy persistence pipeline.
 */
const evidenceHashItemStage = {
  name: 'evidenceHash',
  order: 500,
  processItem(item) {
    const { content_sha256, html_sha256, normalized_length } = hashPage({
      text: item.text || '',
      html: item.html || '',
    });
    return Object.assign({}, item, {
      content_sha256,
      html_sha256,
      normalized_length,
      hashed_at: item.hashed_at || null, // real actors stamp a timestamp; never faked here
    });
  },
};

/**
 * Convenience: the default compliance chains, in canonical order.
 */
function defaultDownloaderMiddlewares(opts = {}) {
  return [
    scopeGateMiddleware,
    makeRobotsTosMiddleware(opts),
    makeRateLimitMiddleware(opts),
    makeFetchTerminalMiddleware(opts),
  ];
}

function defaultItemPipeline() {
  return [scopeReassertItemStage, evidenceHashItemStage];
}

module.exports = {
  ALLOWED_SCOPES,
  scopeInputForRequest,
  scopeGateMiddleware,
  makeRobotsTosMiddleware,
  makeRateLimitMiddleware,
  makeFetchTerminalMiddleware,
  scopeReassertItemStage,
  evidenceHashItemStage,
  defaultDownloaderMiddlewares,
  defaultItemPipeline,
};
