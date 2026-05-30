/**
 * shared/middleware/pipeline.js
 *
 * The compliance BACKBONE, modelled directly on two battle-tested crawler
 * architectures so reviewers can map our guarantees onto patterns they already
 * trust:
 *
 *  - Scrapy (docs.scrapy.org, "Downloader Middleware" + "Item Pipeline" +
 *    "Architecture overview"). Scrapy splits work into:
 *      * DOWNLOADER MIDDLEWARES — ordered hooks between the engine and the
 *        downloader. Each has `process_request(request)` which returns:
 *            None      -> keep processing, hand to the next middleware/fetch
 *            Response  -> short-circuit (no fetch happens)
 *            Request   -> reschedule a different request
 *            raise IgnoreRequest -> DROP this request, it is never fetched.
 *        Lower order number == closer to the engine, runs FIRST on the request
 *        path. We reproduce that exact contract.
 *      * ITEM PIPELINE — ordered `process_item(item)` stages that cleanse,
 *        validate and persist each scraped item; a stage may raise DropItem.
 *
 *  - Crawlee (crawlee.dev). A `RequestQueue` feeds a `Router` that dispatches
 *    each request to a handler. We mirror RequestQueue (enqueue/dequeue ordered)
 *    and the idea of re-asserting policy at the router on EVERY hop, not once at
 *    submit time, because newly-discovered links must be re-gated.
 *
 * WHY THIS MATTERS FOR COMPLIANCE: the single most important property of this
 * product is that a stalking / private-individual request can NEVER reach a
 * fetch. By expressing that as the FIRST, fail-closed downloader middleware
 * (the scope gate), every request — including links discovered mid-crawl —
 * must clear the gate again before any network I/O. The gate is read-only here:
 * we call the existing shared/scope.js validateScope and NEVER rewrite it.
 *
 * Pure (no network, no Apify import) so it is trivially unit-testable; the real
 * actors wire their fetch as the terminal stage. NO FAKE DATA: nothing in this
 * file fabricates a response or a finding.
 */

'use strict';

/**
 * Sentinel a downloader middleware throws to DROP a request before any fetch.
 * Mirrors Scrapy's `scrapy.exceptions.IgnoreRequest`.
 */
class IgnoreRequest extends Error {
  constructor(reason, meta = {}) {
    super(typeof reason === 'string' ? reason : 'request ignored');
    this.name = 'IgnoreRequest';
    this.reason = typeof reason === 'string' ? reason : 'request ignored';
    this.meta = meta && typeof meta === 'object' ? meta : {};
  }
}

/**
 * Sentinel an item-pipeline stage throws to DROP a scraped item.
 * Mirrors Scrapy's `scrapy.exceptions.DropItem`.
 */
class DropItem extends Error {
  constructor(reason, meta = {}) {
    super(typeof reason === 'string' ? reason : 'item dropped');
    this.name = 'DropItem';
    this.reason = typeof reason === 'string' ? reason : 'item dropped';
    this.meta = meta && typeof meta === 'object' ? meta : {};
  }
}

/**
 * Crawlee-style RequestQueue: an ordered FIFO of requests with de-duplication
 * by a caller-supplied uniqueKey (Crawlee dedupes on uniqueKey/url). Discovered
 * links are enqueued here and MUST pass the downloader middleware chain again.
 */
class RequestQueue {
  constructor() {
    this._items = [];
    this._seen = new Set();
  }

  /** @returns {boolean} true if newly enqueued, false if a duplicate. */
  enqueue(request) {
    if (!request || typeof request !== 'object' || typeof request.url !== 'string') {
      throw new Error('enqueue requires a request object with a string url.');
    }
    const key = request.uniqueKey || request.url;
    if (this._seen.has(key)) return false;
    this._seen.add(key);
    this._items.push(request);
    return true;
  }

  dequeue() {
    return this._items.shift() || null;
  }

  get size() {
    return this._items.length;
  }
}

/**
 * Sort a list of stage descriptors by ascending `order` (Scrapy convention:
 * lower number runs first / closer to the engine). Stable for equal orders.
 */
function byOrder(stages) {
  return stages
    .map((s, i) => ({ s, i }))
    .sort((a, b) => (a.s.order - b.s.order) || (a.i - b.i))
    .map((x) => x.s);
}

/**
 * Build a Scrapy-style downloader-middleware chain.
 *
 * Each middleware is `{ name, order, processRequest(request, ctx) }`.
 * processRequest returns:
 *   - undefined / null         -> continue to next middleware (Scrapy: None)
 *   - { response }             -> short-circuit, treat as the fetch result
 *   - { request: <newReq> }    -> replace the request and restart the chain
 *   - throws IgnoreRequest     -> request is dropped, never fetched
 *
 * @param {Array} middlewares
 * @returns {{ ordered: Array, run: function }}
 */
function buildDownloaderChain(middlewares) {
  const ordered = byOrder(middlewares.filter(Boolean));

  /**
   * Run the request through the ordered chain.
   * @returns {{ status, request, response, droppedBy, reason, trace }}
   */
  function run(request, ctx = {}) {
    const trace = [];
    let current = request;
    let restartGuard = 0;

    for (let i = 0; i < ordered.length; i += 1) {
      const mw = ordered[i];
      let result;
      try {
        result = mw.processRequest(current, ctx);
      } catch (err) {
        if (err instanceof IgnoreRequest) {
          trace.push({ mw: mw.name, action: 'ignore', reason: err.reason });
          return {
            status: 'dropped',
            request: current,
            response: null,
            droppedBy: mw.name,
            reason: err.reason,
            trace,
          };
        }
        throw err;
      }

      if (result && result.response !== undefined) {
        trace.push({ mw: mw.name, action: 'short_circuit' });
        return {
          status: 'short_circuit',
          request: current,
          response: result.response,
          droppedBy: null,
          reason: null,
          trace,
        };
      }

      if (result && result.request) {
        // Scrapy: returning a Request reschedules; restart the chain on it.
        restartGuard += 1;
        if (restartGuard > 16) {
          throw new Error('downloader chain restarted too many times (loop?).');
        }
        trace.push({ mw: mw.name, action: 'reschedule' });
        current = result.request;
        i = -1; // restart from the top
        continue;
      }

      // undefined/null => continue (Scrapy: process_request returned None).
      trace.push({ mw: mw.name, action: 'continue' });
    }

    return {
      status: 'pass',
      request: current,
      response: null,
      droppedBy: null,
      reason: null,
      trace,
    };
  }

  return { ordered, run };
}

/**
 * Build a Scrapy-style item pipeline.
 *
 * Each stage is `{ name, order, processItem(item, ctx) }`.
 * processItem returns the (possibly transformed) item to pass downstream, or
 * throws DropItem to discard it. Lower order runs first.
 *
 * @param {Array} stages
 * @returns {{ ordered: Array, run: function }}
 */
function buildItemPipeline(stages) {
  const ordered = byOrder(stages.filter(Boolean));

  function run(item, ctx = {}) {
    const trace = [];
    let current = item;
    for (const stage of ordered) {
      try {
        const out = stage.processItem(current, ctx);
        current = out === undefined ? current : out;
        trace.push({ stage: stage.name, action: 'process' });
      } catch (err) {
        if (err instanceof DropItem) {
          trace.push({ stage: stage.name, action: 'drop', reason: err.reason });
          return {
            status: 'dropped',
            item: current,
            droppedBy: stage.name,
            reason: err.reason,
            trace,
          };
        }
        throw err;
      }
    }
    return { status: 'ok', item: current, droppedBy: null, reason: null, trace };
  }

  return { ordered, run };
}

module.exports = {
  IgnoreRequest,
  DropItem,
  RequestQueue,
  byOrder,
  buildDownloaderChain,
  buildItemPipeline,
};
