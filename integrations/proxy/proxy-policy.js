/**
 * integrations/proxy/proxy-policy.js
 *
 * Pure, zero-I/O policy that decides WHETHER and HOW an Apify Proxy may be used
 * for a given audit request — or REFUSES it. No network, no fs at the decision
 * boundary, so the live client (proxy-client.js) and the tests share one truth.
 *
 * WHY THIS EXISTS (product framing)
 * ---------------------------------
 * A proxy is the most easily-abused part of any crawler: it is the exact tool an
 * evasion/stalking pipeline reaches for to defeat IP bans, rate limits, and geo
 * walls. MirrorTrace uses proxies for the OPPOSITE reason — AVAILABILITY ONLY:
 *   - IP diversity so we are a polite, non-hammering client of a PUBLIC page;
 *   - geo-correct rendering of the USER'S OWN page as their region sees it.
 * It NEVER uses a proxy to look "more human", to outlast a ban, or to get behind
 * a login wall. This module encodes that line. The single most important
 * inversion is `retire_on_block`: a 403/429 is a STOP signal, not a "rotate to a
 * fresh IP and keep going" signal.
 *
 * REFERENCE ARCHITECTURE #1 — Crawlee / Scrapy proxy + session management.
 * Crawlee's ProxyConfiguration rotates proxy URLs (round-robin or sticky via a
 * sessionId), supports tiered proxy lists that UPSHIFT to higher-quality proxies
 * "whenever the crawler encounters a problem with the current proxy on the given
 * domain", and its SessionPool auto-RETIRES a session on 401/403/429 and swaps
 * in a fresh IP to keep scraping
 * (https://crawlee.dev/js/docs/guides/proxy-management,
 *  https://crawlee.dev/blog/proxy-management-in-crawlee,
 *  https://crawlee.dev/js/docs/guides/session-management).
 * We BORROW the mechanics (sessionId-stable proxy URLs, block detection, a tier
 * ladder) but INVERT the reflex: the same 401/403/429 that makes Crawlee retire-
 * and-rotate makes US declare a COMPLIANCE STOP. The "tier ladder" here only
 * ever steps datacenter -> residential for documented GEO-ACCURACY, never to
 * defeat a block. This is the Scrapy item-pipeline "DropItem" pattern applied to
 * transport: the first guard that objects drops the request before any fetch.
 *
 * REFERENCE ARCHITECTURE #2 — Have I Been Pwned k-anonymity range query.
 * HIBP carries the MINIMUM identifying token off the client: only a 5-char SHA-1
 * prefix is sent, the rest stays local
 * (https://www.troyhunt.com/understanding-have-i-been-pwneds-use-of-sha-1-and-k-anonymity/).
 * We carry the same minimum-disclosure stance into proxy SELECTION: geo targeting
 * is coarse (country only — US-state/subdivision targeting is deliberately NOT
 * enabled), and the chosen proxy URL is logged REDACTED (password stripped, only
 * the k-anonymous group+country visible). A proxy decision should reveal the
 * minimum, never become a tracking fingerprint.
 *
 * SCOPE — this file READS shared/scope.js (Codex owns it; we never write it) so
 * a proxy can only ever be built for a subject the real gate already accepts.
 * Two doors, both must open: validateScope AND this proxy policy.
 */

'use strict';

const fs = require('fs');
const path = require('path');
const { validateScope } = require('../../shared/scope.js');

const CONFIG_PATH = path.join(__dirname, 'proxy.config.json');

/** Load + parse the proxy policy config (the only fs touch; callers can inject). */
function loadProxyConfig(configPath = CONFIG_PATH) {
  return JSON.parse(fs.readFileSync(configPath, 'utf8'));
}

/**
 * Block status codes. In Crawlee these trigger retire+rotate to KEEP scraping.
 * Here they are read as "this resource does not want this client" => STOP.
 */
const BLOCK_STATUS = Object.freeze([401, 403, 407, 429, 451, 503]);

/** Transport faults where ONE retry is acceptable (no block signal present). */
const TRANSPORT_FAULTS = Object.freeze([
  'ECONNRESET',
  'ETIMEDOUT',
  'ESOCKETTIMEDOUT',
  'EAI_AGAIN',
  'socket hang up',
]);

/** Refusal codes, so callers/tests can assert the EXACT reason, fail-closed. */
const REFUSAL = Object.freeze({
  SCOPE_REJECTED: 'scope_rejected',
  EVASION_INTENT: 'evasion_intent',
  RESIDENTIAL_NOT_ALLOWED_FOR_SCOPE: 'residential_not_allowed_for_scope',
  RESIDENTIAL_WITHOUT_JUSTIFICATION: 'residential_without_geo_justification',
  GROUP_DENIED: 'group_denied',
  COUNTRY_NOT_ALLOWED: 'country_not_allowed',
  SUBDIVISION_TARGETING_DISABLED: 'subdivision_targeting_disabled',
});

/**
 * Signals in the request that mean the operator wants EVASION, not availability.
 * Any of these flips the decision to a hard refusal — a proxy must never be the
 * tool that defeats a defense. (Names are matched loosely so paraphrases of the
 * same intent are still caught.)
 */
const EVASION_FLAGS = Object.freeze([
  'bypass_ban',
  'bypass_block',
  'bypass_rate_limit',
  'bypass_captcha',
  'solve_captcha',
  'rotate_until_pass',
  'rotate_until_success',
  'evade_block',
  'evade_detection',
  'avoid_ban',
  'defeat_rate_limit',
  'login_wall_bypass',
  'bypass_login',
  'unlimited_retries',
  'retry_until_unblocked',
]);

/** True if the request carries any evasion intent (flags or matching free text). */
function hasEvasionIntent(input) {
  const flags = [];
  if (Array.isArray(input.proxy_intent_flags)) flags.push(...input.proxy_intent_flags);
  if (Array.isArray(input.tasks)) flags.push(...input.tasks);
  if (typeof input.proxy_intent === 'string') flags.push(input.proxy_intent);
  const norm = flags.map((f) => String(f).toLowerCase().trim());
  if (norm.some((f) => EVASION_FLAGS.includes(f))) return true;

  // Free-text laundering ("rotate proxies until it stops blocking me").
  const text = [input.note, input.proxy_note, input.freeText, input.justification]
    .filter((s) => typeof s === 'string')
    .join(' \n ')
    .toLowerCase();
  if (!text) return false;
  const TEXT_EVASION = [
    /bypass(ing)?\s+(the\s+)?(ban|block|rate.?limit|captcha|login)/,
    /(get|work)\s+(a|past|around)\s+(the\s+)?(ban|block|captcha|rate.?limit|login)/,
    /rotate.*(until|so).*(pass|through|unblock|stop|no longer|not)\w*\s*block/,
    /until\s+it\s+(stops?|no longer)\s+block/,
    /avoid\s+(getting\s+)?(banned|blocked|detected|caught)/,
    /look\s+(more\s+)?human/,
    /defeat\s+(the\s+)?(anti.?bot|rate.?limit|block)/,
  ];
  return TEXT_EVASION.some((re) => re.test(text));
}

/**
 * decideProxy(input, opts) -> decision
 *
 * The ordered guard pipeline (Scrapy/Crawlee middleware ordering). The FIRST
 * guard that objects DROPS the request and nothing downstream runs:
 *   1. scope gate        — real shared/scope.js must accept the subject
 *   2. evasion gate       — any evasion intent is a hard refusal
 *   3. group gate          — denied groups (e.g. GOOGLE_SERP) refused
 *   4. residential gate     — dual-use tier; scope+justification required
 *   5. geo gate              — country allow-list; subdivision targeting disabled
 *   6. build (availability)   — emit the proxy spec + the compliance floor
 *
 * Returns { allowed, refusal?, proxySpec?, complianceFloor?, scope }.
 * NEVER throws on a bad request; refusals are values, not exceptions.
 */
function decideProxy(input, opts = {}) {
  const cfg = opts.config || loadProxyConfig();
  const safe = input && typeof input === 'object' ? input : {};

  // ---- Guard 1: the REAL scope gate (read-only use of Coda private person's module) -------
  const scopeResult = validateScope(safe);
  if (!scopeResult.allowed) {
    return drop(REFUSAL.SCOPE_REJECTED, {
      detail: 'The audit subject was refused by the scope gate; no proxy is built.',
      scope_reasons: scopeResult.reasons,
      scope: safe.scope_type || null,
    });
  }
  const scope = safe.scope_type;

  // ---- Guard 2: evasion intent is categorically refused ---------------------
  if (hasEvasionIntent(safe)) {
    return drop(REFUSAL.EVASION_INTENT, {
      detail:
        'Proxies in this product are AVAILABILITY-ONLY. Defeating a ban, rate ' +
        'limit, captcha, or login wall is a hard red line. Refused before any fetch.',
      scope,
    });
  }

  // ---- Guard 3: requested group must be a known, allowed group --------------
  const requestedGroup = (safe.proxy_group || 'DATACENTER').toUpperCase();
  if (cfg.denied_groups && Object.prototype.hasOwnProperty.call(cfg.denied_groups, requestedGroup)) {
    return drop(REFUSAL.GROUP_DENIED, {
      detail: cfg.denied_groups[requestedGroup],
      group: requestedGroup,
      scope,
    });
  }
  if (!cfg.allowed_groups || !cfg.allowed_groups[requestedGroup]) {
    return drop(REFUSAL.GROUP_DENIED, {
      detail: `Proxy group ${requestedGroup} is not in the allowed set.`,
      group: requestedGroup,
      scope,
    });
  }

  // ---- Guard 4: RESIDENTIAL is dual-use -> scope + justification gate --------
  if (requestedGroup === 'RESIDENTIAL') {
    const allowedScopes = cfg.scopes_allowed_residential || [];
    if (!allowedScopes.includes(scope)) {
      return drop(REFUSAL.RESIDENTIAL_NOT_ALLOWED_FOR_SCOPE, {
        detail:
          'Residential proxy is a dual-use tier and is restricted to ' +
          `scope=${allowedScopes.join('|')}. scope=${scope} gets datacenter only.`,
        scope,
      });
    }
    const justification = String(safe.geo_justification || '').trim();
    if (justification.length < 4) {
      return drop(REFUSAL.RESIDENTIAL_WITHOUT_JUSTIFICATION, {
        detail:
          'Residential proxy requires a written geo_justification (a real ' +
          'availability reason, e.g. "page renders per-country for my own locale").',
        scope,
      });
    }
  }

  // ---- Guard 5: geo targeting is coarse + allow-listed (k-anonymity stance) -
  if (safe.subdivision_code) {
    return drop(REFUSAL.SUBDIVISION_TARGETING_DISABLED, {
      detail:
        'US-state / subdivision targeting is intentionally disabled. Finer geo ' +
        'serves no availability purpose and edges toward profiling.',
      scope,
    });
  }
  let countryCode = null;
  if (safe.country_code) {
    countryCode = String(safe.country_code).toUpperCase();
    const allowedCountries = (cfg.geo && cfg.geo.allowed_country_codes) || [];
    if (!allowedCountries.includes(countryCode)) {
      return drop(REFUSAL.COUNTRY_NOT_ALLOWED, {
        detail: `country_code ${countryCode} is not in the availability allow-list.`,
        scope,
      });
    }
  }

  // ---- Build: availability-only proxy spec + the fail-closed compliance floor
  const proxySpec = {
    useApifyProxy: true,
    apifyProxyGroups: [requestedGroup],
  };
  if (countryCode) proxySpec.apifyProxyCountry = countryCode;

  return {
    allowed: true,
    scope,
    intent: 'availability_only',
    proxySpec,
    complianceFloor: Object.freeze({ ...cfg.compliance_floor }),
    note:
      'Availability-only proxy authorized. A block status is a COMPLIANCE STOP, ' +
      'not a retry-with-fresh-IP loop.',
  };
}

/** Internal: shape a refusal value. */
function drop(refusal, extra) {
  return Object.assign({ allowed: false, refusal }, extra);
}

/**
 * classifyResponse(status, errorCode) -> { action, reason }
 *
 * The INVERSION of Crawlee's retire-and-rotate. Given the outcome of a fetch:
 *   - a BLOCK status  -> { action: 'compliance_stop' }  (STOP the subject)
 *   - a transport fault with NO block -> { action: 'retry_once' } (at most once)
 *   - anything else (2xx/3xx/4xx-not-block) -> { action: 'proceed' }
 * This is what makes the proxy non-evasive: detection happens (like Crawlee),
 * but the reflex is to stop, never to chase a fresh IP past a defense.
 */
function classifyResponse(status, errorCode, opts = {}) {
  const floor = opts.complianceFloor || {};
  const s = Number(status);
  if (BLOCK_STATUS.includes(s)) {
    return {
      action: 'compliance_stop',
      reason:
        `Status ${s} indicates the resource is refusing this client. ` +
        'Per retire_on_block, this STOPS the subject for human review — we do ' +
        'NOT rotate to a fresh IP to push past it.',
    };
  }
  if (errorCode) {
    const code = String(errorCode);
    const isTransport = TRANSPORT_FAULTS.some((f) => code.includes(f));
    if (isTransport) {
      const maxRetries = Number(floor.max_proxy_retries);
      const allowRetry = Number.isFinite(maxRetries) ? maxRetries >= 1 : true;
      return {
        action: allowRetry ? 'retry_once' : 'compliance_stop',
        reason: allowRetry
          ? `Transport fault (${code}) with no block signal — one retry permitted.`
          : `Transport fault (${code}) but retries are disabled by policy — stop.`,
      };
    }
  }
  return { action: 'proceed', reason: 'No block or transport fault detected.' };
}

/**
 * buildRedactedProxyUrl(proxySpec, opts) -> redactedUrl
 *
 * Constructs the apify proxy URL form WITHOUT the secret password (k-anonymity
 * stance: log/return the minimum — group + country — never the credential).
 * The real password is injected only at fetch time by the client, never logged.
 *   http://groups-DATACENTER,country-US:<redacted>@proxy.apify.com:8000
 */
function buildRedactedProxyUrl(proxySpec, opts = {}) {
  if (!proxySpec || !proxySpec.useApifyProxy) return null;
  const host = opts.hostname || 'proxy.apify.com';
  const port = opts.port || 8000;
  const parts = [];
  const groups = proxySpec.apifyProxyGroups || [];
  if (groups.length) parts.push(`groups-${groups.join('+')}`);
  if (proxySpec.apifyProxyCountry) parts.push(`country-${proxySpec.apifyProxyCountry}`);
  const username = parts.join(',') || 'auto';
  return `http://${username}:<APIFY_PROXY_PASSWORD>@${host}:${port}`;
}

module.exports = {
  loadProxyConfig,
  decideProxy,
  classifyResponse,
  buildRedactedProxyUrl,
  hasEvasionIntent,
  BLOCK_STATUS,
  TRANSPORT_FAULTS,
  EVASION_FLAGS,
  REFUSAL,
};
