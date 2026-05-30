/**
 * integrations/proxy/proxy-client.js
 *
 * Thin, dry-run-safe wrapper that turns a proxy DECISION (from proxy-policy.js)
 * into the concrete artifact an actor would use:
 *   - on the Apify platform (APIFY_PROXY_PASSWORD set): the full proxy URL with
 *     the real credential, built ONLY in memory and handed to the fetch layer;
 *   - off-platform / no credential: a DRY RUN that returns the REDACTED url it
 *     WOULD build, performs no network call, and asserts no proxy was used.
 *
 * NO-FAKE-DATA: this client never claims a fetch happened, never invents a
 * response, and never logs the password. If there is no credential, it says so.
 *
 * Reference architectures it honors (see proxy-policy.js header for the full
 * citations): Crawlee/Scrapy proxy+session management (sessionId-stable URLs,
 * block detection) used for AVAILABILITY not evasion; HIBP k-anonymity stance
 * (carry the minimum — redacted, coarse-geo — never the secret).
 */

'use strict';

const { decideProxy, buildRedactedProxyUrl, classifyResponse } = require('./proxy-policy.js');

/**
 * prepareProxy(input, opts) -> result
 *
 * Runs the policy, then prepares the proxy artifact. Pure decision + env read;
 * NO network. The caller (an Apify actor's fetch loop) is responsible for the
 * actual request and for honoring `complianceFloor` (robots, rate-limit headers,
 * retire_on_block via classifyResponse).
 */
function prepareProxy(input, opts = {}) {
  const env = opts.env || process.env;
  const decision = decideProxy(input, opts);

  if (!decision.allowed) {
    return {
      ok: false,
      mode: 'refused',
      refusal: decision.refusal,
      detail: decision.detail,
      scope_reasons: decision.scope_reasons,
      // A refusal NEVER yields a usable proxy, dry-run or otherwise.
      proxyUrl: null,
      usedNetwork: false,
    };
  }

  const password = env.APIFY_PROXY_PASSWORD;
  const hostname = env.APIFY_PROXY_HOSTNAME || 'proxy.apify.com';
  const port = Number(env.APIFY_PROXY_PORT) || 8000;
  const redactedUrl = buildRedactedProxyUrl(decision.proxySpec, { hostname, port });

  if (!password) {
    return {
      ok: true,
      mode: 'dry_run',
      detail:
        'APIFY_PROXY_PASSWORD is not set — DRY RUN. No proxy URL was built with a ' +
        'credential, no network call was made. This is the request that WOULD be sent.',
      proxySpec: decision.proxySpec,
      redactedProxyUrl: redactedUrl,
      complianceFloor: decision.complianceFloor,
      usedNetwork: false,
    };
  }

  // Live (on-platform): build the real URL in memory only. We still never log it.
  const parts = [];
  const groups = decision.proxySpec.apifyProxyGroups || [];
  if (groups.length) parts.push(`groups-${groups.join('+')}`);
  if (decision.proxySpec.apifyProxyCountry) {
    parts.push(`country-${decision.proxySpec.apifyProxyCountry}`);
  }
  const username = parts.join(',') || 'auto';
  const liveUrl = `http://${username}:${password}@${hostname}:${port}`;

  return {
    ok: true,
    mode: 'live',
    detail:
      'Credential present — live proxy URL built in memory. The fetch layer must ' +
      'honor complianceFloor (robots, rate-limit headers, retire_on_block).',
    proxySpec: decision.proxySpec,
    // The redacted form is what may be logged; liveUrl is for the fetch layer only.
    redactedProxyUrl: redactedUrl,
    proxyUrl: liveUrl,
    complianceFloor: decision.complianceFloor,
    classifyResponse: (status, errorCode) =>
      classifyResponse(status, errorCode, { complianceFloor: decision.complianceFloor }),
    usedNetwork: false, // prepareProxy itself never fetches; the actor does.
  };
}

module.exports = { prepareProxy };
