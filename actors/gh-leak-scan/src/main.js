/**
 * AUX — Public GitHub Leak Scan
 *
 * An auxiliary actor that orbits the core MirrorTrace pipeline. It answers ONE
 * compliant question about the SELF subject: "did I accidentally commit a secret
 * to one of my OWN public GitHub repos / gists?" — exactly what a self-footprint
 * audit should surface so the user can rotate the leaked credential.
 *
 * ───────────────────────── COMPLIANCE BOUNDARY ─────────────────────────
 * 1. Scope gate: every run is routed through shared/scope.js validateScope and
 *    additionally restricted to scope_type ∈ {self, public_figure}. Account /
 *    repository enumeration is a DUAL-USE technique; per the product rules it is
 *    allowed ONLY for these scopes. consented/brand/safety_evidence are refused.
 * 2. PUBLIC data only: we call GitHub's documented public REST API and fetch
 *    public raw file content. We NEVER bypass authentication, captcha, or rate
 *    limits. A GITHUB_TOKEN, if present, is used purely to RAISE the subject's
 *    own rate limit — never to reach anything non-public.
 * 3. NO FAKE DATA: every emitted event is built from an artifact actually
 *    fetched. If a request fails or returns nothing, we emit nothing — we never
 *    fabricate a repo, a handle, or a leak. Secrets are redacted to a
 *    fingerprint + masked hint by the shared detector before any event exists.
 * 4. No identity/romance/gender/intimacy inference. A leaked key is a
 *    security-hygiene fact about the subject's OWN credential.
 * ─────────────────────────────────────────────────────────────────────────
 *
 * REFERENCE PATTERNS APPLIED:
 *  - SpiderFoot OSINT-module + correlation-engine design: every result is a
 *    TYPED module_event (event_type/source_module/data/confidence/source_url)
 *    carrying handle/host/secret-fingerprint co-occurrence keys, so
 *    shared/correlation.js can link a GitHub-committed leak to the SAME key
 *    found by the crawler/secret detector elsewhere — clustering by surface &
 *    artifact, never by person. (github.com/smicallef/spiderfoot)
 *  - GitHub secret scanning / TruffleHog / gitleaks: "scan public repos & gists
 *    for committed credentials", reframed as a SELF-audit. We REUSE the shared
 *    secret detector instead of reimplementing patterns.
 *    (docs.github.com secret-scanning, github.com/trufflesecurity/trufflehog)
 *  - Apify Website Content Crawler / RAG Web Browser pattern: bounded, polite
 *    crawl (max_repos / max_files_per_repo caps, backoff on 403/429), each
 *    fetched artifact pushed to the dataset as a typed record.
 */

'use strict';

const { Actor, log } = require('apify');
const { gotScraping } = require('got-scraping');

const { validateScope, ALLOWED_SCOPES } = require('../../../shared/scope.js');
const {
  makeUsernameEvent,
  makeRepoSurfaceEvent,
  scanFileForSecrets,
  makeSummaryEvent,
} = require('../../../shared/aux/github-leak-finding.js');

// Dual-use account scanning: ONLY self + public_figure (subset of ALLOWED_SCOPES).
const GH_SCOPES = new Set(['self', 'public_figure']);

const GH_API = 'https://api.github.com';
const USER_AGENT = 'mirrortrace-self-footprint-audit';

// Only inspect small, text-like files whose name/extension suggests config or
// source that commonly carries committed secrets. Keeps the scan precise & cheap.
const CANDIDATE_FILE_RE = /(^|\/)(\.env(\.[\w.-]+)?|.*\.(env|ya?ml|json|js|ts|py|rb|sh|cfg|conf|ini|properties|tf|tfvars|pem|key|txt|md|xml|toml))$/i;
const MAX_FILE_BYTES = 200 * 1024; // skip large blobs; secrets in config are tiny

/** Build request headers; include the token ONLY to lift the own rate limit. */
function ghHeaders() {
  const headers = {
    'User-Agent': USER_AGENT,
    Accept: 'application/vnd.github+json',
    'X-GitHub-Api-Version': '2022-11-28',
  };
  const token = process.env.GITHUB_TOKEN;
  if (token) headers.Authorization = `Bearer ${token}`;
  return headers;
}

/** A single GitHub API GET. Returns { ok, status, body } and never throws. */
async function ghGet(url, { responseType = 'json' } = {}) {
  try {
    const res = await gotScraping({
      url,
      method: 'GET',
      headers: ghHeaders(),
      responseType,
      throwHttpErrors: false,
      timeout: { request: 20000 },
      retry: { limit: 1 },
    });
    return { ok: res.statusCode >= 200 && res.statusCode < 300, status: res.statusCode, body: res.body };
  } catch (err) {
    log.warning(`GitHub request failed for ${url}: ${err.message}`);
    return { ok: false, status: 0, body: null };
  }
}

/** True for a 403/429 that signals rate limiting (back off, never evade). */
function isRateLimited(status, body) {
  if (status === 429) return true;
  if (status === 403) {
    // Secondary/primary rate-limit responses use 403 with a documented body.
    const msg = body && typeof body === 'object' && typeof body.message === 'string' ? body.message : '';
    return /rate limit/i.test(msg);
  }
  return false;
}

Actor.main(async () => {
  const input = (await Actor.getInput()) || {};
  const scopeType = typeof input.scope_type === 'string' ? input.scope_type.trim() : '';
  const handle = typeof input.github_handle === 'string'
    ? input.github_handle.trim().replace(/^@+/, '')
    : '';

  // ── Gate 1: canonical scope gate (same chokepoint the whole product uses). ──
  // This actor's "target" is the subject's own GitHub profile; we feed that real
  // public URL so the gate's target/host checks and its free-text laundering
  // scan (over subject_label) all run against a real value.
  const profileUrl = handle ? `https://github.com/${encodeURIComponent(handle)}` : 'https://github.com/';
  const gateDecision = validateScope({
    scope_type: scopeType,
    target_urls: [profileUrl],
    subject_label: input.subject_label,
    description: input.subject_label,
  });

  if (!gateDecision.allowed) {
    log.error('GitHub leak-scan refused by scope gate.', {
      reasons: gateDecision.reasons,
      violated: gateDecision.violated_red_lines,
    });
    await Actor.pushData({
      record_type: 'gh_leak_event',
      event_type: 'REFUSED',
      source_module: 'aux:gh-leak-scan',
      confidence: 1,
      data: {
        reasons: gateDecision.reasons,
        violated_red_lines: gateDecision.violated_red_lines,
        alternatives: gateDecision.alternatives,
      },
    });
    await Actor.fail('GitHub leak-scan rejected by compliance gate.');
    return;
  }

  // ── Gate 2: dual-use restriction. Even other legal scopes cannot run account
  // enumeration; only self/public_figure. ──
  if (!ALLOWED_SCOPES.includes(scopeType) || !GH_SCOPES.has(scopeType)) {
    log.error('GitHub leak-scan refused: account scanning is restricted to self/public_figure.', {
      scope_type: scopeType,
    });
    await Actor.fail('GitHub account scanning is allowed only for scope_type=self or public_figure.');
    return;
  }

  if (!handle) {
    await Actor.fail('A github_handle is required.');
    return;
  }

  // Pull the shared case id if a case store exists (best-effort, standalone OK).
  const caseStoreName = input.case_store_name || 'mirrortrace-case';
  let caseId = input.case_id || null;
  try {
    const caseStore = await Actor.openKeyValueStore(caseStoreName);
    const caseRecord = await caseStore.getValue('CASE');
    if (caseRecord && caseRecord.case_id) caseId = caseRecord.case_id;
  } catch (err) {
    log.debug(`No case store available (${err.message}); running standalone.`);
  }
  if (!caseId) caseId = 'standalone_gh_leak_scan';

  const maxRepos = clampInt(input.max_repos, 1, 100, 10);
  const maxFilesPerRepo = clampInt(input.max_files_per_repo, 1, 200, 25);
  const includeGists = input.include_gists !== false;

  const counts = { repos_scanned: 0, files_scanned: 0, secrets_found: 0 };

  // Attach case_id to every event and push it to the dataset.
  const emit = async (event) => {
    const record = Object.assign({ case_id: caseId, record_type: 'gh_leak_event' }, event);
    await Actor.pushData(record);
    return record;
  };

  // ── Step 0: confirm the public profile actually exists (real, not assumed). ──
  const userRes = await ghGet(`${GH_API}/users/${encodeURIComponent(handle)}`);
  if (isRateLimited(userRes.status, userRes.body)) {
    log.warning('GitHub rate limited at profile lookup; backing off (set GITHUB_TOKEN to raise your own limit).');
    await emit({ event_type: 'BACKOFF', source_module: 'aux:gh-leak-scan', confidence: 1, data: { status: userRes.status } });
    return;
  }
  if (userRes.status === 404) {
    log.info(`No public GitHub account "${handle}" — nothing to audit. (No event fabricated.)`);
    await Actor.setValue('GH_LEAK_SUMMARY', summaryRecord(caseId, scopeType, input, handle, counts, 'no_such_public_account'));
    return;
  }
  if (!userRes.ok) {
    log.warning(`Profile lookup returned ${userRes.status}; aborting without fabricating data.`);
    await Actor.setValue('GH_LEAK_SUMMARY', summaryRecord(caseId, scopeType, input, handle, counts, `profile_lookup_${userRes.status}`));
    return;
  }

  await emit(makeUsernameEvent({ handle, profileUrl }));
  log.info(`Auditing public GitHub footprint for @${handle}.`);

  // ── Step 1: enumerate the account's PUBLIC repos (most-recently-pushed). ──
  const repos = [];
  const reposRes = await ghGet(
    `${GH_API}/users/${encodeURIComponent(handle)}/repos?per_page=${maxRepos}&sort=pushed&type=owner`,
  );
  if (isRateLimited(reposRes.status, reposRes.body)) {
    log.warning('GitHub rate limited listing repos; backing off.');
  } else if (reposRes.ok && Array.isArray(reposRes.body)) {
    for (const r of reposRes.body) {
      if (r && r.fork) continue; // forks aren't the subject's own published code
      if (r && r.private) continue; // defensive: never touch a private repo
      repos.push(r);
      if (repos.length >= maxRepos) break;
    }
  }

  for (const repo of repos) {
    counts.repos_scanned += 1;
    await emit(makeRepoSurfaceEvent({
      handle,
      repoUrl: repo.html_url,
      name: repo.full_name,
      kind: 'repo',
    }));

    const branch = repo.default_branch || 'main';
    const treeRes = await ghGet(
      `${GH_API}/repos/${encodeURIComponent(handle)}/${encodeURIComponent(repo.name)}/git/trees/${encodeURIComponent(branch)}?recursive=1`,
    );
    if (isRateLimited(treeRes.status, treeRes.body)) {
      log.warning('GitHub rate limited reading a repo tree; backing off for this run.');
      break;
    }
    if (!treeRes.ok || !treeRes.body || !Array.isArray(treeRes.body.tree)) continue;

    let filesThisRepo = 0;
    for (const node of treeRes.body.tree) {
      if (filesThisRepo >= maxFilesPerRepo) break;
      if (!node || node.type !== 'blob' || typeof node.path !== 'string') continue;
      if (!CANDIDATE_FILE_RE.test(node.path)) continue;
      if (Number.isFinite(node.size) && node.size > MAX_FILE_BYTES) continue;

      const rawUrl = `https://raw.githubusercontent.com/${encodeURIComponent(handle)}/${encodeURIComponent(repo.name)}/${encodeURIComponent(branch)}/${node.path.split('/').map(encodeURIComponent).join('/')}`;
      const fileRes = await ghGet(rawUrl, { responseType: 'text' });
      if (isRateLimited(fileRes.status, fileRes.body)) { log.warning('Rate limited fetching a file; stopping.'); break; }
      if (!fileRes.ok || typeof fileRes.body !== 'string') continue;

      filesThisRepo += 1;
      counts.files_scanned += 1;

      const fileUrl = `${repo.html_url}/blob/${branch}/${node.path}`;
      const secretEvents = scanFileForSecrets({
        text: fileRes.body,
        fileUrl,
        handle,
        repoName: repo.full_name,
      });
      for (const ev of secretEvents) {
        counts.secrets_found += 1;
        await emit(ev);
        log.info(`Self-committed secret found in ${repo.full_name}/${node.path} (${ev.meta && ev.meta.vendor}). Value redacted.`);
      }
    }
  }

  // ── Step 2: PUBLIC gists (optional). ──
  if (includeGists) {
    const gistsRes = await ghGet(`${GH_API}/users/${encodeURIComponent(handle)}/gists?per_page=30`);
    if (isRateLimited(gistsRes.status, gistsRes.body)) {
      log.warning('GitHub rate limited listing gists; skipping gists.');
    } else if (gistsRes.ok && Array.isArray(gistsRes.body)) {
      for (const gist of gistsRes.body) {
        if (!gist || gist.public === false) continue; // public gists only
        await emit(makeRepoSurfaceEvent({ handle, repoUrl: gist.html_url, name: gist.id, kind: 'gist' }));
        const files = gist.files && typeof gist.files === 'object' ? Object.values(gist.files) : [];
        for (const f of files) {
          if (!f || typeof f.filename !== 'string' || typeof f.raw_url !== 'string') continue;
          if (!CANDIDATE_FILE_RE.test(f.filename)) continue;
          if (Number.isFinite(f.size) && f.size > MAX_FILE_BYTES) continue;
          const fileRes = await ghGet(f.raw_url, { responseType: 'text' });
          if (isRateLimited(fileRes.status, fileRes.body)) { log.warning('Rate limited on a gist file; stopping gists.'); break; }
          if (!fileRes.ok || typeof fileRes.body !== 'string') continue;
          counts.files_scanned += 1;
          const secretEvents = scanFileForSecrets({
            text: fileRes.body,
            fileUrl: gist.html_url,
            handle,
            repoName: `gist:${gist.id}`,
          });
          for (const ev of secretEvents) {
            counts.secrets_found += 1;
            await emit(ev);
            log.info(`Self-committed secret found in gist ${gist.id}/${f.filename}. Value redacted.`);
          }
        }
      }
    }
  }

  // ── Step 3: a real summary event + a Blacklight-style self-exposure record. ──
  await emit(makeSummaryEvent({ handle, counts }));
  await Actor.setValue('GH_LEAK_SUMMARY', summaryRecord(caseId, scopeType, input, handle, counts, 'completed'));

  log.info('GitHub leak-scan complete.', counts);
});

function clampInt(v, min, max, fallback) {
  const n = Number(v);
  if (!Number.isFinite(n)) return fallback;
  return Math.max(min, Math.min(max, Math.round(n)));
}

function summaryRecord(caseId, scopeType, input, handle, counts, status) {
  return {
    record_type: 'gh_leak_summary',
    source_module: 'aux:gh-leak-scan',
    case_id: caseId,
    scope_type: scopeType,
    subject_label: typeof input.subject_label === 'string' ? input.subject_label : '',
    github_handle: handle,
    status,
    counts,
    generated_at: new Date().toISOString(),
    privacy_note: 'Only PUBLIC GitHub data was read via the documented REST API. Any secret found is redacted to a fingerprint + masked hint; the plaintext credential is never stored or transmitted by this actor.',
  };
}
