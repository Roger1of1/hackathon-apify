#!/usr/bin/env node
/**
 * Machine-readable API readiness audit.
 *
 * It answers one narrow question: "is this repo actually live-wired, or only
 * code-ready with operator credentials/placeholders still pending?" It never
 * calls external APIs and never prints secrets.
 */

'use strict';

const fs = require('fs');
const path = require('path');
const os = require('os');
const { spawnSync } = require('child_process');

const ROOT = path.join(__dirname, '..');

const CORE_ACTOR_ENV = [
  'DISCOVERY_ACTOR_ID',
  'CRAWLER_ACTOR_ID',
  'DIFF_ACTOR_ID',
  'REPORT_ACTOR_ID',
];

const PLACEHOLDER_RE = /YOUR_USERNAME|YOUR_HOST|<[^>]+>/;
const OLD_NAME_RE = new RegExp([
  ['EX', 'DITECTOR'].join('_'),
  '__' + 'EX' + '_REPORT__',
  '__' + 'EX' + '_GRAPH_DEMO__',
  '__' + 'EX' + '_',
].join('|'));

function readIfExists(file) {
  try { return fs.readFileSync(file, 'utf8'); } catch { return ''; }
}

function hasRealValue(env, key) {
  const v = env && typeof env[key] === 'string' ? env[key].trim() : '';
  return !!v && !PLACEHOLDER_RE.test(v);
}

function listFiles(dir, acc = []) {
  let entries;
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return acc; }
  for (const ent of entries) {
    if (ent.name === '.git' || ent.name === 'node_modules') continue;
    const full = path.join(dir, ent.name);
    if (ent.isDirectory()) listFiles(full, acc);
    else if (ent.isFile()) acc.push(full);
  }
  return acc;
}

function grepFiles(root, re) {
  return listFiles(root)
    .filter((file) => /\.(js|json|md|html|css)$/.test(file))
    .flatMap((file) => {
      const rel = path.relative(root, file);
      return re.test(readIfExists(file)) ? [rel] : [];
    });
}

function apifyCliAvailable() {
  const res = spawnSync('apify', ['--version'], { encoding: 'utf8' });
  return {
    ok: res.status === 0,
    version: res.status === 0 ? String(res.stdout || res.stderr).trim() : null,
  };
}

function compareVersion(a, b) {
  const aa = String(a || '').split('.').map((n) => Number(n) || 0);
  const bb = String(b || '').split('.').map((n) => Number(n) || 0);
  for (let i = 0; i < Math.max(aa.length, bb.length); i += 1) {
    const diff = (aa[i] || 0) - (bb[i] || 0);
    if (diff) return diff;
  }
  return 0;
}

function dependencyAuditTail(root) {
  let lock;
  try { lock = JSON.parse(readIfExists(path.join(root, 'package-lock.json'))); } catch { lock = null; }
  const packages = lock && lock.packages;
  const fileType = packages && packages['node_modules/file-type'];
  const crawleeUtils = packages && packages['node_modules/@crawlee/utils'];
  const version = fileType && fileType.version;
  const affected = !!version && compareVersion(version, '13.0.0') >= 0 && compareVersion(version, '21.3.1') <= 0;
  return {
    status: affected ? 'known_upstream_tail' : (version ? 'clear' : 'unverified'),
    file_type_version: version || null,
    via: crawleeUtils ? '@crawlee/playwright -> @crawlee/utils -> file-type' : null,
    advisories: affected ? [
      'GHSA-5v7r-6r5c-r473',
      'GHSA-j47w-4g3g-c36v',
    ] : [],
    note: affected
      ? 'npm audit reports a transitive moderate-risk tail. Do not force a Crawlee downgrade or cross-major file-type override without runtime validation.'
      : 'Inspect with npm audit --omit=dev --json when dependencies change.',
  };
}

function assessApiReadiness(opts = {}) {
  const root = opts.root || ROOT;
  const env = opts.env || process.env;
  const cli = opts.apifyCli || apifyCliAvailable();
  const apifyAuthFile = opts.apifyAuthFile || path.join(os.homedir(), '.apify', 'auth.json');
  const hasApifyCliAuth = fs.existsSync(apifyAuthFile);
  const hasApifyEnvToken = hasRealValue(env, 'APIFY_TOKEN');
  const hasApifyCredentials = hasApifyEnvToken || hasApifyCliAuth;

  const gitConfig = readIfExists(path.join(root, '.git', 'config'));
  const configFiles = [
    'integrations/ingest/ingest.config.json',
    'integrations/standby/chain.config.json',
    'integrations/schedules/schedules.config.json',
    'integrations/webhooks/webhooks.config.json',
    'mcp/client-config.example.json',
  ];
  const placeholderFiles = configFiles.filter((rel) => PLACEHOLDER_RE.test(readIfExists(path.join(root, rel))));
  const actorConfigEnv = opts.actorConfigEnv || [
    'actors/policy-gate/.actor/actor.json',
    'actors/discovery/.actor/actor.json',
    'actors/crawler/.actor/actor.json',
    'actors/diff-evidence/.actor/actor.json',
  ].reduce((acc, rel) => {
    try {
      const actor = JSON.parse(readIfExists(path.join(root, rel)));
      return Object.assign(acc, actor.environmentVariables || {});
    } catch {
      return acc;
    }
  }, {});
  const missingCoreEnv = CORE_ACTOR_ENV.filter((key) => !hasRealValue(env, key) && !hasRealValue(actorConfigEnv, key));
  const oldNameHits = grepFiles(root, OLD_NAME_RE);

  const checks = {
    github_remote: {
      status: /url = https:\/\/github\.com\/Roger1of1\/hackathon-apify\.git/.test(gitConfig) ? 'configured' : 'missing',
      note: 'Remote config exists; push still depends on local GitHub auth.',
    },
    apify_cli: {
      status: cli.ok ? 'installed' : 'missing',
      version: cli.version,
    },
    apify_credentials: {
      status: hasApifyCredentials ? 'present' : 'missing',
      source: hasApifyEnvToken ? 'environment' : (hasApifyCliAuth ? 'cli_auth_file' : null),
      note: 'CLI auth or APIFY_TOKEN is required for actor pushes and live runs. Remote MCP still needs an explicit token handoff.',
    },
    core_metamorph_env: {
      status: missingCoreEnv.length === 0 ? 'ready' : 'missing',
      missing: missingCoreEnv,
      note: 'Must match actors/policy-gate/discovery/crawler/diff-evidence env names.',
    },
    deploy_placeholders: {
      status: placeholderFiles.length === 0 ? 'clear' : 'present',
      files: placeholderFiles,
      note: 'Templates are valid docs, but live deployment still requires replacing them.',
    },
    oauth: {
      status: hasRealValue(env, 'GOOGLE_OAUTH_CLIENT_ID') && hasRealValue(env, 'GITHUB_OAUTH_CLIENT_ID')
        ? 'client_ids_present'
        : 'not_wired',
      note: 'Code intentionally does not fabricate sign-in; PKCE/token exchange remains operator wiring.',
    },
    mcp: {
      status: hasRealValue(env, 'APIFY_TOKEN') && placeholderFiles.indexOf('mcp/client-config.example.json') === -1
        ? 'remote_config_ready'
        : 'template_only',
      note: 'mcp/server.js is a tested local registry/dispatcher; live transport is not bundled.',
    },
    old_branding_globals: {
      status: oldNameHits.length === 0 ? 'clear' : 'present',
      files: oldNameHits,
    },
    dependency_audit: dependencyAuditTail(root),
  };

  const liveReady = checks.apify_cli.status === 'installed'
    && checks.apify_credentials.status === 'present'
    && checks.core_metamorph_env.status === 'ready'
    && checks.deploy_placeholders.status === 'clear'
    && checks.oauth.status === 'client_ids_present';

  const remainingNonUi = [];
  if (checks.apify_cli.status !== 'installed') remainingNonUi.push('Install Apify CLI.');
  if (checks.apify_credentials.status !== 'present') remainingNonUi.push('Login Apify CLI or set APIFY_TOKEN.');
  if (checks.deploy_placeholders.status !== 'clear') remainingNonUi.push('Replace remaining task/webhook ids and operator endpoints.');
  if (checks.core_metamorph_env.status !== 'ready') remainingNonUi.push('Set DISCOVERY_ACTOR_ID / CRAWLER_ACTOR_ID / DIFF_ACTOR_ID / REPORT_ACTOR_ID.');
  if (checks.oauth.status !== 'client_ids_present') remainingNonUi.push('Wire Google/GitHub OAuth PKCE client ids/token exchange for sensitive graph actions.');
  if (checks.mcp.status !== 'remote_config_ready') remainingNonUi.push('Configure remote Apify MCP whitelist with real actor names and token.');

  return {
    generated_at: new Date().toISOString(),
    overall: liveReady ? 'live_ready' : (hasApifyCredentials && missingCoreEnv.length === 0 ? 'operator_setup_pending' : 'code_ready_credentials_pending'),
    checks,
    known_dependency_tails: checks.dependency_audit.status === 'known_upstream_tail'
      ? [checks.dependency_audit]
      : [],
    remaining_non_ui_to_go_live: liveReady ? [] : remainingNonUi,
  };
}

if (require.main === module) {
  process.stdout.write(JSON.stringify(assessApiReadiness(), null, 2) + '\n');
}

module.exports = {
  assessApiReadiness,
  hasRealValue,
  compareVersion,
  dependencyAuditTail,
};
