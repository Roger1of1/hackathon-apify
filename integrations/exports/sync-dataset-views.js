/**
 * integrations/exports/sync-dataset-views.js
 *
 * Compute the merge of integrations/exports/dataset-views.config.json into each
 * target actor's .actor/actor.json `storages.dataset.views` block, which is the
 * Apify-native way to declare dataset views (transformation + display) that the
 * Console output tab renders and the API honours
 * (https://docs.apify.com/platform/actors/development/actor-definition/dataset-schema,
 *  https://docs.apify.com/platform/actors/development/actor-definition/actor-json).
 *
 * DRY RUN BY DEFAULT. This script PRINTS the merged actor.json for review and
 * does NOT write unless --write is passed. Even then it only writes the actor's
 * OWN .actor/actor.json (those files live outside my subtree, so the default is
 * to print a patch the actor-owner can apply, never to silently edit). It makes
 * NO API call and asserts NO deployment.
 *
 * Reference architectures (assigned):
 *   - OpenCTI/MISP+STIX: each view is bound to a marking-definition; syncing the
 *     views is like provisioning the per-marking TAXII collections up front so
 *     consumers can only ever pull the projection their marking allows.
 *   - Apify RAG Web Browser / Website Content Crawler: the views encode the same
 *     "publish a thin typed projection, not the raw record" contract those
 *     actors use for their RAG output.
 *
 * Usage:
 *   node integrations/exports/sync-dataset-views.js           # print merged views for every actor
 *   node integrations/exports/sync-dataset-views.js --write   # also write each .actor/actor.json (owner action)
 */

'use strict';

const fs = require('fs');
const path = require('path');

const REPO_ROOT = path.resolve(__dirname, '..', '..');
const CONFIG_PATH = path.join(__dirname, 'dataset-views.config.json');

function readJson(p) {
  return JSON.parse(fs.readFileSync(p, 'utf8'));
}

/**
 * Turn the config's array of views into the Apify `views` OBJECT keyed by view
 * name. Strips our compliance-only metadata (marking/audience) from what Apify
 * sees, keeping only the apify_view payload Apify understands.
 */
function buildViewsObject(views) {
  const out = {};
  for (const v of views) {
    if (!v || !v.name || !v.apify_view) continue;
    out[v.name] = v.apify_view;
  }
  return out;
}

/**
 * Compute the merged actor.json for one dataset config entry. Returns
 * { actorJsonPath, merged, error? }. Never mutates on disk.
 */
function computeMerge(entry) {
  const actorDir = path.join(REPO_ROOT, entry.actor, '.actor');
  const actorJsonPath = path.join(actorDir, 'actor.json');
  if (!fs.existsSync(actorJsonPath)) {
    return { actorJsonPath, error: `actor.json not found at ${actorJsonPath}` };
  }
  let actorJson;
  try {
    actorJson = readJson(actorJsonPath);
  } catch (e) {
    return { actorJsonPath, error: `could not parse actor.json: ${e.message}` };
  }
  const merged = JSON.parse(JSON.stringify(actorJson));
  merged.storages = merged.storages || {};
  merged.storages.dataset = merged.storages.dataset || { actorSpecification: 1, title: entry.title || 'Dataset' };
  merged.storages.dataset.views = Object.assign(
    {},
    merged.storages.dataset.views || {},
    buildViewsObject(entry.views || []),
  );
  return { actorJsonPath, merged };
}

function run({ write = false } = {}) {
  const config = readJson(CONFIG_PATH);
  const results = [];
  for (const entry of config.datasets || []) {
    const r = computeMerge(entry);
    results.push({ actor: entry.actor, ...r });
    if (r.error) {
      process.stderr.write(`SKIP ${entry.actor}: ${r.error}\n`);
      continue;
    }
    process.stdout.write(`\n=== ${entry.actor} -> ${path.relative(REPO_ROOT, r.actorJsonPath)} ===\n`);
    process.stdout.write(JSON.stringify(r.merged.storages.dataset.views, null, 2) + '\n');
    if (write) {
      fs.writeFileSync(r.actorJsonPath, JSON.stringify(r.merged, null, 2) + '\n');
      process.stdout.write(`WROTE ${r.actorJsonPath}\n`);
    }
  }
  if (!write) {
    process.stdout.write('\nDRY RUN. Re-run with --write to apply these views to each actor.json (actor-owner action).\n');
  }
  return results;
}

if (require.main === module) {
  const write = process.argv.includes('--write');
  run({ write });
}

module.exports = { buildViewsObject, computeMerge, run };
