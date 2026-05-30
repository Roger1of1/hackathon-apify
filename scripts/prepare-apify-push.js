#!/usr/bin/env node
/**
 * Build an isolated Apify CLI upload context for one MirrorTrace actor.
 *
 * The runtime actors intentionally share the repo-level shared/ modules. Apify
 * CLI uploads one Actor directory at a time, so this helper stages the selected
 * Actor together with shared/ while preserving the monorepo paths expected by
 * its Dockerfile. No credentials are copied.
 */

'use strict';

const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const STAGE_ROOT = process.env.MIRRORTRACE_APIFY_STAGE_DIR || '/private/tmp/mirrortrace-apify-stage';
const ACTORS = new Set([
  'policy-gate',
  'discovery',
  'crawler',
  'diff-evidence',
  'report-builder',
]);

function copyDir(from, to) {
  fs.cpSync(from, to, {
    recursive: true,
    filter(source) {
      const name = path.basename(source);
      return name !== 'node_modules' && name !== '.git' && name !== '.DS_Store';
    },
  });
}

function prepare(name) {
  if (!ACTORS.has(name)) throw new Error('Unknown core actor: ' + name);
  const actorRoot = path.join(ROOT, 'actors', name);
  const stage = path.join(STAGE_ROOT, name);
  fs.rmSync(stage, { recursive: true, force: true });
  fs.mkdirSync(path.join(stage, 'actors'), { recursive: true });
  copyDir(path.join(actorRoot, '.actor'), path.join(stage, '.actor'));
  copyDir(path.join(ROOT, 'shared'), path.join(stage, 'shared'));
  copyDir(actorRoot, path.join(stage, 'actors', name));
  fs.copyFileSync(path.join(actorRoot, 'Dockerfile'), path.join(stage, 'Dockerfile'));
  return stage;
}

const requested = process.argv.slice(2);
const names = requested.length ? requested : Array.from(ACTORS);
names.forEach((name) => console.log(prepare(name)));
