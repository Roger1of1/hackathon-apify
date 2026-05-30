#!/usr/bin/env node
/**
 * Locks the English-only web surface. Multilingual policy-gate patterns remain
 * supported in web/app.js through Unicode escapes, so visible web source and
 * rendered copy stay English without weakening refusal coverage.
 */

'use strict';

const fs = require('fs');
const path = require('path');
const assert = require('assert');

const WEB = path.join(__dirname, '..', '..', 'web');
const TEXT_EXTENSIONS = new Set(['.html', '.js', '.json', '.css', '.md', '.txt']);
const failures = [];

function walk(dir) {
  for (const ent of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, ent.name);
    if (ent.isDirectory()) {
      walk(full);
      continue;
    }
    if (!TEXT_EXTENSIONS.has(path.extname(ent.name))) continue;
    const text = fs.readFileSync(full, 'utf8');
    const lines = text.split(/\r?\n/);
    lines.forEach((line, index) => {
      if (/\p{Script=Han}/u.test(line)) {
        failures.push(path.relative(WEB, full) + ':' + (index + 1) + ': ' + line);
      }
    });
  }
}

walk(WEB);
assert.deepStrictEqual(failures, [], 'web/ must remain English-only:\n' + failures.join('\n'));
console.log('\nweb English-only self-test: OK (no Han characters in web/)');
