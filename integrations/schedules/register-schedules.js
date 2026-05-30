/**
 * integrations/schedules/register-schedules.js
 *
 * Idempotently register the MirrorTrace re-audit SCHEDULES on Apify via the
 * public API (POST /v2/schedules). REAL code, INERT without credentials: it
 * refuses live calls unless APIFY_TOKEN is set AND every placeholder in
 * schedules.config.json has been replaced with real ids + a non-identifying
 * subject_token. This repo ships NO credentials and makes NO claim of being
 * deployed. (https://docs.apify.com/api/v2/schedules-post)
 *
 * The cron is NOT trusted from the config file: every schedule's cadence is run
 * back through cadence-policy.evaluateCadence() here, so a hand-edited config can
 * never widen the cadence past the anti-compulsion / scope floors. This is the
 * Scrapy "every item re-validated by the pipeline before persistence" pattern —
 * the config is the spider's output; this script is the item pipeline that may
 * still DROP a schedule.
 *
 * Usage:
 *   APIFY_TOKEN=... node integrations/schedules/register-schedules.js
 * Dry run (no token / placeholders present): prints the exact POST body.
 */

'use strict';

const fs = require('fs');
const path = require('path');
const { evaluateCadence, safeScheduleName } = require('./cadence-policy');

const CONFIG_PATH = path.join(__dirname, 'schedules.config.json');
const APIFY_API = process.env.APIFY_API_BASE || 'https://api.apify.com';
const TOKEN = process.env.APIFY_TOKEN || '';

function readJson(p) {
  return JSON.parse(fs.readFileSync(p, 'utf8'));
}

function hasUnfilledPlaceholders(value) {
  return /<[A-Z_]+>/.test(JSON.stringify(value));
}

/**
 * Build the Apify schedule create body for one config entry, or return an
 * object with `.skip`/`.error` so the caller can report instead of throwing.
 * cron is ALWAYS re-derived from policy, never copied from config.
 */
function buildScheduleBody(entry) {
  const verdict = evaluateCadence({
    scope_type: entry.scope_type,
    cadence: entry.cadence,
    distress_risk_score: entry.distress_risk_score,
    anchor: entry.anchor,
  });
  if (!verdict.allowed) {
    return { error: `cadence rejected: ${verdict.reasons.join(' ')}` };
  }

  // k-anonymous name (throws on PII-looking tokens). Placeholder tokens are
  // intentionally left to the dry-run path below.
  let name = entry.name;
  if (!hasUnfilledPlaceholders(entry.subject_token)) {
    name = safeScheduleName(entry.scope_type, entry.subject_token);
  }

  return {
    body: {
      name,
      isEnabled: entry.isEnabled !== false,
      isExclusive: true,
      cronExpression: verdict.cron,
      timezone: 'UTC',
      description: entry.description,
      actions: entry.actions,
    },
    effectiveFloorMinutes: verdict.effectiveFloorMinutes,
    policyReasons: verdict.reasons,
  };
}

async function main() {
  const config = readJson(CONFIG_PATH);
  const dryRun = !TOKEN;
  if (dryRun) {
    console.log('[register-schedules] APIFY_TOKEN not set — DRY RUN. No requests will be sent.');
  }

  for (const entry of config.schedules) {
    const built = buildScheduleBody(entry);
    if (built.error) {
      console.error(`[rejected] ${entry.name}: ${built.error}`);
      continue;
    }
    const { body, effectiveFloorMinutes, policyReasons } = built;

    const placeholders = hasUnfilledPlaceholders(body.actions) ||
      hasUnfilledPlaceholders(entry.subject_token);

    if (dryRun || placeholders) {
      console.log(`\n[would create schedule] ${body.name}`);
      console.log(`  cron: ${body.cronExpression}  (floor ${effectiveFloorMinutes} min)`);
      console.log(`  policy: ${policyReasons.join(' | ')}`);
      console.log(JSON.stringify(body, null, 2));
      if (!dryRun && placeholders) {
        console.warn(`  -> SKIPPED: fill real task id + subject_token for "${entry.name}".`);
      }
      continue;
    }

    const res = await fetch(`${APIFY_API}/v2/schedules?token=${encodeURIComponent(TOKEN)}`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
    });
    const json = await res.json().catch(() => ({}));
    if (res.ok) {
      console.log(`[created] ${body.name} -> schedule id ${json.data && json.data.id}`);
    } else {
      console.error(`[failed] ${body.name}: HTTP ${res.status}`, json);
    }
  }
}

if (require.main === module) {
  main().catch((err) => {
    console.error('[register-schedules] error:', err.message);
    process.exitCode = 1;
  });
}

module.exports = { main, buildScheduleBody };
