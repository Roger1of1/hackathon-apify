/**
 * integrations/webhooks/register-webhooks.js
 *
 * Idempotently register the MirrorTrace webhooks on Apify via the public API
 * (POST /v2/webhooks). This is REAL code, but it is INERT without credentials:
 * it refuses to run unless APIFY_TOKEN is set and the placeholder ids in
 * webhooks.config.json have been replaced with your real actor/task ids. This
 * repo ships NO credentials and makes NO claim of being deployed.
 *
 * Idempotency: Apify webhook-create accepts an `idempotencyKey`; we derive a
 * stable key per webhook name so re-running this script updates rather than
 * duplicates. (https://docs.apify.com/api/v2/webhooks-post)
 *
 * Usage:
 *   APIFY_TOKEN=... WEBHOOK_RECEIVER_URL=https://your-host/apify-webhook/SECRET \
 *     node integrations/webhooks/register-webhooks.js
 *
 * Dry run (no token / placeholders present): prints what it WOULD send.
 */

'use strict';

const fs = require('fs');
const path = require('path');

const CONFIG_PATH = path.join(__dirname, 'webhooks.config.json');
const TEMPLATE_PATH = path.join(__dirname, 'payload-template.json');
const APIFY_API = process.env.APIFY_API_BASE || 'https://api.apify.com';
const TOKEN = process.env.APIFY_TOKEN || '';
const RECEIVER_URL = process.env.WEBHOOK_RECEIVER_URL || '';

function readJson(p) {
  return JSON.parse(fs.readFileSync(p, 'utf8'));
}

function hasUnfilledPlaceholders(value) {
  return /<[A-Z_]+>|YOUR_HOST/.test(JSON.stringify(value));
}

async function main() {
  const config = readJson(CONFIG_PATH);
  const template = readJson(TEMPLATE_PATH);
  const payloadTemplateString = JSON.stringify(template);

  const dryRun = !TOKEN;
  if (dryRun) {
    console.log('[register-webhooks] APIFY_TOKEN not set — DRY RUN. No requests will be sent.');
  }

  for (const wh of config.webhooks) {
    const requestUrl = RECEIVER_URL || wh.requestUrl;
    const body = {
      isAdHoc: false,
      eventTypes: wh.eventTypes,
      condition: wh.condition,
      requestUrl,
      payloadTemplate: payloadTemplateString,
      shouldInterpolateStrings: true,
      idempotencyKey: `mirrortrace-${wh.name}`,
      description: wh.description,
    };

    if (dryRun || hasUnfilledPlaceholders(body.condition) || hasUnfilledPlaceholders(requestUrl)) {
      console.log(`\n[would register] ${wh.name}`);
      console.log(JSON.stringify(body, null, 2));
      if (!dryRun) {
        console.warn(`  -> SKIPPED: fill placeholders for "${wh.name}" (real actor id + receiver URL) before live registration.`);
      }
      continue;
    }

    const res = await fetch(`${APIFY_API}/v2/webhooks?token=${encodeURIComponent(TOKEN)}`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
    });
    const json = await res.json().catch(() => ({}));
    if (res.ok) {
      console.log(`[registered] ${wh.name} -> webhook id ${json.data && json.data.id}`);
    } else {
      console.error(`[failed] ${wh.name}: HTTP ${res.status}`, json);
    }
  }
}

if (require.main === module) {
  main().catch((err) => {
    console.error('[register-webhooks] error:', err.message);
    process.exitCode = 1;
  });
}

module.exports = { main };
