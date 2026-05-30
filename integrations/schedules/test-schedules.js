/**
 * integrations/schedules/test-schedules.js
 *
 * Self-contained, zero-dependency tests for the Schedules cadence policy and the
 * (dry-run) registration body builder. Lives in integrations/ (my subtree) — NOT
 * in test/ (Codex owns that). Run: `node integrations/schedules/test-schedules.js`.
 *
 * Core properties asserted:
 *  - scope gate fails closed (consented/brand/safety_evidence cannot be scheduled)
 *  - there is NO high-frequency option, and higher distress => SLOWER cadence
 *  - cron is always re-derived from policy, never trusted from config
 *  - schedule names are k-anonymous (HIBP stance): no emails/handles/names
 */

'use strict';

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const {
  evaluateCadence,
  safeScheduleName,
  distressFloorMinutes,
  SCHEDULABLE_SCOPES,
} = require('./cadence-policy.js');
const { buildScheduleBody } = require('./register-schedules.js');

let pass = 0;
let fail = 0;
function check(name, fn) {
  try {
    fn();
    pass += 1;
    console.log(`  PASS  ${name}`);
  } catch (err) {
    fail += 1;
    console.log(`  FAIL  ${name}: ${err.message}`);
  }
}

console.log('\n[1] scope gate fails closed (recurring monitoring is dual-use)');

for (const bad of ['consented', 'brand', 'safety_evidence', '', 'ex', undefined]) {
  check(`scope_type="${bad}" -> not schedulable`, () => {
    const v = evaluateCadence({ scope_type: bad, cadence: 'weekly' });
    assert.strictEqual(v.allowed, false);
    assert.ok(v.reasons.join(' ').toLowerCase().includes('schedul'));
  });
}

for (const good of SCHEDULABLE_SCOPES) {
  check(`scope_type="${good}" with a valid cadence -> allowed`, () => {
    const v = evaluateCadence({ scope_type: good, cadence: 'weekly' });
    assert.strictEqual(v.allowed, true);
    assert.match(v.cron, /^\d+ \d+ \* \* (\*|\d)$/);
  });
}

console.log('\n[2] no high-frequency option; unknown cadence is rejected');

for (const bad of ['hourly', 'minutely', 'every5min', 'realtime', '', 'compulsive']) {
  check(`cadence="${bad}" -> rejected`, () => {
    const v = evaluateCadence({ scope_type: 'self', cadence: bad });
    assert.strictEqual(v.allowed, false);
  });
}

console.log('\n[3] anti-compulsion: higher distress => SLOWER (never faster)');

check('distress floor is monotonic non-decreasing in distress', () => {
  const low = distressFloorMinutes(0.1);
  const mid = distressFloorMinutes(0.4);
  const high = distressFloorMinutes(0.9);
  assert.ok(low <= mid && mid <= high, `${low} <= ${mid} <= ${high}`);
  assert.ok(high > low, 'high distress must be strictly slower than low');
});

check('requesting daily under high distress is slowed to >= weekly', () => {
  const v = evaluateCadence({ scope_type: 'self', cadence: 'daily', distress_risk_score: 0.9 });
  assert.strictEqual(v.allowed, true);
  assert.ok(v.effectiveFloorMinutes >= 7 * 24 * 60, `floor was ${v.effectiveFloorMinutes}`);
  assert.ok(v.reasons.join(' ').toLowerCase().includes('anti-compulsion'));
});

check('unknown distress score is treated cautiously (>= daily floor)', () => {
  const v = evaluateCadence({ scope_type: 'self', cadence: 'daily', distress_risk_score: 'NaN' });
  assert.ok(v.effectiveFloorMinutes >= 24 * 60);
});

console.log('\n[4] k-anonymous naming (HIBP stance): no PII in schedule names');

check('short hash-prefix token -> accepted name', () => {
  const n = safeScheduleName('self', '5BAA6');
  assert.strictEqual(n, 'mirrortrace-reaudit-self-5baa6');
});

for (const pii of ['alice@example.com', 'verylonghandlename1234', 'a b', '']) {
  check(`PII-looking token "${pii}" -> rejected`, () => {
    assert.throws(() => safeScheduleName('self', pii));
  });
}

check('non-schedulable scope cannot be named', () => {
  assert.throws(() => safeScheduleName('brand', 'abcde'));
});

console.log('\n[5] register: cron is re-derived from policy, config drops on bad cadence');

check('buildScheduleBody rejects a config entry with a forbidden scope', () => {
  const r = buildScheduleBody({ scope_type: 'brand', cadence: 'daily', actions: [] });
  assert.ok(r.error, 'expected an error verdict');
});

check('buildScheduleBody emits a deterministic weekly cron for cadence=closure', () => {
  const r = buildScheduleBody({
    scope_type: 'self',
    cadence: 'closure',
    subject_token: '5baa6',
    anchor: { anchorWeekday: 1, anchorHourUtc: 9, anchorMinuteUtc: 0 },
    actions: [{ type: 'RUN_ACTOR_TASK', actorTaskId: 'task123' }],
  });
  assert.ok(r.body, 'expected a body');
  assert.strictEqual(r.body.cronExpression, '0 9 * * 1');
  assert.strictEqual(r.body.name, 'mirrortrace-reaudit-self-5baa6');
});

console.log('\n[6] shipped config is a TEMPLATE (placeholders, never live)');

check('schedules.config.json contains only schedulable scopes + placeholders', () => {
  const cfg = JSON.parse(
    fs.readFileSync(path.join(__dirname, 'schedules.config.json'), 'utf8'),
  );
  assert.ok(Array.isArray(cfg.schedules) && cfg.schedules.length > 0);
  for (const s of cfg.schedules) {
    assert.ok(SCHEDULABLE_SCOPES.includes(s.scope_type), `bad scope ${s.scope_type}`);
  }
  // Must still carry unfilled placeholders (no real ids committed).
  assert.match(JSON.stringify(cfg), /<[A-Z_]+>/);
});

console.log(`\n[schedules tests] ${pass} passed, ${fail} failed\n`);
if (fail > 0) process.exitCode = 1;
