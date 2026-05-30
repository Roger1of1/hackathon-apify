#!/usr/bin/env node
/**
 * shared/enrich/reidentification_selftest.js
 *
 * Dependency-free self-tests for the re-identification ("mosaic effect")
 * enrichment. Run standalone with:
 *   node shared/enrich/reidentification_selftest.js
 *
 * NO FAKE DATA: quasi-identifying events are produced by the REAL pii-detector
 * over honest sample page text (clearly a test fixture), or built via the real
 * makeEvent constructor. No fabricated population data, no fake anonymity counts.
 * The population prior is the module's CLEARLY-LABELLED TEMPLATE.
 *
 * Proves:
 *   1. QI extraction is honest: only frozen EVENT_TYPES + EXPLICIT meta.qi_field
 *      tags count; nothing is inferred; protected attributes are impossible.
 *   2. The mosaic threshold: a single QI field is NOT a finding; >=2 distinct
 *      co-published fields ARE.
 *   3. k-anonymity generalization math: more/stronger QIs => smaller anonymity
 *      set => higher risk; a precise postal address alone nearly singles you out.
 *   4. RED LINE: there is no sex/gender/romance/relationship quasi-identifier,
 *      and a meta.qi_field tag for such a thing is refused.
 *   5. TEMPLATE honesty: output reports prior_basis 'TEMPLATE'.
 *   6. REUSE: findings flow through stix-evidence.toObservedData (STIX 2.1) and
 *      land on severity.js bands; raw QI values are NOT in the STIX object.
 */

'use strict';

const assert = require('assert');

const {
  EVENT_TYPES, VISIBILITY, RISK, makeEvent,
} = require('../detectors/event-types.js');
const { detectPii } = require('../detectors/pii-detector.js');
const { DEFAULT_K } = require('./k-anonymity.js');
const {
  QUASI_IDENTIFIER,
  TAGGED_QI_POWER,
  TEMPLATE_PRIORS,
  qiFieldFor,
  groupQuasiIdentifiersBySurface,
  estimateAnonymitySet,
  reidentificationRisk,
  buildSurfaceFinding,
  enrichReidentification,
  findingToObservedData,
} = require('./reidentification.js');

let pass = 0;
function t(name, fn) {
  try { fn(); pass += 1; console.log(`  PASS  ${name}`); }
  catch (e) { console.error(`  FAIL  ${name}: ${e.message}`); process.exitCode = 1; }
}

// ---- Honest fixtures (clearly test data, never presented as real) ----------

// A self-controlled "about" page text co-publishing several harmless-alone facts.
const ABOUT_TEXT = [
  'Hi, I am @jane_doe. Based in Springfield.',
  'You can reach me at jane.doe@example.com.',
  'I live at 1421 Elm Street.',
].join('\n');

const SURFACE = 'https://jane.example/about';

// Real PII events from the real detector over the fixture text.
const piiEvents = detectPii({ text: ABOUT_TEXT, url: SURFACE, scope_type: 'self', visibility: VISIBILITY.INDEXED });

console.log('[reidentification / honest QI extraction]');

t('qiFieldFor maps frozen QI event types', () => {
  const handleEv = piiEvents.find((e) => e.event_type === EVENT_TYPES.PII_HANDLE_PUBLIC);
  assert.ok(handleEv, 'fixture should yield a handle event');
  const qi = qiFieldFor(handleEv);
  assert.ok(qi && qi.field === 'handle', 'handle event should map to handle QI');
});

t('email is NOT a quasi-identifier (it is a direct identifier, handled elsewhere)', () => {
  const emailEv = piiEvents.find((e) => e.event_type === EVENT_TYPES.PII_EMAIL_PUBLIC);
  assert.ok(emailEv, 'fixture should yield an email event');
  assert.strictEqual(qiFieldFor(emailEv), null, 'email must not be treated as a QI here');
  assert.ok(!Object.prototype.hasOwnProperty.call(QUASI_IDENTIFIER, EVENT_TYPES.PII_EMAIL_PUBLIC));
});

t('nothing is INFERRED: a plain PII text event without a qi_field tag is not a QI', () => {
  // A phone event is not in QUASI_IDENTIFIER and carries no qi_field tag.
  const phoneish = makeEvent({
    event_type: EVENT_TYPES.PII_PHONE_PUBLIC, source_module: 'x', data: '555-123-4567',
  });
  assert.strictEqual(qiFieldFor(phoneish), null);
});

t('explicit meta.qi_field tag is honored only for allowed fields', () => {
  const employerEv = makeEvent({
    event_type: EVENT_TYPES.PII_GEO_HINT_PUBLIC, // carrier type; tag drives QI
    source_module: 'x', data: 'Acme Corp', meta: { qi_field: 'employer' },
  });
  const qi = qiFieldFor(employerEv);
  assert.ok(qi && qi.field === 'employer', 'employer tag should resolve');
  assert.strictEqual(qi.power, TAGGED_QI_POWER.employer);
});

console.log('[reidentification / RED LINES]');

t('no protected/intimacy quasi-identifier exists in the frozen maps', () => {
  const banned = ['sex', 'gender', 'sexuality', 'romance', 'intimacy', 'relationship', 'orientation', 'live_location'];
  const all = JSON.stringify({ QUASI_IDENTIFIER, TAGGED_QI_POWER }).toLowerCase();
  for (const b of banned) {
    assert.ok(!all.includes(`"${b}"`) && !all.includes(`:${b}`), `must not key on ${b}`);
    assert.ok(!Object.prototype.hasOwnProperty.call(TAGGED_QI_POWER, b), `${b} must not be a tagged QI`);
  }
});

t('a meta.qi_field tag for a banned attribute is REFUSED (not inferred, not honored)', () => {
  const sneaky = makeEvent({
    event_type: EVENT_TYPES.PII_GEO_HINT_PUBLIC, source_module: 'x',
    data: 'whatever', meta: { qi_field: 'gender' },
  });
  assert.strictEqual(qiFieldFor(sneaky), null, 'banned tagged field must not become a QI');
});

console.log('[reidentification / mosaic threshold]');

t('a SINGLE quasi-identifier is not a mosaic finding', () => {
  const onlyCity = makeEvent({
    event_type: EVENT_TYPES.PII_GEO_HINT_PUBLIC, source_module: 'pii', data: 'Springfield', source_url: SURFACE,
  });
  const finding = buildSurfaceFinding('jane.example', [onlyCity]);
  assert.strictEqual(finding, null, 'one field alone must not produce a finding');
});

t('>=2 distinct co-published QIs DO produce a finding', () => {
  // The fixture co-publishes a handle, a city hint, and a postal address.
  const out = enrichReidentification(piiEvents);
  assert.ok(out.findings.length >= 1, 'fixture mosaic should yield a finding');
  const f = out.findings[0];
  assert.ok(f.anonymity.distinct_field_count >= 2, 'finding must combine >=2 fields');
  assert.ok(f.anonymity.fields.includes('handle'));
  assert.ok(f.anonymity.fields.includes('postal_address'));
});

t('duplicate occurrences of the SAME field do not inflate the mosaic', () => {
  const city1 = makeEvent({ event_type: EVENT_TYPES.PII_GEO_HINT_PUBLIC, source_module: 'pii', data: 'Springfield', source_url: SURFACE });
  const city2 = makeEvent({ event_type: EVENT_TYPES.PII_GEO_HINT_PUBLIC, source_module: 'pii', data: 'Springfield', source_url: SURFACE });
  const a = estimateAnonymitySet([city1, city2]);
  assert.strictEqual(a.distinct_field_count, 1, 'two city hints are still one field');
});

console.log('[reidentification / k-anonymity generalization math]');

t('more/stronger QIs shrink the anonymity set monotonically', () => {
  const city = makeEvent({ event_type: EVENT_TYPES.PII_GEO_HINT_PUBLIC, source_module: 'pii', data: 'Springfield', source_url: SURFACE });
  const handle = makeEvent({ event_type: EVENT_TYPES.PII_HANDLE_PUBLIC, source_module: 'pii', data: '@jane', source_url: SURFACE, meta: { handle: 'jane' } });
  const postal = makeEvent({ event_type: EVENT_TYPES.PII_POSTAL_PUBLIC, source_module: 'pii', data: '1421 Elm Street', source_url: SURFACE });

  const one = estimateAnonymitySet([city]).anonymity_set;
  const two = estimateAnonymitySet([city, handle]).anonymity_set;
  const three = estimateAnonymitySet([city, handle, postal]).anonymity_set;
  assert.ok(one > two && two > three, `expected shrinking set, got ${one} > ${two} > ${three}`);
});

t('a precise postal address alone nearly singles you out (high power)', () => {
  const postal = makeEvent({ event_type: EVENT_TYPES.PII_POSTAL_PUBLIC, source_module: 'pii', data: '1421 Elm Street', source_url: SURFACE });
  const a = estimateAnonymitySet([postal]);
  // power 0.95 -> retained ~10^-1.9 ~ 1/79 of 1e6 -> low thousands, far below base.
  assert.ok(a.anonymity_set < 100000, `postal should narrow hard, got ${a.anonymity_set}`);
});

t('risk rises as anonymity set falls; unique => 100; large crowd => low', () => {
  const rUnique = reidentificationRisk(1);
  const rThreshold = reidentificationRisk(DEFAULT_K);
  const rCrowd = reidentificationRisk(1_000_000);
  assert.strictEqual(rUnique.risk_score, 100, 'unique must be max risk');
  assert.ok(rUnique.risk_score > rThreshold.risk_score, 'unique > at-threshold');
  assert.ok(rThreshold.risk_score > rCrowd.risk_score, 'at-threshold > big crowd');
  assert.strictEqual(rCrowd.risk_score, 0, 'a full-population crowd is zero risk');
});

t('below_k flag fires exactly when the anonymity set is under the k threshold', () => {
  assert.strictEqual(reidentificationRisk(DEFAULT_K - 1).below_k, true);
  assert.strictEqual(reidentificationRisk(DEFAULT_K).below_k, false);
});

console.log('[reidentification / TEMPLATE honesty + provenance]');

t('output declares the prior basis as TEMPLATE (not fabricated real data)', () => {
  assert.strictEqual(TEMPLATE_PRIORS.prior_basis, 'TEMPLATE');
  const out = enrichReidentification(piiEvents);
  assert.strictEqual(out.prior_basis, 'TEMPLATE');
  for (const f of out.findings) {
    assert.strictEqual(f.anonymity.prior_basis, 'TEMPLATE');
    assert.strictEqual(f.event.data.prior_basis, 'TEMPLATE');
  }
});

t('the finding event cites the modelling reference and omits sex by design', () => {
  const out = enrichReidentification(piiEvents);
  const meta = out.findings[0].event.meta;
  assert.ok(/Sweeney/.test(meta.model_ref), 'must cite Sweeney');
  assert.ok(/sex deliberately omitted/i.test(meta.model_ref), 'must note red-line omission');
});

console.log('[reidentification / REUSE of canonical layers]');

t('findings flow through severity.js bandFor (shared band scale)', () => {
  const out = enrichReidentification(piiEvents);
  const f = out.findings[0];
  const validBands = new Set(['critical', 'high', 'medium', 'low', 'info']);
  assert.ok(validBands.has(f.risk.band), `band must be canonical, got ${f.risk.band}`);
});

t('findingToObservedData reuses stix-evidence and carries NO raw QI values', () => {
  const out = enrichReidentification(piiEvents);
  const od = findingToObservedData(out.findings[0], { now: '2026-05-30T00:00:00Z' });
  assert.ok(od && od.type === 'observed-data' && od.spec_version === '2.1', 'must be STIX 2.1 observed-data');
  const serialized = JSON.stringify(od);
  // The raw street address / city / handle must NOT appear in the exported STIX.
  assert.ok(!serialized.includes('1421 Elm Street'), 'raw postal must not be exported');
  assert.ok(!serialized.includes('jane_doe'), 'raw handle must not be exported');
  // But the field NAMES and the anonymity magnitude SHOULD be present.
  assert.ok(serialized.includes('postal_address'), 'field name should be present');
  assert.ok(serialized.includes('anonymity_set'), 'anonymity magnitude should be present');
});

t('the synthetic finding event is a valid module_event of the frozen EXPOSURE_SUMMARY type', () => {
  const out = enrichReidentification(piiEvents);
  const ev = out.findings[0].event;
  assert.strictEqual(ev.record_type, 'module_event');
  assert.strictEqual(ev.event_type, EVENT_TYPES.EXPOSURE_SUMMARY);
  // visibility inherits INDEXED because the fixture surface was indexed.
  assert.strictEqual(ev.visibility, VISIBILITY.INDEXED);
});

console.log('[reidentification / grouping by surface]');

t('QIs on DIFFERENT surfaces do not cross-combine into one mosaic', () => {
  const cityA = makeEvent({ event_type: EVENT_TYPES.PII_GEO_HINT_PUBLIC, source_module: 'pii', data: 'Springfield', source_url: 'https://a.example/x' });
  const postalB = makeEvent({ event_type: EVENT_TYPES.PII_POSTAL_PUBLIC, source_module: 'pii', data: '1421 Elm Street', source_url: 'https://b.example/y' });
  const groups = groupQuasiIdentifiersBySurface([cityA, postalB]);
  assert.strictEqual(groups.size, 2, 'two distinct surfaces');
  const out = enrichReidentification([cityA, postalB]);
  assert.strictEqual(out.findings.length, 0, 'one QI per surface => no mosaic on either');
});

console.log(`\nreidentification: ${pass} checks passed, ${process.exitCode ? 'WITH FAILURES' : '0 failures'}`);
