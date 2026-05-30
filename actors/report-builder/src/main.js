/**
 * A6 — Report Builder
 *
 * The terminal stage. Reads the immutable EVIDENCE_INDEX + CASE record, computes
 * ONLY the compliant scores from shared/scoring.js, and renders the report in
 * THREE formats:
 *   - Obsidian-flavored Markdown (frontmatter + wikilink-friendly)
 *   - CSV (one row per evidence item)
 *   - JSON (the full machine-readable bundle)
 *
 * Scores are limited to: exposure_score, evidence_quality_score,
 * actionability_score, distress_risk_score. There is intentionally NO romantic /
 * jealousy / availability score anywhere — the scoring module simply does not
 * expose one, so it cannot be rendered.
 *
 * When distress_risk_score is high, the report includes a "Closure Mode" block:
 * a wellbeing intervention to reduce compulsive checking. This is the product's
 * stated purpose ("reduce compulsive checking"), expressed in the deliverable.
 *
 * No fabrication: every number derives from real captured/diffed data. If the
 * crawl was empty, the report says so honestly.
 */

'use strict';

const { Actor, log } = require('apify');
const { computeScores } = require('../../../shared/scoring.js');

/**
 * Derive crawl-summary inputs for exposure scoring from the real evidence items.
 */
function summarizeCrawl(entries) {
  const hosts = new Set();
  for (const e of entries) {
    try {
      hosts.add(new URL(e.url).hostname);
    } catch {
      /* ignore unparseable */
    }
  }
  return {
    reachablePages: entries.length,
    distinctHosts: hosts.size,
    // We treat every preserved public page as indexable for exposure purposes.
    indexablePages: entries.length,
  };
}

/**
 * Map evidence-index entries into the shape scoring.js expects, marking which
 * items are self-owned / have a removal path. These flags come from the CASE
 * scope (a "self" audit means the user owns those surfaces) — never invented.
 */
function enrichForScoring(entries, scopeType) {
  return entries.map((e) => ({
    ...e,
    self_owned: scopeType === 'self',
    // Conservative: only claim a removal path when we actually know one exists.
    has_removal_path: false,
  }));
}

function csvEscape(value) {
  const s = value === null || value === undefined ? '' : String(value);
  if (/[",\n]/.test(s)) return `"${s.replace(/"/g, '""')}"`;
  return s;
}

function buildCsv(entries) {
  const header = [
    'url',
    'change',
    'timestamp',
    'content_sha256',
    'html_sha256',
    'html_key',
    'screenshot_key',
  ];
  const rows = [header.join(',')];
  for (const e of entries) {
    rows.push([
      csvEscape(e.url),
      csvEscape(e.change),
      csvEscape(e.timestamp),
      csvEscape(e.content_sha256),
      csvEscape(e.html_sha256),
      csvEscape(e.html_key),
      csvEscape(e.screenshot_key),
    ].join(','));
  }
  return rows.join('\n');
}

/**
 * Closure Mode block — surfaced when distress_risk_score is high. This is the
 * wellbeing core of the product: it actively discourages compulsive re-checking.
 */
function closureModeBlock(scores, checksPerDay) {
  return [
    '> [!warning] Closure Mode suggested',
    '>',
    `> Your distress-risk signal is **${scores.distress_risk_score}/100**`
      + (checksPerDay ? ` (you reported checking ~${checksPerDay}×/day).` : '.'),
    '>',
    '> This tool exists to give you a *scheduled* answer so you can stop checking',
    '> in between. Consider:',
    '> - Set this audit to run on a schedule (min interval 1 min on Apify, but',
    '>   daily/weekly is healthier) and **only read the report when it arrives**.',
    '> - Turn off ad-hoc manual runs for a week.',
    '> - If this is about a specific person, remember: this product audits *your*',
    '>   footprint and preserves evidence of harm to *you* — it cannot and will',
    '>   not surveil them. That boundary is part of the closure.',
    '> - If checking is causing distress, a brief conversation with someone you',
    '>   trust (or a professional) is a healthier next step than another scan.',
  ].join('\n');
}

function buildMarkdown({ caseRecord, index, scores, checksPerDay }) {
  const entries = index.entries || [];
  const summary = index.summary || {};
  const now = new Date().toISOString();

  const lines = [];
  // Obsidian frontmatter.
  lines.push('---');
  lines.push(`title: "Footprint Audit — ${caseRecord.subject_label || caseRecord.case_id}"`);
  lines.push(`case_id: ${caseRecord.case_id}`);
  lines.push(`scope_type: ${caseRecord.scope_type}`);
  lines.push(`generated: ${now}`);
  lines.push('tags: [mirrortrace, footprint-audit, self-evidence]');
  lines.push(`exposure_score: ${scores.exposure_score}`);
  lines.push(`evidence_quality_score: ${scores.evidence_quality_score}`);
  lines.push(`actionability_score: ${scores.actionability_score}`);
  lines.push(`distress_risk_score: ${scores.distress_risk_score}`);
  lines.push('---');
  lines.push('');
  lines.push(`# Footprint Audit — ${caseRecord.subject_label || caseRecord.case_id}`);
  lines.push('');
  lines.push(`**Scope:** \`${caseRecord.scope_type}\`  ·  **Case:** \`${caseRecord.case_id}\``);
  if (caseRecord.authorization_evidence_url) {
    lines.push(`**Authorization on file:** ${caseRecord.authorization_evidence_url}`);
  }
  lines.push('');

  // Compliance banner — make the boundaries explicit in the deliverable itself.
  lines.push('> [!info] What this report is — and is not');
  lines.push('> This is a **public footprint audit / evidence preservation** report.');
  lines.push('> It does **not** track private individuals, infer relationships, or');
  lines.push('> analyze anyone\'s photos. Blocked sources were **not** bypassed.');
  lines.push('');

  // Scores.
  lines.push('## Scores');
  lines.push('');
  lines.push('| Metric | Score |');
  lines.push('| --- | --- |');
  lines.push(`| Exposure | ${scores.exposure_score} / 100 |`);
  lines.push(`| Evidence quality | ${scores.evidence_quality_score} / 100 |`);
  lines.push(`| Actionability | ${scores.actionability_score} / 100 |`);
  lines.push(`| Distress risk | ${scores.distress_risk_score} / 100 |`);
  lines.push('');

  if (scores.closure_mode_recommended) {
    lines.push(closureModeBlock(scores, checksPerDay));
    lines.push('');
  }

  // Summary of this run.
  lines.push('## This run');
  lines.push('');
  lines.push(`- Captures: **${summary.captures ?? 0}**`);
  lines.push(`- New items: **${summary.new ?? 0}**`);
  lines.push(`- Changed items: **${summary.changed ?? 0}**`);
  lines.push(`- Unchanged (not reported): **${summary.unchanged ?? 0}**`);
  if (summary.crawl_aborted) {
    lines.push('- ⚠️ The crawl **backed off** on a blocked source and stopped early.'
      + ' See `backoff_for_human_review` records. We did not evade the block.');
  }
  lines.push('');

  // Evidence items.
  lines.push('## Evidence index (changes only)');
  lines.push('');
  if (entries.length === 0) {
    lines.push('_No new or changed public items in this run._');
  } else {
    for (const e of entries) {
      lines.push(`### ${e.change === 'new' ? '🆕' : '✏️'} ${e.url}`);
      lines.push('');
      lines.push(`- **Captured:** ${e.timestamp}`);
      lines.push(`- **content_sha256:** \`${e.content_sha256}\``);
      lines.push(`- **html_sha256:** \`${e.html_sha256}\``);
      if (e.previous_content_sha256) {
        lines.push(`- **previous content_sha256:** \`${e.previous_content_sha256}\``);
      }
      lines.push(`- **Preserved html:** \`${e.html_key || 'n/a'}\``);
      lines.push(`- **Screenshot:** \`${e.screenshot_key || 'n/a'}\``);
      lines.push('');
    }
  }

  lines.push('---');
  lines.push('_Generated by MirrorTrace (Self Footprint Audit Pro). Compliant scoring only._');
  lines.push('');
  return lines.join('\n');
}

Actor.main(async () => {
  const input = (await Actor.getInput()) || {};
  const caseStoreName = input.case_store_name || 'mirrortrace-case';
  const caseStore = await Actor.openKeyValueStore(caseStoreName);

  const caseRecord = await caseStore.getValue('CASE');
  if (!caseRecord) {
    log.error('No CASE record; the report builder must run after the pipeline.');
    await Actor.fail('Missing CASE record.');
    return;
  }
  const index = (await caseStore.getValue('EVIDENCE_INDEX')) || { entries: [], summary: {} };
  const entries = index.entries || [];
  const checksPerDay = typeof input.checks_per_day === 'number' ? input.checks_per_day : 0;

  // Compute ONLY compliant scores.
  const scores = computeScores({
    crawlSummary: summarizeCrawl(entries),
    evidenceItems: enrichForScoring(entries, caseRecord.scope_type),
    wellbeing: { checks_per_day: checksPerDay, scope_type: caseRecord.scope_type },
  });

  // Render three formats.
  const markdown = buildMarkdown({ caseRecord, index, scores, checksPerDay });
  const csv = buildCsv(entries);
  const jsonBundle = {
    case: caseRecord,
    generated_at: new Date().toISOString(),
    scores,
    summary: index.summary || {},
    evidence_index: entries,
  };

  // Persist all three to KV (named keys) and push a summary row to the dataset.
  await caseStore.setValue('REPORT', jsonBundle);
  await caseStore.setValue('report.md', markdown, { contentType: 'text/markdown; charset=utf-8' });
  await caseStore.setValue('report.csv', csv, { contentType: 'text/csv; charset=utf-8' });
  await caseStore.setValue('report.json', jsonBundle); // JSON (default contentType)

  // Also expose the canonical OUTPUT on the run's default KV store.
  await Actor.setValue('OUTPUT', jsonBundle);

  await Actor.pushData({
    record_type: 'report',
    case_id: caseRecord.case_id,
    scope_type: caseRecord.scope_type,
    ...scores,
    items: entries.length,
    generated_at: jsonBundle.generated_at,
  });

  log.info('Report built in 3 formats (md, csv, json).', {
    caseId: caseRecord.case_id,
    items: entries.length,
    closure_mode: scores.closure_mode_recommended,
  });
});
