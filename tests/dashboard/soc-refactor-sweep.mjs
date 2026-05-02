#!/usr/bin/env node
// Phase 2 + 3 console QA sweep — walk every page in the new IA,
// capture screenshots, record console errors, flag pages that
// rendered with no body / no API data / red error states.
//
// Output: tests/results/run-soc-sweep-<DATE>/{screenshots,REPORT.md}
//
// Usage:
//   node tests/dashboard/soc-refactor-sweep.mjs \
//        --admin=http://127.0.0.1:9443 \
//        --user=admin --pass='aegis-test-1234'
//
// Prereqs:
//   make run-dev      # in another terminal
//   make mock-load    # gives the dashboard data to render
//   npx playwright install chromium  # one-time

import { chromium } from 'playwright';
import { mkdir, writeFile } from 'node:fs/promises';
import { resolve, join } from 'node:path';

const argv = Object.fromEntries(
  process.argv.slice(2)
    .filter(a => a.startsWith('--'))
    .map(a => { const i = a.indexOf('='); return i < 0 ? [a.slice(2), true] : [a.slice(2, i), a.slice(i + 1)]; })
);
const ADMIN = argv.admin || 'http://127.0.0.1:9443';
const USER  = argv.user  || 'admin';
const PASS  = argv.pass  || 'aegis-test-1234';
const STAMP = new Date().toISOString().slice(0, 16).replace(/[-:T]/g, '');
const OUT   = resolve(argv.out || `tests/results/run-soc-sweep-${STAMP}`);

// Page surface from app.jsx NAV array. Each row: { id, label, group }.
const PAGES = [
  // Security Ops
  { id: 'overview',         label: 'Overview',           group: 'Security Ops' },
  { id: 'live',             label: 'Live Feed',          group: 'Security Ops' },
  { id: 'incidents',        label: 'Incidents',          group: 'Security Ops' },
  { id: 'investigation',    label: 'Investigation',      group: 'Security Ops' },
  { id: 'attack-analytics', label: 'Attack Analytics',   group: 'Security Ops' },
  { id: 'threat-intel',     label: 'Threat Intel',       group: 'Security Ops' },
  // Policy
  { id: 'rules',            label: 'Rules',              group: 'Policy' },
  { id: 'detectors',        label: 'Detectors',          group: 'Policy' },
  { id: 'access-lists',     label: 'Access Lists',       group: 'Policy' },
  { id: 'upstreams',        label: 'Routing & Upstreams',group: 'Policy' },
  { id: 'compliance',       label: 'Compliance',         group: 'Policy' },
  // Observability
  { id: 'performance',      label: 'Performance',        group: 'Observability' },
  { id: 'health',           label: 'Health & SLOs',      group: 'Observability' },
  { id: 'audit',            label: 'Audit Trail',        group: 'Observability' },
  { id: 'scaling',          label: 'Scaling',            group: 'Observability' },
  // Admin
  { id: 'settings',         label: 'Settings',           group: 'Admin' },
  { id: 'reports',          label: 'Reports',            group: 'Admin' },
  { id: 'help',             label: 'Help & Guide',       group: 'Admin' },
];

// Hash redirects we should also probe — old bookmarks should still work.
const REDIRECTS = [
  { from: 'attacks',   to: 'attack-analytics' },
  { from: 'analytics', to: 'performance' },
  { from: 'tiers',     to: 'detectors' },
  { from: 'tracking',  to: 'health' },
  { from: 'blacklist', to: 'access-lists' },
  { from: 'whitelist', to: 'access-lists' },
];

async function main() {
  await mkdir(join(OUT, 'screenshots'), { recursive: true });
  const browser = await chromium.launch({ headless: true });
  const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 } });
  const page = await ctx.newPage();

  // Per-page console + network error capture.
  const findings = [];
  let currentLabel = '';
  page.on('console', msg => {
    if (msg.type() === 'error') {
      findings.push({ page: currentLabel, kind: 'console.error', detail: msg.text().slice(0, 200) });
    }
  });
  page.on('pageerror', err => {
    findings.push({ page: currentLabel, kind: 'pageerror', detail: String(err).slice(0, 200) });
  });
  page.on('response', r => {
    const url = r.url();
    if (url.includes('/api/') && r.status() >= 400) {
      findings.push({ page: currentLabel, kind: `api ${r.status()}`, detail: url.replace(ADMIN, '') });
    }
  });

  // Login.
  console.log('=> login');
  currentLabel = 'login';
  await page.goto(`${ADMIN}/dashboard/`, { waitUntil: 'domcontentloaded' });
  // The login form may be at /login or surfaced inline.
  await page.waitForLoadState('networkidle', { timeout: 5000 }).catch(() => {});
  // Detect login state — if there's a 'user' or 'username' input, fill it.
  const userInput = page.locator('input[name="user"], input[name="username"], input[type="text"]').first();
  if (await userInput.count()) {
    await userInput.fill(USER);
    const pwInput = page.locator('input[type="password"]').first();
    if (await pwInput.count()) await pwInput.fill(PASS);
    const submit = page.locator('button[type="submit"], button.primary').filter({ hasText: /sign in|login|log in/i }).first();
    if (await submit.count()) {
      await submit.click().catch(() => {});
      await page.waitForLoadState('networkidle', { timeout: 5000 }).catch(() => {});
    }
  }

  // Per-page sweep.
  const pageReports = [];
  for (const { id, label, group } of PAGES) {
    currentLabel = label;
    const findingsBefore = findings.length;
    console.log(`=> ${group} / ${label} (#/${id})`);
    await page.goto(`${ADMIN}/dashboard/#/${id}`, { waitUntil: 'domcontentloaded' });
    await page.waitForLoadState('networkidle', { timeout: 4000 }).catch(() => {});
    await page.waitForTimeout(500); // settle SSR-ish polling
    const titleText = await page.locator('h1.page-title').first().textContent().catch(() => '');
    const bodyHas = {
      hasH1:        !!titleText && titleText.trim().length > 0,
      hasNaN:       /NaN|undefined/.test(await page.content()),
      hasEmptyCard: await page.locator('.card').count() > 0,
      activeNav:    await page.locator(`.nav-item.active`).first().textContent().catch(() => ''),
    };
    const shotPath = join(OUT, 'screenshots', `${id}.png`);
    await page.screenshot({ path: shotPath, fullPage: true });
    pageReports.push({
      id, label, group,
      titleText: (titleText || '').trim(),
      activeNav: (bodyHas.activeNav || '').trim(),
      hasH1: bodyHas.hasH1,
      hasNaN: bodyHas.hasNaN,
      cards: bodyHas.hasEmptyCard,
      newFindings: findings.slice(findingsBefore),
      shot: `screenshots/${id}.png`,
    });
  }

  // Redirect probes.
  const redirectReports = [];
  for (const { from, to } of REDIRECTS) {
    currentLabel = `redirect ${from}→${to}`;
    await page.goto(`${ADMIN}/dashboard/#/${from}`, { waitUntil: 'domcontentloaded' });
    await page.waitForLoadState('networkidle', { timeout: 3000 }).catch(() => {});
    await page.waitForTimeout(300);
    const finalHash = await page.evaluate(() => location.hash);
    redirectReports.push({ from, to, finalHash, ok: finalHash === `#/${to}` });
  }

  await browser.close();

  // Render REPORT.md.
  const passes = pageReports.filter(p => p.hasH1 && !p.hasNaN && p.newFindings.length === 0);
  const partial = pageReports.filter(p => p.hasH1 && (p.hasNaN || p.newFindings.length > 0));
  const fail = pageReports.filter(p => !p.hasH1);

  let md = `# SOC console refactor sweep — ${STAMP}\n\n`;
  md += `> Auto-generated by \`tests/dashboard/soc-refactor-sweep.mjs\`. Walks every page in the new IA, captures screenshots + console errors, flags NaN / undefined / empty bodies.\n\n`;
  md += `## Headline\n\n`;
  md += `- Pages walked: **${pageReports.length}**\n`;
  md += `- Pass (h1 ok, no NaN, no errors): **${passes.length}**\n`;
  md += `- Partial (rendered but with errors / NaN): **${partial.length}**\n`;
  md += `- Fail (no h1): **${fail.length}**\n`;
  md += `- Redirects pass: **${redirectReports.filter(r => r.ok).length} / ${redirectReports.length}**\n`;
  md += `- Total findings: **${findings.length}**\n\n`;

  md += `## Pages\n\n`;
  md += `| Status | Group | Label | Hash | h1 text | Active nav | NaN? | Cards | Findings | Screenshot |\n`;
  md += `|--------|-------|-------|------|---------|------------|------|-------|----------|------------|\n`;
  for (const p of pageReports) {
    const status = !p.hasH1 ? 'FAIL' : (p.hasNaN || p.newFindings.length > 0) ? 'PARTIAL' : 'PASS';
    md += `| ${status} | ${p.group} | ${p.label} | \`#/${p.id}\` | ${p.titleText || '(missing)'} | ${p.activeNav} | ${p.hasNaN ? 'YES' : 'no'} | ${p.cards ? 'yes' : 'no'} | ${p.newFindings.length} | [![](${p.shot})](${p.shot}) |\n`;
  }

  md += `\n## Hash redirects\n\n`;
  md += `| From | To | Final hash | OK? |\n|------|-----|------------|-----|\n`;
  for (const r of redirectReports) {
    md += `| \`#/${r.from}\` | \`#/${r.to}\` | \`${r.finalHash}\` | ${r.ok ? '✓' : 'FAIL'} |\n`;
  }

  if (findings.length > 0) {
    md += `\n## All findings\n\n`;
    md += `| Page | Kind | Detail |\n|------|------|--------|\n`;
    for (const f of findings) {
      md += `| ${f.page} | ${f.kind} | \`${f.detail.replace(/\|/g, '\\|')}\` |\n`;
    }
  } else {
    md += `\n## All findings\n\nNo console errors, page errors, or 4xx/5xx API responses captured.\n`;
  }

  await writeFile(join(OUT, 'REPORT.md'), md, 'utf-8');
  console.log(`\nDone. Report: ${OUT}/REPORT.md`);
  console.log(`Pass / Partial / Fail: ${passes.length} / ${partial.length} / ${fail.length}`);
}

main().catch(err => { console.error(err); process.exit(1); });
