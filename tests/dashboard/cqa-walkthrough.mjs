#!/usr/bin/env node
// CQA round-3 — full Console feature walkthrough with screenshots.
//
// Goes beyond the per-route baseline `capture-screenshots.mjs`:
// for each page, opens the key interactive elements (forms,
// modals, drawers, edit flows, rollback confirms, etc.) and
// captures a PNG of each state. Records console errors per
// page so a passing run is "no red errors anywhere".
//
// Usage:
//   node tests/dashboard/cqa-walkthrough.mjs \
//        --admin=http://127.0.0.1:9443 \
//        --user=admin --pass='aegis-test-1234' \
//        --out=tests/results/run-cqa-round3-<DATE>/screenshots
//
// Requires `npx playwright install chromium` once.

import { chromium } from 'playwright';
import { mkdir, writeFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';

const argv = Object.fromEntries(
  process.argv.slice(2)
    .filter(a => a.startsWith('--'))
    .map(a => {
      const i = a.indexOf('=');
      return i < 0 ? [a.slice(2), true] : [a.slice(2, i), a.slice(i + 1)];
    })
);

const ADMIN = argv.admin || process.env.AEGIS_ADMIN || 'http://127.0.0.1:9443';
const USER  = argv.user  || process.env.AEGIS_ADMIN_USER || 'admin';
const PASS  = argv.pass  || process.env.AEGIS_ADMIN_PASS || 'aegis-test-1234';
const OUT   = resolve(argv.out || `tests/results/run-cqa-walkthrough-${new Date().toISOString().slice(0,10).replace(/-/g,'')}/screenshots`);

// Each step: { name, action(page), screenshot? = name + '.png' }.
// Actions are lambdas so we can chain side effects (click → wait
// → assert) before the snap. `screenshot: false` skips capture.
const PAGES = [
  {
    route: 'overview',
    title: 'Overview',
    steps: [
      { name: 'baseline' },
      // We don't actually click "Block" because it'd mutate
      // state during a screenshot run. Hover only.
      { name: 'hover-block-button', action: async (p) => {
        const btn = p.locator('button.btn.sm.danger', { hasText: 'Block' }).first();
        if (await btn.count()) await btn.hover().catch(() => {});
      } },
    ],
  },
  {
    route: 'live',
    title: 'Live Feed',
    steps: [
      { name: 'baseline' },
      { name: 'pause-toggle', action: async (p) => {
        const btn = p.locator('button', { hasText: /Pause|Resume/ }).first();
        if (await btn.count()) await btn.click().catch(() => {});
        await p.waitForTimeout(300);
      } },
    ],
  },
  { route: 'attacks',   title: 'Attack Events', steps: [{ name: 'baseline' }] },
  { route: 'analytics', title: 'Analytics',     steps: [{ name: 'baseline' }] },
  {
    route: 'audit',
    title: 'Audit Log',
    steps: [
      { name: 'baseline' },
      // CQF-T11 chip group
      { name: 'time-range-1h', action: async (p) => {
        const btn = p.locator('button', { hasText: /^1h$/ }).first();
        if (await btn.count()) await btn.click().catch(() => {});
        await p.waitForTimeout(200);
      } },
      { name: 'time-range-all', action: async (p) => {
        const btn = p.locator('button', { hasText: /^all$/ }).first();
        if (await btn.count()) await btn.click().catch(() => {});
        await p.waitForTimeout(200);
      } },
    ],
  },
  {
    route: 'rules',
    title: 'Rule Manager',
    steps: [
      { name: 'baseline' },
      // HACK-T3 simulator card lives on this page. Don't run it
      // (would mutate); just confirm the card renders.
    ],
  },
  {
    route: 'tiers',
    title: 'Tier Config',
    steps: [
      { name: 'baseline' },
      // CQF-T3 — open the Edit on the base mask row, capture,
      // then Cancel so we don't leave the page mutated.
      { name: 'mask-edit-base', action: async (p) => {
        const editBtn = p
          .locator('div', { hasText: 'Detector Mask' })
          .first()
          .locator('button.btn', { hasText: /^Edit$/ })
          .first();
        if (await editBtn.count()) {
          await editBtn.click().catch(() => {});
          await p.waitForTimeout(300);
        }
      } },
      { name: 'mask-cancel', action: async (p) => {
        const cancel = p.locator('button.btn', { hasText: /^Cancel$/ }).first();
        if (await cancel.count()) await cancel.click().catch(() => {});
        await p.waitForTimeout(200);
      } },
    ],
  },
  {
    route: 'upstreams',
    title: 'Upstreams',
    steps: [
      { name: 'baseline' },
    ],
  },
  {
    route: 'blacklist',
    title: 'Blacklist',
    steps: [
      { name: 'baseline' },
      // CQF-T2 — open Add Entry form
      { name: 'add-entry-form', action: async (p) => {
        const btn = p.locator('button', { hasText: /Add entry/ }).first();
        if (await btn.count()) await btn.click().catch(() => {});
        await p.waitForTimeout(300);
      } },
      { name: 'cancel-form', action: async (p) => {
        const btn = p.locator('button', { hasText: /^Cancel$/ }).first();
        if (await btn.count()) await btn.click().catch(() => {});
        await p.waitForTimeout(200);
      } },
    ],
  },
  {
    route: 'whitelist',
    title: 'Whitelist',
    steps: [
      { name: 'baseline' },
      { name: 'add-entry-form', action: async (p) => {
        const btn = p.locator('button', { hasText: /Add entry/ }).first();
        if (await btn.count()) await btn.click().catch(() => {});
        await p.waitForTimeout(300);
      } },
    ],
  },
  {
    route: 'settings',
    title: 'Settings',
    steps: [
      { name: 'baseline' },
      // ConfigVersions card scrolled into view
      { name: 'config-versions-scroll', action: async (p) => {
        const card = p.locator('div', { hasText: /Config history|version/i }).first();
        if (await card.count()) await card.scrollIntoViewIfNeeded().catch(() => {});
        await p.waitForTimeout(200);
      } },
      // MTLS SAN allowlist card (CQF-T7-allowed-sans / MTLS-T7)
      { name: 'mtls-sans-card', action: async (p) => {
        const card = p.locator('div', { hasText: /Allowed SANs/ }).first();
        if (await card.count()) await card.scrollIntoViewIfNeeded().catch(() => {});
        await p.waitForTimeout(200);
      } },
    ],
  },
  {
    route: 'tracking',
    title: 'Tracking',
    steps: [{ name: 'baseline' }],
  },
  {
    route: 'scaling',
    title: 'Scaling',
    steps: [{ name: 'baseline' }],
  },
  {
    route: 'help',
    title: 'Help',
    steps: [{ name: 'baseline' }],
  },
];

// Cross-cutting (TopBar, Sidebar) — captured separately at end.
const CROSS_CUTTING = [
  {
    name: 'topbar-buttons',
    action: async (p) => {
      // Just hover the icon-btn group so the tooltip is visible
      // — clicking would either drain or sign-out. Both are
      // destructive for a screenshot-only run.
      const buttons = p.locator('div.topbar button.icon-btn');
      const n = await buttons.count();
      if (n > 0) await buttons.nth(0).hover().catch(() => {});
    },
  },
];

async function main() {
  await mkdir(OUT, { recursive: true });
  const browser = await chromium.launch({ headless: true });
  const ctx = await browser.newContext({
    viewport: { width: 1440, height: 900 },
    ignoreHTTPSErrors: true,
  });

  // 1. Login — POST /admin/login, cookies land in context.
  const loginRes = await ctx.request.post(`${ADMIN}/admin/login`, {
    data: { user: USER, password: PASS },
  });
  if (!loginRes.ok()) {
    const body = await loginRes.text();
    throw new Error(`login failed: ${loginRes.status()} ${body}`);
  }
  console.log(`login OK (${loginRes.status()})`);

  // 2. Walk each page, run each step, capture screenshot.
  const page = await ctx.newPage();
  const consoleErrors = [];
  page.on('pageerror', err => consoleErrors.push({ kind: 'pageerror', text: err.message }));
  page.on('console', m => {
    if (m.type() === 'error') {
      consoleErrors.push({ kind: 'console.error', text: m.text() });
    }
  });

  await page.goto(`${ADMIN}/dashboard/`, { waitUntil: 'domcontentloaded', timeout: 10000 });
  await page.waitForSelector('main.content', { timeout: 5000 });

  const report = [];
  let captured = 0;
  let failed = 0;

  for (const { route, title, steps } of PAGES) {
    const url = `${ADMIN}/dashboard/#/${route}`;
    await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 10000 });
    try {
      await page.waitForFunction(
        r => location.hash === `#/${r}`, route, { timeout: 3000 },
      );
    } catch (e) {
      console.error(`route ${route}: hash never settled`);
    }
    await page.waitForTimeout(400);

    const pageDir = join(OUT, route);
    await mkdir(pageDir, { recursive: true });

    const stepResults = [];
    for (const step of steps) {
      const errBefore = consoleErrors.length;
      if (step.action) {
        try {
          await step.action(page);
        } catch (e) {
          console.error(`step ${route}/${step.name} failed: ${e.message}`);
        }
      }
      const file = join(pageDir, `${step.name}.png`);
      try {
        await page.screenshot({ path: file, fullPage: true });
        captured++;
      } catch (e) {
        failed++;
        console.error(`screenshot ${route}/${step.name} failed: ${e.message}`);
      }
      const newErrors = consoleErrors.slice(errBefore);
      stepResults.push({ name: step.name, file, console_errors_during_step: newErrors });
      console.log(`captured ${route}/${step.name}`);
    }
    report.push({ route, title, steps: stepResults });
  }

  // Cross-cutting (TopBar)
  const ccDir = join(OUT, '_cross');
  await mkdir(ccDir, { recursive: true });
  for (const cc of CROSS_CUTTING) {
    const errBefore = consoleErrors.length;
    if (cc.action) {
      try { await cc.action(page); } catch (_) {}
    }
    const file = join(ccDir, `${cc.name}.png`);
    try { await page.screenshot({ path: file, fullPage: false }); captured++; }
    catch (e) { failed++; console.error(`cc ${cc.name}: ${e.message}`); }
    report.push({
      route: '_cross', title: 'Cross-cutting (TopBar/Sidebar)',
      steps: [{
        name: cc.name, file,
        console_errors_during_step: consoleErrors.slice(errBefore),
      }],
    });
  }

  await browser.close();

  // 3. Write the run-report JSON + a Markdown index.
  const report_json = {
    admin: ADMIN, captured, failed,
    total_console_errors: consoleErrors.length,
    pages: report,
  };
  await writeFile(
    join(OUT, '..', 'walkthrough.json'),
    JSON.stringify(report_json, null, 2),
  );

  const lines = [];
  lines.push('# CQA round-3 walkthrough — screenshot index\n');
  lines.push(`Admin: \`${ADMIN}\``);
  lines.push(`Captured: **${captured}** screenshots across **${report.length}** pages`);
  lines.push(`Failed:    ${failed}`);
  lines.push(`Browser console errors: **${consoleErrors.length}**\n`);
  if (consoleErrors.length > 0) {
    lines.push('## Console errors\n');
    for (const e of consoleErrors) {
      lines.push(`- \`${e.kind}\` — ${e.text}`);
    }
    lines.push('');
  }
  lines.push('## Per-page screenshots\n');
  for (const p of report) {
    lines.push(`### ${p.title} (${p.route})\n`);
    for (const s of p.steps) {
      const rel = s.file.replace(OUT + '/', 'screenshots/');
      lines.push(`- **${s.name}** — ![${s.name}](${rel})`);
    }
    lines.push('');
  }
  await writeFile(join(OUT, '..', 'README.md'), lines.join('\n'));

  console.log(`\nCaptured ${captured} screenshots into ${OUT}`);
  console.log(`Console errors during run: ${consoleErrors.length}`);
  if (failed > 0) process.exit(1);
}

main().catch(err => {
  console.error(err);
  process.exit(1);
});
