#!/usr/bin/env node
// DD-T4 — per-page screenshot regression baseline.
//
// Drives a headless Chromium against a running aegis-bin admin
// endpoint, logs in once with the dev-config credentials, and
// captures one PNG per dashboard route. Output goes into
// `tests/results/run-10-2026-04-30-dashboard-redesign/screenshots/`
// by default — override with --out=<dir>.
//
// Usage:
//   node tests/dashboard/capture-screenshots.mjs \
//        --admin=http://127.0.0.1:9443 \
//        --user=admin --pass='aegis-test-1234' \
//        --out=tests/results/run-10-2026-04-30-dashboard-redesign/screenshots
//
// Requires `npx playwright install chromium` once on the host.

import { chromium } from 'playwright';
import { mkdir } from 'node:fs/promises';
import { join, resolve } from 'node:path';

const argv = Object.fromEntries(
  process.argv.slice(2)
    .filter(a => a.startsWith('--'))
    .map(a => {
      const i = a.indexOf('=');
      return i < 0
        ? [a.slice(2), true]
        : [a.slice(2, i), a.slice(i + 1)];
    })
);

const ADMIN = argv.admin || process.env.AEGIS_ADMIN || 'http://127.0.0.1:9443';
const USER  = argv.user  || process.env.AEGIS_ADMIN_USER || 'admin';
const PASS  = argv.pass  || process.env.AEGIS_ADMIN_PASS || 'aegis-test-1234';
const OUT   = resolve(
  argv.out
  || 'tests/results/run-10-2026-04-30-dashboard-redesign/screenshots'
);

const ROUTES = [
  'overview', 'live', 'attacks', 'analytics', 'audit',
  'rules', 'tiers', 'blacklist', 'whitelist', 'settings',
  'tracking', 'help',
];

async function main() {
  await mkdir(OUT, { recursive: true });

  const browser = await chromium.launch({ headless: true });
  const ctx = await browser.newContext({
    viewport: { width: 1440, height: 900 },
    ignoreHTTPSErrors: true,
  });

  // 1. Login — POST /admin/login. Cookies land in the browser context.
  const loginRes = await ctx.request.post(`${ADMIN}/admin/login`, {
    data: { user: USER, password: PASS },
  });
  if (!loginRes.ok()) {
    const body = await loginRes.text();
    throw new Error(`login failed: ${loginRes.status()} ${body}`);
  }
  console.log(`login OK (${loginRes.status()})`);

  // 2. Walk each route and screenshot.
  const page = await ctx.newPage();
  page.on('pageerror', err => console.error(`pageerror: ${err.message}`));
  page.on('console', m => {
    if (m.type() === 'error') console.error(`console: ${m.text()}`);
  });

  await page.goto(`${ADMIN}/dashboard/`, { waitUntil: 'domcontentloaded', timeout: 10000 });
  // Wait for the React mount to settle.
  await page.waitForSelector('main.content', { timeout: 5000 });

  for (const route of ROUTES) {
    const url = `${ADMIN}/dashboard/#/${route}`;
    await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 10000 });
    await page.waitForFunction(
      r => location.hash === `#/${r}`,
      route,
      { timeout: 3000 }
    );
    // Give animations / SSE one tick to settle.
    await page.waitForTimeout(400);
    const file = join(OUT, `${route}.png`);
    await page.screenshot({ path: file, fullPage: true });
    console.log(`captured ${route} → ${file}`);
  }

  await browser.close();
  console.log(`\nWrote ${ROUTES.length} screenshots to ${OUT}`);
}

main().catch(err => {
  console.error(err);
  process.exit(1);
});
