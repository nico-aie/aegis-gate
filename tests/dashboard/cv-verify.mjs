import { chromium } from 'playwright';
const ADMIN = 'http://127.0.0.1:9443';
const browser = await chromium.launch({ headless: true });
const ctx = await browser.newContext({ viewport: { width: 1440, height: 1100 }, ignoreHTTPSErrors: true });
const loginRes = await ctx.request.post(`${ADMIN}/admin/login`, { data: { user: 'admin', password: 'aegis-test-1234' } });
console.log(`login: ${loginRes.status()}`);
const page = await ctx.newPage();
await page.goto(`${ADMIN}/dashboard/#/settings`, { waitUntil: 'domcontentloaded', timeout: 10000 });
await page.waitForTimeout(800);
// Click first row to expand
await page.click('text=mode_set').catch(() => {});
await page.waitForTimeout(400);
await page.screenshot({ path: '/tmp/cv-expanded.png', fullPage: true });
await browser.close();
console.log('saved /tmp/cv-expanded.png');
