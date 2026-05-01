import { chromium } from 'playwright';
const ADMIN = 'http://127.0.0.1:9443';
const browser = await chromium.launch({ headless: true });
const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 }, ignoreHTTPSErrors: true });
const loginRes = await ctx.request.post(`${ADMIN}/admin/login`, { data: { user: 'admin', password: 'aegis-test-1234' } });
console.log(`login: ${loginRes.status()}`);
const page = await ctx.newPage();
await page.goto(`${ADMIN}/dashboard/#/rules`, { waitUntil: 'domcontentloaded', timeout: 10000 });
await page.waitForTimeout(800);
// Click the Simulate button
await page.click('text=Simulate');
await page.waitForTimeout(800);
await page.screenshot({ path: '/tmp/sim-verdict.png', fullPage: true });
await browser.close();
console.log('saved /tmp/sim-verdict.png');
