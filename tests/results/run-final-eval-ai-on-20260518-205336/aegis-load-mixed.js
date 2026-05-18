// Mixed legit/attack traffic on the data plane, AI detector ON.
// Spoofs many source IPs via X-Forwarded-For so the burst & per-IP
// limiter sees a realistic spread (otherwise everything collapses
// onto 127.0.0.1).
//
// Goal: measure WAF behavior under sustained ~500 RPS with ~30% attack
// mix; capture p50/p95/p99, block rate, AI-rule rate.
//
// Usage:
//   k6 run --vus 60 --duration 30s tests/.../aegis-load-mixed.js

import http from "k6/http";
import { Trend, Rate, Counter } from "k6/metrics";

const target = __ENV.WAF_TARGET || "http://127.0.0.1:8080";
const duration = __ENV.DURATION || "30s";
const vus = parseInt(__ENV.VUS || "60", 10);

const lat   = new Trend("waf_latency_ms", true);
const blockRate = new Rate("blocked");
const aiHits = new Counter("ai_rule_hits");
const allowedRate = new Rate("allowed");

export const options = {
  scenarios: { mixed: { executor: "constant-vus", vus, duration } },
};

// Spread requests across 200 synthetic source IPs (10.x.x.x range)
function spoofIp(vu, iter) {
  // 200-IP pool indexed by (vu * 7 + iter) mod 200
  const idx = (vu * 7 + iter) % 2000;
  const a = 10, b = 50 + ((idx >> 4) & 0xff), c = (idx & 0xff), d = 100 + (iter & 0x3f);
  return `${a}.${b}.${c}.${d}`;
}

const legit = [
  "/", "/api/list", "/static/app.js", "/favicon.ico",
  "/rest/products/search?q=apple", "/api/health",
  "/api/list?page=2&limit=20", "/news/2026/02/release-notes",
  "/oauth/callback?code=abc123&state=xyz",
  "/search?q=running+shoes",
];

const attacks = [
  "/q?u=1%27%20AND%20extractvalue(1,concat(0x7e,(SELECT%20version())))--",
  "/rest/products/search?q=%27;drop+table+users--",
  "/q?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E",
  "/q?q=%3Csvg%2Fonload%3Dalert(1)%3E",
  "/static/../../../../../../etc/passwd",
  "/redirect?to=http%3A%2F%2F169.254.169.254%2F",
  "/redirect?to=file%3A%2F%2F%2Fetc%2Fpasswd",
  "/q?q=apple%60id%60",
  "/api/products?id[]=admin&id[]=user",
  "/rest/products/search?q=1+OR+1=1",
];

export default function () {
  const isAttack = Math.random() < 0.05;
  const pool = isAttack ? attacks : legit;
  const path = pool[Math.floor(Math.random() * pool.length)];
  const ip = spoofIp(__VU, __ITER);

  const res = http.get(`${target}${path}`, {
    headers: {
      "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605",
      "Accept": "text/html,application/json;q=0.9",
      "Accept-Language": "en-US,en;q=0.8",
      "Referer": "https://example.com/",
      "X-Forwarded-For": ip,
    },
    tags: { kind: isAttack ? "attack" : "legit" },
  });
  lat.add(res.timings.duration);
  const blocked = res.status === 403;
  blockRate.add(blocked);
  allowedRate.add(!blocked);
  const rule = res.headers["X-Waf-Rule-Id"] || res.headers["x-waf-rule-id"] || "";
  if (rule.split(",").map((r) => r.trim()).indexOf("ai") !== -1) aiHits.add(1);
}
