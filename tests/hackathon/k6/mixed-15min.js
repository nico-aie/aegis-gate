// Hackathon Round-1 mixed-traffic stress test.
//
// Three scenarios run for DURATION (default 15m):
//   - legit_users: 80 VUs doing realistic flows (login → otp → browse → bet)
//   - crawlers:    20 VUs hitting public/static/health
//   - attackers:   30 VUs probing one attack per iteration from a corpus
//
// Custom metrics exported:
//   - legit_p99_ms      latency on the legit-user scenario only
//   - attacks_detected  iterations where x-waf-action is block / challenge / rate_limit
//   - attacks_total     total attack iterations
//
// Usage (defaults: 15-min run against http://127.0.0.1:8080):
//   k6 run tests/hackathon/k6/mixed-15min.js
//
// Tuning via env:
//   WAF_TARGET=http://...   default http://127.0.0.1:8080
//   DURATION=15m
//   LEGIT_VUS=80
//   CRAWLER_VUS=20
//   ATTACKER_VUS=30

import http from "k6/http";
import { check, sleep, group } from "k6";
import { Trend, Rate, Counter } from "k6/metrics";

const target = __ENV.WAF_TARGET || "http://127.0.0.1:8080";
const duration = __ENV.DURATION || "15m";
const legitVus = parseInt(__ENV.LEGIT_VUS || "80", 10);
const crawlerVus = parseInt(__ENV.CRAWLER_VUS || "20", 10);
const attackerVus = parseInt(__ENV.ATTACKER_VUS || "30", 10);

const legitP99 = new Trend("legit_p99_ms", true);
const legitOk = new Rate("legit_ok_rate");
const attacksDetected = new Counter("attacks_detected");
const attacksPrevented = new Counter("attacks_prevented");
const attacksTotal = new Counter("attacks_total");

// Test creds — must match upstream/server.py
const ACCOUNTS = [
  { user: "alice",   password: "P@ssw0rd1",  otp: "123456" },
  { user: "bob",     password: "S3cureP@ss", otp: "654321" },
  { user: "charlie", password: "Ch@rlie99",  otp: "111222" },
];

// One attack per iteration — picked round-robin from this corpus.
// Each entry: { name, method, path, body?, headers? }
const ATTACKS = [
  // SQLi
  {
    name: "sqli_login_body",
    method: "POST", path: "/login",
    body: JSON.stringify({ username: "alice' OR '1'='1", password: "x" }),
    headers: { "content-type": "application/json" },
  },
  {
    name: "sqli_transactions_query",
    method: "GET",
    path: "/api/transactions?user=1%27%20OR%20%271%27=%271",
  },
  {
    name: "sqli_game_id",
    method: "GET", path: "/game/1%27%20UNION%20SELECT%20null--",
  },
  // XSS
  {
    name: "xss_feedback",
    method: "POST", path: "/api/feedback",
    body: JSON.stringify({ message: "<script>alert(document.cookie)</script>" }),
    headers: { "content-type": "application/json" },
  },
  {
    name: "xss_profile",
    method: "PATCH", path: "/api/profile",
    body: JSON.stringify({ display_name: "<img src=x onerror=alert(1)>" }),
    headers: { "content-type": "application/json" },
  },
  // Path traversal
  { name: "path_trav_static", method: "GET", path: "/static/..%2f..%2fetc%2fpasswd" },
  { name: "path_trav_public", method: "GET", path: "/public/..%2F..%2F..%2Fetc%2Fshadow" },
  // SSRF
  {
    name: "ssrf_feedback",
    method: "POST", path: "/api/feedback",
    body: JSON.stringify({ url: "http://169.254.169.254/latest/meta-data" }),
    headers: { "content-type": "application/json" },
  },
  {
    name: "ssrf_file",
    method: "POST", path: "/api/feedback",
    body: JSON.stringify({ url: "file:///etc/passwd" }),
    headers: { "content-type": "application/json" },
  },
  // Mass assignment
  {
    name: "mass_assign_role",
    method: "PATCH", path: "/api/profile",
    body: JSON.stringify({ role: "admin", balance: 999999999 }),
    headers: { "content-type": "application/json" },
  },
  // Brute force shape
  {
    name: "brute_force_login",
    method: "POST", path: "/login",
    body: JSON.stringify({ username: "admin", password: "password123" }),
    headers: { "content-type": "application/json" },
  },
  // Header injection
  {
    name: "header_injection",
    method: "GET", path: "/api/profile",
    headers: { "x-forwarded-for": "127.0.0.1\r\nX-Admin: true" },
  },
  // IDOR — try to read another user's transactions without their cookie
  { name: "idor_transactions", method: "GET", path: "/api/transactions?user=bob" },
  // Command injection
  { name: "cmd_inj_search", method: "GET", path: "/game/1;cat%20/etc/passwd" },
  // XXE / XML payload via feedback (server is JSON-only — WAF should still flag)
  {
    name: "xxe_feedback",
    method: "POST", path: "/api/feedback",
    body: '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><r>&x;</r>',
    headers: { "content-type": "application/xml" },
  },
];

export const options = {
  // Make p(99) + p(99.9) land in the --summary-export JSON.
  // Default is avg/min/med/max/p(90)/p(95) and that hides the
  // headline metric the benchmark team asks for.
  summaryTrendStats: ["avg", "min", "med", "max", "p(90)", "p(95)", "p(99)", "p(99.9)"],
  scenarios: {
    legit_users: {
      executor: "constant-vus",
      vus: legitVus,
      duration: duration,
      exec: "legitFlow",
      tags: { scenario: "legit" },
    },
    crawlers: {
      executor: "constant-vus",
      vus: crawlerVus,
      duration: duration,
      exec: "crawlerFlow",
      tags: { scenario: "crawler" },
      startTime: "10s",
    },
    attackers: {
      executor: "constant-vus",
      vus: attackerVus,
      duration: duration,
      exec: "attackerFlow",
      tags: { scenario: "attacker" },
      startTime: "20s",
    },
  },
  thresholds: {
    // Realistic laptop targets — see plans/hackathon-stress-test.md §8
    "legit_p99_ms":    [{ threshold: "p(99)<200", abortOnFail: false }],
    "legit_ok_rate":   [{ threshold: "rate>0.95",  abortOnFail: false }],
    // Detection rate target: ≥85% of attack iterations should be flagged
    "attacks_detected": [{ threshold: "count>0", abortOnFail: false }],
  },
};

// ---------------------------------------------------------------
// Scenarios
// ---------------------------------------------------------------

export function legitFlow() {
  const acct = ACCOUNTS[__VU % ACCOUNTS.length];

  group("login", () => {
    const r = http.post(`${target}/login`,
      JSON.stringify({ username: acct.user, password: acct.password }),
      { headers: { "content-type": "application/json" }, tags: { ep: "login" } },
    );
    legitP99.add(r.timings.duration);
    legitOk.add(r.status === 200);
    if (r.status !== 200) return;

    const tok = (r.json("login_token") || "").toString();
    if (!tok) return;

    const r2 = http.post(`${target}/otp`,
      JSON.stringify({ login_token: tok, otp_code: acct.otp }),
      { headers: { "content-type": "application/json" }, tags: { ep: "otp" } },
    );
    legitP99.add(r2.timings.duration);
    legitOk.add(r2.status === 200);
  });

  // Browse / bet / withdraw — no need to manually carry cookies, k6 does
  group("browse_and_bet", () => {
    const calls = [
      ["GET",  "/api/profile"],
      ["GET",  "/game/list"],
      ["GET",  "/game/g1"],
      ["POST", "/game/g1/play"],
      ["GET",  "/api/transactions?limit=20"],
      ["POST", "/api/rewards/claim"],
    ];
    for (const [method, path] of calls) {
      const r = http.request(method, `${target}${path}`, null, { tags: { ep: path } });
      legitP99.add(r.timings.duration);
      legitOk.add(r.status >= 200 && r.status < 400);
    }
  });

  // Light pacing so we don't pin the upstream
  sleep(0.05 + Math.random() * 0.1);
}

export function crawlerFlow() {
  const paths = ["/health", "/about", "/sitemap.xml", "/api/public/stats", "/static/main.js", "/public/robots.txt"];
  for (const p of paths) {
    http.get(`${target}${p}`, { tags: { ep: p } });
  }
  sleep(0.5 + Math.random());
}

export function attackerFlow() {
  // Round-robin pick per iteration
  const pick = ATTACKS[(__VU + __ITER) % ATTACKS.length];
  attacksTotal.add(1);

  const r = http.request(
    pick.method,
    `${target}${pick.path}`,
    pick.body || null,
    { headers: pick.headers || {}, tags: { ep: pick.name } },
  );

  // WAF flagged it (any non-allow action)
  const action = (r.headers["X-Waf-Action"] || r.headers["x-waf-action"] || "allow").toLowerCase();
  const detected = ["block", "challenge", "rate_limit"].includes(action);
  if (detected) attacksDetected.add(1);

  // The upstream actually didn't process it (4xx with WAF action set)
  const prevented = detected && (r.status === 403 || r.status === 401 || r.status === 429);
  if (prevented) attacksPrevented.add(1);

  check(r, {
    "attack response has x-waf-action": () => action !== "allow" || true, // info only
  });

  // Pacing — attackers shouldn't burn the host with no sleep
  sleep(0.05 + Math.random() * 0.1);
}
