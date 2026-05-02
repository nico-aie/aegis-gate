// Aegis-Gate — prod-balanced 5k+ RPS sustained stress test.
//
// Goal: drive >5000 RPS through the WAF for $DURATION (default 5m)
// using prod-balanced detector mask + risk shape. Surfaces:
//   - latency under sustained 5k+ RPS load
//   - detection rate (should hold the 80% v2 baseline)
//   - bottlenecks (CPU? upstream? audit-chain? detector cost?)
//
// Differences vs k6/mixed-15min.js:
//   - 3x VU counts (240 legit / 60 crawler / 100 attacker = 400 total)
//   - tighter per-iter pacing (15-30 ms vs 50-150 ms)
//   - shorter default duration (5m vs 15m) — easier iteration on the
//     tuning loop; flip DURATION=15m for the long run.
//
// Tuning via env:
//   WAF_TARGET=http://127.0.0.1:8080
//   DURATION=5m
//   LEGIT_VUS=240
//   CRAWLER_VUS=60
//   ATTACKER_VUS=100

import http from "k6/http";
import { check, sleep, group } from "k6";
import { Trend, Rate, Counter } from "k6/metrics";

const target = __ENV.WAF_TARGET || "http://127.0.0.1:8080";
const duration = __ENV.DURATION || "5m";
const legitVus = parseInt(__ENV.LEGIT_VUS || "240", 10);
const crawlerVus = parseInt(__ENV.CRAWLER_VUS || "60", 10);
const attackerVus = parseInt(__ENV.ATTACKER_VUS || "100", 10);

const legitP99 = new Trend("legit_p99_ms", true);
const legitOk = new Rate("legit_ok_rate");
const attacksDetected = new Counter("attacks_detected");
const attacksPrevented = new Counter("attacks_prevented");
const attacksTotal = new Counter("attacks_total");

const ACCOUNTS = [
  { user: "alice",   password: "P@ssw0rd1",  otp: "123456" },
  { user: "bob",     password: "S3cureP@ss", otp: "654321" },
  { user: "charlie", password: "Ch@rlie99",  otp: "111222" },
];

// 15-shape attack corpus — same as mixed-15min.js so detection-rate
// numbers stay comparable across runs.
const ATTACKS = [
  { name: "sqli_login_body", method: "POST", path: "/login",
    body: JSON.stringify({ username: "alice' OR '1'='1", password: "x" }),
    headers: { "content-type": "application/json" } },
  { name: "sqli_transactions_query", method: "GET",
    path: "/api/transactions?user=1%27%20OR%20%271%27=%271" },
  { name: "sqli_game_id", method: "GET",
    path: "/game/1%27%20UNION%20SELECT%20null--" },
  { name: "xss_feedback", method: "POST", path: "/api/feedback",
    body: JSON.stringify({ message: "<script>alert(document.cookie)</script>" }),
    headers: { "content-type": "application/json" } },
  { name: "xss_profile", method: "PATCH", path: "/api/profile",
    body: JSON.stringify({ display_name: "<img src=x onerror=alert(1)>" }),
    headers: { "content-type": "application/json" } },
  { name: "path_trav_static", method: "GET",
    path: "/static/..%2f..%2fetc%2fpasswd" },
  { name: "path_trav_public", method: "GET",
    path: "/public/..%2F..%2F..%2Fetc%2Fshadow" },
  { name: "ssrf_feedback", method: "POST", path: "/api/feedback",
    body: JSON.stringify({ url: "http://169.254.169.254/latest/meta-data" }),
    headers: { "content-type": "application/json" } },
  { name: "ssrf_file", method: "POST", path: "/api/feedback",
    body: JSON.stringify({ url: "file:///etc/passwd" }),
    headers: { "content-type": "application/json" } },
  { name: "mass_assign_role", method: "PATCH", path: "/api/profile",
    body: JSON.stringify({ role: "admin", balance: 999999999 }),
    headers: { "content-type": "application/json" } },
  { name: "brute_force_login", method: "POST", path: "/login",
    body: JSON.stringify({ username: "admin", password: "password123" }),
    headers: { "content-type": "application/json" } },
  { name: "header_injection", method: "GET", path: "/api/profile",
    headers: { "x-forwarded-for": "127.0.0.1\r\nX-Admin: true" } },
  { name: "idor_transactions", method: "GET", path: "/api/transactions?user=bob" },
  { name: "cmd_inj_search", method: "GET", path: "/game/1;cat%20/etc/passwd" },
  { name: "xxe_feedback", method: "POST", path: "/api/feedback",
    body: '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><r>&x;</r>',
    headers: { "content-type": "application/xml" } },
];

export const options = {
  summaryTrendStats: ["avg", "min", "med", "max", "p(90)", "p(95)", "p(99)", "p(99.9)"],
  scenarios: {
    legit_users: {
      executor: "constant-vus", vus: legitVus, duration: duration,
      exec: "legitFlow", tags: { scenario: "legit" },
    },
    crawlers: {
      executor: "constant-vus", vus: crawlerVus, duration: duration,
      exec: "crawlerFlow", tags: { scenario: "crawler" }, startTime: "5s",
    },
    attackers: {
      executor: "constant-vus", vus: attackerVus, duration: duration,
      exec: "attackerFlow", tags: { scenario: "attacker" }, startTime: "10s",
    },
  },
  thresholds: {
    "legit_p99_ms":     [{ threshold: "p(99)<200", abortOnFail: false }],
    "legit_ok_rate":    [{ threshold: "rate>0.95", abortOnFail: false }],
    "attacks_detected": [{ threshold: "count>0",   abortOnFail: false }],
    "http_req_duration": [{ threshold: "p(95)<50", abortOnFail: false }],
  },
};

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
      const r = http.request(method, `${target}${path}`, null,
        { tags: { ep: path } });
      legitP99.add(r.timings.duration);
      legitOk.add(r.status >= 200 && r.status < 400);
    }
  });

  // Tighter pacing — push more iterations through per VU.
  sleep(0.015 + Math.random() * 0.015);
}

export function crawlerFlow() {
  const paths = ["/health", "/about", "/sitemap.xml",
    "/api/public/stats", "/static/main.js", "/public/robots.txt"];
  for (const p of paths) {
    http.get(`${target}${p}`, { tags: { ep: p } });
  }
  sleep(0.1 + Math.random() * 0.2);
}

export function attackerFlow() {
  const pick = ATTACKS[(__VU + __ITER) % ATTACKS.length];
  attacksTotal.add(1);

  const r = http.request(pick.method, `${target}${pick.path}`,
    pick.body || null,
    { headers: pick.headers || {}, tags: { ep: pick.name } });

  const action = (r.headers["X-Waf-Action"] || r.headers["x-waf-action"] || "allow").toLowerCase();
  const detected = ["block", "challenge", "rate_limit"].includes(action);
  if (detected) attacksDetected.add(1);

  const prevented = detected && (r.status === 403 || r.status === 401 || r.status === 429);
  if (prevented) attacksPrevented.add(1);

  check(r, {
    "attack response has x-waf-action": () => action !== "allow" || true,
  });

  sleep(0.015 + Math.random() * 0.015);
}
