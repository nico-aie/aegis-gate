// Aegis-Gate — prod-balanced 5k+ RPS throughput-focused stress test (v2).
//
// Goal: sustain >5000 RPS through the WAF for $DURATION (default 2m)
// from a single source IP without saturating macOS ephemeral ports.
//
// Differences vs prod-balanced-5k.js:
//   - constant-arrival-rate executor (k6 holds rate; we don't pace via sleep)
//   - one request per iteration (no 9-call legitFlow groups — that ballooned
//     the connection count under VU-per-pacer driving)
//   - tiny VU pool (50 + 20 + 30) — k6 reuses HTTP keep-alive within each VU,
//     so few VUs = few sockets = no TIME_WAIT pile-up
//   - no per-iter sleep; the executor handles timing
//
// What's still the same:
//   - 15-shape attack corpus (detection comparable across runs)
//   - same scenarios: legit / crawler / attacker
//   - same WAF target

import http from "k6/http";
import { Trend, Rate, Counter } from "k6/metrics";

const target = __ENV.WAF_TARGET || "http://127.0.0.1:8080";
const duration = __ENV.DURATION || "2m";
const legitRps = parseInt(__ENV.LEGIT_RPS || "4000", 10);
const crawlerRps = parseInt(__ENV.CRAWLER_RPS || "300", 10);
const attackerRps = parseInt(__ENV.ATTACKER_RPS || "1000", 10);

const legitP99 = new Trend("legit_p99_ms", true);
const legitOk = new Rate("legit_ok_rate");
const attacksDetected = new Counter("attacks_detected");
const attacksPrevented = new Counter("attacks_prevented");
const attacksTotal = new Counter("attacks_total");

const ACCOUNTS = [
  { user: "alice",   password: "P@ssw0rd1" },
  { user: "bob",     password: "S3cureP@ss" },
  { user: "charlie", password: "Ch@rlie99" },
];

const LEGIT_PATHS = [
  ["GET",  "/api/profile",                null],
  ["GET",  "/game/list",                  null],
  ["GET",  "/game/g1",                    null],
  ["POST", "/game/g1/play",               null],
  ["GET",  "/api/transactions?limit=20",  null],
  ["POST", "/api/rewards/claim",          null],
  ["GET",  "/health",                     null],
];

const CRAWLER_PATHS = [
  "/health", "/about", "/sitemap.xml",
  "/api/public/stats", "/static/main.js", "/public/robots.txt",
];

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
  // VU pools sized so each VU only needs to handle a handful of in-flight
  // requests at sub-ms latency. With keep-alive on (default), a tiny pool
  // = a tiny socket count = no TIME_WAIT pile-up on loopback.
  scenarios: {
    legit_users: {
      executor: "constant-arrival-rate",
      rate: legitRps, timeUnit: "1s",
      duration: duration,
      preAllocatedVUs: 50, maxVUs: 100,
      exec: "legitFlow", tags: { scenario: "legit" },
    },
    crawlers: {
      executor: "constant-arrival-rate",
      rate: crawlerRps, timeUnit: "1s",
      duration: duration,
      preAllocatedVUs: 10, maxVUs: 30,
      exec: "crawlerFlow", tags: { scenario: "crawler" },
      startTime: "5s",
    },
    attackers: {
      executor: "constant-arrival-rate",
      rate: attackerRps, timeUnit: "1s",
      duration: duration,
      preAllocatedVUs: 30, maxVUs: 60,
      exec: "attackerFlow", tags: { scenario: "attacker" },
      startTime: "10s",
    },
  },
  thresholds: {
    "legit_p99_ms":      [{ threshold: "p(99)<200", abortOnFail: false }],
    "legit_ok_rate":     [{ threshold: "rate>0.95", abortOnFail: false }],
    "http_req_duration": [{ threshold: "p(95)<50",  abortOnFail: false }],
  },
};

export function legitFlow() {
  // One request per iteration. Round-robin across the path mix
  // weighted slightly toward GETs.
  const idx = (__ITER + __VU) % LEGIT_PATHS.length;
  const [method, path, body] = LEGIT_PATHS[idx];
  const r = http.request(method, `${target}${path}`, body, {
    tags: { ep: path },
    headers: body ? { "content-type": "application/json" } : {},
  });
  legitP99.add(r.timings.duration);
  legitOk.add(r.status >= 200 && r.status < 400);
}

export function crawlerFlow() {
  const p = CRAWLER_PATHS[(__ITER + __VU) % CRAWLER_PATHS.length];
  http.get(`${target}${p}`, { tags: { ep: p } });
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
}
