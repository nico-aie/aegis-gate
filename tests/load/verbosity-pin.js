// Aegis-Gate — Verbosity pin (P8)
//
// Drives a steady stream of malicious requests at the data plane
// while toggling /api/logging through `info → silent → info`.
// Verifies that the audit endpoint stops returning fresh entries
// during the silent window even though clients keep getting 403s.
//
// Run with:
//   k6 run tests/load/verbosity-pin.js

import http from "k6/http";
import { check, sleep } from "k6";
import { Counter } from "k6/metrics";

const target = __ENV.WAF_TARGET || "http://host.docker.internal:8080";
const admin = __ENV.WAF_ADMIN || "https://host.docker.internal:9443";

const blocks = new Counter("blocks");
const silentNewEntries = new Counter("audit_entries_during_silent");

export const options = {
  scenarios: {
    pin: {
      executor: "shared-iterations",
      vus: 1,
      iterations: 1,
      maxDuration: "30s",
    },
    traffic: {
      executor: "constant-arrival-rate",
      rate: 100, timeUnit: "1s", duration: "20s",
      preAllocatedVUs: 30,
      exec: "trafficLoop",
    },
  },
  thresholds: {
    "audit_entries_during_silent": ["count==0"],
  },
  insecureSkipTLSVerify: true,
};

// Login once at startup; abort the whole run on failure. Reads
// `Set-Cookie` headers directly because the server emits Secure
// cookies which k6's jar drops over plain HTTP.
export function setup() {
  const r = http.post(`${admin}/admin/login`,
    JSON.stringify({ user: __ENV.ADMIN_USER, password: __ENV.ADMIN_PASS }),
    { headers: { "content-type": "application/json" } });
  if (r.status >= 400) {
    throw new Error(
      `admin login failed: ${r.status} (check ADMIN_USER + ADMIN_PASS env)`,
    );
  }
  const setCookies = r.headers["Set-Cookie"];
  const raw = Array.isArray(setCookies) ? setCookies.join(",") : (setCookies || "");
  const session = extractCookie(raw, "aegis_session");
  const csrf = extractCookie(raw, "aegis_csrf");
  if (!csrf) throw new Error("aegis_csrf cookie missing in login response");
  return { csrf, session };
}

function extractCookie(setCookieHeader, name) {
  const re = new RegExp(`${name}=([^;,\\s]+)`);
  const m = setCookieHeader.match(re);
  return m ? m[1] : null;
}

function buildAdminHeaders(data) {
  const cookie = data.session
    ? `aegis_session=${data.session}; aegis_csrf=${data.csrf}`
    : `aegis_csrf=${data.csrf}`;
  return {
    "content-type": "application/json",
    "x-csrf-token": data.csrf,
    cookie,
  };
}

function setLevel(headers, level) {
  http.put(`${admin}/api/logging`, JSON.stringify({ level }), { headers });
}

function auditHigh() {
  const r = http.get(`${admin}/api/audit/since?cursor=0&limit=1`);
  if (r.status !== 200) return 0;
  return JSON.parse(r.body).next_cursor || 0;
}

export function trafficLoop() {
  const r = http.get(
    `${target}/api?x=' OR 1=1 --`,
    { headers: { "x-aegis-test": "verbosity-pin" } },
  );
  if (r.status === 403) blocks.add(1);
}

export default function (data) {
  const headers = buildAdminHeaders(data);
  const before = auditHigh();
  setLevel(headers, "silent");
  sleep(8); // 8s of traffic at 100 rps = 800 blocks
  const during = auditHigh();
  setLevel(headers, "info");
  silentNewEntries.add(during - before);

  // Restore default for follow-on tests.
  setLevel(headers, "info");
}
