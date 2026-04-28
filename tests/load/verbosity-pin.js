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

function login() {
  const jar = http.cookieJar();
  const r = http.post(`${admin}/admin/login`,
    JSON.stringify({ user: __ENV.ADMIN_USER, password: __ENV.ADMIN_PASS }),
    { headers: { "content-type": "application/json" }, jar });
  if (r.status >= 400) throw new Error(`login: ${r.status}`);
  return { jar, csrf: jar.cookiesForURL(admin)["aegis_csrf"] };
}

function setLevel(ctx, level) {
  http.put(`${admin}/api/logging`, JSON.stringify({ level }), {
    headers: { "content-type": "application/json", "x-csrf-token": ctx.csrf },
    jar: ctx.jar,
  });
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

export default function () {
  const ctx = login();
  // baseline cursor before silent window
  const before = auditHigh();
  setLevel(ctx, "silent");
  sleep(8);                       // 8s of traffic at 100 rps = 800 blocks
  const during = auditHigh();
  setLevel(ctx, "info");
  silentNewEntries.add(during - before);

  // Restore default for follow-on tests.
  setLevel(ctx, "info");
}
