// Aegis-Gate — Risk-strike permanent block (P6)
//
// Drives a single source IP through enough malicious events to
// exhaust the lifetime strike counter, then verifies that
// follow-up *clean* requests from that IP are still blocked
// because of the strike-block invariant — score decay must not
// reopen the door.
//
// Run with:
//   k6 run tests/load/risk-strikes.js
//
// Environment:
//   WAF_TARGET    data plane         (default http://host.docker.internal:8080)
//   WAF_ADMIN     control plane      (default https://host.docker.internal:9443)
//   ADMIN_USER    admin login user
//   ADMIN_PASS    admin password
//   STRIKE_LIMIT  must match the running config's `risk.strikes.block_at` (default 50)

import http from "k6/http";
import { check, group } from "k6";
import { Rate, Trend } from "k6/metrics";

const target = __ENV.WAF_TARGET || "http://host.docker.internal:8080";
const admin = __ENV.WAF_ADMIN || "https://host.docker.internal:9443";
const strikeLimit = parseInt(__ENV.STRIKE_LIMIT || "50", 10);
const sourceIp = "203.0.113.42";

const cleanBlocked = new Rate("clean_request_blocked_after_strike");
const blockReached = new Rate("strike_block_reached");
const blockLatency = new Trend("strike_block_latency_ms", true);

export const options = {
  scenarios: {
    strikes: {
      executor: "shared-iterations",
      vus: 1,
      iterations: 1,
      maxDuration: "60s",
    },
  },
  thresholds: {
    "strike_block_reached": ["rate==1"],
    "clean_request_blocked_after_strike": ["rate==1"],
  },
  insecureSkipTLSVerify: true,
};

function loginAdmin() {
  const jar = http.cookieJar();
  const res = http.post(`${admin}/admin/login`,
    JSON.stringify({ user: __ENV.ADMIN_USER, password: __ENV.ADMIN_PASS }),
    { headers: { "content-type": "application/json" }, jar },
  );
  if (res.status >= 400) throw new Error(`admin login: ${res.status}`);
  const csrf = jar.cookiesForURL(admin)["aegis_csrf"];
  return { jar, csrf };
}

function malicious() {
  return http.get(
    `${target}/api?id=1+UNION+SELECT+password+FROM+users`,
    { headers: { "x-forwarded-for": sourceIp } },
  );
}

function clean() {
  return http.get(`${target}/get`, {
    headers: { "x-forwarded-for": sourceIp },
  });
}

export default function () {
  const ctx = loginAdmin();

  // Reset risk state for the source IP so the run is deterministic.
  http.put(`${admin}/api/risk/${sourceIp}/reset`, "{}", {
    headers: { "x-csrf-token": ctx.csrf, "content-type": "application/json" },
    jar: ctx.jar,
  });

  group("drive to strike block", () => {
    const t0 = Date.now();
    let blocked = false;
    for (let i = 0; i < strikeLimit + 5; i++) {
      const res = malicious();
      if (res.status === 403) blocked = true;
    }
    blockReached.add(blocked);
    blockLatency.add(Date.now() - t0);
  });

  group("clean traffic still blocked", () => {
    const res = clean();
    cleanBlocked.add(res.status === 403);
    check(res, { "strike-blocked clean req returns 403": (r) => r.status === 403 });
  });

  // Snapshot the post-state so the run leaves a clear trail.
  const snap = http.get(`${admin}/api/risk/${sourceIp}`, { jar: ctx.jar });
  console.log("post-state risk snapshot:", snap.body);

  // Cleanup so re-runs start from zero strikes.
  http.put(`${admin}/api/risk/${sourceIp}/reset`, "{}", {
    headers: { "x-csrf-token": ctx.csrf, "content-type": "application/json" },
    jar: ctx.jar,
  });
}
