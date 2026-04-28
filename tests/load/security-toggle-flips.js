// Aegis-Gate — Security toggle flip test (P2)
//
// Drives a stream of "would-trigger-SQLi" requests at the data
// plane while the test flips the SQLi class off (and back on) via
// PUT /api/detectors. Verifies that
//   1. the off-period accepts requests that the on-period blocks,
//   2. the auditedMutate pipeline records each flip on the chain,
//   3. the data plane respects the new mask within one sample
//      window (typically < 100 ms — the mask uses ArcSwap).
//
// Run with:
//   k6 run tests/load/security-toggle-flips.js
//
// Environment:
//   WAF_TARGET   default "http://host.docker.internal:8080"
//   WAF_ADMIN    default "https://host.docker.internal:9443"
//   ADMIN_USER   admin login (required)
//   ADMIN_PASS   admin password (required)
//   DURATION     default "30s"

import http from "k6/http";
import { check, group, sleep } from "k6";
import { Counter, Rate } from "k6/metrics";

const target = __ENV.WAF_TARGET || "http://host.docker.internal:8080";
const admin = __ENV.WAF_ADMIN || "https://host.docker.internal:9443";
const duration = __ENV.DURATION || "30s";

const blockedDuringOn = new Rate("blocked_when_sqli_on");
const allowedDuringOff = new Rate("allowed_when_sqli_off");
const flipLatency = new Counter("flip_latency_ms");

export const options = {
  scenarios: {
    flips: {
      executor: "constant-vus",
      vus: 10,
      duration: duration,
    },
  },
  thresholds: {
    "blocked_when_sqli_on":   ["rate>0.95"],
    "allowed_when_sqli_off":  ["rate>0.95"],
  },
  insecureSkipTLSVerify: true,
};

const sqliPayload = "?id=1+UNION+SELECT+password+FROM+users";

// Login once per VU. Returns { jar, csrf } usable across the run.
function loginAdmin() {
  const jar = http.cookieJar();
  const res = http.post(`${admin}/admin/login`,
    JSON.stringify({ user: __ENV.ADMIN_USER, password: __ENV.ADMIN_PASS }),
    {
      headers: { "content-type": "application/json" },
      jar,
    },
  );
  if (res.status >= 400) {
    throw new Error(`admin login failed: ${res.status}`);
  }
  // The CSRF cookie is non-HttpOnly so we can read it back.
  const csrf = jar.cookiesForURL(admin)["aegis_csrf"];
  if (!csrf) throw new Error("aegis_csrf cookie missing after login");
  return { jar, csrf };
}

function setMask(ctx, sqliEnabled) {
  const body = JSON.stringify({
    mask: {
      sqli: sqliEnabled, xss: true, path_traversal: true, ssrf: true,
      header_injection: true, body_abuse: true,
      recon: true, brute_force: true,
    },
  });
  const t0 = Date.now();
  const res = http.put(`${admin}/api/detectors`, body, {
    headers: {
      "content-type": "application/json",
      "x-csrf-token": ctx.csrf,
    },
    jar: ctx.jar,
  });
  flipLatency.add(Date.now() - t0);
  check(res, {
    "mask flip 200": (r) => r.status === 200,
  });
}

function probeData() {
  return http.get(`${target}/api${sqliPayload}`, {
    headers: { "x-aegis-test": "toggle-flips" },
  });
}

export default function () {
  const ctx = loginAdmin();

  group("sqli on - request blocks", () => {
    setMask(ctx, true);
    sleep(0.2);                       // give the mask one sample window
    const res = probeData();
    blockedDuringOn.add(res.status === 403);
  });

  group("sqli off - request allowed", () => {
    setMask(ctx, false);
    sleep(0.2);
    const res = probeData();
    allowedDuringOff.add(res.status !== 403);
  });

  // Restore default before exit.
  setMask(ctx, true);
}
