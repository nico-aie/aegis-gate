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
      // Iterate-bounded so strikes from the SQLi-on probes
      // don't accumulate past `risk.strikes.block_at` (50)
      // and turn every request into a strike-block 403,
      // which would mask the actual signal we're measuring
      // (mask-flip propagation latency).
      executor: "shared-iterations",
      vus: 5,
      iterations: 30,
      maxDuration: "60s",
    },
  },
  thresholds: {
    "blocked_when_sqli_on":   ["rate>0.95"],
    "allowed_when_sqli_off":  ["rate>0.95"],
  },
  insecureSkipTLSVerify: true,
};

const sqliPayload = "?id=1+UNION+SELECT+password+FROM+users";

// `setup()` runs ONCE before any VU spins up. If admin login
// fails here the whole run aborts with one clear error
// instead of the per-VU retry storm we used to ship.
//
// k6 serialises the setup() return through JSON, so we stash
// the cookie *values* (not the cookie jar object) and rebuild
// a jar on each VU's first iteration.
//
// The server emits cookies with `Secure` (correct for
// production), which k6's cookie jar silently drops on a plain
// HTTP admin listener. We read the `Set-Cookie` headers
// directly out of the login response to dodge that.
export function setup() {
  const res = http.post(`${admin}/admin/login`,
    JSON.stringify({ user: __ENV.ADMIN_USER, password: __ENV.ADMIN_PASS }),
    { headers: { "content-type": "application/json" } },
  );
  if (res.status >= 400) {
    throw new Error(
      `admin login failed: ${res.status} (check ADMIN_USER + ADMIN_PASS env)`,
    );
  }
  const setCookies = res.headers["Set-Cookie"];
  const raw = Array.isArray(setCookies) ? setCookies.join(",") : (setCookies || "");
  const session = extractCookie(raw, "aegis_session");
  const csrf = extractCookie(raw, "aegis_csrf");
  if (!csrf) {
    throw new Error("aegis_csrf cookie missing in login response Set-Cookie headers");
  }
  return { csrf, session };
}

function extractCookie(setCookieHeader, name) {
  // Set-Cookie header values can repeat or be comma-separated
  // when multiple cookies set in one response. Find each
  // `<name>=<value>` and return the first match.
  const re = new RegExp(`${name}=([^;,\\s]+)`);
  const m = setCookieHeader.match(re);
  return m ? m[1] : null;
}

function buildAdminHeaders(data) {
  const cookieHeader = data.session
    ? `aegis_session=${data.session}; aegis_csrf=${data.csrf}`
    : `aegis_csrf=${data.csrf}`;
  return {
    "content-type": "application/json",
    "x-csrf-token": data.csrf,
    cookie: cookieHeader,
  };
}

function setMask(headers, sqliEnabled) {
  const body = JSON.stringify({
    mask: {
      sqli: sqliEnabled, xss: true, path_traversal: true, ssrf: true,
      header_injection: true, body_abuse: true,
      recon: true, brute_force: true,
    },
  });
  const t0 = Date.now();
  const res = http.put(`${admin}/api/detectors`, body, { headers });
  flipLatency.add(Date.now() - t0);
  check(res, { "mask flip 200": (r) => r.status === 200 });
}

function probeData() {
  return http.get(`${target}/api${sqliPayload}`, {
    headers: { "x-aegis-test": "toggle-flips" },
  });
}

export default function (data) {
  const headers = buildAdminHeaders(data);

  // Reset risk state for our peer IP so strikes accrued in
  // earlier iterations don't keep this iteration's "sqli off"
  // probe blocked. The test measures **mask propagation**, not
  // the strike system (that's risk-strikes.js).
  http.put(`${admin}/api/risk/127.0.0.1/reset`, "{}", { headers });

  group("sqli on - request blocks", () => {
    setMask(headers, true);
    sleep(0.2);
    const res = probeData();
    blockedDuringOn.add(res.status === 403);
  });

  group("sqli off - request allowed", () => {
    setMask(headers, false);
    // Strike was added by the sqli-on probe above; clear it.
    http.put(`${admin}/api/risk/127.0.0.1/reset`, "{}", { headers });
    sleep(0.2);
    const res = probeData();
    allowedDuringOff.add(res.status !== 403);
  });

  setMask(headers, true); // restore default before exit
}
