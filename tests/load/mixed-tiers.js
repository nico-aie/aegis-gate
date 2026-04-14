// Aegis-Gate — Mixed-tier traffic load test
//
// Sends a blend of CRITICAL/HIGH/MEDIUM requests to verify the
// tier-policy fail-mode contract: CRITICAL must never fail-open,
// MEDIUM may be shed under pressure.
//
// Run with:
//   k6 run tests/load/mixed-tiers.js

import http from "k6/http";
import { check } from "k6";
import { Counter } from "k6/metrics";

const target = __ENV.WAF_TARGET || "http://host.docker.internal:8080";

const criticalFailOpen = new Counter("critical_fail_open");

export const options = {
  scenarios: {
    critical: {
      executor: "constant-arrival-rate",
      rate: 500, timeUnit: "1s", duration: "60s",
      preAllocatedVUs: 50, maxVUs: 200,
      exec: "criticalPath",
    },
    high: {
      executor: "constant-arrival-rate",
      rate: 2000, timeUnit: "1s", duration: "60s",
      preAllocatedVUs: 100, maxVUs: 400,
      exec: "highPath",
    },
    medium: {
      executor: "constant-arrival-rate",
      rate: 3000, timeUnit: "1s", duration: "60s",
      preAllocatedVUs: 100, maxVUs: 400,
      exec: "mediumPath",
    },
  },
  thresholds: {
    "critical_fail_open": ["count==0"],
    "http_req_failed{tier:critical}": ["rate<0.001"],
  },
};

export function criticalPath() {
  const res = http.get(`${target}/api/payments`, {
    tags: { tier: "critical" },
  });
  // Any 2xx on critical path during a simulated backend failure is a fail-open.
  if (res.status >= 200 && res.status < 300 && __ENV.SIMULATE_BACKEND_DOWN) {
    criticalFailOpen.add(1);
  }
  check(res, { "critical responded": (r) => r.status !== 0 });
}

export function highPath() {
  http.get(`${target}/api/users`, { tags: { tier: "high" } });
}

export function mediumPath() {
  http.get(`${target}/static/index.html`, { tags: { tier: "medium" } });
}
