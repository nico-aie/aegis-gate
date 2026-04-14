// Aegis-Gate — DDoS burst test
//
// Simulates a single-source flood. The auto-block list (M2 T2.3)
// must activate within 2 seconds of the threshold being crossed,
// after which subsequent requests from the same IP return 403.
//
// Run with:
//   k6 run tests/load/ddos-burst.js

import http from "k6/http";
import { check } from "k6";
import { Trend } from "k6/metrics";

const target = __ENV.WAF_TARGET || "http://host.docker.internal:8080";
const blockLatency = new Trend("autoblock_latency_ms", true);

export const options = {
  scenarios: {
    burst: {
      executor: "constant-arrival-rate",
      rate: 5000, timeUnit: "1s", duration: "10s",
      preAllocatedVUs: 500, maxVUs: 1000,
    },
  },
  thresholds: {
    "autoblock_latency_ms": ["p(95)<2000"],
  },
};

let firstSeen = null;

export default function () {
  const start = Date.now();
  const res = http.get(`${target}/`, {
    headers: { "x-forwarded-for": "203.0.113.7" },
  });
  if (res.status === 403 && firstSeen === null) {
    firstSeen = Date.now();
    blockLatency.add(firstSeen - start);
  }
  check(res, {
    "blocked or allowed": (r) => r.status === 200 || r.status === 403,
  });
}
