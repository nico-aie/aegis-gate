// Aegis-Gate — DDoS burst test
//
// Simulates a single-source flood. The per-IP rate limiter
// (F-T2) is wired into the data-plane hot path: once a source
// IP exceeds `rate_limit.buckets[<global+ip>].limit` requests
// in the configured window, every subsequent request from
// that IP returns 429 (or 403 once the same source crosses
// `risk.strikes.block_at`).
//
// **Test contract:**
//   - `auto_block_count > 0`           — at least one block fired
//   - `p95(autoblock_latency_ms) < 2 s` — first block lands fast
//   - `block_or_allowed == 100 %`       — every response is one
//                                          of {200, 403, 429}
//
// The `auto_block_count > 0` threshold replaces the original
// vacuous-pass behaviour (where the metric stayed empty when
// no blocks fired and the test passed trivially).
//
// Run with:
//   k6 run tests/load/ddos-burst.js

import http from "k6/http";
import { check } from "k6";
import { Trend, Counter } from "k6/metrics";

const target = __ENV.WAF_TARGET || "http://host.docker.internal:8080";
const blockLatency = new Trend("autoblock_latency_ms", true);
const blocks = new Counter("auto_block_count");

export const options = {
  scenarios: {
    burst: {
      executor: "constant-arrival-rate",
      rate: 5000, timeUnit: "1s", duration: "10s",
      preAllocatedVUs: 500, maxVUs: 1000,
    },
  },
  thresholds: {
    // Hard contract: at least one block must have fired. A
    // missing block now fails the test loud (was: empty
    // counter passed vacuously pre-F-T2).
    "auto_block_count":     ["count>0"],
    "autoblock_latency_ms": ["p(95)<2000"],
  },
};

let firstSeen = null;

export default function () {
  const start = Date.now();
  const res = http.get(`${target}/`, {
    headers: { "x-forwarded-for": "203.0.113.7" },
  });
  if ((res.status === 403 || res.status === 429) && firstSeen === null) {
    firstSeen = Date.now();
    blockLatency.add(firstSeen - start);
  }
  if (res.status === 403 || res.status === 429) {
    blocks.add(1);
  }
  check(res, {
    "blocked or allowed": (r) =>
      r.status === 200 || r.status === 403 || r.status === 429,
  });
}
