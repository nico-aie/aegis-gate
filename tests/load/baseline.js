// Aegis-Gate — Baseline load test
//
// Golden-path RPS + latency SLO check. Runs against a fresh
// gateway with the dev config. CI gate: p99 <= 5ms, RPS >= 5000.
//
// Run with:
//   k6 run tests/load/baseline.js
//
// Environment:
//   WAF_TARGET  default "http://host.docker.internal:8080"
//   DURATION    default "60s"
//   VUS         default "200"

import http from "k6/http";
import { check } from "k6";
import { Trend, Rate } from "k6/metrics";

const target = __ENV.WAF_TARGET || "http://host.docker.internal:8080";
const duration = __ENV.DURATION || "60s";
const vus = parseInt(__ENV.VUS || "200", 10);

const allowLatency = new Trend("allow_latency_ms", true);
const allowRate = new Rate("allow_success");

export const options = {
  scenarios: {
    baseline: {
      executor: "constant-vus",
      vus: vus,
      duration: duration,
    },
  },
  thresholds: {
    "allow_latency_ms": ["p(99)<5"],
    "allow_success":    ["rate>0.999"],
    "http_reqs":        ["rate>5000"],
  },
};

export default function () {
  const res = http.get(`${target}/get`, {
    headers: { "x-aegis-test": "baseline" },
  });
  allowLatency.add(res.timings.duration);
  allowRate.add(res.status === 200);
  check(res, { "status is 200": (r) => r.status === 200 });
}
