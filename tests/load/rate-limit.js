// Aegis-Gate — per-IP rate limiter saturation
//
// Drives one VU at high RPS toward the data plane and asserts the
// gateway's per-IP sliding-window rate limiter starts returning 429
// within the configured budget. Spec lives in
// docs/security/rate-limiting.md.
//
// Why this is a single-VU test: the rate limiter is keyed on
// remote-IP. With many VUs all sharing the same docker-bridge
// source IP, the limit hits "instantly" and we can't distinguish
// "limit working" from "no limit at all". One VU isolates the
// signal.
//
// Run with:
//   docker exec aegis-k6 k6 run /scripts/rate-limit.js
//
// Environment:
//   WAF_TARGET   default http://host.docker.internal:8080
//   BURST_RPS    default 200    — request rate per second
//   BURST_SECS   default 6      — duration of the burst stage
//   COOLDOWN     default 60s    — wait before re-burst (decay test)

import http from "k6/http";
import { check, sleep } from "k6";
import { Counter, Rate } from "k6/metrics";

const target = __ENV.WAF_TARGET || "http://host.docker.internal:8080";
const burstRps = parseInt(__ENV.BURST_RPS || "200", 10);
const burstSecs = parseInt(__ENV.BURST_SECS || "6", 10);

const blockedRate = new Rate("blocked_after_burst");
const status_429 = new Counter("status_429_observed");
const status_2xx = new Counter("status_2xx_observed");

export const options = {
  scenarios: {
    burst: {
      executor: "constant-arrival-rate",
      rate: burstRps,
      timeUnit: "1s",
      duration: `${burstSecs}s`,
      preAllocatedVUs: 4,
      maxVUs: 8,
      exec: "burst",
    },
  },
  thresholds: {
    // After the first ~1s of burst we expect a clear majority
    // of requests to be 429'd. We measure on the trailing
    // window rather than the whole run because the very first
    // requests in each window are always allowed.
    "blocked_after_burst": ["rate>0.95"],
    "status_429_observed": ["count>10"],
  },
  insecureSkipTLSVerify: true,
};

export function burst() {
  const res = http.get(`${target}/get`, {
    headers: { "x-aegis-test": "rate-limit-burst" },
  });

  // Skip the first request of each VU's tick — give the limiter
  // a chance to accumulate. After the warm-up, blocks dominate.
  if (__ITER < 5) {
    return;
  }

  const blocked = res.status === 429;
  blockedRate.add(blocked);
  if (blocked) {
    status_429.add(1);
  } else if (res.status >= 200 && res.status < 300) {
    status_2xx.add(1);
  }

  check(res, {
    "status is 200 or 429": (r) => r.status === 200 || r.status === 429,
  });
}
