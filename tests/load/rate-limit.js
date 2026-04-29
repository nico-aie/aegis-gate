// Aegis-Gate — per-IP rate limiter saturation
//
// Drives one source IP at high RPS toward the data plane and
// asserts the gateway's per-IP sliding-window rate limiter
// starts returning 429. Spec lives in
// docs/security/rate-limiting.md.
//
// Why a single source IP: the rate limiter is keyed on
// remote-IP. With many VUs all sharing the same docker-bridge
// source IP, the limit hits "instantly" and we can't distinguish
// "limit working" from "no limit at all". A handful of VUs all
// from 127.0.0.1 lets us drive the rate while keeping the
// keying signal clear.
//
// **Burst sizing.** The burst MUST exceed the configured
// `rate_limit.buckets[ip].limit` within the
// `BURST_SECS` window or the limiter will never fire and
// the threshold below will fail (it's not a gateway bug —
// it means the test under-shot). The default config
// (`config/waf.test.yaml`) sets the budget at
// `10 000 / 60 s`; the defaults here drive 2 000 RPS × 8 s
// = 16 000 reqs which clears the budget by 60 % even after
// the sliding window absorbs the first second.
//
// Run with:
//   docker exec aegis-k6 k6 run /scripts/rate-limit.js
//
// Environment:
//   WAF_TARGET   default http://host.docker.internal:8080
//   BURST_RPS    default 2000  — request rate per second
//   BURST_SECS   default 8     — duration of the burst stage
//                  (BURST_RPS × BURST_SECS must exceed the
//                  configured limiter budget)

import http from "k6/http";
import { check } from "k6";
import { Counter, Rate } from "k6/metrics";

const target = __ENV.WAF_TARGET || "http://host.docker.internal:8080";
const burstRps = parseInt(__ENV.BURST_RPS || "2000", 10);
const burstSecs = parseInt(__ENV.BURST_SECS || "8", 10);

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
      preAllocatedVUs: 32,
      maxVUs: 128,
      exec: "burst",
    },
  },
  thresholds: {
    // The first thousands of the burst stage flow through the
    // limiter freely (we have to fill the sliding window).
    // After saturation, we expect a clear majority of requests
    // to be 429-blocked OR 403 strike-blocked once the
    // accumulated denials cross `risk.strikes.block_at`. The
    // `blocked_after_burst` rate counts both — the `status_429`
    // counter only counts the rate-limit code path so we still
    // verify the gateway emits 429 specifically.
    // The first burstSecs × burstRps reqs minus the budget all
    // pass through (limiter doesn't fire while there's budget).
    // Setting a floor of 0.30 catches "limiter never fired"
    // (which would be < 0.05) while tolerating realistic
    // budgets where ~half the burst is allowed.
    "blocked_after_burst": ["rate>0.30"],
    "status_429_observed": ["count>10"],
  },
  insecureSkipTLSVerify: true,
};

export function burst() {
  const res = http.get(`${target}/get`, {
    headers: { "x-aegis-test": "rate-limit-burst" },
  });

  // Once strikes accumulate past `risk.strikes.block_at`, every
  // subsequent request takes the strike-block 403 path before
  // the rate-limiter even runs. We treat both 403 and 429 as
  // "blocked" for the high-level rate but ONLY count 429 as
  // proof the rate-limit branch actually fired.
  const blocked429 = res.status === 429;
  const blocked403 = res.status === 403;
  blockedRate.add(blocked429 || blocked403);
  if (blocked429) {
    status_429.add(1);
  } else if (res.status >= 200 && res.status < 300) {
    status_2xx.add(1);
  }

  check(res, {
    "status is 200, 403, or 429": (r) =>
      r.status === 200 || r.status === 403 || r.status === 429,
  });
}
