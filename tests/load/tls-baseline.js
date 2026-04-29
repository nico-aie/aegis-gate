// Aegis-Gate — Baseline load test over HTTPS
//
// Companion to baseline.js — same shape, but talks TLS 1.3 to
// the data-plane HTTPS listener so the SLO numbers include the
// handshake + record-layer cost. Operators care about both: the
// plaintext baseline measures the inner pipeline; this one
// measures what real-world clients see.
//
// Skip cleanly when WAF_TLS_TARGET is unset OR the listener
// refuses connections (most dev configs don't bind :8443).
//
// Run with:
//   docker exec aegis-k6 k6 run -e WAF_TLS_TARGET=https://host.docker.internal:8443 /scripts/tls-baseline.js
//
// Environment:
//   WAF_TLS_TARGET  default empty — when unset, k6 exits 0 with an info banner
//   DURATION        default "30s"
//   VUS             default "100"

import http from "k6/http";
import { check } from "k6";
import { Trend, Rate } from "k6/metrics";

const target = __ENV.WAF_TLS_TARGET || "";
const duration = __ENV.DURATION || "30s";
const vus = parseInt(__ENV.VUS || "100", 10);

const tlsLatency = new Trend("tls_request_ms", true);
const tlsHandshake = new Trend("tls_handshake_ms", true);
const tlsSuccess = new Rate("tls_success");

export const options = {
  // No vus / iterations when we have nothing to point at — exit
  // immediately in setup() so CI doesn't fail the run.
  scenarios: target
    ? {
        baseline_tls: {
          executor: "constant-vus",
          vus: vus,
          duration: duration,
        },
      }
    : {},
  thresholds: target
    ? {
        // Handshake amortises across keep-alive — 50ms p95 is
        // generous; rustls + ECDSA P-256 hits ~3ms locally and
        // ~15ms cross-AZ.
        tls_handshake_ms: ["p(95)<50"],
        // Inner request latency over TLS — same SLO as the
        // plaintext baseline (5ms p99 on dedicated hw); we
        // relax to 10ms here to absorb shared-host variance.
        tls_request_ms: ["p(99)<10"],
        tls_success: ["rate>0.999"],
        http_reqs: ["rate>1000"],
      }
    : {},
  // `insecureSkipTLSVerify` so k6 accepts the dev cert chain;
  // production runs use a real CA + omit this flag.
  insecureSkipTLSVerify: true,
};

export function setup() {
  if (!target) {
    console.log(
      "INFO: WAF_TLS_TARGET unset — skipping TLS baseline. Set " +
        "WAF_TLS_TARGET=https://host.docker.internal:8443 to enable."
    );
    return { skip: true };
  }
  // One probe so the script fails fast with a clear message
  // when the listener isn't bound, instead of producing 100 % zero
  // counters.
  const probe = http.get(target + "/", { timeout: "2s" });
  if (probe.status === 0) {
    console.warn(
      `WARN: ${target} did not accept the TLS handshake — skipping ` +
        "baseline run. Bind a :8443 listener and re-run."
    );
    return { skip: true };
  }
  return { skip: false };
}

export default function (data) {
  if (data && data.skip) {
    // setup() already logged the reason. Just no-op the iteration —
    // we can't cancel the per-vu-iterations executor that the
    // empty-scenarios fallback creates, but we can avoid making
    // any HTTP calls.
    return;
  }
  const res = http.get(`${target}/get`, {
    headers: { "x-aegis-test": "tls-baseline" },
    tags: { name: "GET /get over TLS" },
  });
  tlsLatency.add(res.timings.duration);
  // res.timings.tls_handshaking is 0 on reused keep-alive
  // connections; we only record real handshakes.
  if (res.timings.tls_handshaking > 0) {
    tlsHandshake.add(res.timings.tls_handshaking);
  }
  tlsSuccess.add(res.status === 200);
  check(res, { "status is 200": (r) => r.status === 200 });
}
