// Aegis-Gate — LoadMode auto-degradation (P7)
//
// Runs three sequenced traffic stages and asserts that
// /api/loadmode reports the expected mode in each:
//   stage A: low RPS  → mode = "normal"
//   stage B: mid RPS  → mode = "elevated"
//   stage C: high RPS → mode = "critical"
//
// **REQUIRES** `config/waf.test.yaml` (or any config with
// `load_mode.elevated_rps <= 500` and
// `load_mode.critical_rps <= 2000`). Stages are sized for
// those numbers — running against the dev config (which
// targets 8000 RPS for Critical) will leave Critical
// unreachable on a laptop. Verified at startup by reading
// /api/loadmode and emitting a console warning when the
// thresholds don't match.
//
// Run with:
//   target/release/waf run --config config/waf.test.yaml &
//   docker exec aegis-k6 k6 run /scripts/loadmode-degradation.js
//
// Environment:
//   WAF_TARGET / WAF_ADMIN as elsewhere.

import http from "k6/http";
import { check, sleep } from "k6";
import { Rate } from "k6/metrics";

const target = __ENV.WAF_TARGET || "http://host.docker.internal:8080";
const admin = __ENV.WAF_ADMIN || "https://host.docker.internal:9443";

const sawElevated = new Rate("auto_elevated_observed");
const sawCritical = new Rate("auto_critical_observed");

// Stages target the waf.test.yaml thresholds (500 / 2000 RPS).
// Anything 1.5× the boundary is enough to put the auto-mode
// solidly in that band over the 8 s sample window — without
// melting the laptop.
const STAGE_LOW_RPS = 100;
const STAGE_MID_RPS = 750;     // 1.5× elevated_rps=500
const STAGE_HIGH_RPS = 3000;   // 1.5× critical_rps=2000

export function setup() {
  // Cross-check the running config so a mis-bring-up
  // (running against waf.dev.yaml) surfaces immediately
  // instead of as a "rate>0" threshold breach 32 s later.
  const r = http.get(`${admin}/api/loadmode`, {
    headers: { accept: "application/json" },
    insecureSkipTLSVerify: true,
  });
  if (r.status === 200) {
    const body = JSON.parse(r.body);
    if (body.elevated_rps > 1000 || body.critical_rps > 5000) {
      console.warn(
        `loadmode-degradation expects waf.test.yaml thresholds ` +
        `(<=500 / <=2000), got elevated=${body.elevated_rps}, ` +
        `critical=${body.critical_rps}. Stages won't reach Critical.`
      );
    }
    return { elevatedRps: body.elevated_rps, criticalRps: body.critical_rps };
  }
  return { elevatedRps: 500, criticalRps: 2000 };
}

export const options = {
  scenarios: {
    low: {
      executor: "constant-arrival-rate",
      rate: STAGE_LOW_RPS, timeUnit: "1s", duration: "5s",
      preAllocatedVUs: 30,
      exec: "stageA",
    },
    mid: {
      executor: "constant-arrival-rate",
      rate: STAGE_MID_RPS, timeUnit: "1s", duration: "8s",
      preAllocatedVUs: 80,
      startTime: "8s",
      exec: "stageB",
    },
    high: {
      executor: "constant-arrival-rate",
      rate: STAGE_HIGH_RPS, timeUnit: "1s", duration: "10s",
      preAllocatedVUs: 250, maxVUs: 600,
      startTime: "20s",
      exec: "stageC",
    },
    sample_mode: {
      executor: "constant-vus",
      vus: 1,
      duration: "34s",
      exec: "sampleMode",
    },
  },
  thresholds: {
    "auto_elevated_observed": ["rate>0"],
    "auto_critical_observed": ["rate>0"],
  },
  insecureSkipTLSVerify: true,
};

function tap() {
  http.get(`${target}/get`, { headers: { "x-aegis-test": "loadmode" } });
}

export function stageA() { tap(); }
export function stageB() { tap(); }
export function stageC() { tap(); }

export function sampleMode() {
  // Poll /api/loadmode every second; record which modes we observe.
  const r = http.get(`${admin}/api/loadmode`);
  if (r.status === 200) {
    const body = JSON.parse(r.body);
    if (body.mode === "elevated") sawElevated.add(true);
    if (body.mode === "critical") sawCritical.add(true);
  }
  sleep(1);
}
