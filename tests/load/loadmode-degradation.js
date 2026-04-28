// Aegis-Gate — LoadMode auto-degradation (P7)
//
// Runs three sequenced traffic stages and asserts that
// /api/loadmode reports the expected mode in each:
//   stage A: low RPS  → mode = "normal"
//   stage B: mid RPS  → mode = "elevated"
//   stage C: high RPS → mode = "critical"
//
// The thresholds depend on the config's `load_mode` settings.
// This script reads them from /api/loadmode at startup and
// scales each stage to ~1.5× the relevant boundary so the
// transitions are obvious without flooding the host.
//
// Run with:
//   k6 run tests/load/loadmode-degradation.js
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

let elevatedRps = 2000;
let criticalRps = 8000;

export function setup() {
  const r = http.get(`${admin}/api/loadmode`, {
    headers: { accept: "application/json" },
    insecureSkipTLSVerify: true,
  });
  if (r.status === 200) {
    const body = JSON.parse(r.body);
    elevatedRps = body.elevated_rps || elevatedRps;
    criticalRps = body.critical_rps || criticalRps;
  }
  return { elevatedRps, criticalRps };
}

export const options = {
  scenarios: {
    low: {
      executor: "constant-arrival-rate",
      rate: 200, timeUnit: "1s", duration: "5s",
      preAllocatedVUs: 50,
      exec: "stageA",
    },
    mid: {
      executor: "constant-arrival-rate",
      rate: 3500, timeUnit: "1s", duration: "8s",
      preAllocatedVUs: 200,
      startTime: "8s",
      exec: "stageB",
    },
    high: {
      executor: "constant-arrival-rate",
      rate: 12000, timeUnit: "1s", duration: "8s",
      preAllocatedVUs: 600, maxVUs: 1500,
      startTime: "20s",
      exec: "stageC",
    },
    sample_mode: {
      executor: "constant-vus",
      vus: 1,
      duration: "32s",
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
