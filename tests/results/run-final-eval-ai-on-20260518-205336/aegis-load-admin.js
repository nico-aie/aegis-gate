// Admin-plane latency probe — exercises the HTTP server hot path
// without the detector chain. Gives a clean read on baseline I/O latency.
import http from "k6/http";
import { Trend } from "k6/metrics";

const target = __ENV.WAF_ADMIN || "http://127.0.0.1:9443";
const duration = __ENV.DURATION || "20s";
const vus = parseInt(__ENV.VUS || "32", 10);

const lat = new Trend("admin_latency_ms", true);

export const options = {
  scenarios: { admin_baseline: { executor: "constant-vus", vus, duration } },
  thresholds: { admin_latency_ms: ["p(99)<25"] },
};

export default function () {
  const res = http.get(`${target}/metrics`);
  lat.add(res.timings.duration);
}
