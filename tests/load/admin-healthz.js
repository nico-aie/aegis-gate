// Pure-WAF throughput probe.
//
// Hits the admin-port /healthz/ready endpoint, which never
// touches the data-plane upstream forwarder. Used by the
// runtime/workers perf sweep to isolate Layer-1 in-process
// throughput from the upstream-pool TIME_WAIT ceiling that
// the proxied path hits on a laptop.
//
// ENV:
//   WAF_ADMIN   default "http://host.docker.internal:19443"
//   DURATION    default "30s"
//   VUS         default "20"

import http from "k6/http";
import { Rate, Trend } from "k6/metrics";

const target = __ENV.WAF_ADMIN || "http://host.docker.internal:19443";
const duration = __ENV.DURATION || "30s";
const vus = parseInt(__ENV.VUS || "20", 10);

const rdyLatency = new Trend("ready_latency_ms", true);
const rdyRate = new Rate("ready_success");

export const options = {
  scenarios: {
    sweep: {
      executor: "constant-vus",
      vus: vus,
      duration: duration,
    },
  },
  thresholds: {
    "http_reqs": ["rate>0"],
  },
};

export default function () {
  const res = http.get(`${target}/healthz/ready`, {
    headers: { "x-aegis-test": "workers-perf" },
    timeout: "5s",
  });
  rdyLatency.add(res.timings.duration);
  rdyRate.add(res.status === 200);
}
