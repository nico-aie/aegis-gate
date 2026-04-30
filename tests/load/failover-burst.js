// Failover-burst load profile.
//
// Used by `tests/cluster/06-mid-burst-failover.sh` to measure the
// LB failover budget when one cluster node dies mid-burst.
//
// Distinct from `baseline.js` because:
//   - constant-arrival-rate (rate-controlled, not VU-controlled)
//     so we don't saturate the local ephemeral-port pool while
//     the upstream forwarder still does new TCP per-request,
//   - fixed 200 RPS for 30 s = 6000 reqs total (well under both
//     the WAF's per-IP guard AND the host's TCP TIME_WAIT budget),
//   - the default k6 success threshold is relaxed because hard
//     failover (SIGKILL) carries a 4 s `inter × fall` window where
//     5xx is expected. The test script does the rest of the
//     interpretation.
//
// ENV overrides:
//   WAF_TARGET    default "http://localhost:9180" (the LB VIP)
//   DURATION      default "30s"
//   RPS           default 200

import http from "k6/http";
import { Rate, Trend } from "k6/metrics";

const target = __ENV.WAF_TARGET || "http://localhost:9180";
const duration = __ENV.DURATION || "30s";
const rps = parseInt(__ENV.RPS || "200", 10);

const allowLatency = new Trend("allow_latency_ms", true);
const allowRate = new Rate("allow_success");

export const options = {
  scenarios: {
    burst: {
      executor: "constant-arrival-rate",
      rate: rps,
      timeUnit: "1s",
      duration: duration,
      // Pool sized for slow responses during the failover blip.
      preAllocatedVUs: 50,
      maxVUs: 200,
    },
  },
  thresholds: {
    // Real assertion lives in the bash test — k6 just needs to not abort.
    "http_reqs": ["rate>0"],
  },
};

export default function () {
  const res = http.get(`${target}/get`, {
    headers: { "x-aegis-test": "failover" },
    timeout: "5s",
  });
  allowLatency.add(res.timings.duration);
  allowRate.add(res.status === 200);
}
