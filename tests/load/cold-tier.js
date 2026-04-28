// Aegis-Gate — `/api/cold-tier` inventory contract (F-T9, P8).
//
// `/api/cold-tier` enumerates configured `audit.sinks` so the
// dashboard can show "where audit events flow". This script
// verifies:
//
//   1. The endpoint is reachable from an authenticated session.
//   2. Each sink row carries `id`, `kind`, `destination`,
//      `delivery`.
//   3. **Splunk HEC tokens never appear in the response body.**
//      Defence-in-depth — even the dev/test config redacts the
//      `secret:` substring; a regression here would leak
//      production tokens through the dashboard.
//
// Run with:
//   docker exec aegis-k6 k6 run \
//     -e WAF_ADMIN=http://host.docker.internal:9443 \
//     -e ADMIN_USER=admin -e ADMIN_PASS=aegis-test-1234 \
//     /scripts/cold-tier.js

import http from "k6/http";
import { check } from "k6";
import { Counter } from "k6/metrics";

const admin = __ENV.WAF_ADMIN || "http://host.docker.internal:9443";

const sink_inventory_ok = new Counter("sink_inventory_ok");
const secret_leak_observed = new Counter("secret_leak_observed");

export const options = {
  scenarios: {
    verify: {
      executor: "shared-iterations",
      vus: 1,
      iterations: 5,
      maxDuration: "30s",
    },
  },
  thresholds: {
    "sink_inventory_ok":     ["count>=5"],
    "secret_leak_observed":  ["count==0"],
  },
  insecureSkipTLSVerify: true,
};

export function setup() {
  const res = http.post(`${admin}/admin/login`,
    JSON.stringify({ user: __ENV.ADMIN_USER, password: __ENV.ADMIN_PASS }),
    { headers: { "content-type": "application/json" } });
  if (res.status >= 400) {
    throw new Error(
      `admin login failed: ${res.status} (check ADMIN_USER + ADMIN_PASS)`,
    );
  }
  const setCookies = res.headers["Set-Cookie"];
  const raw = Array.isArray(setCookies) ? setCookies.join(",") : (setCookies || "");
  const session = extractCookie(raw, "aegis_session");
  const csrf = extractCookie(raw, "aegis_csrf");
  if (!csrf) throw new Error("aegis_csrf cookie missing in login response");
  return { csrf, session };
}

function extractCookie(setCookieHeader, name) {
  const re = new RegExp(`${name}=([^;,\\s]+)`);
  const m = setCookieHeader.match(re);
  return m ? m[1] : null;
}

function buildAdminHeaders(data) {
  const cookie = data.session
    ? `aegis_session=${data.session}; aegis_csrf=${data.csrf}`
    : `aegis_csrf=${data.csrf}`;
  return {
    "content-type": "application/json",
    "x-csrf-token": data.csrf,
    cookie,
  };
}

export default function (data) {
  const r = http.get(`${admin}/api/cold-tier`, {
    headers: buildAdminHeaders(data),
  });

  if (r.status !== 200) {
    console.error("GET /api/cold-tier failed:", r.status, r.body);
    return;
  }

  // Defence-in-depth: never leak tokens. Match the patterns
  // tests/api/cold-tier.sh checks for.
  if (/secret:|token_ref|token=|hec[-_]token/i.test(r.body)) {
    secret_leak_observed.add(1);
    console.error("LEAK: response contains secret-like substring:", r.body);
  }

  const body = JSON.parse(r.body);
  const ok = check(body, {
    "sinks array":           (b) => Array.isArray(b.sinks),
    "fallback_buffer_bytes": (b) => typeof b.fallback_buffer_bytes === "number",
    "every row has id":      (b) => (b.sinks || []).every((s) => typeof s.id === "string"),
    "every row has kind":    (b) => (b.sinks || []).every((s) => typeof s.kind === "string"),
    "every row has dest":    (b) => (b.sinks || []).every((s) => typeof s.destination === "string"),
    "every row has delivery": (b) => (b.sinks || []).every((s) => typeof s.delivery === "string"),
  });
  if (ok) sink_inventory_ok.add(1);
}
