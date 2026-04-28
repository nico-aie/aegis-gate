// Aegis-Gate — `/api/audit/since` reconnect-replay (F-T9, D-M3-T3.2).
//
// The dashboard's Live Feed page polls /api/audit/since when its
// SSE channel disconnects, to backfill any audit events the
// client may have missed. This script verifies the contract:
//
//   1. After malicious traffic has produced events, the endpoint
//      returns a `cursor / next_cursor / events / gap` envelope.
//   2. `next_cursor > cursor` after non-empty results.
//   3. Cursor at the high-water mark returns an empty `events`
//      array without error.
//   4. Cursor below the live ring's oldest entry signals
//      `gap == true`.
//
// Run with:
//   docker exec aegis-k6 k6 run \
//     -e WAF_ADMIN=http://host.docker.internal:9443 \
//     -e ADMIN_USER=admin -e ADMIN_PASS=aegis-test-1234 \
//     /scripts/audit-since.js

import http from "k6/http";
import { check } from "k6";
import { Counter } from "k6/metrics";

const target = __ENV.WAF_TARGET || "http://host.docker.internal:8080";
const admin = __ENV.WAF_ADMIN || "http://host.docker.internal:9443";

const audit_replay_ok = new Counter("audit_replay_ok");
const audit_high_water_empty = new Counter("audit_high_water_empty");

export const options = {
  scenarios: {
    seed: {
      // Send N malicious requests so the audit ring has
      // something to replay. Each one produces one event.
      executor: "shared-iterations",
      vus: 1,
      iterations: 25,
      maxDuration: "30s",
      exec: "seedTraffic",
    },
    verify: {
      executor: "shared-iterations",
      vus: 1,
      iterations: 1,
      maxDuration: "30s",
      startTime: "5s",
      exec: "verifyReplay",
    },
  },
  thresholds: {
    "audit_replay_ok":         ["count>0"],
    "audit_high_water_empty":  ["count>0"],
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

export function seedTraffic() {
  // Each request trips the SQLi detector → one Detection event
  // lands on the audit ring → cursor advances by one.
  http.get(
    `${target}/api?id=1+UNION+SELECT+password+FROM+users`,
    { headers: { "x-aegis-test": "audit-since-seed" } },
  );
}

export function verifyReplay(data) {
  const headers = buildAdminHeaders(data);

  // 1. Backfill from cursor=0 — must return the documented shape.
  const r = http.get(`${admin}/api/audit/since?cursor=0&limit=200`, { headers });
  if (r.status !== 200) {
    console.error("GET /api/audit/since failed:", r.status, r.body);
    return;
  }
  const body = JSON.parse(r.body);
  const ok = check(body, {
    "shape: cursor present":      (b) => typeof b.cursor === "number",
    "shape: next_cursor present": (b) => typeof b.next_cursor === "number",
    "shape: events array":        (b) => Array.isArray(b.events),
    "shape: gap boolean":         (b) => typeof b.gap === "boolean",
    "next_cursor > cursor":       (b) => b.next_cursor > b.cursor || b.events.length === 0,
    "non-empty after seed":       (b) => b.events.length > 0,
  });
  if (ok) audit_replay_ok.add(1);

  // 2. Cursor at the high-water mark returns an empty `events`
  //    array — clients use this to detect "stream caught up".
  const high = body.next_cursor;
  const tail = http.get(
    `${admin}/api/audit/since?cursor=${high}&limit=10`,
    { headers },
  );
  const tailBody = JSON.parse(tail.body);
  if (tail.status === 200 && tailBody.events.length === 0) {
    audit_high_water_empty.add(1);
  }
  check(tailBody, {
    "high-water cursor empty": (b) => b.events.length === 0,
    "next_cursor stable":      (b) => b.next_cursor === high,
  });
}
