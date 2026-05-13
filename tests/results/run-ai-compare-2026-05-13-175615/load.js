import http from 'k6/http';
import { check } from 'k6';
import { SharedArray } from 'k6/data';
import { Counter, Trend } from 'k6/metrics';

const RPS = Number(__ENV.RPS || 500);
const DURATION = __ENV.DURATION || '30s';
const ATTACK_PCT = Number(__ENV.ATTACK_PCT || 60);
const TARGET = __ENV.TARGET || 'http://127.0.0.1:8080';

// CORPUS_PATH is the path k6 sees inside its working dir. The
// harness writes the expanded corpus to <case_dir>/corpus.json and
// passes the absolute path via --env CORPUS_PATH=... .
const CORPUS_PATH = __ENV.CORPUS_PATH;
if (!CORPUS_PATH) {
  throw new Error('CORPUS_PATH env var is required (path to ai-corpus.json)');
}

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

// Load corpus once per VU pool, shared across iterations.
const ATTACK = new SharedArray('attack', function () {
  return JSON.parse(open(CORPUS_PATH)).attacks;
});
const CLEAN = new SharedArray('clean', function () {
  return JSON.parse(open(CORPUS_PATH)).clean;
});

const detectedAttacks = new Counter('detected_attacks');
const allowedAttacks  = new Counter('allowed_attacks');
const blockedClean    = new Counter('blocked_clean');
const allowedClean    = new Counter('allowed_clean');
const attackLatency   = new Trend('attack_latency_ms', true);
const cleanLatency    = new Trend('clean_latency_ms', true);

function pickFrom(arr) { return arr[Math.floor(Math.random() * arr.length)]; }

export default function () {
  const isAttack = Math.random() * 100 < ATTACK_PCT;
  const c = pickFrom(isAttack ? ATTACK : CLEAN);
  // Assemble the URL from path + query (both come pre-encoded
  // from the corpus generator so we never re-encode here).
  const url = TARGET + c.path + (c.query ? '?' + c.query : '');
  const params = { headers: { 'accept': '*/*' } };
  if (c.user_agent) {
    params.headers['user-agent'] = c.user_agent;
  }
  if (c.extra_header) {
    params.headers[c.extra_header[0].toLowerCase()] = c.extra_header[1];
  }
  if (c.content_type) {
    params.headers['content-type'] = c.content_type;
  }
  let res;
  const m = c.method;
  if (m === 'POST') {
    res = http.post(url, c.body, params);
  } else if (m === 'PUT') {
    res = http.put(url, c.body, params);
  } else if (m === 'DELETE') {
    res = http.del(url, c.body, params);
  } else if (m === 'PATCH') {
    res = http.patch(url, c.body, params);
  } else {
    res = http.get(url, params);
  }
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
