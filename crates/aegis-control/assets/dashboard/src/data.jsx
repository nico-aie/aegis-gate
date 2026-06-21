/* global React */
const { useState, useEffect, useRef, useMemo, useCallback } = React;

// ============= Static reference data =============

const ROUTES = [
  '/api/login', '/api/profile', '/api/orders', '/api/checkout', '/api/admin',
  '/static/css/style.css', '/static/js/app.js', '/public/index.html',
  '/wp-admin/install.php', '/.env', '/.git/config', '/aws/credentials',
  '/api/users', '/api/products', '/sitemap.xml', '/robots.txt', '/favicon.ico',
  '/index.php', '/containers/json', '/api/analytics/events', '/api/v2/auth',
  '/actuator/env', '/phpmyadmin', '/healthz',
];

const REGIONS = ['singapore', 'us-primary', 'eu-frankfurt', 'tokyo', 'sydney', 'mumbai'];
const METHODS = ['GET', 'POST', 'GET', 'GET', 'GET', 'PUT', 'DELETE', 'OPTIONS'];

const ATTACK_CATS = [
  { id: 'sqli',           label: 'SQLi',           color: '#F6465D' },
  { id: 'ssrf',           label: 'SSRF',           color: '#A78BFA' },
  { id: 'recon',          label: 'Recon',          color: '#3B82F6' },
  { id: 'path_traversal', label: 'Path Traversal', color: '#F0B90B' },
  { id: 'honeypot',       label: 'Honeypot',       color: '#EC4899' },
  { id: 'xss',            label: 'XSS',            color: '#2DD4BF' },
  { id: 'cmdi',           label: 'CMDi',           color: '#FF8896' },
  { id: 'lfi',            label: 'LFI',            color: '#10B981' },
  { id: 'ssti',           label: 'SSTi',           color: '#9CA3AF' },
];

const ATTACKER_GEO = [
  { ip: '110.35.80.116',  cc: 'KR', city: 'Seoul',     lat: 37.56,  lon: 126.97 },
  { ip: '195.178.110.162',cc: 'NL', city: 'Amsterdam', lat: 52.37,  lon: 4.89 },
  { ip: '34.47.62.202',   cc: 'US', city: 'Ashburn',   lat: 39.04,  lon: -77.49 },
  { ip: '71.6.239.61',    cc: 'US', city: 'Walnut',    lat: 34.02,  lon: -117.86 },
  { ip: '118.26.104.78',  cc: 'CN', city: 'Beijing',   lat: 39.91,  lon: 116.41 },
  { ip: '204.76.203.206', cc: 'US', city: 'New York',  lat: 40.71,  lon: -74.01 },
  { ip: '192.177.79.149', cc: 'GB', city: 'London',    lat: 51.51,  lon: -0.13 },
  { ip: '178.62.193.41',  cc: 'DE', city: 'Frankfurt', lat: 50.11,  lon: 8.68 },
  { ip: '46.166.139.111', cc: 'LT', city: 'Vilnius',   lat: 54.69,  lon: 25.28 },
  { ip: '202.55.137.24',  cc: 'IN', city: 'Mumbai',    lat: 19.08,  lon: 72.88 },
  { ip: '103.224.182.7',  cc: 'AU', city: 'Sydney',    lat: -33.87, lon: 151.21 },
  { ip: '177.85.34.221',  cc: 'BR', city: 'São Paulo', lat: -23.55, lon: -46.63 },
  { ip: '95.214.55.10',   cc: 'RU', city: 'Moscow',    lat: 55.75,  lon: 37.62 },
  { ip: '41.220.72.99',   cc: 'NG', city: 'Lagos',     lat: 6.52,   lon: 3.38 },
  { ip: '185.220.101.42', cc: 'RO', city: 'Bucharest', lat: 44.43,  lon: 26.10 },
];

// Origin point for arcs (your datacenter — Singapore)
const ORIGIN = { lat: 1.35, lon: 103.82 };

const RULES = [
  { id: 'owasp-sqli-001', name: 'SQLi: UNION SELECT', kind: 'custom',  pri: 100, field: 'any', op: 'regex', pattern: '(?i)\\bunion\\b\\s+\\bselect\\b', action: 'block', risk: 80, enabled: true,  cat: 'sqli', last: '12s ago', hits1h: 1247 },
  { id: 'owasp-sqli-001', name: 'SQLi: UNION SELECT', kind: 'builtin', pri: 100, field: 'any', op: 'regex', pattern: '(?i)\\bunion\\b\\s+\\bselect\\b', action: 'block', risk: 80, enabled: true,  cat: 'sqli', last: '12s ago', hits1h: 980 },
  { id: 'owasp-sqli-002', name: 'SQLi: Boolean Injection', kind: 'custom', pri: 101, field: 'any', op: 'regex', pattern: "(?i)\\b(or|and)\\b\\s*\\d+\\s*=\\s*\\d+", action: 'block', risk: 70, enabled: true, cat: 'sqli', last: '1m ago', hits1h: 412 },
  { id: 'owasp-sqli-002', name: 'SQLi: Boolean Injection', kind: 'builtin', pri: 101, field: 'any', op: 'regex', pattern: "(?i)\\b(or|and)\\b\\s*\\d+\\s*=\\s*\\d+", action: 'block', risk: 70, enabled: true, cat: 'sqli', last: '1m ago', hits1h: 308 },
  { id: 'owasp-sqli-003', name: 'SQLi: SQL Comments', kind: 'builtin', pri: 102, field: 'any', op: 'regex', pattern: "(?:--|#|/\\*).*$", action: 'challenge', risk: 40, enabled: true, cat: 'sqli', last: '4m ago', hits1h: 145 },
  { id: 'owasp-sqli-004', name: 'SQLi: DML Statements', kind: 'custom', pri: 103, field: 'any', op: 'regex', pattern: "(?i)\\b(drop|truncate|alter)\\s+(table|database)\\b", action: 'block', risk: 90, enabled: true, cat: 'sqli', last: '8s ago', hits1h: 802 },
  { id: 'owasp-sqli-004', name: 'SQLi: DML Statements', kind: 'builtin', pri: 103, field: 'any', op: 'regex', pattern: "(?i)\\b(drop|truncate|alter)\\s+(table|database)\\b", action: 'block', risk: 90, enabled: true, cat: 'sqli', last: '8s ago', hits1h: 612 },
  { id: 'owasp-sqli-005', name: 'SQLi: Stored Procedures', kind: 'custom', pri: 104, field: 'any', op: 'regex', pattern: "(?i)\\b(exec|execute)\\s+xp_cmdshell\\b", action: 'block', risk: 95, enabled: true, cat: 'sqli', last: '19m ago', hits1h: 21 },
  { id: 'owasp-sqli-006', name: 'SQLi: Time-Based Blind', kind: 'custom', pri: 105, field: 'any', op: 'regex', pattern: "(?i)\\bsleep\\s*\\(\\s*\\d+\\s*\\)", action: 'block', risk: 85, enabled: true, cat: 'sqli', last: '32s ago', hits1h: 234 },
  { id: 'owasp-sqli-007', name: 'SQLi: Information Schema', kind: 'custom', pri: 106, field: 'any', op: 'regex', pattern: "(?i)\\binformation_schema\\b", action: 'challenge', risk: 50, enabled: true, cat: 'sqli', last: '3m ago', hits1h: 89 },
  { id: 'owasp-ssrf-001', name: 'SSRF: Internal Addresses', kind: 'custom', pri: 400, field: 'any', op: 'regex', pattern: "(?i)(localhost|127\\.0\\.0\\.1|10\\.|192\\.168\\.|169\\.254\\.|::1)", action: 'block', risk: 85, enabled: true, cat: 'ssrf', last: '6s ago', hits1h: 1893 },
  { id: 'owasp-xss-001',  name: 'XSS: Script Tag',          kind: 'builtin', pri: 200, field: 'any', op: 'regex', pattern: "<script[^>]*>", action: 'block', risk: 75, enabled: true, cat: 'xss', last: '52s ago', hits1h: 521 },
  { id: 'owasp-xss-002',  name: 'XSS: Event Handler',       kind: 'builtin', pri: 201, field: 'any', op: 'regex', pattern: "on\\w+\\s*=", action: 'block', risk: 65, enabled: true, cat: 'xss', last: '2m ago', hits1h: 187 },
  { id: 'owasp-pt-001',   name: 'Path Traversal',           kind: 'builtin', pri: 300, field: 'path', op: 'regex', pattern: "\\.\\./", action: 'block', risk: 80, enabled: true, cat: 'path_traversal', last: '14s ago', hits1h: 712 },
  { id: 'owasp-recon-001',name: 'Recon: Admin Paths',       kind: 'builtin', pri: 500, field: 'path', op: 'regex', pattern: "(/wp-admin|/phpmyadmin|/admin\\.php)", action: 'challenge', risk: 45, enabled: true, cat: 'recon', last: '8s ago', hits1h: 2104 },
  { id: 'owasp-cmdi-001', name: 'CMDi: Shell Metachars',    kind: 'builtin', pri: 600, field: 'any', op: 'regex', pattern: ";\\s*(cat|ls|wget|curl|nc)\\b", action: 'block', risk: 90, enabled: true, cat: 'cmdi', last: '25s ago', hits1h: 388 },
  { id: 'owasp-lfi-001',  name: 'LFI: /etc/passwd',         kind: 'builtin', pri: 700, field: 'any', op: 'regex', pattern: "/etc/passwd", action: 'block', risk: 90, enabled: true, cat: 'lfi', last: '47s ago', hits1h: 156 },
  { id: 'honeypot-001',   name: 'Honeypot: /.env',           kind: 'custom', pri: 50, field: 'path', op: 'eq', pattern: '/.env', action: 'block', risk: 100, enabled: true, cat: 'honeypot', last: '3s ago', hits1h: 4521 },
  { id: 'honeypot-002',   name: 'Honeypot: /.git/config',    kind: 'custom', pri: 51, field: 'path', op: 'eq', pattern: '/.git/config', action: 'block', risk: 100, enabled: true, cat: 'honeypot', last: '11s ago', hits1h: 1102 },
];

const TIERS = [
  { name: 'basic',    desc: 'Public marketing routes',     routes: 12, rateLimit: 'lenient',  detectors: 4, challenge: 'js-only',     tls: 'modern',  hits1h: 184523 },
  { name: 'enhanced', desc: 'Authenticated app surface',   routes: 38, rateLimit: 'standard', detectors: 6, challenge: 'js+captcha',  tls: 'modern',  hits1h: 92847 },
  { name: 'strict',   desc: 'Admin & financial endpoints', routes: 7,  rateLimit: 'strict',   detectors: 7, challenge: 'strict',      tls: 'fips',    hits1h: 4218 },
  { name: 'public-static', desc: 'Static assets, CDN-fronted', routes: 3, rateLimit: 'lenient', detectors: 2, challenge: 'none', tls: 'modern', hits1h: 412384 },
];

const BLACKLIST = [
  { id: 'b1', type: 'cidr', value: '185.220.101.0/24', scope: 'global', action: 'block', reason: 'Tor exit node range — recurring abuse',         expires: null,                  created: '2026-04-12', hits24: 8421, lastHit: '2s ago' },
  { id: 'b2', type: 'ip',   value: '110.35.80.116',    scope: 'global', action: 'block', reason: 'SQLi flood from this IP (rate>1k/min)',          expires: '2026-05-15T00:00:00Z', created: '2026-04-28', hits24: 2104, lastHit: '11s ago' },
  { id: 'b3', type: 'asn',  value: 'AS14061',          scope: 'global', action: 'challenge', reason: 'DigitalOcean — high abuse signal',          expires: null,                  created: '2026-03-05', hits24: 4128, lastHit: '34s ago' },
  { id: 'b4', type: 'cidr', value: '46.166.139.0/24',  scope: 'route:/api/admin', action: 'block', reason: 'Brute-force admin login',              expires: '2026-05-01T00:00:00Z', created: '2026-04-26', hits24: 91,   lastHit: '4m ago' },
  { id: 'b5', type: 'fingerprint', value: 'fp:985730a7cc0fc937', scope: 'global', action: 'block', reason: 'Headless Chrome / botnet TLS fp', expires: null, created: '2026-04-20', hits24: 12482, lastHit: 'now' },
  { id: 'b6', type: 'ip',   value: '195.178.110.162',  scope: 'global', action: 'block', reason: 'Recon scanner — 1500+ honeypot hits',           expires: null,                  created: '2026-04-22', hits24: 1521, lastHit: '7s ago' },
  { id: 'b7', type: 'asn',  value: 'AS16276',          scope: 'tier:basic', action: 'challenge', reason: 'OVH — frequent scrapers',                 expires: null,                  created: '2026-02-18', hits24: 821,  lastHit: '1m ago' },
  { id: 'b8', type: 'cidr', value: '95.214.55.0/24',   scope: 'global', action: 'block', reason: 'Known C2 infrastructure',                       expires: '2026-06-15T00:00:00Z', created: '2026-04-15', hits24: 442,  lastHit: '15s ago' },
  { id: 'b9', type: 'country', value: 'KP', country: 'Korea, DPR',  flag: '🇰🇵', scope: 'global', action: 'block',     reason: 'Sanctioned jurisdiction — compliance',           expires: null,                  created: '2026-01-04', hits24: 218,   lastHit: '6m ago' },
  { id: 'b10', type: 'country', value: 'IR', country: 'Iran',       flag: '🇮🇷', scope: 'global', action: 'block',     reason: 'Sanctioned jurisdiction — compliance',           expires: null,                  created: '2026-01-04', hits24: 412,   lastHit: '38s ago' },
  { id: 'b11', type: 'country', value: 'RU', country: 'Russia',     flag: '🇷🇺', scope: 'tier:strict', action: 'challenge', reason: 'Geo-restriction on admin tier',          expires: null,                  created: '2026-03-12', hits24: 1842,  lastHit: '4s ago' },
  { id: 'b12', type: 'country', value: 'CN', country: 'China',      flag: '🇨🇳', scope: 'route:/api/admin', action: 'challenge', reason: 'Heightened-risk geo on admin paths', expires: null,                  created: '2026-02-08', hits24: 3214,  lastHit: '12s ago' },
];

const WHITELIST = [
  { id: 'w1', type: 'ip',   value: '203.0.113.42',     scope: 'global', bypass: ['rate-limit'], reason: 'Office NAT — SOC team egress', expires: null, created: '2026-01-04', bypasses24: 1284, lastBypass: '1m ago' },
  { id: 'w2', type: 'cidr', value: '52.94.32.0/20',    scope: 'global', bypass: ['rate-limit', 'detector:sqli'], reason: 'AWS health-check CIDR for ELB', expires: null, created: '2026-01-04', bypasses24: 47218, lastBypass: '2s ago' },
  { id: 'w3', type: 'asn',  value: 'AS15169',          scope: 'global', bypass: ['rate-limit'], reason: 'Verified Googlebot crawler ASN', expires: null, created: '2025-11-12', bypasses24: 18421, lastBypass: '4s ago' },
  { id: 'w4', type: 'ip',   value: '198.51.100.7',     scope: 'route:/api/payments', bypass: ['challenge'], reason: 'Payment partner webhook — must not be challenged', expires: '2026-12-31T00:00:00Z', created: '2026-02-08', bypasses24: 824, lastBypass: '12m ago' },
  { id: 'w5', type: 'fingerprint', value: 'fp:internal-soc-tls-2026', scope: 'global', bypass: ['all'], reason: 'Pen-test team TLS fingerprint — quarterly engagement, signed off by Hannah Cho 2026-04-25', expires: '2026-05-25T00:00:00Z', created: '2026-04-25', bypasses24: 21, lastBypass: '8m ago' },
  { id: 'w6', type: 'cidr', value: '10.32.0.0/16',     scope: 'global', bypass: ['rate-limit', 'detector:sqli', 'detector:xss'], reason: 'Internal RFC1918 — service-to-service', expires: null, created: '2025-09-01', bypasses24: 281542, lastBypass: 'now' },
  { id: 'w7', type: 'country', value: 'SG', country: 'Singapore', flag: '🇸🇬', scope: 'global',          bypass: ['rate-limit'],     reason: 'Home-country traffic — relaxed rate-limit',         expires: null,                  created: '2025-10-04', bypasses24: 184238, lastBypass: 'now' },
  { id: 'w8', type: 'country', value: 'JP', country: 'Japan',     flag: '🇯🇵', scope: 'tier:basic',      bypass: ['challenge'],      reason: 'Trusted partner geo — skip JS challenge on basic',  expires: null,                  created: '2026-02-18', bypasses24: 28412,  lastBypass: '3s ago' },
  { id: 'w9', type: 'country', value: 'GB', country: 'UK',         flag: '🇬🇧', scope: 'route:/api/payments', bypass: ['rate-limit'], reason: 'Payment-partner home country — webhook bursts',     expires: '2026-12-31T00:00:00Z', created: '2026-03-22', bypasses24: 4218,   lastBypass: '12s ago' },
];

const UPSTREAMS = [
  { name: 'us-primary',     members: 8, healthy: 8, lb: 'least_conn', cb: 'closed', p99: 42, rps: 1240 },
  { name: 'us-secondary',   members: 6, healthy: 5, lb: 'least_conn', cb: 'half-open', p99: 81, rps: 320 },
  { name: 'eu-frankfurt',   members: 6, healthy: 6, lb: 'p2c',        cb: 'closed', p99: 38, rps: 982 },
  { name: 'apac-singapore', members: 4, healthy: 4, lb: 'least_conn', cb: 'closed', p99: 51, rps: 642 },
  { name: 'apac-tokyo',     members: 4, healthy: 3, lb: 'least_conn', cb: 'open',   p99: 0,  rps: 0 },
];

const CLUSTER = [
  { id: 'aegis-01', addr: '10.32.4.11:8443',  ver: 'v0.5.16', role: 'node',     lastHB: '0s',  leases: ['witness', 'state-snap'] },
  { id: 'aegis-02', addr: '10.32.4.12:8443',  ver: 'v0.5.16', role: 'follower', lastHB: '1s',  leases: [] },
  { id: 'aegis-03', addr: '10.32.4.13:8443',  ver: 'v0.5.16', role: 'follower', lastHB: '0s',  leases: ['gitops-sync'] },
  { id: 'aegis-04', addr: '10.32.4.14:8443',  ver: 'v0.5.15', role: 'follower', lastHB: '2s',  leases: [], skew: true },
  { id: 'aegis-05', addr: '10.32.4.15:8443',  ver: 'v0.5.16', role: 'follower', lastHB: '1s',  leases: [] },
];

const CERTS = [
  { host: 'api.aegis.example.com',   issuer: "Let's Encrypt", days: 78,  source: 'acme' },
  { host: 'admin.aegis.example.com', issuer: "Let's Encrypt", days: 24,  source: 'acme' },
  { host: 'webhook.aegis.example.com', issuer: 'DigiCert',     days: 412, source: 'static' },
  { host: 'mtls.aegis.example.com',  issuer: 'Internal CA',   days: 5,   source: 'mtls' },
  { host: 'edge.aegis.example.com',  issuer: "Let's Encrypt", days: 91,  source: 'acme' },
];

const ALERTS = [
  { sev: 'warn', name: 'SLOBudgetBurning',     since: '24m', runbook: '/runbooks/slo-burn.md', desc: 'availability burn rate 2x normal' },
  { sev: 'info', name: 'CertExpiryApproaching', since: '6h',  runbook: '/runbooks/cert-renew.md', desc: 'mtls.aegis.example.com expires in 5 days' },
  { sev: 'info', name: 'ClusterVersionSkew',    since: '2h',  runbook: '/runbooks/cluster-rollout.md', desc: 'aegis-04 lags by one minor version' },
];

const ADMIN_LOG = [
  { ts: '17:11:43', class: 'admin',  actor: 'admin',  action: 'rule.update', target: 'owasp-sqli-007', reason: 'risk 50 -> 60', hash: 'a4f2e9c1b3d7' },
  { ts: '17:09:14', class: 'system', actor: 'gitops', action: 'config.sync', target: 'main@a8b1f2c',   reason: 'auto-pull',     hash: 'a4f2e9c1b3d6' },
  { ts: '17:04:02', class: 'admin',  actor: 'admin',  action: 'blacklist.add', target: '110.35.80.116', reason: 'SQLi flood', hash: 'a4f2e9c1b3d5' },
  { ts: '16:58:21', class: 'admin',  actor: 'admin',  action: 'tier.update', target: 'strict',         reason: 'detector +recon', hash: 'a4f2e9c1b3d4' },
  { ts: '16:51:09', class: 'system', actor: 'system', action: 'cert.renew', target: 'api.aegis.example.com', reason: 'auto-renew', hash: 'a4f2e9c1b3d3' },
  { ts: '16:42:55', class: 'admin',  actor: 'admin',  action: 'whitelist.add', target: 'fp:internal-soc-tls-2026', reason: 'pen-test 2026 Q2', hash: 'a4f2e9c1b3d2' },
  { ts: '16:30:11', class: 'admin',  actor: 'admin',  action: 'rule.create', target: 'honeypot-002', reason: 'new honeypot path', hash: 'a4f2e9c1b3d1' },
  { ts: '16:18:43', class: 'system', actor: 'system', action: 'audit.witness', target: 'block 412998', reason: 'witness-sig ok', hash: 'a4f2e9c1b3d0' },
];

// ============= Live data simulation =============

let _liveSeq = 1660000;
function makeLiveEvent(t) {
  const cat = ATTACK_CATS[Math.floor(Math.random() * ATTACK_CATS.length)];
  const isAttack = Math.random() < 0.18;
  const ipPool = ATTACKER_GEO[Math.floor(Math.random() * ATTACKER_GEO.length)];
  const region = REGIONS[Math.floor(Math.random() * REGIONS.length)];
  const method = METHODS[Math.floor(Math.random() * METHODS.length)];
  const path = ROUTES[Math.floor(Math.random() * ROUTES.length)];

  let action, risk, tier, rules;
  if (isAttack) {
    risk = 60 + Math.floor(Math.random() * 40);
    action = risk >= 75 ? 'block' : 'challenge';
    tier = risk >= 90 ? 'crit' : 'high';
    rules = [`owasp-${cat.id}-${String(Math.floor(Math.random()*9)+1).padStart(3,'0')}`];
  } else {
    risk = Math.floor(Math.random() * 35);
    action = 'allow';
    tier = risk > 20 ? 'med' : 'low';
    rules = [];
  }
  const ts = new Date(t || Date.now());
  const hh = String(ts.getHours()).padStart(2, '0');
  const mm = String(ts.getMinutes()).padStart(2, '0');
  const ss = String(ts.getSeconds()).padStart(2, '0');
  return {
    id: ++_liveSeq,
    ts: `${hh}:${mm}:${ss}`,
    epoch: Date.now(),
    ip: ipPool.ip,
    geo: ipPool,
    method,
    path,
    region,
    tier,
    risk,
    action,
    rules,
    cat: isAttack ? cat.id : null,
  };
}

function useLiveFeed(maxLen = 60, paused = false, ratePerSec = 6) {
  const [events, setEvents] = useState(() => {
    const arr = [];
    const now = Date.now();
    for (let i = 0; i < 24; i++) arr.push(makeLiveEvent(now - i * 1000));
    return arr.reverse();
  });
  useEffect(() => {
    if (paused) return;
    const interval = setInterval(() => {
      const burst = Math.max(1, Math.round(ratePerSec / 2 + Math.random() * ratePerSec));
      setEvents(prev => {
        const next = [...prev];
        for (let i = 0; i < burst; i++) next.push(makeLiveEvent());
        return next.slice(-maxLen);
      });
    }, 800);
    return () => clearInterval(interval);
  }, [paused, ratePerSec, maxLen]);
  return events;
}

// Time series — traffic vs blocked, last N points
function useTrafficSeries(points = 60, paused = false) {
  const [series, setSeries] = useState(() => {
    const arr = [];
    for (let i = 0; i < points; i++) {
      const total = 80 + Math.floor(Math.random() * 60) + (Math.sin(i / 5) * 30);
      const blocked = Math.max(0, Math.floor(total * (0.04 + Math.random() * 0.18)));
      arr.push({ t: i, total: Math.max(20, Math.round(total)), blocked });
    }
    return arr;
  });
  useEffect(() => {
    if (paused) return;
    const id = setInterval(() => {
      setSeries(prev => {
        const last = prev[prev.length - 1] || { t: 0 };
        const t = last.t + 1;
        const burst = Math.random() < 0.08;
        const total = Math.round(70 + Math.random() * 80 + (burst ? 100 : 0));
        const blocked = Math.max(0, Math.round(total * (0.05 + Math.random() * 0.15) + (burst ? 30 : 0)));
        return [...prev.slice(1), { t, total, blocked }];
      });
    }, 1000);
    return () => clearInterval(id);
  }, [paused]);
  return series;
}

function useTicking(intervalMs = 1000) {
  const [tick, setTick] = useState(0);
  useEffect(() => {
    const id = setInterval(() => setTick(t => t + 1), intervalMs);
    return () => clearInterval(id);
  }, [intervalMs]);
  return tick;
}

// ============= DD-T2 — real-API wiring =============

// Single-shot JSON fetch with periodic refresh. Any endpoint
// failure falls back to whatever `fallback` is — keeps the
// dashboard rendering even when a backend handler crashes mid-
// session. Returns `{ data, loading, error, reload }`.
function useApi(url, { intervalMs = 5000, fallback = null } = {}) {
  // FIX 2026-05-04 (round 2) — the page-head subtitle was
  // "flashing continuously" because `useApi` was caught in a
  // re-render storm: every caller passes fresh `{ intervalMs,
  // fallback: { pools: {} } }` object literals, so the
  // destructured values changed identity on every render →
  // `reload` was recreated → `useEffect` cleanup+re-arm fired
  // → setInterval started a fresh timer that fired within ms
  // → setState bumped a new render → repeat. The cumulative
  // effect was a setState every animation frame, which the
  // user perceives as a flickering subtitle.
  //
  // Fix: stabilise via refs. `useEffect` depends only on the
  // URL; the interval and fallback are read from refs so they
  // can change without re-arming the timer.
  //
  // (Also kept from round 1 — `error` is suppressed once we've
  // ever successfully fetched, so the "fetch failed" pill
  // doesn't flap on transient blips.)
  const optsRef = useRef({ intervalMs, fallback });
  optsRef.current = { intervalMs, fallback };
  const everOkRef = useRef(false);

  const [state, setState] = useState({
    data: fallback, loading: true, error: null, lastFetchOk: false,
  });

  const reload = useCallback(() => {
    fetch(url, { credentials: 'same-origin', cache: 'no-store' })
      .then(r => r.ok ? r.json() : Promise.reject(new Error(`HTTP ${r.status}`)))
      .then(data => {
        everOkRef.current = true;
        setState({ data, loading: false, error: null, lastFetchOk: true });
      })
      .catch(error => setState(s => ({
        data: s.data ?? optsRef.current.fallback,
        loading: false,
        error: everOkRef.current ? null : error,
        lastFetchOk: false,
      })));
  }, [url]);

  useEffect(() => {
    reload();
    const ms = optsRef.current.intervalMs ?? 5000;
    if (ms > 0) {
      const id = setInterval(reload, ms);
      return () => clearInterval(id);
    }
  }, [reload]);

  return { ...state, reload };
}

// Live request stream from /dashboard/sse. Drop-in replacement for
// useLiveFeed — produces the same row shape (id, ts, ip, method,
// path, region, tier, risk, action, rules, cat, geo) so the Live
// Feed page renders without conditionals. Returns
// `{ events, connected }`; pages that only need rows should
// destructure both anyway so they can show the connection state.
let _realLiveSeq = 0;
// 2026-05-05 — normalize raw tier values from the audit chain into the
// dashboard's display labels. The WAF emits `critical | high | medium |
// low` (matching `aegis_core::tier::Tier` post-rename, with `catch_all`
// kept as a serde alias). Map them to the short `crit / high / med /
// low` pills the existing renderer expects.
function normalizeWafTier(raw) {
  if (!raw) return null;
  const s = String(raw).toLowerCase();
  if (s === 'critical' || s === 'crit') return 'crit';
  if (s === 'high') return 'high';
  if (s === 'medium' || s === 'med') return 'med';
  if (s === 'low' || s === 'catch_all' || s === 'catchall') return 'low';
  return null;
}
// Risk-bucket label — used as a LAST-RESORT fallback when the audit
// event doesn't carry a `tier` (e.g. very old events from before the
// 2026-05-05 fix). New events should always populate `ev.tier` so this
// branch becomes dead in practice. Kept for backfill of legacy rows.
function tierForRisk(r) {
  if (r >= 90) return 'crit';
  if (r >= 60) return 'high';
  if (r >= 25) return 'med';
  return 'low';
}
function fmtTs(epoch) {
  const d = new Date(epoch);
  const h = String(d.getHours()).padStart(2, '0');
  const m = String(d.getMinutes()).padStart(2, '0');
  const s = String(d.getSeconds()).padStart(2, '0');
  return `${h}:${m}:${s}`;
}
// 2026-05-25 — for cumulative-gate rows (`risk-challenge` / `risk-score`),
// append the contributing detector(s) from `fields.detectors` so the feed
// reveals WHAT raised the score (e.g. ["risk-challenge", "recon_path"])
// instead of just the gate name — the QC "log looks like no detector fired
// but still challenged" gap. Per-request detector blocks already carry the
// detector list AS the rule_id, so those are left untouched (no dup).
// Contract §3 decision vocabulary is the only Action the UI surfaces.
// WS/TCP tunnel audit actions map to their decision: a blocked frame IS
// a `block`; open/close are non-blocking lifecycle = `allow` (the
// lifecycle itself stays visible in the Proto column as ws-open/ws-close).
const WS_DECISION = {
  websocket_frame_block: 'block',
  websocket_open: 'allow',
  websocket_close: 'allow',
  tcp_tunnel_open: 'allow',
  tcp_tunnel_close: 'allow',
};
function decisionAction(action) {
  return WS_DECISION[action] || action || 'allow';
}

// BUG-streaming-surfaces — the Proto column reflects the SURFACE, not the
// lifecycle/verdict. A WebSocket connection (the `GET … 101` upgrade) or any
// blocked WS frame (`fields.surface === 'websocket'`) reads `websocket`; a
// streamed `text/event-stream` response (`fields.streamed`) reads `sse`. The
// verdict (allow/block) stays in the Action column. TCP tunnels keep their
// existing labels. (Chrome DevTools parity: one surface-typed connection row.)
function streamingProto(action, ev, f) {
  if (action === 'tcp_tunnel_open') return 'tcp-open';
  if (action === 'tcp_tunnel_close') return 'tcp-close';
  const status = Number(f.status ?? ev.status);
  // A WebSocket connection is identifiable three ways: the successful
  // `101` upgrade (allow), a blocked frame after upgrade
  // (`fields.surface === 'websocket'`), OR a WS *upgrade request* that was
  // blocked at the HTTP layer (risk-score / detector) BEFORE the 101 — those
  // carry `status 403` + no surface, but the echoed request headers still
  // show `Upgrade: websocket`. Treat all three as `websocket` so a blocked
  // handshake reads the same surface as an allowed one (Chrome parity).
  if (f.surface === 'websocket' || status === 101 || isWsUpgradeReq(f)) return 'websocket';
  if (f.streamed === true) return 'sse';
  return 'http';
}

// True when the echoed request headers indicate a WebSocket upgrade
// (`Upgrade: websocket`). Present on block events at the default `Info`
// verbosity; absent below it (then the row falls back to `http`).
function isWsUpgradeReq(f) {
  const up = f.request_headers && f.request_headers.upgrade;
  return typeof up === 'string' && up.toLowerCase() === 'websocket';
}

// Lifecycle events that are always `allow` and carry no decision signal —
// hidden from the Live Feed (one connection row, not three). They remain in
// the durable Audit Trail + sinks for forensics.
const FEED_HIDDEN_ACTIONS = new Set(['websocket_open', 'websocket_close']);

// Labels emitted as `rule_id` for context but which aren't §5 rule_ids
// (the detector/rule/model that caused the decision). Dropped so the
// Rules column reads `—` for plain allows + WS lifecycle, per the
// interop contract, instead of showing `allow` / `ws_bridge_started` /
// `ws_bridge_closed` (which also use underscores, not the §5 hyphen form).
const NON_RULE_LABELS = new Set(['allow', 'none', 'ws_bridge_started', 'ws_bridge_closed']);
function isRealRule(id) {
  return !!id && !NON_RULE_LABELS.has(id) && !id.startsWith('ws_bridge');
}
function feedRules(ruleId, fields, fallback) {
  if (!isRealRule(ruleId)) {
    return (fallback || []).filter(isRealRule);
  }
  const isGate = ruleId === 'risk-challenge' || ruleId === 'risk-score';
  const raw = fields && typeof fields.detectors === 'string' ? fields.detectors : '';
  const dets = raw ? raw.split(',').map(s => s.trim()).filter(Boolean) : [];
  return isGate && dets.length ? [ruleId, ...dets] : [ruleId];
}
// 2026-05-03 — backfill Live Feed from /api/audit/since on mount
// so an analyst landing on the page mid-incident sees recent
// events instead of "1 of 1 events" + the SSE connect handshake.
// We read the audit ring once, render those rows immediately,
// then layer the SSE stream on top for real-time follow-up.
// Fields go through the same mapper the SSE branch uses so the
// table shape is identical.
function mapAuditToLiveRow(ev, seq) {
  const f = (ev.fields && typeof ev.fields === 'object') ? ev.fields : {};
  const tsRaw = ev.ts || ev.ts_ms;
  const epoch = typeof tsRaw === 'number'
    ? tsRaw
    : (typeof tsRaw === 'string' ? Date.parse(tsRaw) : Date.now());
  const risk = ev.risk_score || 0;
  const action = ev.action || 'allow';
  const ip = ev.client_ip || ev.ip || '0.0.0.0';
  const ruleId = ev.rule_id || ev.reason || null;
  const protocol = streamingProto(action, ev, f);
  return {
    id: seq,
    ts: fmtTs(epoch),
    epoch,
    ip,
    geo: null,
    method: f.method || ev.method || 'GET',
    path: f.path || ev.path || '/',
    region: f.region || ev.region || '',
    tier: normalizeWafTier(ev.tier) || tierForRisk(risk),
    // true when the tier above came from the risk-bucket fallback (no route
    // tier on the event) — the renderer marks it as inferred, not authoritative.
    tierInferred: !normalizeWafTier(ev.tier),
    risk,
    action: decisionAction(action),
    rules: feedRules(ruleId, f, ev.rules),
    cat: ev.category || ev.cat || null,
    status: f.status || ev.status || (action === 'block' ? 403 : 200),
    latency: f.latency_ms || ev.latency_ms || 0,
    request_id: ev.request_id || null,
    class: ev.class || null,
    reason: ev.reason || null,
    protocol,
    fields: f,
  };
}

function useRealLiveFeed(maxLen = 60, paused = false) {
  const [events, setEvents] = useState([]);
  const [connected, setConnected] = useState(false);

  // Backfill once on mount.  Filter to real request decisions
  // (block / allow / challenge / rate_limit / timeout /
  // circuit_breaker) so the SSE-internal connect / heartbeat
  // events don't pad the visible buffer.
  useEffect(() => {
    let cancelled = false;
    // F6 (2026-06-11) — scope=fleet so the backfill includes cross-node
    // rows (the SSE live feed is already fleet-wide; this stops the
    // reload from dropping peers' events). The server falls back to the
    // local ring when no fleet cache is wired (single-node).
    fetch(`/api/audit/since?tail=1&scope=fleet&limit=${maxLen}`, { credentials: 'same-origin' })
      .then(r => r.ok ? r.json() : null)
      .then(data => {
        if (cancelled || !data || !Array.isArray(data.events)) return;
        const REAL_ACTIONS = new Set([
          'allow', 'block', 'challenge', 'rate_limit',
          'timeout', 'circuit_breaker',
          // A blocked WS frame is a real `block` decision (current emit) —
          // already covered by `block`. `websocket_frame_block` kept as a
          // legacy alias for pre-B2 rows still in the durable ring.
          'websocket_frame_block',
        ]);
        // BUG-streaming-surfaces — ws-open/ws-close lifecycle rows are dropped
        // from the Live Feed (Audit Trail keeps them).
        const backfilled = data.events
          .filter(ev => REAL_ACTIONS.has(ev.action) && !FEED_HIDDEN_ACTIONS.has(ev.action))
          .map(ev => mapAuditToLiveRow(ev, ++_realLiveSeq));
        if (backfilled.length > 0) {
          setEvents(prev => {
            // Preserve any SSE rows that already arrived; merge by epoch.
            const merged = [...backfilled, ...prev]
              .sort((a, b) => a.epoch - b.epoch);
            return merged.slice(-maxLen);
          });
        }
      })
      .catch(() => { /* backfill failed — SSE alone is fine */ });
    return () => { cancelled = true; };
  }, [maxLen]);

  useEffect(() => {
    if (paused) return;
    let es;
    try {
      es = new EventSource('/dashboard/sse', { withCredentials: true });
      es.onopen = () => setConnected(true);
      es.onerror = () => setConnected(false);
      es.onmessage = (e) => {
        try {
          const ev = JSON.parse(e.data);
          // FIX 2026-05-03 — the data plane emits AuditEvent with
          // method / path / status / latency_ms nested under
          // `fields`; older code read them at the top level which
          // is why Live Feed showed an empty Path column. Read
          // from `fields` first and fall back to top-level only
          // for forward compatibility.
          const f = (ev.fields && typeof ev.fields === 'object') ? ev.fields : {};
          const tsRaw = ev.ts || ev.ts_ms;
          const epoch = typeof tsRaw === 'number'
            ? tsRaw
            : (typeof tsRaw === 'string' ? Date.parse(tsRaw) : Date.now());
          const risk = ev.risk_score || 0;
          const action = ev.action || 'allow';
          // F7/F8 (2026-06-11) — when the config plane applies a new
          // version fleet-wide, re-broadcast it so version-sensitive
          // cards (e.g. the detector mask) re-sync to authoritative
          // state without a hard page reload. Carries the applied
          // version so listeners can refresh their `If-Match` basis.
          if (action === 'config_reload') {
            try {
              window.dispatchEvent(new CustomEvent('aegis:config-reload', {
                detail: { version: f.version ?? ev.version ?? null },
              }));
            } catch (_) { /* CustomEvent unsupported — non-fatal */ }
          }
          // BUG-streaming-surfaces — drop ws-open/ws-close lifecycle rows
          // from the Live Feed (Chrome parity: the GET..101 handshake row +
          // any block rows represent the connection; lifecycle stays in the
          // Audit Trail). The config_reload dispatch above already ran.
          if (FEED_HIDDEN_ACTIONS.has(action)) return;
          const ip = ev.client_ip || ev.ip || '0.0.0.0';
          const ruleId = ev.rule_id || ev.reason || null;
          // Proto reflects the surface (websocket / sse / http); the
          // verdict stays in the Action column. See `streamingProto`.
          const protocol = streamingProto(action, ev, f);
          const mapped = {
            id: ++_realLiveSeq,
            ts: fmtTs(epoch),
            epoch,
            ip,
            geo: null,
            method: f.method || ev.method || 'GET',
            path: f.path || ev.path || '/',
            region: f.region || ev.region || '',
            tier: normalizeWafTier(ev.tier) || tierForRisk(risk),
            // see backfill path above — flags a risk-bucket fallback tier.
            tierInferred: !normalizeWafTier(ev.tier),
            risk,
            action: decisionAction(action),
            rules: feedRules(ruleId, f, ev.rules),
            cat: ev.category || ev.cat || null,
            status: f.status || ev.status || (action === 'block' ? 403 : 200),
            latency: f.latency_ms || ev.latency_ms || 0,
            // CQF — surface the canonical request_id + the audit
            // class so the RequestDetail drawer can deep-link.
            request_id: ev.request_id || null,
            class: ev.class || null,
            reason: ev.reason || null,
            protocol,
            // Keep the raw fields object so the drawer can render
            // every backend-emitted scalar (status, route_id,
            // tier, anything detector-specific) without needing
            // a frontend schema update each time.
            fields: f,
          };
          setEvents(prev => [...prev, mapped].slice(-maxLen));
        } catch (_) { /* ignore malformed line */ }
      };
    } catch (_) {
      // EventSource not available; leave events empty
    }
    return () => { if (es) es.close(); };
  }, [paused, maxLen]);
  return { events, connected };
}

// Hook: rules list. Returns the real list from /api/rules with a
// reload function for after a mutation.
function useRulesApi() {
  // HACK-T1 — fallback switched to empty list. The Rule Manager
  // page renders an honest empty state when the live API hasn't
  // answered yet rather than seeding curated demo rules.
  return useApi('/api/rules', { intervalMs: 0, fallback: { rules: [] } });
}

// Hook: blacklist + whitelist
function useBlacklistApi() {
  // HACK-T1 — empty list rather than seeded fixture.
  return useApi('/api/blacklist', { intervalMs: 10000, fallback: { entries: [] } });
}
function useWhitelistApi() {
  // HACK-T1 — empty list rather than seeded fixture.
  return useApi('/api/whitelist', { intervalMs: 10000, fallback: { entries: [] } });
}

// Hook: WAF status (uptime, version, mode, rule count) — DD
// satisfies Hackathon "Health/Status View" requirement.
function useStatusApi() {
  return useApi('/api/about', { intervalMs: 5000, fallback: null });
}

// Hook: stats + timeseries for Overview
function useStatsApi() {
  return useApi('/api/stats', { intervalMs: 2000, fallback: null });
}
function useTimeseriesApi(window = 900, step = 5) {
  return useApi(`/api/stats/timeseries?window=${window}&step=${step}`, { intervalMs: 5000, fallback: null });
}

// Hook: attacks distribution + top
function useAttacksDistributionApi(window = 900) {
  return useApi(`/api/attacks/distribution?window=${window}`, { intervalMs: 5000, fallback: null });
}
function useAttacksTopApi(window = 900, limit = 10) {
  // ≤3s poll so the fleet-merged gauge (publish ~2s) stays inside the
  // ≤5s budget (cluster plan §2c).
  return useApi(`/api/attacks/top?window=${window}&limit=${limit}`, { intervalMs: 3000, fallback: null });
}
// HACK-T4 — Tier-B bonus: config-change timeline. Filters
// the audit ring to `class = Admin` events and returns them
// newest-first. Cheap server-side; we poll on a 5 s cadence
// so the timeline picks up new mutations within one tick.
function useConfigVersionsApi(limit = 50) {
  return useApi(`/api/config/versions?limit=${limit}`, { intervalMs: 5000, fallback: null });
}

// FIX 2026-05-03: global fetch interceptor + central
// CSRF-aware mutation helper. The interceptor catches the
// session-expired CSRF reject (HTTP 403 + reason: "csrf_*")
// from EVERY mutation call site (refactored or not), surfaces
// a toast, and redirects to /admin/login after 1.5 s. Without
// this, operators hit "Add failed: missing aegis_csrf cookie"
// with no context + no way back to login.
//
// Install once at module load. Idempotent — repeated installs
// (HMR / hot-reload) re-wrap our own wrapper, harmlessly.
(function installCsrfFetchInterceptor() {
  if (typeof window === 'undefined' || window.__aegisCsrfFetchInstalled) {
    return;
  }
  window.__aegisCsrfFetchInstalled = true;
  const _origFetch = window.fetch.bind(window);
  window.fetch = async (...args) => {
    const r = await _origFetch(...args);
    // F12 (2026-06-11 cluster QC) — session dropped mid-session. The
    // admin gate returns 401 {reason:"admin_unauthenticated"} on every
    // /api/* fetch once the session lapses; pre-fix the SPA kept
    // rendering stale chrome and silently stopped updating, so a SOC
    // analyst stared at frozen data unaware they were logged out. Catch
    // it globally (mirrors the 403/CSRF handling below) and bounce to
    // login, preserving where they were via `next=`.
    if (r.status === 401 && !window.__aegisCsrfRedirecting) {
      const url = typeof args[0] === 'string' ? args[0] : (args[0]?.url ?? '');
      // Only react to API calls (the data layer). Don't loop on the
      // login page's own probes or non-API navigations.
      if (url.includes('/api/')) {
        window.__aegisCsrfRedirecting = true;
        try {
          const method = (args[1]?.method ?? args[0]?.method ?? 'GET').toUpperCase();
          window.localStorage.setItem('__aegisLastRedirect', JSON.stringify({
            ts: new Date().toISOString(),
            url,
            method,
            status: 401,
            reason: 'admin_unauthenticated',
            note: 'global fetch interceptor (401) → /admin/login',
          }));
        } catch (_storage) { /* storage disabled — non-fatal */ }
        const toast = window.aegisToast || ((m) => console.warn('[auth]', m));
        toast('Session expired — redirecting to login…', 'warn');
        const next = encodeURIComponent(window.location.pathname + window.location.hash);
        setTimeout(() => {
          window.location.href = `/admin/login?next=${next}`;
        }, 1200);
      }
      return r;
    }
    if (r.status === 403 && !window.__aegisCsrfRedirecting) {
      try {
        const cloned = r.clone();
        const body = await cloned.json();
        // RUN3-NEW-3 (2026-05-08) — tighter heuristic. The
        // canonical CSRF reject shape from MutationError is
        // `{ok: false, reason: "csrf_*", ...}`. Requiring
        // `ok === false` filters out unrelated 403s that happen
        // to carry a `reason` field starting with `csrf_` (e.g.
        // an audit-log entry being passed through a wrapper).
        if (typeof body?.reason === 'string'
            && body.reason.startsWith('csrf_')
            && body.ok === false) {
          window.__aegisCsrfRedirecting = true;
          // RUN3-NEW-3 — capture trigger context so the next
          // operator hitting this redirect has actionable
          // evidence. localStorage survives the navigation to
          // /admin/login. Operators reporting the issue can
          // paste back this entry from devtools, giving us
          // confirmation of which fetch tripped the redirect
          // (vs the QA-suspected coincidence with reset_state).
          try {
            const url = typeof args[0] === 'string'
              ? args[0]
              : (args[0]?.url ?? 'unknown');
            const method = (args[1]?.method ?? args[0]?.method ?? 'GET').toUpperCase();
            window.localStorage.setItem('__aegisLastRedirect', JSON.stringify({
              ts:     new Date().toISOString(),
              url,
              method,
              status: r.status,
              reason: body.reason,
              note:   'global fetch interceptor → /admin/login',
            }));
          } catch (_storage) {
            // localStorage might be disabled / quota-exceeded;
            // non-fatal — the redirect still happens.
          }
          const toast = window.aegisToast
            || ((m) => console.warn('[csrf]', m));
          toast('Session expired — redirecting to login…', 'warn');
          setTimeout(() => {
            window.location.href = '/admin/login';
          }, 1500);
        }
      } catch (_e) {
        // Body wasn't JSON or already consumed; non-fatal.
        // Caller still gets the original Response.
      }
    }
    return r;
  };
})();

// Central CSRF-aware mutation helper for new code.
//
// `body` is JSON-stringified when present; pass null for
// methods like DELETE / no-body POST.
async function csrfMutate(url, { method = 'POST', body = null, ifMatch = undefined } = {}) {
  const csrf = document.cookie.split('; ')
    .find(c => c.startsWith('aegis_csrf='))?.slice(11) || '';
  const headers = { 'x-csrf-token': csrf };
  // F7 (2026-06-11) — optimistic-concurrency precondition. Callers
  // that read a versioned resource (e.g. the detector mask) echo the
  // version here so the server rejects (412) a write built on a stale
  // view instead of clobbering a concurrent change.
  if (ifMatch !== undefined && ifMatch !== null) {
    headers['if-match'] = String(ifMatch);
  }
  let init = { method, credentials: 'same-origin', headers };
  if (body !== null && body !== undefined) {
    headers['content-type'] = 'application/json';
    init.body = typeof body === 'string' ? body : JSON.stringify(body);
  }
  // 2026-05-28 — config-plane writes (folded console toggles + PUT
  // /api/config) can return 409 {ok:false, error:"version_conflict"}
  // when a concurrent edit bumped the shared config version between the
  // server reading it and the CAS activate. The folded toggle handlers
  // re-read the current version server-side, so simply re-issuing the
  // same request converges. Bounded auto-retry with small backoff; a
  // persistent conflict (e.g. a full-doc PUT against a stale base)
  // surfaces to the caller after the retries are exhausted.
  let r;
  let parsed;
  for (let attempt = 0; ; attempt++) {
    r = await fetch(url, init);
    parsed = await r.json().catch(() => ({}));
    if (r.status === 409 && parsed && parsed.error === 'version_conflict' && attempt < 2) {
      await new Promise((res) => setTimeout(res, 150 * (attempt + 1)));
      continue;
    }
    break;
  }
  // Detect session-expired CSRF reject. The server returns
  // {ok: false, reason: "csrf_missing_cookie" | "csrf_missing_header"
  // | "csrf_mismatch"} with HTTP 403 (see
  // aegis_control::api::mutation::MutationError).
  // RUN3-NEW-3 (2026-05-08) — match `ok: false` too so we don't
  // trip on non-error 403 bodies that happen to carry a
  // `reason` field starting with `csrf_`. Same diagnostic stash
  // as the global interceptor for cross-correlation.
  if (r.status === 403
      && typeof parsed?.reason === 'string'
      && parsed.reason.startsWith('csrf_')
      && parsed.ok === false) {
    if (typeof window !== 'undefined' && !window.__aegisCsrfRedirecting) {
      window.__aegisCsrfRedirecting = true;
      try {
        window.localStorage.setItem('__aegisLastRedirect', JSON.stringify({
          ts:     new Date().toISOString(),
          url,
          method,
          status: r.status,
          reason: parsed.reason,
          note:   'csrfMutate → /admin/login',
        }));
      } catch (_storage) {
        // localStorage disabled / quota exceeded — non-fatal.
      }
      const toast = window.aegisToast || ((m) => console.warn(m));
      toast('Session expired — redirecting to login…', 'warn');
      setTimeout(() => {
        window.location.href = '/admin/login';
      }, 1500);
    }
  }
  // 2026-05-05 — spread parsed FIRST so the response body's fields
  // are exposed, then write `status: r.status` LAST so HTTP status
  // always wins. Without this order, a body like
  // `{"status":"resolved"}` (from PUT /api/incidents/{id}/resolve)
  // would overwrite the HTTP 200 with the string "resolved",
  // breaking the `r.status >= 200 && r.status < 300` success check
  // and causing every Resolve click to surface "resolve failed:
  // status resolved". Body-side `status` is still accessible at
  // `r.body_status` for callers that need it.
  return {
    ...parsed,
    body_status: parsed?.status,
    status: r.status,
  };
}

// HACK-T4 rollback — POST /api/config/versions/{seq}/rollback.
// Returns the dispatcher outcome (decision_action, before,
// after) or an error object on 4xx/5xx.
async function configRollback(seq) {
  return csrfMutate(`/api/config/versions/${encodeURIComponent(seq)}/rollback`,
                    { method: 'POST' });
}

// HACK-T4 — actions the dashboard knows are rollback-able.
// Mirrors `pub const ROLLBACKABLE_ACTIONS` in
// `aegis-control::api::rollback`. Keep in sync; operators see
// the Rollback button only on these rows.
const ROLLBACKABLE_ACTIONS = [
  'mode_set',                // v1
  'risk_thresholds_set',     // v2
  'zero_trust_sans_set',           // v2
  'zero_trust_sans_removed',       // v2
  'blacklist_add',           // v3
  'blacklist_remove',        // v3
  'whitelist_add',           // v3
  'whitelist_remove',        // v3
  'detector_mask_set',       // v4
  'verbosity_set',           // v5
  'loadmode_set',            // v5
  'rule_create',             // v6
  'rule_update',             // v6
  'rule_delete',             // v6
  'rule_toggle',             // v6
];

// MTLS-T7 — Allowed SAN allowlist. Read once + on demand;
// the underlying store is hot-reloadable so we don't need
// aggressive polling. The mutation helpers below are the
// audit-mutated PUT / DELETE / POST-test endpoints.
function useMtlsSansApi() {
  return useApi('/api/zero-trust/downstream/sans', { intervalMs: 15000, fallback: { allowed: [] } });
}
async function mtlsSansPut(allowed) {
  return csrfMutate('/api/zero-trust/downstream/sans', { method: 'PUT', body: JSON.stringify({ allowed }) });
}

// M002 (2026-05-07) — operator override for the LoadGauge mode.
// PUT body shape (see crates/aegis-control/src/api/load_mode.rs):
//   { override: "normal" | "elevated" | "critical" | "unset" }
function useLoadModeApi() {
  return useApi('/api/loadmode', { intervalMs: 5000, fallback: null });
}
async function loadmodePut(modeOrUnset) {
  return csrfMutate('/api/loadmode', {
    method: 'PUT',
    body: JSON.stringify({ override: modeOrUnset }),
  });
}

// M004 (2026-05-07) — Settings page surface hooks. All read-only;
// the corresponding mutation handlers (terminate session, toggle
// break-glass, update integration URLs) aren't wired in
// admin_dispatch yet, so the dashboard renders these as
// information-only cards. Future work: add audit-mutated
// DELETE /api/admin/sessions/{id}, POST /api/admin/break-glass,
// PUT /api/integrations.
function useAdminSessionsApi() {
  return useApi('/api/admin/sessions', { intervalMs: 15000, fallback: null });
}
function useBreakGlassApi() {
  return useApi('/api/admin/break-glass', { intervalMs: 5000, fallback: null });
}
function useIntegrationsApi() {
  return useApi('/api/integrations', { intervalMs: 60000, fallback: null });
}
async function mtlsSansDelete(san) {
  return csrfMutate(`/api/zero-trust/downstream/sans/${encodeURIComponent(san)}`, {
    method: 'DELETE',
    headers: { 'x-csrf-token': csrf },
    credentials: 'same-origin',
  });
  return { status: r.status, ...(await r.json().catch(() => ({}))) };
}
async function mtlsSansTest(san) {
  return csrfMutate(`/api/zero-trust/downstream/sans/${encodeURIComponent(san)}/test`, { method: 'POST' });
}

// CQF-T2 — Blacklist + Whitelist add / delete. Audit-mutated;
// `kind` is `'blacklist'` or `'whitelist'`. The body shape is
// the AccessListEntry the Rust store deserialises:
//   { id, kind: 'ip'|'cidr'|'asn', value, note, expires_at?, bypass: [] }
async function accessListAdd(kind, entry) {
  return csrfMutate(`/api/${kind}`, { method: 'POST', body: JSON.stringify(entry) });
}
async function accessListDelete(kind, id) {
  return csrfMutate(`/api/${kind}/${encodeURIComponent(id)}`, { method: 'DELETE' });
}

// CQF-T1 — admin logout. POSTs /admin/logout with the CSRF
// header. The handler responds 204 + Set-Cookie clearing
// both `aegis_session` and `aegis_csrf` so the browser
// drops them. We then redirect the operator to the login
// screen.
async function adminLogout() {
  const csrf = document.cookie.split('; ').find(c => c.startsWith('aegis_csrf='))?.slice(11) || '';
  const r = await fetch('/admin/logout', {
    method: 'POST',
    headers: { 'x-csrf-token': csrf },
    credentials: 'same-origin',
  });
  return { status: r.status };
}

// HACK-T3 — Tier-A bonus: rule simulator. POST a synthetic
// request and get back the live decision tree. CSRF cookie+
// header same as other audit-mutated POSTs (the simulator
// itself is read-only but reuses the dashboard's gated POST
// path).
async function rulesSimulate(body) {
  // 2026-05-11 F-01 — previous version built the CSRF token but
  // never sent it as a header, and the function had no return
  // statement so callers got `undefined`. The simulator panel's
  // `setResult(undefined)` then made every render guard
  // (`result && result.status === 200`) false and the result
  // never appeared in the UI even though the API returned 200
  // with a well-formed JSON body.
  const csrf = document.cookie.split('; ').find(c => c.startsWith('aegis_csrf='))?.slice(11) || '';
  const r = await fetch('/api/rules/simulate', {
    method: 'POST',
    credentials: 'same-origin',
    headers: {
      'content-type': 'application/json',
      'x-csrf-token': csrf,
    },
    body: JSON.stringify(body),
  });
  const parsed = await r.json().catch(() => ({}));
  // Return a single shape the simulator panel can render:
  // HTTP status + whatever the backend put in the body. The
  // body keys (decision_action, rule_id, risk_score,
  // detectors_fired, signals, tier, muted_detectors) are
  // spread on top so the component reads them directly.
  return { status: r.status, ...parsed };
}

// HACK-T1 — live hooks for PageAttackEvents. Each one is
// already wired server-side; this is just the dashboard
// adapter so the page can stop using `Math.random`.
function useAttacksByDetectorApi(window = 3600) {
  // ≤3s poll for the fleet-merged gauge (cluster plan §2c).
  return useApi(`/api/attacks/by-detector?window=${window}`, { intervalMs: 3000, fallback: null });
}
function useBotMixApi(window = 3600) {
  return useApi(`/api/bots/mix?window=${window}`, { intervalMs: 10000, fallback: null });
}
function useThreatIntelApi(window = 3600, limit = 20) {
  return useApi(`/api/threat-intel/hits?window=${window}&limit=${limit}`, { intervalMs: 10000, fallback: null });
}

// Hook: audit log with filters
function useAuditLogApi({ ip, ruleId, requestId, from, to, limit = 200 } = {}) {
  const params = new URLSearchParams();
  // 2026-05-23 — tail=1 returns the NEWEST `limit` events (back of the
  // ring). Without it, cursor=0 returns the OLDEST retained events, so
  // Recent Requests / Audit Trail / the Investigation pivot froze on
  // stale traffic after a flood. (Respects the ip/rule_id filters.)
  params.set('tail', '1');
  // F6 (2026-06-11) — fleet-merged backfill so the Audit Trail /
  // Investigation pivots show cross-node rows on reload, matching the
  // fleet-wide SSE live feed. Server falls back to local when no fleet
  // cache is wired. Filters (ip / rule_id / request_id) apply post-merge.
  params.set('scope', 'fleet');
  if (limit) params.set('limit', String(limit));
  if (ip) params.set('ip', ip);
  if (ruleId) params.set('rule_id', ruleId);
  if (requestId) params.set('request_id', requestId);
  if (from) params.set('from', String(from));
  if (to) params.set('to', String(to));
  return useApi(`/api/audit/since?${params.toString()}`, { intervalMs: 3000, fallback: null });
}

// Hook: route table — read-only view of the routing trie. Fed by
// /api/routes (CI-T5). Cached server-side for 30s; client polls
// every 30s so a hot-reload surfaces within one tick.
function useRoutesApi() {
  return useApi('/api/routes', { intervalMs: 30000, fallback: { routes: [] } });
}
function useTiersApi() {
  // HACK-T1 — empty list rather than seeded fixture.
  return useApi('/api/tiers', { intervalMs: 30000, fallback: { tiers: [] } });
}

// CQF-T6 — derive a per-path risk heatmap client-side from
// `/api/audit/since`. The endpoint returns up to `limit` events
// with `fields.path` + `risk_score`; we group by path, take the
// max risk per path (heatmap intensity), sort, and keep the top
// `top` paths. A purpose-built backend aggregator would be the
// long-term fix; this is enough to retire the hardcoded rows
// flagged in CQA-T1 / T14 today.
function useTopRiskPathsApi(limit = 200, top = 8) {
  const api = useApi(`/api/audit/since?tail=1&scope=fleet&limit=${limit}`, {
    intervalMs: 5000,
    fallback: { events: [] },
  });
  const events = Array.isArray(api?.data?.events) ? api.data.events : [];
  // Group by path → max risk
  const byPath = new Map();
  for (const ev of events) {
    const p = ev?.fields?.path;
    const r = Number(ev?.risk_score ?? 0);
    if (!p) continue;
    const cur = byPath.get(p) || 0;
    if (r > cur) byPath.set(p, r);
  }
  const rows = Array.from(byPath.entries())
    .map(([path, score]) => ({
      path,
      // RiskHeatmap expects intensity ∈ [0, 1]; risk_score is 0..100.
      intensity: Math.max(0, Math.min(1, score / 100)),
    }))
    .sort((a, b) => b.intensity - a.intensity)
    .slice(0, top);
  return { ...api, rows };
}

// CQF-T3 — detector mask read + audit-mutated PUT. The PUT
// handler (handle_detectors_put) lives in admin_mutate.rs;
// body shape per `DetectorsPutBody` in detectors.rs:
//   { "mask": {sqli, xss, path_traversal, ssrf, header_injection,
//              body_abuse, recon, brute_force},
//     "overrides": { "<tier>": {…}|null, … } }
function useDetectorsApi() {
  return useApi('/api/detectors', { intervalMs: 30000, fallback: null });
}
// F7 (2026-06-11) — `ifMatch` is the `config_version` the caller last
// read from GET /api/detectors. The server uses it as the CAS
// `expected`, returning 412 if the mask moved under the caller.
async function detectorsPut(body, { ifMatch } = {}) {
  return csrfMutate('/api/detectors', {
    method: 'PUT',
    body: JSON.stringify(body),
    ifMatch,
  });
}

// Hook: cluster, slo, certs, alerts, gitops, upstreams (Tracking page)
// HACK-T1 — fallbacks switched from static fixtures to `null`
// per Hackathon v2.3 §2.2 ("Dashboard uses... local state, or
// simulated responses that make the UI state inconsistent with
// the real WAF-PROXY state"). Pages must render an honest
// empty state when the live API returns nothing.
function useClusterApi()  { return useApi('/api/cluster',         { intervalMs: 5000, fallback: null }); }
// 2026-05-27 — cluster config-plane status: active version + per-node
// applied version (drift). Backed by GET /api/config (ConfigStore).
function useConfigApi()   { return useApi('/api/config',          { intervalMs: 5000, fallback: null }); }
function useSloApi()      { return useApi('/api/slo',             { intervalMs: 10000, fallback: null }); }
function useCertsApi()    { return useApi('/api/certs',           { intervalMs: 30000, fallback: null }); }
function useLatencyApi()  { return useApi('/api/analytics/latency',{ intervalMs: 5000, fallback: null }); }
function useRouteLatencyApi() { return useApi('/api/analytics/latency/routes',{ intervalMs: 5000, fallback: null }); }
function useDetectorLatencyApi() { return useApi('/api/analytics/latency/detectors',{ intervalMs: 5000, fallback: null }); }
function useAnalyticsRoutesApi() { return useApi('/api/analytics/routes',{ intervalMs: 10000, fallback: null }); }
function useIncidentsApi(){ return useApi('/api/incidents',         { intervalMs: 5000, fallback: null }); }
function useThreatIntelFeedsApi() { return useApi('/api/threat-intel/feeds', { intervalMs: 30000, fallback: null }); }
function useGeoipStatusApi() { return useApi('/api/geoip/status',   { intervalMs: 60000, fallback: null }); }

// Phase-3 incident mutations (CSRF-double-submit, POST). All
// three route through `csrfMutate` so the CSRF cookie + header
// + 403 session-expiry redirect are handled uniformly.
//
// FIX 2026-05-04 — `incidentAck` was broken: it called
// `csrfMutate` (correct) but the call's `headers` object
// referenced a `csrf` variable that wasn't in scope, and the
// dead `if (!r.ok)` lines after `return` would never run.
// Calling Ack threw a `ReferenceError` that doAct swallowed
// because it called `window.toast` (typo for aegisToast).
// All three now follow the same shape — small, lockstep,
// returns `{ status, ...body }` per the csrfMutate contract.
async function incidentAck(id, opts) {
  return csrfMutate(`/api/incidents/${encodeURIComponent(id)}/ack`, {
    method: 'POST',
    body: JSON.stringify(opts || {}),
  });
}
async function incidentSnooze(id, minutes, note) {
  return csrfMutate(`/api/incidents/${encodeURIComponent(id)}/snooze`, {
    method: 'POST',
    body: JSON.stringify({ minutes, note }),
  });
}
async function incidentResolve(id, note) {
  return csrfMutate(`/api/incidents/${encodeURIComponent(id)}/resolve`, {
    method: 'POST',
    body: JSON.stringify({ note }),
  });
}
function useAlertsApi()   { return useApi('/api/alerts',          { intervalMs: 5000, fallback: null }); }
function useGitopsApi()   { return useApi('/api/gitops/status',   { intervalMs: 30000, fallback: null }); }
// HACK-T1 — empty list rather than seeded fixture.
function useUpstreamsApi(){ return useApi('/api/upstreams',       { intervalMs: 5000, fallback: { pools: [] } }); }
// SC-1 — per-upstream smart-cache stats (L1 in-process today; backend field
// distinguishes in_memory vs redis once the L2 tier ships).
function useCacheStatsApi(){ return useApi('/api/cache/stats',     { intervalMs: 5000, fallback: { pools: [] } }); }
// CC-T1.1 — full upstream-pool config view (members, lb, health,
// circuit-breaker, connection pool, referenced_by_routes).
// CC-T1.1.b shipped the audit-mutated PUT/DELETE; helpers below.
function useUpstreamsConfigApi() {
  return useApi('/api/upstreams/config', {
    intervalMs: 30000,
    fallback: { pools: {} },
  });
}

// CC-T1.1.b — upstream pool mutation helpers. CSRF cookie+header
// pattern from rulesPut / settingsModePut.
async function upstreamsConfigPut(pools) {
  const csrf = document.cookie.split('; ').find(c => c.startsWith('aegis_csrf='))?.slice(11) || '';
  const r = await fetch('/api/upstreams/config', { method: 'PUT', body: JSON.stringify({ pools }),
  });
  return r.json().catch(() => ({ error: `HTTP ${r.status}` }));
}
async function poolUpsert(name, body) {
  const csrf = document.cookie.split('; ').find(c => c.startsWith('aegis_csrf='))?.slice(11) || '';
  const r = await fetch(`/api/upstreams/pool/${encodeURIComponent(name)}`, {
    method: 'PUT',
    headers: { 'content-type': 'application/json', 'x-csrf-token': csrf },
    credentials: 'same-origin',
    body: JSON.stringify(body),
  });
  // Pass through the HTTP status so the caller can distinguish
  // 409 (route-reference guard) from 400 (validation).
  const json = await r.json().catch(() => ({ error: `HTTP ${r.status}` }));
  return { status: r.status, ...json };
}
async function poolDelete(name) {
  const csrf = document.cookie.split('; ').find(c => c.startsWith('aegis_csrf='))?.slice(11) || '';
  const r = await fetch(`/api/upstreams/pool/${encodeURIComponent(name)}`, {
    method: 'DELETE',
    headers: { 'x-csrf-token': csrf },
    credentials: 'same-origin',
  });
  // 409 with referenced_by_routes payload is normal — caller renders it.
  const json = await r.json().catch(() => ({ error: `HTTP ${r.status}` }));
  return { status: r.status, ...json };
}

// TI-T — tier mutation. Updates pipeline + thresholds for one
// of the four canonical tiers (critical / high / medium / low).
// Backend constrains the tier name to that enum; an unknown
// name returns 400 `validation`.
async function tierPut(name, body) {
  return csrfMutate(`/api/tiers/${encodeURIComponent(name)}`, {
    method: 'PUT',
    body: JSON.stringify(body),
  });
}

// AI-T10 — runtime on/off for the AI detector. GET is open-on-
// session; PUT is audit-mutated + CSRF-gated. The dashboard's
// merged Detectors panel uses both: GET on mount to seed the
// toggle state, PUT when the operator flips it.
function useAiEnabledApi() {
  return useApi('/api/ai/enabled', { intervalMs: 10000, fallback: { enabled: false, feature_present: false } });
}
async function aiEnabledPut(enabled) {
  const csrf = document.cookie.split('; ').find(c => c.startsWith('aegis_csrf='))?.slice(11) || '';
  const r = await fetch('/api/ai/enabled', {
    method: 'PUT',
    headers: { 'content-type': 'application/json', 'x-csrf-token': csrf },
    credentials: 'same-origin',
    body: JSON.stringify({ enabled: !!enabled }),
  });
  const json = await r.json().catch(() => ({ error: `HTTP ${r.status}` }));
  return { status: r.status, ...json };
}

// 2026-05-29 — runtime `confidence_threshold` for the AI detector.
// Same shape as useAiEnabledApi/aiEnabledPut: GET surfaces the LIVE
// value (from the shared AtomicU32) plus `default` (the cfg-loaded
// value at boot) so the dashboard can show "current vs. config"
// without re-parsing YAML. PUT is audit-mutated + CSRF-gated and
// routes through the cluster config plane, so the value persists
// and propagates to every node.
function useAiConfidenceApi() {
  return useApi('/api/ai/confidence', {
    intervalMs: 10000,
    fallback: { confidence_threshold: 0.85, default: 0.85, feature_present: false },
  });
}
async function aiConfidencePut(confidenceThreshold) {
  const csrf = document.cookie.split('; ').find(c => c.startsWith('aegis_csrf='))?.slice(11) || '';
  const r = await fetch('/api/ai/confidence', {
    method: 'PUT',
    headers: { 'content-type': 'application/json', 'x-csrf-token': csrf },
    credentials: 'same-origin',
    body: JSON.stringify({ confidence_threshold: Number(confidenceThreshold) }),
  });
  const json = await r.json().catch(() => ({ error: `HTTP ${r.status}` }));
  return { status: r.status, ...json };
}

// AI model hot-reload. GET surfaces whether a reloadable model exists and from
// what path; POST re-reads `cfg.ai.model_path` and atomically swaps the new
// model into the live detector (per-node, local — NOT a config-plane change,
// so on a multi-node fleet trigger it on each node). CSRF-gated + audit-logged.
function useAiReloadApi() {
  return useApi('/api/ai/reload', {
    intervalMs: 30000,
    fallback: { feature_present: false },
  });
}
// F9 (2026-06-11 cluster QC) — bound the model reload with a client
// timeout. The QC saw "↻ Reload model" leave the tab stuck >45 s: the
// request hung server-side (e.g. no .onnx configured) and the await
// never resolved, so the loading state never cleared and the operator
// had to hard-reload. AbortController caps the wait so the UI always
// recovers to an actionable error instead of an indefinite spinner.
const AI_RELOAD_TIMEOUT_MS = 20000;
async function aiReloadPost() {
  const csrf = document.cookie.split('; ').find(c => c.startsWith('aegis_csrf='))?.slice(11) || '';
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), AI_RELOAD_TIMEOUT_MS);
  try {
    const r = await fetch('/api/ai/reload', {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-csrf-token': csrf },
      credentials: 'same-origin',
      signal: controller.signal,
    });
    const json = await r.json().catch(() => ({ error: `HTTP ${r.status}` }));
    return { status: r.status, ...json };
  } catch (e) {
    if (e && e.name === 'AbortError') {
      return {
        status: 504,
        ok: false,
        error: `reload timed out after ${AI_RELOAD_TIMEOUT_MS / 1000}s — the running model is kept; check the model path / node logs`,
      };
    }
    return { status: 0, ok: false, error: e?.message || String(e) };
  } finally {
    clearTimeout(timer);
  }
}

// 2026-05-11 PR #7 — runtime toggle for the three-rung
// response-filter (`Pipeline::on_body_frame`). GET is open-on-
// session; PUT is audit-mutated + CSRF-gated.
function useResponseFilterApi() {
  return useApi('/api/response-filter', {
    intervalMs: 15000,
    fallback: { scrub_stack_traces: true, mask_internal_ips: true, redact_dlp: true, wired: false },
  });
}
async function responseFilterPut(patch) {
  const csrf = document.cookie.split('; ').find(c => c.startsWith('aegis_csrf='))?.slice(11) || '';
  const r = await fetch('/api/response-filter', {
    method: 'PUT',
    headers: { 'content-type': 'application/json', 'x-csrf-token': csrf },
    credentials: 'same-origin',
    body: JSON.stringify({
      scrub_stack_traces: !!patch.scrub_stack_traces,
      mask_internal_ips:  !!patch.mask_internal_ips,
      redact_dlp:         !!patch.redact_dlp,
    }),
  });
  const json = await r.json().catch(() => ({ error: `HTTP ${r.status}` }));
  return { status: r.status, ...json };
}

// RT-T6 — route mutation helpers. Mirror poolUpsert / poolDelete
// so the RouteEditModal + DeleteRouteModal flow behaves the same
// way (CSRF cookie + header, status passed through).
async function routeUpsert(id, body) {
  const csrf = document.cookie.split('; ').find(c => c.startsWith('aegis_csrf='))?.slice(11) || '';
  const r = await fetch(`/api/routes/${encodeURIComponent(id)}`, {
    method: 'PUT',
    headers: { 'content-type': 'application/json', 'x-csrf-token': csrf },
    credentials: 'same-origin',
    body: JSON.stringify(body),
  });
  const json = await r.json().catch(() => ({ error: `HTTP ${r.status}` }));
  return { status: r.status, ...json };
}
// PR3 — Test route tool. Read-only; CSRF-gated. Body shape:
// `{ host, method, path }`. Response: `{ matched: {...} | null, reason }`.
async function routeTest(host, method, path) {
  const csrf = document.cookie.split('; ').find(c => c.startsWith('aegis_csrf='))?.slice(11) || '';
  const r = await fetch('/api/routes/test', {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-csrf-token': csrf },
    credentials: 'same-origin',
    body: JSON.stringify({ host: host || '', method, path }),
  });
  const json = await r.json().catch(() => ({ error: `HTTP ${r.status}` }));
  return { status: r.status, ...json };
}

// routing-upstream #2 — one-shot upstream member connectivity probe.
// Read-only GET (no CSRF); returns { ok, dns, tcp, tls, http } stages.
async function probeMember(addr, scheme, hostHeader, healthPath) {
  const qs = new URLSearchParams({ addr: addr || '', scheme: scheme || 'http' });
  if (hostHeader) qs.set('host_header', hostHeader);
  if (healthPath) qs.set('health_path', healthPath);
  const r = await fetch(`/api/upstreams/probe?${qs.toString()}`, { credentials: 'same-origin' });
  const json = await r.json().catch(() => ({ error: `HTTP ${r.status}` }));
  return { status: r.status, ...json };
}
async function routeDelete(id) {
  const csrf = document.cookie.split('; ').find(c => c.startsWith('aegis_csrf='))?.slice(11) || '';
  const r = await fetch(`/api/routes/${encodeURIComponent(id)}`, {
    method: 'DELETE',
    headers: { 'x-csrf-token': csrf },
    credentials: 'same-origin',
  });
  // 409 last_catchall is the only structured failure; pass status through.
  const json = await r.json().catch(() => ({ error: `HTTP ${r.status}` }));
  return { status: r.status, ...json };
}
function useRuntimeApi()  { return useApi('/api/runtime',         { intervalMs: 60000, fallback: null }); }
// SC-T2 — Layer-3 backend health. Polls every 5 s to match the
// server-side cache TTL the Redis backend uses; idle in_memory
// nodes still get a fresh number every tick (cheap).
function useStateApi()    { return useApi('/api/state',           { intervalMs: 5000, fallback: null }); }

// SC-T2 — operator-initiated drain. Flips
// `readiness.draining` so subsequent /healthz/ready probes
// return 503; LBs (HAProxy / Nginx / k8s endpoints) stop
// routing new traffic to this node. Audit-mutated; CSRF-gated.
async function adminDrainPost() {
  const csrf = document.cookie.split('; ').find(c => c.startsWith('aegis_csrf='))?.slice(11) || '';
  const r = await fetch('/admin/drain', {
    method: 'POST',
    headers: { 'x-csrf-token': csrf },
    credentials: 'same-origin' });
}

// DD-T6 — rule CRUD wrapper. Handles CSRF + error mapping.
async function rulesPost(body) {
  const csrf = document.cookie.split('; ').find(c => c.startsWith('aegis_csrf='))?.slice(11) || '';
  const r = await fetch('/api/rules', {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-csrf-token': csrf },
    credentials: 'same-origin',
    body: JSON.stringify(body),
  });
  return r.json().catch(() => ({ error: `HTTP ${r.status}` }));
}
// 2026-06-21 (P4) — AI rule generation. POST an intent (+ optional id) to the
// copilot; returns { ok, body, validation } or { error } (503 when copilot off).
// Advisory only — the body prefills the editor; nothing is applied.
async function rulesGenerate({ intent, id }) {
  const csrf = document.cookie.split('; ').find(c => c.startsWith('aegis_csrf='))?.slice(11) || '';
  const r = await fetch('/api/copilot/rule', {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-csrf-token': csrf },
    credentials: 'same-origin',
    body: JSON.stringify({ intent, id }),
  });
  return r.json().catch(() => ({ error: `HTTP ${r.status}` }));
}
async function rulesPut(id, body) {
  const csrf = document.cookie.split('; ').find(c => c.startsWith('aegis_csrf='))?.slice(11) || '';
  const r = await fetch(`/api/rules/${encodeURIComponent(id)}`, {
    method: 'PUT',
    headers: { 'content-type': 'application/json', 'x-csrf-token': csrf },
    credentials: 'same-origin',
    body: JSON.stringify(body),
  });
  return r.json().catch(() => ({ error: `HTTP ${r.status}` }));
}
async function rulesDelete(id) {
  const csrf = document.cookie.split('; ').find(c => c.startsWith('aegis_csrf='))?.slice(11) || '';
  const r = await fetch(`/api/rules/${encodeURIComponent(id)}`, {
    method: 'DELETE',
    headers: { 'x-csrf-token': csrf },
    credentials: 'same-origin',
  });
  return r.json().catch(() => ({ error: `HTTP ${r.status}` }));
}
async function rulesToggle(id) {
  const csrf = document.cookie.split('; ').find(c => c.startsWith('aegis_csrf='))?.slice(11) || '';
  const r = await fetch(`/api/rules/${encodeURIComponent(id)}/toggle`, {
    method: 'PUT',
    headers: { 'x-csrf-token': csrf },
    credentials: 'same-origin',
  });
  return r.json().catch(() => ({ error: `HTTP ${r.status}` }));
}

// CI-T12 — risk thresholds (read + audit-mutated PUT).
function useRiskThresholdsApi() {
  return useApi('/api/risk/thresholds', {
    intervalMs: 5000,
    fallback: { enabled: true, challenge_at: 40, block_at: 80, max: 100 },
  });
}
async function settingsRiskThresholdsPut(body) {
  const csrf = document.cookie.split('; ').find(c => c.startsWith('aegis_csrf='))?.slice(11) || '';
  const r = await fetch('/api/risk/thresholds', {
    method: 'PUT',
    headers: { 'content-type': 'application/json', 'x-csrf-token': csrf },
    credentials: 'same-origin',
    body: JSON.stringify(body),
  });
  return r.json().catch(() => ({ error: `HTTP ${r.status}` }));
}

// 2026-05-20 — canary honeypot paths (read + audit-mutated PUT).
// GET returns `{ paths, count, enabled }`; PUT replaces the whole
// set and hot-applies it via the shared CanaryPaths handle. Same
// CSRF + JSON pattern as the risk-thresholds pair above.
function useCanaryPathsApi() {
  return useApi('/api/risk/canary-paths', {
    intervalMs: 15000,
    fallback: { paths: [], count: 0, enabled: false },
  });
}
async function canaryPathsPut(paths) {
  const csrf = document.cookie.split('; ').find(c => c.startsWith('aegis_csrf='))?.slice(11) || '';
  const r = await fetch('/api/risk/canary-paths', {
    method: 'PUT',
    headers: { 'content-type': 'application/json', 'x-csrf-token': csrf },
    credentials: 'same-origin',
    body: JSON.stringify({ paths }),
  });
  const json = await r.json().catch(() => ({ error: `HTTP ${r.status}` }));
  return { status: r.status, ...json };
}

// CI-T6 — settings mutation helpers. Same CSRF + JSON pattern as
// the Rule CRUD wrappers above.
async function settingsModePut(mode) {
  const csrf = document.cookie.split('; ').find(c => c.startsWith('aegis_csrf='))?.slice(11) || '';
  const r = await fetch('/api/mode', {
    method: 'PUT',
    headers: { 'content-type': 'application/json', 'x-csrf-token': csrf },
    credentials: 'same-origin',
    body: JSON.stringify({ mode }),
  });
  return r.json().catch(() => ({ error: `HTTP ${r.status}` }));
}
function useModeApi() {
  return useApi('/api/mode', { intervalMs: 5000, fallback: { mode: 'enforce' } });
}

// CC-T2.* — alert-receivers (read + audit-mutated PUT/DELETE/POST-test).
// Backend returns receivers with secrets redacted to last-4 chars
// (`bot_token_redacted`, `webhook_url_redacted`, `routing_key_redacted`).
// Edits MUST send the full secret value; leaving the secret field empty in
// an edit form means "keep existing secret" — the dashboard must merge the
// new partial with the cached redacted view client-side.
function useAlertReceiversApi() {
  // CQF-T13 — was reaching through `window.useApi` for no
  // reason. Direct reference matches every other hook in this
  // file and avoids the indirection if the global ever drifts.
  return useApi('/api/alert-receivers', {
    intervalMs: 5000,
    fallback: { receivers: [] },
  });
}
async function alertReceiversPut(receivers) {
  const csrf = document.cookie.split('; ').find(c => c.startsWith('aegis_csrf='))?.slice(11) || '';
  const r = await fetch('/api/alert-receivers', {
    method: 'PUT',
    headers: { 'content-type': 'application/json', 'x-csrf-token': csrf },
    credentials: 'same-origin',
    body: JSON.stringify({ receivers }),
  });
  return r.json().catch(() => ({ error: `HTTP ${r.status}` }));
}
async function alertReceiverDelete(name) {
  const csrf = document.cookie.split('; ').find(c => c.startsWith('aegis_csrf='))?.slice(11) || '';
  const r = await fetch(`/api/alert-receivers/${encodeURIComponent(name)}`, {
    method: 'DELETE',
    headers: { 'x-csrf-token': csrf },
    credentials: 'same-origin',
  });
  return r.json().catch(() => ({ error: `HTTP ${r.status}` }));
}
async function alertReceiverTest(name) {
  const csrf = document.cookie.split('; ').find(c => c.startsWith('aegis_csrf='))?.slice(11) || '';
  const r = await fetch(`/api/alert-receivers/${encodeURIComponent(name)}/test`, {
    method: 'POST',
    headers: { 'x-csrf-token': csrf },
    credentials: 'same-origin',
  });
  return r.json().catch(() => ({ error: `HTTP ${r.status}` }));
}

// DD-T7 — config-version polling. Returns { applied: bool, latencyMs }.
// `expectedVersion` is the version returned by a successful mutation;
// the hook polls /api/config/version every 250ms until version moves
// past `expectedVersion` or `timeoutMs` elapses.
// Current activated config-plane version (0 on error). Read BEFORE a
// mutation so the caller can waitForVersion(before + 1) — config-plane
// mutations (rules, detectors, upstreams, routes) apply asynchronously
// on the watcher's next poll, so reloading immediately races the apply.
async function currentConfigVersion() {
  try {
    const r = await fetch('/api/config/version', { credentials: 'same-origin', cache: 'no-store' });
    if (!r.ok) return 0;
    const j = await r.json();
    // F2 (2026-06-11) — field renamed `version` → `audit_chain_len`.
    return Number(j.audit_chain_len) || 0;
  } catch (_) {
    return 0;
  }
}

async function waitForVersion(expectedVersion, timeoutMs = 10000) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    try {
      const r = await fetch('/api/config/version', { credentials: 'same-origin', cache: 'no-store' });
      if (r.ok) {
        const j = await r.json();
        if (j.audit_chain_len >= expectedVersion) {
          // N2 — this (connected) node has applied; kick off the
          // non-blocking fleet-convergence pill so the operator sees
          // cross-node apply without it blocking the table reload.
          notifyConfigConvergence();
          return { applied: true, latencyMs: Date.now() - start, version: j.audit_chain_len, node: j.applied_on_node };
        }
      }
    } catch (_) { /* retry */ }
    await new Promise(res => setTimeout(res, 250));
  }
  return { applied: false, latencyMs: timeoutMs };
}

// N2 (2026-06-11) — read the cluster config-doc version + per-node applied
// roster from `/api/config` (ConfigStore). DISTINCT from
// `/api/config/version` (the LOCAL audit-chain length, `audit_chain_len`):
// this `version` is the fleet-shared doc version every node converges to,
// and `applied` is `[{ node, version }]` per live node.
async function fetchConfigState() {
  try {
    const r = await fetch('/api/config', { credentials: 'same-origin', cache: 'no-store' });
    if (!r.ok) return null;
    const j = await r.json();
    return {
      version: Number(j.version) || 0,
      applied: Array.isArray(j.applied) ? j.applied : [],
      backend: !!j.backend,
      // A5 — this node's current global mode (enforce / log_only), so the
      // drift surface can show "applied vN · mode" alongside the version.
      mode: typeof j.mode === 'string' ? j.mode : null,
    };
  } catch (_) {
    return null;
  }
}

// N2 (2026-06-11) — non-blocking fleet-convergence pill. After a config
// mutation, watch the per-node applied roster until every live node has
// applied the current cluster doc version, then surface "Applied on N/N
// nodes". Silent on single-node fleets (the per-action "saved" toast
// already covers it) and when there's no shared backend. Fire-and-forget:
// never blocks the caller's reload. With the config nudge (N2) this
// resolves in ~ms; the warn path only trips if a peer is genuinely lagging.
function notifyConfigConvergence(timeoutMs = 8000) {
  (async () => {
    const initial = await fetchConfigState();
    // No shared backend / single node → nothing fleet-wide to report.
    if (!initial || !initial.backend || initial.applied.length <= 1) return;
    const target = initial.version;
    const total = initial.applied.length;
    const start = Date.now();
    while (Date.now() - start < timeoutMs) {
      const s = await fetchConfigState();
      if (s) {
        const tot = s.applied.length;
        const ready = s.applied.filter(a => Number(a.version) >= target).length;
        if (tot > 0 && ready >= tot) {
          // A5 — stamp the node's current global mode onto the pill so the
          // operator sees both convergence axes (version + enforce/log_only).
          const modeTag = s.mode ? ` · ${s.mode}` : '';
          window.aegisToast(`Applied on ${ready}/${tot} nodes`, 'ok',
            `v${target}${modeTag} · ${Date.now() - start}ms`);
          return;
        }
      }
      await new Promise(res => setTimeout(res, 250));
    }
    // Timed out before full convergence — surface the partial state so a
    // lagging peer is visible rather than silently assumed-applied.
    const s = await fetchConfigState();
    const ready = s ? s.applied.filter(a => Number(a.version) >= target).length : 0;
    window.aegisToast(`Applied on ${ready}/${total} nodes — still converging`, 'warn', `v${target}`);
  })();
}

Object.assign(window, {
  ATTACK_CATS, ATTACKER_GEO, ORIGIN, ROUTES, REGIONS,
  RULES, TIERS, BLACKLIST, WHITELIST, UPSTREAMS, CLUSTER, CERTS, ALERTS, ADMIN_LOG,
  // CQF-T15 — useLiveFeed + useTrafficSeries dropped from the
  // export list. Both used Math.random for fake-data simulation
  // and were retired from every render path during HACK-T1; they
  // remain as helpers in this file for any future test harness
  // but are no longer hung off `window`. useTicking and
  // makeLiveEvent are kept — useTicking drives session-uptime
  // counters (no random) and makeLiveEvent is harness-only.
  useTicking, makeLiveEvent,
  // DD-T2 + DD-T6 + DD-T7 — real-API hooks
  useApi, useRealLiveFeed,
  useRulesApi, useBlacklistApi, useWhitelistApi,
  useStatusApi, useStatsApi, useTimeseriesApi,
  useCacheStatsApi,
  useAttacksDistributionApi, useAttacksTopApi,
  // HACK-T1 — live hooks retiring `Math.random` on Attack Events
  useAttacksByDetectorApi, useBotMixApi, useThreatIntelApi,
  // HACK-T3 — Tier-A rule simulator
  rulesSimulate,
  // HACK-T4 — Tier-B config-change timeline + rollback
  useConfigVersionsApi, configRollback, ROLLBACKABLE_ACTIONS,
  useAuditLogApi,
  useClusterApi, useConfigApi, useSloApi, useCertsApi, useLatencyApi, useRouteLatencyApi, useDetectorLatencyApi, useAnalyticsRoutesApi,
  useIncidentsApi, useThreatIntelFeedsApi, useGeoipStatusApi,
  incidentAck, incidentSnooze, incidentResolve,
  useAlertsApi, useGitopsApi, useUpstreamsApi, useRuntimeApi,
  // SC-T2 — Scaling page hooks + drain mutation
  useStateApi, adminDrainPost,
  // CC-T1.1 — upstream-pool config view + CC-T1.1.b mutation helpers
  useUpstreamsConfigApi, upstreamsConfigPut, poolUpsert, poolDelete,
  // RT-T6 — route mutations
  routeUpsert, routeDelete, routeTest, probeMember,
  // AI-T10 — AI detector runtime on/off
  useAiEnabledApi, aiEnabledPut,
  // 2026-05-29 — AI runtime confidence_threshold
  useAiConfidenceApi, aiConfidencePut,
  // AI model hot-reload (POST /api/ai/reload)
  useAiReloadApi, aiReloadPost,
  // 2026-05-11 PR #7 — response-filter rung toggles
  useResponseFilterApi, responseFilterPut,
  // TI-T — audit-mutated tier edits
  tierPut,
  useRoutesApi, useTiersApi,
  rulesPost, rulesPut, rulesDelete, rulesToggle, rulesGenerate, waitForVersion, currentConfigVersion,
  fetchConfigState, notifyConfigConvergence,
  // CI-T6 — settings mutations
  useModeApi, settingsModePut,
  // CI-T12 — risk thresholds (read + audit-mutated PUT)
  useRiskThresholdsApi, settingsRiskThresholdsPut,
  // 2026-05-20 — canary honeypot paths (read + audit-mutated PUT)
  useCanaryPathsApi, canaryPathsPut,
  // CC-T2.* — alert-receivers (read + audit-mutated PUT/DELETE/POST-test)
  useAlertReceiversApi, alertReceiversPut, alertReceiverDelete, alertReceiverTest,
  // MTLS-T7 — Allowed SAN allowlist (read + audit-mutated PUT/DELETE/POST-test)
  useMtlsSansApi, mtlsSansPut, mtlsSansDelete, mtlsSansTest,
  // M002 (2026-05-07) — load mode read + audit-mutated PUT
  useLoadModeApi, loadmodePut,
  // M004 (2026-05-07) — Settings page read-only sections
  useAdminSessionsApi, useBreakGlassApi, useIntegrationsApi,
  // CQF-T1 — admin logout
  adminLogout,
  // CQF-T2 — Blacklist + Whitelist add/delete
  accessListAdd, accessListDelete,
  // CQF-T3 — Detector mask read + audit-mutated PUT
  useDetectorsApi, detectorsPut,
  // 2026-05-09 — Traffic Gates needs a generic CSRF-aware PUT
  // helper for the new audit-mutated endpoints. csrfMutate has
  // existed since CC-T2 but wasn't on window.
  csrfMutate,
  // CQF-T6 — Top-risk-paths heatmap derived from /api/audit/since
  useTopRiskPathsApi,
});
