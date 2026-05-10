/* global React */
const { useState: useStateH } = React;

// PageHelp — operator onboarding + reference. Rewritten 2026-05-04
// to match what's actually in the SPA: the page restructures
// over the last weeks (Routing & Upstreams, merged Detectors
// page, Audit Trail scoped to admin events, AI detector toggle)
// had drifted out of the previous content. Everything below
// references real pages, real endpoints, real workflows.
function PageHelp() {
  const [tab, setTab] = useStateH('start');

  const TABS = [
    { id: 'start',     label: 'Get started' },
    { id: 'how',       label: 'How it works' },
    { id: 'glossary',  label: 'Glossary' },
    { id: 'workflows', label: 'Workflows' },
    { id: 'faq',       label: 'FAQ' },
  ];

  return (
    <>
      <div className="page-head">
        <div>
          <h1 className="page-title">Help &amp; Guide</h1>
          <p className="page-subtitle">
            Operator onboarding · live reference for what's in this console
          </p>
        </div>
        <div className="page-actions">
          <a className="btn" href="https://github.com/" target="_blank" rel="noreferrer">
            <window.I.External /> Repo
          </a>
        </div>
      </div>

      <div style={{ display: 'flex', borderBottom: '1px solid var(--hairline)', marginBottom: 14, gap: 0 }}>
        {TABS.map(t => (
          <button key={t.id} onClick={() => setTab(t.id)} style={{
            padding: '10px 18px', background: 'transparent', border: 'none',
            color: tab === t.id ? 'var(--brand-yellow)' : 'var(--ink-mute)',
            borderBottom: tab === t.id ? '2px solid var(--brand-yellow)' : '2px solid transparent',
            fontSize: 13, fontWeight: 600, cursor: 'pointer',
          }}>{t.label}</button>
        ))}
      </div>

      {tab === 'start' && <TabGetStarted />}
      {tab === 'how' && <TabHowItWorks />}
      {tab === 'glossary' && <TabGlossary />}
      {tab === 'workflows' && <TabWorkflows />}
      {tab === 'faq' && <TabFaq />}
    </>
  );
}

// ─── Get started ───────────────────────────────────────────────
function TabGetStarted() {
  const STEPS = [
    {
      n: 1, t: 'Watch traffic land in real time',
      d: 'Live Feed streams every audit event the WAF emits — request decisions, blocks, websocket open/close, audit chain entries. Each row tells you what fired and why. Click a row to inspect.',
      cta: 'Open Live Feed →', to: '#/live',
    },
    {
      n: 2, t: 'Investigate an incident',
      d: 'Investigation page is the analyst surface — Recent requests table (newest first), per-detector breakdown last 1h, bot-mix donut, drill into any IP. Click an audit-feed row in Live Feed to land here pre-filtered.',
      cta: 'Open Investigation →', to: '#/investigation',
    },
    {
      n: 3, t: 'Wire your real backend',
      d: 'Routing & Upstreams is the operator\'s daily-driver page. Add a route, type a backend address — the modal creates the upstream pool inline. Audit-mutated, hot-swap, no restart.',
      cta: 'Open Routing & Upstreams →', to: '#/upstreams',
    },
    {
      n: 4, t: 'Tune the detector mask & tier overrides',
      d: 'Detectors & Tiers combines the per-class mask (sqli/xss/ssrf/…), the read-only score reference (5-tier framework), per-tier mask overrides, and the AI detector toggle. Each chip carries the dominant score so posture is readable at a glance. Flip a class off without a restart — the data plane stops running it within one hot-reload tick.',
      cta: 'Open Detectors & Tiers →', to: '#/detectors',
    },
    {
      n: 5, t: 'Configure the four traffic gates',
      d: 'Traffic Gates surfaces the four binary short-circuits that fire before the detector chain: access list, strike-block, rate limit, DDoS gate. Live config + edit modal for rate limit and DDoS thresholds (audit-mutated, hot-reload). Watch the Spike-active banner during volumetric incidents.',
      cta: 'Open Traffic Gates →', to: '#/traffic-gates',
    },
    {
      n: 6, t: 'See where the latency went',
      d: 'Performance shows per-stage and per-route p50/p95/p99 from the live Prometheus histogram. SLO burn lives on Health & SLOs. Cluster peers, cert freshness, and runtime sizing live on Scaling.',
      cta: 'Open Performance →', to: '#/performance',
    },
    {
      n: 7, t: 'Audit any operator change',
      d: 'Audit Trail is the hash-chained record of admin actions, logins, and system events. Per-request decisions live on the Investigation and Live Feed pages — flip the class chip on Audit Trail to bring them in if you need a single timeline.',
      cta: 'Open Audit Trail →', to: '#/audit',
    },
  ];

  return (
    <>
      {/* QC / first-time-tester callout — points to the source-
          of-truth feature playbook. Keeps the operator-onboarding
          (the steps below) and the QC mission (the playbook)
          discoverable from one place. */}
      <div className="card" style={{ padding: '12px 16px', marginBottom: 14, display: 'flex', alignItems: 'center', gap: 12 }}>
        <window.I.Book />
        <div style={{ flex: 1, fontSize: 12, color: 'var(--ink-mute)', lineHeight: 1.5 }}>
          <strong style={{ color: 'var(--ink)' }}>Testing the system?</strong>{' '}
          The <strong>Feature Playbook</strong> is the single source of truth — one row per feature,
          with concrete steps to verify each one and explicit pass criteria.
          Open <code>docs/FEATURES.md</code> in the repo and walk top-to-bottom.
        </div>
      </div>
      <div className="grid-12">
      {STEPS.map(s => (
        <div key={s.n} className="col-4 card" style={{ padding: 16 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 8 }}>
            <span style={{
              width: 28, height: 28, borderRadius: 6,
              background: 'var(--brand-yellow)', color: '#0B0E11',
              display: 'inline-flex', alignItems: 'center', justifyContent: 'center',
              fontWeight: 700, fontSize: 13,
            }}>{s.n}</span>
            <div style={{ fontSize: 13, fontWeight: 600 }}>{s.t}</div>
          </div>
          <div style={{ fontSize: 12, color: 'var(--ink-mute)', lineHeight: 1.6, marginBottom: 12 }}>{s.d}</div>
          <a href={s.to} className="btn sm" style={{ textDecoration: 'none' }}>{s.cta}</a>
        </div>
      ))}
      </div>
    </>
  );
}

// ─── How it works ──────────────────────────────────────────────
function TabHowItWorks() {
  return (
    <div className="grid-12">
      <div className="col-12 card" style={{ padding: 16 }}>
        <div style={{ fontSize: 14, fontWeight: 600, marginBottom: 8 }}>Request flow</div>
        <div style={{ fontSize: 12, color: 'var(--ink-mute)', lineHeight: 1.65 }}>
          Every request goes through a fixed pipeline:
          <ol style={{ marginTop: 8, paddingLeft: 18 }}>
            <li><strong>Listener</strong> accepts the connection on <code>:8080</code> (HTTP) or <code>:8443</code> (TLS, with SNI-driven cert selection).</li>
            <li><strong>Route resolution</strong> matches the request's host + path + method against the route table (first-match-wins, top to bottom).</li>
            <li><strong>Traffic gates</strong> — four binary short-circuits fire in cheapest-first order before the detector chain: <em>access list</em> (IP/CIDR/ASN/country), <em>strike-block</em> (lifetime per-IP strikes ≥ <code>risk.strikes.block_at</code>; opt-in, default off since 2026-05-10), <em>rate limit</em> (token bucket → 429), <em>DDoS gate</em> (per-IP sliding-window auto-block → 403 + 5-min TTL). All four configurable from the Traffic Gates page; all four hot-reloadable. The cumulative IP risk thresholds (#3 on the page) tune the score-based challenge / block path that follows the detector chain — same page so the per-IP-risk story sits in one place.</li>
            <li><strong>Detector chain</strong> — every detector enabled in the mask runs on the request: SQLi, XSS, path traversal, SSRF, header injection, body abuse, recon, brute_force, command_injection, template_injection, nosql_injection, open_redirect, plus the AI detector if it's on.</li>
            <li><strong>Risk + tier gate</strong> — detector signals add to a per-request composite score; if it crosses the route's tier threshold (critical 50 / high 70 / medium 80 / low 90), the request is blocked (HTTP 403 / 429). Separately, every detector hit also increments the client IP's <em>cumulative IP risk score</em>, which has its own thresholds on the Traffic Gates page → "Cumulative IP risk thresholds" (next to Strike-Block).</li>
            <li><strong>Forward</strong> — if allowed, the request is proxied to the route's upstream pool with the configured scheme, load-balancing, host-header rewrite, etc.</li>
            <li><strong>Audit + metrics</strong> — every decision lands as a hash-chained audit event and one entry per Prometheus histogram bucket.</li>
          </ol>
        </div>
      </div>

      <div className="col-6 card" style={{ padding: 16 }}>
        <div style={{ fontSize: 14, fontWeight: 600, marginBottom: 8 }}>Routes &amp; pools</div>
        <div style={{ fontSize: 12, color: 'var(--ink-mute)', lineHeight: 1.65 }}>
          A <strong>route</strong> matches incoming traffic and forwards to <strong>one upstream pool</strong>.
          A pool can have one or more backend members (load-balanced); the same pool can be reused
          by several routes. First-match-wins, top to bottom.
          <br/><br/>
          Edit both from <a href="#/upstreams" style={{ color: 'var(--brand-yellow)' }}>Routing &amp; Upstreams</a>.
          The Add Route modal can create the pool inline so you can wire a backend in one step.
          Saves are audit-mutated and hot-swap without a restart.
        </div>
      </div>

      <div className="col-6 card" style={{ padding: 16 }}>
        <div style={{ fontSize: 14, fontWeight: 600, marginBottom: 8 }}>Tiers</div>
        <div style={{ fontSize: 12, color: 'var(--ink-mute)', lineHeight: 1.65 }}>
          Four canonical tiers — <code>critical</code>, <code>high</code>, <code>medium</code>, <code>low</code>.
          Each carries a <strong>risk threshold</strong> (composite score that triggers a block — lower = stricter).
          A route inherits the default tier or pins one via <code>tier_override</code>.
          Edit the threshold via the <strong>Edit tier</strong> button on Detectors &amp; Tiers.
          <br/><br/>
          The legacy per-tier <code>block_threshold</code> field is descriptive metadata only — the
          live rate cap lives on the <a href="#/traffic-gates" style={{ color: 'var(--brand-yellow)' }}>Traffic Gates</a> page (one global rate-limit + DDoS gate).
          The tier <em>pipeline</em> string list is also descriptive — the
          live filter is the global <strong>detector mask</strong> at the top of Detectors &amp; Tiers.
        </div>
      </div>

      <div className="col-6 card" style={{ padding: 16 }}>
        <div style={{ fontSize: 14, fontWeight: 600, marginBottom: 8 }}>Detectors</div>
        <div style={{ fontSize: 12, color: 'var(--ink-mute)', lineHeight: 1.65 }}>
          Twelve regex/heuristic classes (sqli, xss, path_traversal, ssrf, header_injection,
          body_abuse, recon, brute_force, command_injection, template_injection,
          nosql_injection, open_redirect) plus the AI detector.
          The <strong>mask</strong> is the runtime gate — flip a class off and the chain skips it
          on the next request. Mask edits are hash-chained.
          <br/><br/>
          The <strong>AI detector</strong> runs an operator-supplied ONNX model
          (<code>data/ai_model/waf_model.onnx</code>) and emits a binary attack/normal verdict.
          Toggle on/off via the Enable button on the Detectors &amp; Tiers page (audit-mutated <code>PUT /api/ai/enabled</code>).
        </div>
      </div>

      <div className="col-6 card" style={{ padding: 16 }}>
        <div style={{ fontSize: 14, fontWeight: 600, marginBottom: 8 }}>Traffic gates</div>
        <div style={{ fontSize: 12, color: 'var(--ink-mute)', lineHeight: 1.65 }}>
          Four binary block-or-pass gates run before the detector chain (cheapest-first):
          <ol style={{ marginTop: 6, paddingLeft: 18 }}>
            <li><strong>Access list</strong> — IP / CIDR / ASN / country (403)</li>
            <li><strong>Strike-block</strong> — lifetime per-IP strikes ≥ <code>risk.strikes.block_at</code> (403). Opt-in; default disabled.</li>
            <li><strong>Rate limit</strong> — token bucket; recoverable when window slides (429)</li>
            <li><strong>DDoS gate</strong> — per-IP sliding-window auto-block; 5-min TTL (403)</li>
          </ol>
          Rate limit returns 429 with automatic recovery; DDoS gate returns 403
          with a TTL'd quarantine — opposite enforcement semantics, distinct use
          cases (see <code>docs/operator/traffic-gates.md</code>).
          All four are audit-mutated and hot-reloadable from the
          <a href="#/traffic-gates" style={{ color: 'var(--brand-yellow)' }}> Traffic Gates</a> page.
        </div>
      </div>

      <div className="col-6 card" style={{ padding: 16 }}>
        <div style={{ fontSize: 14, fontWeight: 600, marginBottom: 8 }}>What's audit-mutated</div>
        <div style={{ fontSize: 12, color: 'var(--ink-mute)', lineHeight: 1.65 }}>
          Every config change goes through one path:
          <ul style={{ marginTop: 6, paddingLeft: 18 }}>
            <li>CSRF double-submit verified at the entrance</li>
            <li>Audit chain entry committed (hash-chained, before/after diff)</li>
            <li>Live state hot-swapped via atomic ArcSwap</li>
          </ul>
          Routes, upstream pools, the detector mask, AI on/off, tier thresholds,
          rules, alert receivers, mode toggles, access lists, rate-limit, DDoS
          gate — all of them.
          See the chain on <a href="#/audit" style={{ color: 'var(--brand-yellow)' }}>Audit Trail</a>.
        </div>
      </div>
    </div>
  );
}

// ─── Glossary ──────────────────────────────────────────────────
function TabGlossary() {
  const ENTRIES = [
    ['Route',
      'A match definition (host + path + method + match_type) that forwards traffic to exactly one upstream pool. Order matters — first match wins.'],
    ['Upstream pool',
      'A logical group of backend members behind a load-balancing strategy (round-robin, least-conn, weighted, p2c, consistent hash). Has a circuit breaker, optional health probe, and a connection pool.'],
    ['Member',
      'One backend address (IP:port) inside a pool. Carries optional `host_header` for vhost / SNI override, weight, and zone tag.'],
    ['Tier',
      'A per-request policy bundle — risk_threshold (per-request block score, 0-100) plus a challenges_enabled toggle (defaults false; opt-in PoW rung). Four canonical tiers: critical / high / medium / low. Routes inherit the default or pin via tier_override. challenges_enabled = false escalates the cumulative-IP-risk challenge rung straight to block on that tier (no PoW). Cumulative threshold values are global by default (edit on Traffic Gates → #3); per-tier cumulative_challenge_at / cumulative_block_at overrides exist on the wire shape but are API-only (the dashboard doesn\'t surface inputs).'],
    ['Traffic gates',
      'Four binary block-or-pass short-circuits that run before the detector chain (in firing order): access list, strike-block, rate limit, DDoS gate. Cheapest-first so a known-bad IP costs minimum CPU. Distinct from the signal-emitting detector chain — gates read shared cluster state and return a yes/no decision, not a score. All four are configured from the Traffic Gates page.'],
    ['Rate limit',
      'Per-IP token bucket (sliding-window count). Returns 429 + X-WAF-Action: rate_limit when exceeded; recovery is automatic as the window slides. Configured at e.g. 1000 req / 60 s — tuned for "API rate fairness" (catches abusive clients gracefully). Audit-mutated PUT /api/rate-limit; per-IP state preserved across edits.'],
    ['DDoS gate',
      'Per-IP sliding-window auto-block. Returns 403 + X-WAF-Action: block when burst exceeded; quarantines the IP for block_ttl_s (default 300 s). Configured at e.g. 1000 req / 10 s — tuned for "sustained-burst quarantine" (catches actual flood attacks). Cluster-scoped via StateBackend::auto_block. Audit-mutated PUT /api/gates/ddos.'],
    ['Detector',
      'An attack-class analyzer (sqli, xss, path_traversal, ssrf, header_injection, body_abuse, recon, brute_force, command_injection, template_injection, nosql_injection, open_redirect, ai). Each detector emits a Signal { tag, score } that contributes to the request\'s risk score.'],
    ['Detector mask',
      'The runtime per-class on/off table, edited from the Detectors & Tiers page. Audit-mutated, hot-swap. Flips take effect on the next request. Each chip on the mask grid carries the dominant score for its class so operators see "sqli · 60" tinted by the calibrated 5-tier framework.'],
    ['Risk score (per-request)',
      'Sum of detector signals on this single request. Compared against the matched tier\'s risk_threshold; ≥ threshold → block.'],
    ['IP risk',
      'Cumulative strike score for a single client IP. Decays exponentially (default half-life 5 min). Surfaced in the Investigation page\'s "Recent requests" table — high IP risk + allowed action means past requests from this IP triggered detectors but the current request didn\'t.'],
    ['Action',
      'Final disposition for a request: allow (proxied to the upstream), block (HTTP 403/429), or strike (allow but tag for risk accumulation). The challenge ladder (JS / CAPTCHA) is a separate response track for bot-suspicious traffic.'],
    ['Audit chain',
      'SHA-256 hash-chained NDJSON log under /tmp/aegis-dev-audit.jsonl. Every config mutation + detection writes an entry; each entry includes the previous hash. Verify integrity with `waf audit verify --from <path>`.'],
    ['Audit Trail (page)',
      'Dashboard view of the audit chain. Defaults to admin / access / system events; flip the class chip to "requests" or "all" to bring per-request decisions in.'],
    ['AI detector',
      'ML-based detector backed by an operator-supplied ONNX model. Binary verdict (attack vs normal) at a configurable confidence threshold. Build the binary with `--features ai`, set `cfg.ai.enabled: true`, toggle on/off at runtime via the Detectors & Tiers page.'],
    ['Mode',
      'Global enforce / log-only switch (Settings page). Log-only emits all detections to audit + metrics but never blocks — used for burn-in of new rules.'],
    ['Hash-chained',
      'Each audit entry carries the SHA-256 of the previous entry. Tampering detectable: re-hash the chain and compare to the witness sign-off.'],
    ['Specificity-based resolution',
      'Routes are evaluated by specificity, not YAML order: most-specific host first (exact > wildcard > default), then longest path prefix, then explicit method filters. Add/edit order does not affect resolution; the routes table is sorted by effective priority desc.'],
    ['Fallback route (`default: true`)',
      'Marks a route as the catch-all for its host scope — handles requests that no other route matches. Each host can have one fallback. Without any fallback, unmatched traffic returns 404 (deny-by-default). Replaces the rigid pre-PR2 invariant that required a `path: "/"` route with no host pin.'],
    ['Paused route (`enabled: false`)',
      'A route that stays in config but skips request matching, as if it didn\'t exist. Useful for staging variants, A/B switches, or quickly pulling a misbehaving route without losing the configuration. Visible in `/api/routes` and the dashboard table (dimmed) so the operator sees what\'s paused.'],
    ['Host header override',
      'Per-member `host_header:` field. Drives both the outbound `Host` AND the TLS SNI for HTTPS upstreams. Required for multi-vhost backends (Cloudflare-fronted, GitHub Pages, shared nginx).'],
    ['Cumulative IP risk score',
      'Per-IP score that accumulates across requests and decays exponentially (default half-life 5 min from `risk.decay_half_life`). Two thresholds gate the challenge ladder: `risk.thresholds.challenge_at` (default 40 — JS / CAPTCHA before allow) and `risk.thresholds.block_at` (default 80 — refuse all further requests from this IP at the access gate, before any detector runs, until decay drops the score below). Edit live on Traffic Gates → "Cumulative IP risk thresholds" (next to Strike-Block). Distinct from the per-request tier risk threshold (Detectors & Tiers → Edit tier).'],
    ['Strike count (lifetime)',
      'A separate per-IP counter that never decays — `risk.strikes.block_at` (default 50 lifetime malicious events) permanently blocks the IP until an operator resets it via `POST /api/risk/{ip}/reset`. The "you ran out of chances" gate, distinct from the score-and-decay gate above. Opt-in: `risk.strikes.enabled` defaults to `false` (since 2026-05-10) so the contract\'s X-WAF-Risk-Score accumulation+decay invariant is testable in isolation. Enable + tune from Traffic Gates → Strike-Block card → Edit (audit-mutated PUT /api/gates/strikes).'],
  ];

  return (
    <div className="card" style={{ padding: 0 }}>
      <table className="tbl tbl-compact">
        <thead><tr><th style={{ width: 220 }}>Term</th><th>Meaning</th></tr></thead>
        <tbody>
          {ENTRIES.map(([t, d]) => (
            <tr key={t}>
              <td className="mono" style={{ color: 'var(--brand-yellow)' }}>{t}</td>
              <td className="dim">{d}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

// ─── Workflows ─────────────────────────────────────────────────
function TabWorkflows() {
  const WORKFLOWS = [
    {
      t: 'Wire a new backend (route + pool in one step)',
      steps: [
        'Routing & Upstreams → + Add route.',
        'Fill Route ID, Path (e.g. /news), and (optional) Host header for vhost matching.',
        'Under "Forward to", type the backend IP:port directly (e.g. 10.0.1.10:8080) — the modal will create a pool with the route\'s ID.',
        'Pick scheme (auto / http / https / h2c / grpc / tcp) and an optional Host header for SNI override.',
        'Save. The pool + route both land in one audit chain entry; the proxy hot-swaps in milliseconds.',
        'Verify: curl -i -H "Host: <yourhost>" http://127.0.0.1:8080<path>',
      ],
    },
    {
      t: 'Block an attacker mid-incident',
      steps: [
        'Investigation → Recent requests, or Live Feed.',
        'Click the offending row — the request inspector opens.',
        'Pivot on the client IP (footer button) → Top Attackers shows the IP with full context.',
        'Access Lists → Blacklist → Add entry (kind: ip, value: the offending IP, reason: incident ticket).',
        'Save. The data plane consults the live blacklist on the next request — the IP is rejected at the gate before any detector runs.',
      ],
    },
    {
      t: 'Test a new rule before enforcing',
      steps: [
        'Settings → flip Mode to log_only.',
        'Rule Manager → New rule. Write the DSL, click Validate (catches syntax errors locally).',
        'Save & deploy. The rule is live but log_only mode means nothing actually blocks.',
        'Watch Investigation → Recent requests for false positives.',
        'When confident, Settings → Mode → enforce. Real blocks resume.',
      ],
    },
    {
      t: 'Tighten the rate limit or DDoS gate mid-incident',
      steps: [
        'Traffic Gates → look at the Rate Limit card (current limit / window / scope) and the DDoS Gate card (per-IP limit / window / block TTL / spike trigger).',
        'For a misbehaving-but-not-malicious client (429 is fine): Rate Limit → Edit. Lower the limit or shorten the window. Save (audit-mutated, hot-reload).',
        'For a sustained flood (need to quarantine the IP entirely): DDoS Gate → Edit. Tighten per_ip_limit + window, raise block_ttl_s. Save.',
        'For repeat offenders accumulating strikes: Strike-Block → Edit → flip Enabled on (or tune block_at). The lifetime counter that already climbed will fire immediately — per-IP state preserved across edits, no free reset.',
        'Per-IP state is preserved across all edits — flooding sources do not get a free reset when thresholds tighten.',
        'Verify: watch the Spike-active banner on the DDoS card and cross-reference Investigation → Top Attackers.',
      ],
    },
    {
      t: 'Tune the AI detector',
      steps: [
        'Detectors page → AI row → ▸ details.',
        'Watch the Predictions / Attack rate / Mean inference / Fallbacks tiles for ~10 min of real traffic.',
        'If the attack rate is too high (false positives), edit cfg.ai.confidence_threshold in the YAML (start at 0.85, raise to 0.95 if needed) and restart.',
        'Or click Disable on the AI row to take the detector out of the chain entirely — audit-mutated, hot-swap.',
      ],
    },
    {
      t: 'Geo-block a country',
      steps: [
        'Access Lists → Blacklist → Add entry → Type: country.',
        'Pick the ISO 3166-1 alpha-2 code (US, CN, RU, …) and optional reason.',
        'Save. Requires the GeoIP DB to be wired (make geoip-link COUNTRY_DB=<path>).',
        'Verify: curl -H "X-Forwarded-For: 8.8.8.8" http://127.0.0.1:8080/  — XFF rewrites the source IP for testing.',
      ],
    },
    {
      t: 'Trust a partner network',
      steps: [
        'Access Lists → Whitelist → Add entry → Type: cidr (or ip / asn).',
        'Pick the bypass scope (specific detectors, rate-limit, or all). "all" gives full bypass — use only for known-trusted infra.',
        'Set an expiry if temporary (pen-test engagement, vendor sweep).',
        'Add a clear reason — auditors will read it.',
      ],
    },
    {
      t: 'Investigate a 5xx spike',
      steps: [
        'Performance → look at upstream latency p99 by route. Spike suggests a slow backend.',
        'Routing & Upstreams → click the affected route → Edit pool → check member health, weights, circuit-breaker state.',
        'If circuit is open, the proxy is shedding traffic. Fix the upstream, then the breaker auto-resets after open_duration.',
        'Cross-reference Live Feed for matching upstream errors.',
      ],
    },
    {
      t: 'Renew a TLS certificate',
      steps: [
        'For ACME-managed certs: nothing to do — the WAF auto-renews 30 days before expiry.',
        'For static certs: replace the file at the path in cfg.tls.certificates[].cert_path. The notify-watcher hot-reloads.',
        'For dev: make reset-cert regenerates the self-signed dev cert.',
      ],
    },
  ];

  return (
    <div className="grid-12">
      {WORKFLOWS.map((w, i) => (
        <div key={i} className="col-6 card" style={{ padding: 16 }}>
          <div style={{ fontSize: 13, fontWeight: 600, marginBottom: 10 }}>{w.t}</div>
          <ol style={{ margin: 0, paddingLeft: 18, fontSize: 12, lineHeight: 1.7, color: 'var(--ink-mute)' }}>
            {w.steps.map((s, j) => <li key={j}>{s}</li>)}
          </ol>
        </div>
      ))}
    </div>
  );
}

// ─── FAQ ───────────────────────────────────────────────────────
function TabFaq() {
  const QA = [
    {
      q: 'A request shows IP risk = 100 but the action is ALLOW. Bug?',
      a: 'No. The "IP risk" column is the cumulative IP risk score for that client IP — it accumulates across requests and decays over time (default half-life 5 min). A single request can be allowed (it didn\'t trigger any detector this time) while the IP carries high cumulative risk from earlier hits. To make cumulative IP risk also block, lower `risk.thresholds.block_at` from Traffic Gates → "Cumulative IP risk thresholds" (next to Strike-Block). Watch out for false positives if legitimate users share an IP (NAT / corporate proxy).',
    },
    {
      q: 'Why is "Audit Trail" hiding request decisions by default?',
      a: 'Operators usually open Audit Trail to see config history (rule edits, mode toggles, access-list adds). Per-request decisions live on Investigation and Live Feed. Audit Trail defaults to admin / access / system events; flip the class chip to "requests" or "all" to bring them back.',
    },
    {
      q: 'I created a route inline with a new backend, but the test request returns 406.',
      a: 'The 406 is from the upstream\'s edge (likely content negotiation rejecting curl\'s default headers), not from the WAF. Aegis returns the upstream status verbatim. Add a browser-shaped User-Agent + Accept: text/html to your curl and try again. Confirm by tailing /tmp/aegis-dev-audit.jsonl — action: "allow" proves the WAF forwarded.',
    },
    {
      q: 'How do I test a route by hostname?',
      a: 'Two options: (1) curl -H "Host: vnexpress.net" http://127.0.0.1:8080/news — overrides the Host header per request, no DNS changes. (2) For HTTPS, curl --resolve vnexpress.net:8443:127.0.0.1 https://vnexpress.net:8443/news — tells curl to send SNI for vnexpress.net to localhost. See docs/operator/upstream-cookbook.md Recipe 3.5.',
    },
    {
      q: 'I toggled a detector OFF on the tier pipeline list. Why is it still firing?',
      a: 'The tier pipeline list is descriptive metadata today — the live runtime gate is the detector mask at the top of the Detectors & Tiers page, not the per-tier pipeline list. Flip it off there (or use a per-tier override). Real per-tier execution gating is a follow-up.',
    },
    {
      q: 'How do I enable the AI detector?',
      a: 'Build with the feature: FEATURES="redis geoip alerts ai" make build (the default Makefile target now includes ai). Symlink your model: make ai-link MODEL=<path-to-onnx>. Set cfg.ai.enabled: true in your config. After boot, runtime on/off is hot via the Detectors & Tiers page Enable/Disable button.',
    },
    {
      q: 'Tier definitions edit in the dashboard — does it actually change traffic flow?',
      a: 'Yes. Two live per-tier knobs surfaced on the dashboard (2026-05-10 R3): (1) risk_threshold — per-request block score, fires when this single request\'s detector scores sum past it. (2) challenges_enabled — flip on/off to control whether the cumulative-IP-risk challenge rung emits a PoW puzzle (true) or escalates straight to block (false, the default). Detector mask overrides are also per-tier and live in the same Edit Tier modal. The tier wire shape additionally accepts cumulative_challenge_at / cumulative_block_at per-tier overrides for API clients (PUT /api/tiers/<name>), but the dashboard doesn\'t surface inputs since most deployments are well-served by the global cumulative thresholds (Traffic Gates → #3). The legacy block_threshold (req/s) and pipeline list fields are descriptive metadata only.',
    },
    {
      q: 'What\'s the difference between Rate Limit and the DDoS gate?',
      a: 'Both are per-IP "limit + window" gates but with opposite enforcement: Rate Limit returns 429 with automatic recovery as the window slides — designed for steady-state per-IP API budgets where misbehaving clients should back off and retry. DDoS gate returns 403 with a 5-minute TTL\'d quarantine — designed for sustained-burst quarantine where the IP is flooding (e.g. 100 req/s for 10 s). Configure both on Traffic Gates; tune the rate limit looser (e.g. 1000/60 s) and the DDoS gate tighter (e.g. 1000/10 s). Detail in docs/operator/traffic-gates.md.',
    },
    {
      q: 'How does light mode persist?',
      a: 'localStorage key aegis_theme. The pre-paint script in index.html reads it before the SPA loads, so there\'s no flash. Falls back to the OS prefers-color-scheme on first visit.',
    },
    {
      q: 'Where do per-request audit events go?',
      a: 'NDJSON file at /tmp/aegis-dev-audit.jsonl (configurable via cfg.audit.sinks). Hash-chained — verify with waf audit verify --from <path>. SIEM forwarding (CEF / LEEF / OCSF / Kafka / syslog) is configured via cfg.audit.sinks too — see docs/observability/siem-log-forwarding.md.',
    },
    {
      q: 'Can I script the dashboard?',
      a: 'Yes — every audit-mutated action has a documented HTTP endpoint. Login via POST /admin/login → grab the cookie + CSRF, then PUT /api/routes/{id}, /api/upstreams/pool/{id}, /api/detectors, /api/ai/enabled, /api/tiers/{name}, /api/rate-limit, /api/gates/ddos, /api/gates/strikes, /api/blacklist, /api/whitelist, etc. Full schema in docs/control-plane/api.openapi.yaml.',
    },
    {
      q: 'How do I reset everything to defaults in dev?',
      a: 'pkill -KILL -f "target/release/waf" && make run-dev. The dev profile has no on-disk state for the writeable surfaces (mask / routes / pools), so a restart returns to config/dev.yaml as authoritative. Production profiles persist via Redis + the audit chain.',
    },
  ];

  return (
    <div className="grid-12">
      {QA.map(({ q, a }, i) => (
        <div key={i} className="col-6 card" style={{ padding: 16 }}>
          <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--ink)', marginBottom: 8 }}>{q}</div>
          <div style={{ fontSize: 12, color: 'var(--ink-mute)', lineHeight: 1.6 }}>{a}</div>
        </div>
      ))}
    </div>
  );
}

Object.assign(window, { PageHelp });
