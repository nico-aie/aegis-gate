/* global React, ReactDOM */
const { useState, useEffect } = React;

// ============== Sidebar nav model ==============
//
// SOC-grade IA (plans/console-soc-refactor.md, Phase 2):
//   - 4 groups (was 4 — same count, different boundaries)
//   - 17 page slots (was 13)
//   - Blacklist + Whitelist merged into one "Access Lists" page
//   - "Configuration" → "Policy"; "Tracking" → "Observability"
//   - 5 NEW pages (Phase 3): Incidents, Investigation, Threat
//     Intel, Performance, Reports. Items here today; the page
//     bodies show a friendly "ships in Phase 3" stub until then.
//
// Page IDs kept stable for back-compat. Hash routes redirected
// for the renames: #blacklist / #whitelist → #access-lists,
// #tracking → #health, #attacks → #attack-analytics.
const NAV = [
  { group: 'Security Ops', items: [
    { id: 'overview',      label: 'Overview',         icon: <window.I.Shield />,   badge: null },
    { id: 'copilot',       label: 'Copilot',          icon: <window.I.Sparkles />, badge: 'AI', tone: 'warn' },
    { id: 'live',          label: 'Live Feed',        icon: <window.I.Activity />, badge: 'LIVE', tone: 'live' },
    { id: 'incidents',     label: 'Incidents',        icon: <window.I.Siren />,    badge: 'NEW', tone: 'warn' },
    { id: 'investigation', label: 'Investigation',    icon: <window.I.Search />,   badge: 'NEW', tone: 'warn' },
    { id: 'top-attackers', label: 'Top Attackers',    icon: <window.I.Siren />,    badge: null },
    // 2026-05-10 — Threat Intel sidebar entry retired. Backend
    // (TAXII / MISP feed scraper, ThreatIntelStore) still ships
    // and matches indicators in the data plane; the dashboard
    // surface was empty in every default config (no feeds wired,
    // GeoIP behind a build feature). Re-add this entry when a
    // default profile populates `cfg.threat_intel.feeds`.
  ]},
  { group: 'Policy', items: [
    // 2026-05-09 — reordered per operator request. The flow now
    // mirrors the request lifecycle: traffic enters via a route
    // → hits the four request-flow gates → runs the detector
    // chain → operator-authored rules apply.
    // "Traffic Gates" is the new page surfacing all four binary
    // gates (access list, strike-block, rate-limit, DDoS) with
    // telemetry + edit controls. Access Lists keeps its dedicated
    // CRUD page since the entry-by-entry editor is heavyweight.
    // 2026-05-10 — Compliance sidebar entry retired alongside the
    // lock-by-mode deferral (see plans/future/compliance-profiles.md).
    // Re-add when the lock returns.
    { id: 'upstreams',     label: 'Routing & Upstreams', icon: <window.I.Server />, badge: null },
    { id: 'traffic-gates', label: 'Traffic Gates',    icon: <window.I.Shield />,   badge: 'NEW', tone: 'warn' },
    { id: 'access-lists',  label: 'Access Lists',     icon: <window.I.Ban />,      badge: null },
    { id: 'detectors',     label: 'Detectors & Tiers', icon: <window.I.Cluster />, badge: null },
    { id: 'rules',         label: 'Rules',            icon: <window.I.Layers />,   badge: null },
  ]},
  { group: 'Observability', items: [
    { id: 'performance',   label: 'Performance',      icon: <window.I.Gauge />,    badge: 'NEW', tone: 'warn' },
    { id: 'health',        label: 'Health & SLOs',    icon: <window.I.Heart />,    badge: 'SLO', tone: 'warn' },
    { id: 'audit',         label: 'Audit Trail',      icon: <window.I.Book />,     badge: null },
    { id: 'scaling',       label: 'Scaling',          icon: <window.I.Cluster />,  badge: null },
  ]},
  { group: 'Admin', items: [
    { id: 'settings',      label: 'Settings',         icon: <window.I.Settings />, badge: null },
    { id: 'reports',       label: 'Reports',          icon: <window.I.Download />, badge: 'NEW', tone: 'warn' },
    { id: 'help',          label: 'Help & Guide',     icon: <window.I.Book />,     badge: null },
  ]},
];

// Hash-route redirects for Phase 2 renames. Old bookmarks keep
// working — the App router rewrites the hash before resolving.
const ROUTE_REDIRECTS = {
  'attacks':   'attack-analytics',
  'analytics': 'performance',
  'tiers':     'detectors',
  'tracking':  'health',
  'blacklist': 'access-lists',
  'whitelist': 'access-lists',
  // 2026-05-07 — Routing & Upstreams page lives at #/upstreams.
  // Documentation, bookmarks, and intuitive guesses (#/routing)
  // used to silently land on Overview pre-H002. Now they redirect.
  'routing':   'upstreams',
  // LOW-SO-02 (2026-05-12) — sidebar label "Live Feed" suggests
  // `#/live-feed` but the route is `#/live`. Alias the long form
  // so guessed-by-label bookmarks resolve.
  'live-feed': 'live',
  // LOW-OBS-02 (2026-05-12) — same pattern: sidebar reads
  // "Health & SLOs" but the route is `#/health`. Alias the
  // longer guess.
  'health-slos': 'health',
};

// 2026-05-07 — H002 fix. `location.hash.slice(2)` returns
// `investigation?pivot=abc&kind=request_id` for deep-links from the
// Live-Feed drawer. The router used to switch on that whole string,
// fall through to the `default` case, and silently render Overview.
// Now the router splits path/query, matches the path only, and
// preserves the query string so PageInvestigation's own useEffect
// can read it via `location.hash`.
const splitHashRoute = (raw) => {
  const q = raw.indexOf('?');
  return q === -1
    ? { path: raw, query: '' }
    : { path: raw.slice(0, q), query: raw.slice(q) };
};

// ============== TopBar ==============
//
// HU-T2 — wired to real data instead of hardcoded "v1.4.2 · 5 nodes
// · Healthy" placeholders. Sources:
//   - version / build_sha / environment ← /api/about (useStatusApi)
//   - cluster size                       ← /api/cluster (useClusterApi)
// Fallbacks render an em-dash when the API is unreachable so the
// visitor can tell "no data" from "value is N".
function TopBar() {
  const status = window.useStatusApi();
  const cluster = window.useClusterApi();
  const version = status.data?.version || '—';
  const env = (status.data?.environment || 'unknown').toLowerCase();
  const peers = cluster.data?.peers || [];
  const peerCount = peers.length;
  const isLeader = cluster.data?.is_leader;
  // Health rollup: green when we know we have at least one node and
  // /api/about is reachable; warn when /api/about is up but cluster
  // has no peer info yet; err when /api/about itself is failing.
  const healthTone = status.error ? 'err' : (peerCount === 0 ? 'warn' : 'ok');
  const healthLabel = status.error
    ? 'API unreachable'
    : peerCount === 0
      ? 'Standalone'
      : `Cluster ${peerCount} node${peerCount === 1 ? '' : 's'}${isLeader ? ' · leader' : ''}`;

  return (
    <div className="topbar">
      <div className="brand">
        <div className="brand-mark">A</div>
        <div>
          <div className="brand-name">
            Aegis WAF
            <span className="brand-version" style={{ marginLeft: 6 }}>v{version}</span>
          </div>
          <div style={{ fontSize: 10, color: 'var(--ink-faint)', letterSpacing: 0.4 }}>
            ENTERPRISE CONTROL PLANE
          </div>
        </div>
      </div>

      <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
        {/* MED-03 (2026-05-11) — hide the env pill entirely when
            the env is "unknown" rather than rendering a red
            "UNKNOWN" alarm. Operators on a fresh dev boot were
            getting a P1-shaped pill at the top of every page on
            an otherwise healthy cluster; the pill should reflect
            actual operational signal, not a missing config
            label. Labeled envs (dev, staging, prod) still render
            so operators see *which* env they're on. */}
        {env !== 'unknown' && (
          <span
            className={`env-pill ${env}`}
            title={`Environment: ${env}`}
          >● {env.toUpperCase()}</span>
        )}
        {status.data?.mtls_break_glass_active && (
          <span
            className="pill down"
            title="AEGIS_MTLS_BREAK_GLASS=1 was set at boot — mTLS `required` is downgraded to `optional`. Unset env + restart to return to enforced mode."
            style={{ marginLeft: 4, animation: 'pulse 2s ease-in-out infinite' }}
          >
            ⚠ MTLS BREAK-GLASS
          </span>
        )}
      </div>

      <div style={{ flex: 1 }} />

      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
        <span style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 11, color: 'var(--ink-mute)' }}>
          <span className={`led ${healthTone}`} /> {healthLabel}
        </span>
        {(() => {
          // CQF-T10 — notifications bell. 2026-05-21 — re-wired from
          // /api/alerts to the overlay-aware /api/incidents enriched
          // list. The old source read `tracking.ack_store`, a DIFFERENT
          // overlay store than the Incidents page resolve (which writes
          // to IncidentTracker via /api/incidents), so a resolved alert
          // never cleared the badge. Counting enriched incidents with
          // status `firing` (acked/snoozed/resolved excluded) keeps the
          // badge in lock-step with the Incidents page. Falls back to
          // `raw_alerts.firing` when the SLO engine isn't wired (tests).
          const incidentsApi = window.useIncidentsApi();
          const list = incidentsApi.data?.incidents;
          const firing = Array.isArray(list)
            ? list.filter(i => i.status === 'firing').length
            : (incidentsApi.data?.raw_alerts?.firing?.length || 0);
          return (
            <button
              className="icon-btn"
              title={firing > 0 ? `${firing} firing alert${firing === 1 ? '' : 's'}` : 'No firing alerts'}
              style={{ position: 'relative' }}
              onClick={() => { location.hash = '#/incidents'; }}
            >
              <window.I.Bell />
              {firing > 0 && (
                <span style={{
                  position: 'absolute',
                  top: 2, right: 2,
                  minWidth: firing > 9 ? 14 : 10, height: 10,
                  padding: firing > 9 ? '0 3px' : 0,
                  borderRadius: 5,
                  background: 'var(--down)',
                  color: '#000',
                  fontSize: 8, fontWeight: 700, lineHeight: '10px',
                  textAlign: 'center',
                  display: 'flex', alignItems: 'center', justifyContent: 'center',
                }}>{firing > 99 ? '99+' : firing}</span>
              )}
            </button>
          );
        })()}
        <ThemeToggle />
        <div className="user-chip">
          <div className="avatar">AD</div>
          <div style={{ display: 'flex', flexDirection: 'column' }}>
            <span style={{ fontSize: 12, color: 'var(--ink)', fontWeight: 600, lineHeight: 1.2 }}>admin</span>
            <span style={{ fontSize: 10, color: 'var(--ink-dim)' }}>SUPER · TOTP</span>
          </div>
        </div>
        {/* CQF-T14 — TopBar drain button. Two-step confirm; calls
            /admin/drain (audit-mutated; flips readiness so external
            LBs stop routing new traffic). The Scaling page also
            exposes the same action; this button mirrors it for
            quick access during incident response. */}
        <button
          className="icon-btn"
          title="Drain this node (readiness → false)"
          style={{ color: 'var(--warn)' }}
          onClick={async () => {
            if (!confirm('Drain this node? /healthz/ready will return 503 and external LBs will stop routing new traffic. In-flight requests continue.')) return;
            try {
              const r = await window.adminDrainPost();
              if (r && r.status === 'draining') {
                window.aegisToast(`Drain initiated · node ${r.node || 'unknown'} · already=${r.already ?? false}`, 'ok');
              } else {
                const msg = (r && (r.error || r.message)) || 'unknown response';
                window.aegisToast(`Drain failed: ${msg}`, 'err');
              }
            } catch (e) {
              window.aegisToast(`Drain error: ${e.message || e}`, 'err');
            }
          }}
        >
          <window.I.Pause />
        </button>
        {/* CQF-T1 — operator logout. POSTs /admin/logout with CSRF; handler returns
            204 + Set-Cookie clearing both aegis_session and aegis_csrf. We
            redirect to the login screen so the next mutation has no auth state
            to lean on. */}
        <button
          className="icon-btn"
          title="Sign out"
          onClick={async () => {
            try {
              const r = await window.adminLogout();
              if (r.status === 204 || r.status === 200) {
                window.aegisToast && window.aegisToast('Signed out', 'ok');
              } else {
                window.aegisToast && window.aegisToast(`Logout returned ${r.status}`, 'warn');
              }
            } catch (e) {
              window.aegisToast && window.aegisToast(`Logout error: ${e.message || e}`, 'err');
            } finally {
              // Always navigate away — even when the network call fails the
              // safest thing is to abandon the session UI.
              location.href = '/admin/login';
            }
          }}
        >
          <window.I.LogOut />
        </button>
      </div>
    </div>
  );
}

// ============== Sidebar ==============
//
// CQF-T9 — sidebar footer is wired to /api/about. Build is the
// short SHA + version; uptime is computed from the boot timestamp
// the API returns. Falls back to em-dashes when the API is
// unreachable so the footer never lies about a value it doesn't
// have.
// Theme toggle — flips the `data-theme` attribute on <html> and
// persists the choice to localStorage. The pre-paint script in
// index.html reads localStorage on next page load so the choice
// sticks.
function ThemeToggle() {
  const [theme, setTheme] = useState(() => {
    try { return document.documentElement.dataset.theme || 'dark'; }
    catch (_) { return 'dark'; }
  });
  const flip = () => {
    const next = theme === 'dark' ? 'light' : 'dark';
    document.documentElement.dataset.theme = next;
    try { localStorage.setItem('aegis_theme', next); } catch (_) {}
    setTheme(next);
  };
  return (
    <button
      className="icon-btn"
      onClick={flip}
      title={theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode'}
      style={{ marginRight: 4 }}
    >
      {theme === 'dark' ? (
        // Sun (currently dark → click for light)
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
          <circle cx="12" cy="12" r="4" />
          <path d="M12 2v2M12 20v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41M2 12h2M20 12h2M4.93 19.07l1.41-1.41M17.66 6.34l1.41-1.41" />
        </svg>
      ) : (
        // Moon (currently light → click for dark)
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
          <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z" />
        </svg>
      )}
    </button>
  );
}

function fmtUptimeFromMs(deltaMs) {
  if (!Number.isFinite(deltaMs) || deltaMs < 0) return '—';
  const sec = Math.floor(deltaMs / 1000);
  const days = Math.floor(sec / 86400);
  const hours = Math.floor((sec % 86400) / 3600);
  const mins = Math.floor((sec % 3600) / 60);
  if (days > 0) return `${days}d ${hours}h`;
  if (hours > 0) return `${hours}h ${mins}m`;
  return `${mins}m`;
}

function Sidebar({ active, onNav }) {
  const status = window.useStatusApi();
  const version = status.data?.version || '';
  const buildSha = status.data?.build_sha || '';
  const buildLabel = (version && buildSha)
    ? `${version}-${String(buildSha).slice(0, 4)}`
    : (version || '—');
  // useStatusApi polls every 5s, so this re-renders naturally
  // without a separate clock.
  let uptimeLabel = '—';
  const startedRaw = status.data?.started_at || status.data?.boot_ts || status.data?.start_time;
  if (startedRaw) {
    const started = Date.parse(startedRaw);
    if (Number.isFinite(started)) {
      uptimeLabel = fmtUptimeFromMs(Date.now() - started);
    }
  }

  return (
    <aside className="sidebar">
      <div style={{ flex: 1, overflowY: 'auto', padding: '12px 8px' }}>
        {NAV.map(g => (
          <div key={g.group} className="nav-group">
            <div className="nav-heading">{g.group}</div>
            {g.items.map(it => (
              <button key={it.id} onClick={() => onNav(it.id)}
                className={`nav-item ${active === it.id ? 'active' : ''}`}>
                <span className="nav-icon">{it.icon}</span>
                <span className="nav-label">{it.label}</span>
                {it.badge && (
                  <span className={`nav-badge ${it.tone || ''} ${it.tone === 'live' ? 'live-dot' : ''}`}>{it.badge}</span>
                )}
              </button>
            ))}
          </div>
        ))}
      </div>
      <div style={{ padding: 12, borderTop: '1px solid var(--hairline)', fontSize: 10, color: 'var(--ink-faint)' }}>
        <div style={{ marginBottom: 4 }}>BUILD <span className="num" style={{ color: 'var(--ink-mute)' }} title={buildSha || ''}>{buildLabel}</span></div>
        <div>UPTIME <span className="num" style={{ color: 'var(--ink-mute)' }}>{uptimeLabel}</span></div>
      </div>
    </aside>
  );
}

// ============== Status Bar ==============
//
// HU-T2 — replaces hardcoded "5/5 · 14s · verified · in-sync · 14d 22h"
// with real data where APIs already expose it. Fields the backend
// doesn't yet emit are shown with a "demo" tone so the operator
// can tell which numbers are authoritative.
//
// Real:
//   - cluster N/peers  ← /api/cluster
//   - GitOps state     ← /api/gitops/status
//   - Build SHA + ver  ← /api/about
//   - Tick (uptime in current page session)
// Demo (no backend yet):
//   - SSE connected indicator (status reflects whether the page
//     opens an SSE; not currently observed at this level)
//   - Audit chain "verified" pill (witness signing is shipped but
//     no realtime verify is exposed via API)
function StatusBar({ tick }) {
  const cluster = window.useClusterApi();
  const gitops = window.useGitopsApi();
  const status = window.useStatusApi();
  const peers = cluster.data?.peers || [];
  const healthy = peers.filter(p => p.healthy !== false).length;
  const total = peers.length;
  // 2026-05-03 — soften the GitOps tone when the operator
  // hasn't configured the integration at all.  Previously
  // `gitopsState || 'unknown'` rendered as red "UNKNOWN" on
  // every fresh dev WAF, indistinguishable from a real failure.
  // Now: configured + healthy = ok, configured + drift = warn,
  // configured + unknown = info, not configured at all = muted
  // "off" pill (neutral grey, not red).
  const gitopsConfigured = Boolean(gitops.data?.repo) || Boolean(gitops.data?.repo_url);
  const rawState = gitops.data?.state || gitops.data?.status;
  const gitopsState = rawState
    || (gitopsConfigured ? 'unknown' : 'off');
  const gitopsTone = gitopsState === 'in_sync' || gitopsState === 'in-sync' ? 'ok'
                   : gitopsState === 'drift' ? 'warn'
                   : gitopsState === 'off' ? 'neutral'
                   : rawState ? 'info' : 'neutral';
  const version = status.data?.version || '—';
  const buildSha = status.data?.build_sha;
  const buildLabel = buildSha ? `${version}-${String(buildSha).slice(0, 4)}` : version;

  return (
    <div className="statusbar">
      <span>Cluster <span className={`num ${total === 0 ? 'dim' : ''}`}>
        {total === 0 ? 'single-node' : `${healthy}/${total}`}
      </span></span>
      <span className="dim">|</span>
      <span>GitOps <span className={`pill ${gitopsTone}`}>{gitopsState}</span></span>
      <span style={{ marginLeft: 'auto' }}>Build <span className="num">{buildLabel}</span> · session {tick}s</span>
    </div>
  );
}

// ============== Error boundary ==============
//
// 2026-05-03 — operators reported "auto-refresh shows white page"
// on a few pages (e.g. Routing & Upstreams).  Root cause: a
// component throws during a polling-driven re-render (race on
// API shape, undefined access on a transient empty payload, etc.)
// and React unmounts the whole tree because there's no error
// boundary above it.  This boundary catches the error, keeps the
// shell + sidebar visible, and renders an actionable retry card
// so the operator can navigate away or reload without losing the
// session.
class PageErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { error: null };
  }
  static getDerivedStateFromError(error) {
    return { error };
  }
  componentDidCatch(error, info) {
    // Log to the browser console so the operator (or QA) can
    // capture the stack from DevTools.  No telemetry path yet.
    console.error('[aegis-console] page render crashed:', error, info);
  }
  componentDidUpdate(prevProps) {
    // Reset on route change so navigating to a working page
    // un-traps the boundary without a full reload.
    if (prevProps.route !== this.props.route && this.state.error) {
      this.setState({ error: null });
    }
  }
  render() {
    if (this.state.error) {
      const msg = this.state.error?.message || String(this.state.error);
      return React.createElement(
        'div',
        { className: 'card', style: { padding: 24, maxWidth: 720, margin: '32px auto' } },
        React.createElement('h2', { style: { marginTop: 0 } }, 'Page render error'),
        React.createElement(
          'p',
          { style: { color: 'var(--ink-mute)' } },
          'This page hit a JavaScript error while rendering. The shell + sidebar still work — pick a different page or reload.',
        ),
        React.createElement(
          'pre',
          {
            style: {
              background: 'var(--surface-2)',
              padding: 12,
              borderRadius: 6,
              fontSize: 11,
              overflow: 'auto',
              maxHeight: 240,
            },
          },
          msg,
        ),
        React.createElement(
          'div',
          { style: { display: 'flex', gap: 8, marginTop: 12 } },
          React.createElement(
            'button',
            {
              className: 'btn primary',
              onClick: () => this.setState({ error: null }),
            },
            'Retry render',
          ),
          React.createElement(
            'button',
            {
              className: 'btn',
              onClick: () => { window.location.hash = '#/overview'; this.setState({ error: null }); },
            },
            'Back to Overview',
          ),
          React.createElement(
            'button',
            {
              className: 'btn',
              onClick: () => window.location.reload(),
            },
            'Reload page',
          ),
        ),
      );
    }
    return this.props.children;
  }
}

// 2026-05-07 — visible fallback for unmatched hash routes. Replaces
// the prior silent-Overview default so routing bugs don't hide.
function PageNotFound({ route }) {
  return (
    <div style={{ padding: 32 }}>
      <h1 className="page-title">Page not found</h1>
      <p style={{ color: 'var(--ink-mute)', marginTop: 8 }}>
        No page matches <code>#/{route}</code>.
      </p>
      <button
        type="button"
        className="btn"
        style={{ marginTop: 16 }}
        onClick={() => { location.hash = '#/overview'; }}
      >
        Back to Overview
      </button>
    </div>
  );
}

// ============== App ==============
function App() {
  // Resolve hash → route, applying redirects for renamed pages.
  // Strips `?query` so deep-links like
  // `#/investigation?pivot=req-abc&kind=request_id` route to
  // `investigation` and the page reads its own params from
  // `location.hash`.
  const resolveRoute = () => {
    const raw = location.hash.slice(2) || 'overview';
    const { path } = splitHashRoute(raw);
    return ROUTE_REDIRECTS[path] || path;
  };
  const [route, setRoute] = useState(resolveRoute);
  const tick = window.useTicking(2000);

  // Compact density + yellow accent are the defaults; no tweaks
  // panel in this build. Apply once.
  useEffect(() => {
    document.documentElement.dataset.density = 'compact';
    document.documentElement.dataset.accent = 'yellow';
  }, []);

  // Hash routing — apply Phase-2 renames on every hash change so
  // pasted-in old URLs land on the new page. Query string is
  // preserved across redirects so deep-links survive the rewrite.
  useEffect(() => {
    const onHash = () => {
      const raw = location.hash.slice(2) || 'overview';
      const { path, query } = splitHashRoute(raw);
      const resolved = ROUTE_REDIRECTS[path];
      if (resolved) {
        location.replace(`#/${resolved}${query}`);
        setRoute(resolved);
      } else {
        setRoute(path);
      }
    };
    window.addEventListener('hashchange', onHash);
    return () => window.removeEventListener('hashchange', onHash);
  }, []);
  const nav = id => { location.hash = `/${id}`; };

  let page = null;
  switch (route) {
    case 'overview':         page = <window.PageOverview />; break;
    case 'live':             page = <window.PageLiveFeed />; break;
    case 'incidents':        page = <window.PageIncidents />; break;
    case 'investigation':    page = <window.PageInvestigation />; break;
    case 'top-attackers':    page = <window.PageTopAttackers />; break;
    // Attack-Analytics merged into Investigation (2026-05-03).
    // Old hash links keep working — redirect to Investigation.
    case 'attack-analytics': page = <window.PageInvestigation />; break;
    // Threat-intel + Compliance pages retired 2026-05-10. Stale
    // deep links fall through to the default `PageOverview` below.
    case 'copilot':          page = <window.PageCopilot />; break;
    case 'rules':            page = <window.PageRuleManager />; break;
    case 'detectors':        page = <window.PageTierConfig />; break;
    case 'access-lists':     page = <window.PageAccessLists />; break;
    case 'upstreams':        page = <window.PageUpstreams />; break;
    case 'traffic-gates':    page = <window.PageTrafficGates />; break;
    case 'performance':      page = <window.PageAnalytics />; break;
    case 'health':           page = <window.PageTracking />; break;
    case 'audit':            page = <window.PageAuditLog />; break;
    case 'scaling':          page = <window.PageScaling />; break;
    case 'settings':         page = <window.PageSettings />; break;
    case 'reports':          page = <window.PageReports />; break;
    case 'help':             page = <window.PageHelp />; break;
    // 2026-05-07 — H002. Unknown routes used to silently render
    // PageOverview, which hid routing bugs (e.g. typos in hash
    // links, or this exact pivot bug). A visible 404 surfaces them.
    default:                 page = <PageNotFound route={route} />;
  }

  return (
    <div className="app density-compact">
      <TopBar />
      <Sidebar active={route} onNav={nav} />
      <main className="content">
        <PageErrorBoundary route={route}>{page}</PageErrorBoundary>
      </main>
      <StatusBar tick={tick} />
      <window.ToastContainer />
    </div>
  );
}

ReactDOM.createRoot(document.getElementById('root')).render(<App />);
