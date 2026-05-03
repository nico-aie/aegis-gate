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
    { id: 'live',          label: 'Live Feed',        icon: <window.I.Activity />, badge: 'LIVE', tone: 'live' },
    { id: 'incidents',     label: 'Incidents',        icon: <window.I.Siren />,    badge: 'NEW', tone: 'warn' },
    { id: 'investigation', label: 'Investigation',    icon: <window.I.Search />,   badge: 'NEW', tone: 'warn' },
    { id: 'attack-analytics', label: 'Attack Analytics', icon: <window.I.BarChart />, badge: null },
    { id: 'threat-intel',  label: 'Threat Intel',     icon: <window.I.Globe />,    badge: 'NEW', tone: 'warn' },
  ]},
  { group: 'Policy', items: [
    { id: 'rules',         label: 'Rules',            icon: <window.I.Layers />,   badge: null },
    { id: 'detectors',     label: 'Detectors',        icon: <window.I.Cluster />,  badge: null },
    { id: 'access-lists',  label: 'Access Lists',     icon: <window.I.Ban />,      badge: null },
    { id: 'upstreams',     label: 'Routing & Upstreams', icon: <window.I.Server />, badge: null },
    { id: 'compliance',    label: 'Compliance',       icon: <window.I.Check />,    badge: 'NEW', tone: 'warn' },
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
        <span className={`env-pill ${env}`}>● {env.toUpperCase()}</span>
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
          // CQF-T10 — notifications bell wired to /api/alerts.
          // Badge shows the count of currently-firing alerts (no
          // ack flow exposed here; that lives on the Tracking
          // page). Click opens the Tracking page filtered to
          // firing alerts via a hash-state convention; if no
          // hook is wired the click still navigates so the
          // operator lands somewhere useful.
          const alertsApi = window.useAlertsApi();
          const firing = (alertsApi.data?.firing || []).length;
          return (
            <button
              className="icon-btn"
              title={firing > 0 ? `${firing} firing alert${firing === 1 ? '' : 's'}` : 'No firing alerts'}
              style={{ position: 'relative' }}
              onClick={() => { location.hash = '#/tracking'; }}
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
  const gitopsState = gitops.data?.state || gitops.data?.status;
  const gitopsTone = gitopsState === 'in_sync' || gitopsState === 'in-sync' ? 'ok'
                   : gitopsState === 'drift' ? 'warn'
                   : gitopsState ? 'info' : 'neutral';
  const version = status.data?.version || '—';
  const buildSha = status.data?.build_sha;
  const buildLabel = buildSha ? `${version}-${String(buildSha).slice(0, 4)}` : version;

  return (
    <div className="statusbar">
      <span title="Demo indicator — SSE state isn't observed at the topbar level">
        <span className="led warn"></span> SSE (demo)
      </span>
      <span className="dim">|</span>
      <span>Cluster <span className="num">{total === 0 ? 'standalone' : `${healthy}/${total}`}</span></span>
      <span className="dim">|</span>
      <span title="Demo indicator — chain verify isn't exposed in realtime; use `waf audit verify`">
        Audit chain <span className="pill warn">demo</span>
      </span>
      <span className="dim">|</span>
      <span>GitOps <span className={`pill ${gitopsTone}`}>{gitopsState || 'unknown'}</span></span>
      <span style={{ marginLeft: 'auto' }}>Build <span className="num">{buildLabel}</span> · session {tick}s</span>
    </div>
  );
}

// ============== App ==============
function App() {
  // Resolve hash → route, applying redirects for renamed pages.
  const resolveRoute = () => {
    const raw = location.hash.slice(2) || 'overview';
    return ROUTE_REDIRECTS[raw] || raw;
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
  // pasted-in old URLs land on the new page.
  useEffect(() => {
    const onHash = () => {
      const raw = location.hash.slice(2) || 'overview';
      const resolved = ROUTE_REDIRECTS[raw];
      if (resolved) {
        location.replace(`#/${resolved}`);
        setRoute(resolved);
      } else {
        setRoute(raw);
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
    case 'attack-analytics': page = <window.PageAttackEvents />; break;
    case 'threat-intel':     page = <window.PageThreatIntel />; break;
    case 'rules':            page = <window.PageRuleManager />; break;
    case 'detectors':        page = <window.PageTierConfig />; break;
    case 'access-lists':     page = <window.PageAccessLists />; break;
    case 'upstreams':        page = <window.PageUpstreams />; break;
    case 'compliance':       page = <window.PageCompliance />; break;
    case 'performance':      page = <window.PageAnalytics />; break;
    case 'health':           page = <window.PageTracking />; break;
    case 'audit':            page = <window.PageAuditLog />; break;
    case 'scaling':          page = <window.PageScaling />; break;
    case 'settings':         page = <window.PageSettings />; break;
    case 'reports':          page = <window.PageReports />; break;
    case 'help':             page = <window.PageHelp />; break;
    default:                 page = <window.PageOverview />;
  }

  return (
    <div className="app density-compact">
      <TopBar />
      <Sidebar active={route} onNav={nav} />
      <main className="content">{page}</main>
      <StatusBar tick={tick} />
      <window.ToastContainer />
    </div>
  );
}

ReactDOM.createRoot(document.getElementById('root')).render(<App />);
