/* global React, ReactDOM */
const { useState, useEffect } = React;

// ============== Sidebar nav model ==============
const NAV = [
  { group: 'Operator', items: [
    { id: 'overview', label: 'Overview',      icon: <window.I.Shield />,   badge: null },
    { id: 'live',     label: 'Live Feed',     icon: <window.I.Activity />, badge: 'LIVE', tone: 'live' },
    { id: 'attacks',  label: 'Attack Events', icon: <window.I.Siren />,    badge: null },
    { id: 'analytics',label: 'Analytics',     icon: <window.I.BarChart />, badge: null },
    { id: 'audit',    label: 'Audit Log',     icon: <window.I.Book />,     badge: null },
  ]},
  { group: 'Configuration', items: [
    { id: 'rules',    label: 'Rule Manager',  icon: <window.I.Layers />,   badge: null },
    { id: 'tiers',    label: 'Tier Config',   icon: <window.I.Cluster />,  badge: null },
    { id: 'upstreams',label: 'Upstreams',     icon: <window.I.Server />,   badge: null },
    { id: 'blacklist',label: 'Blacklist',     icon: <window.I.Ban />,      badge: null, tone: 'down' },
    { id: 'whitelist',label: 'Whitelist',     icon: <window.I.Check />,    badge: null, tone: 'up' },
    { id: 'settings', label: 'Settings',      icon: <window.I.Settings />, badge: null },
  ]},
  { group: 'Tracking', items: [
    { id: 'tracking', label: 'Tracking',      icon: <window.I.Gauge />,    badge: 'SLO', tone: 'warn' },
    // SC-T2 — Scaling page: L1 in-node workers + L2 cluster
    // peers + L3 shared-state backend health, in one stack.
    { id: 'scaling',  label: 'Scaling',       icon: <window.I.Cluster />,  badge: null },
  ]},
  { group: 'Resources', items: [
    { id: 'help',     label: 'Help & Guide',  icon: <window.I.Book />,     badge: null },
  ]},
];

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
      </div>

      <div style={{ flex: 1 }} />

      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
        <span style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 11, color: 'var(--ink-mute)' }}>
          <span className={`led ${healthTone}`} /> {healthLabel}
        </span>
        <button className="icon-btn" title="Notifications" style={{ position: 'relative' }}>
          <window.I.Bell />
          <span style={{ position: 'absolute', top: 4, right: 4, width: 6, height: 6, borderRadius: '50%', background: 'var(--down)' }} />
        </button>
        <div className="user-chip">
          <div className="avatar">AD</div>
          <div style={{ display: 'flex', flexDirection: 'column' }}>
            <span style={{ fontSize: 12, color: 'var(--ink)', fontWeight: 600, lineHeight: 1.2 }}>admin</span>
            <span style={{ fontSize: 10, color: 'var(--ink-dim)' }}>SUPER · TOTP</span>
          </div>
        </div>
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
function Sidebar({ active, onNav }) {
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
        <div style={{ marginBottom: 4 }}>BUILD <span className="num" style={{ color: 'var(--ink-mute)' }}>1.4.2-3a8f</span></div>
        <div>UPTIME <span className="num" style={{ color: 'var(--ink-mute)' }}>14d 22h</span></div>
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
  const [route, setRoute] = useState(() => location.hash.slice(2) || 'overview');
  const tick = window.useTicking(2000);

  // Compact density + yellow accent are the defaults; no tweaks
  // panel in this build. Apply once.
  useEffect(() => {
    document.documentElement.dataset.density = 'compact';
    document.documentElement.dataset.accent = 'yellow';
  }, []);

  // Hash routing
  useEffect(() => {
    const onHash = () => setRoute(location.hash.slice(2) || 'overview');
    window.addEventListener('hashchange', onHash);
    return () => window.removeEventListener('hashchange', onHash);
  }, []);
  const nav = id => { location.hash = `/${id}`; };

  let page = null;
  switch (route) {
    case 'overview':  page = <window.PageOverview />; break;
    case 'live':      page = <window.PageLiveFeed />; break;
    case 'attacks':   page = <window.PageAttackEvents />; break;
    case 'analytics': page = <window.PageAnalytics />; break;
    case 'audit':     page = <window.PageAuditLog />; break;
    case 'rules':     page = <window.PageRuleManager />; break;
    case 'tiers':     page = <window.PageTierConfig />; break;
    case 'upstreams': page = <window.PageUpstreams />; break;
    case 'blacklist': page = <window.ListPage kind="blacklist" />; break;
    case 'whitelist': page = <window.ListPage kind="whitelist" />; break;
    case 'settings':  page = <window.PageSettings />; break;
    case 'tracking':  page = <window.PageTracking />; break;
    case 'scaling':   page = <window.PageScaling />; break;
    case 'help':      page = <window.PageHelp />; break;
    default:          page = <window.PageOverview />;
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
