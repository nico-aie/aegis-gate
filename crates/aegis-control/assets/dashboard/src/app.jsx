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
    { id: 'blacklist',label: 'Blacklist',     icon: <window.I.Ban />,      badge: null, tone: 'down' },
    { id: 'whitelist',label: 'Whitelist',     icon: <window.I.Check />,    badge: null, tone: 'up' },
    { id: 'settings', label: 'Settings',      icon: <window.I.Settings />, badge: null },
  ]},
  { group: 'Tracking', items: [
    { id: 'tracking', label: 'Tracking',      icon: <window.I.Gauge />,    badge: 'SLO', tone: 'warn' },
  ]},
  { group: 'Resources', items: [
    { id: 'help',     label: 'Help & Guide',  icon: <window.I.Book />,     badge: null },
  ]},
];

// ============== TopBar ==============
function TopBar({ env }) {
  return (
    <div className="topbar">
      <div className="brand">
        <div className="brand-mark">A</div>
        <div>
          <div className="brand-name">Aegis WAF<span className="brand-version" style={{ marginLeft: 6 }}>v1.4.2</span></div>
          <div style={{ fontSize: 10, color: 'var(--ink-faint)', letterSpacing: 0.4 }}>ENTERPRISE CONTROL PLANE</div>
        </div>
      </div>

      <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
        <span className={`env-pill ${env}`}>● {env.toUpperCase()}</span>
        <span className="env-pill" style={{ background: 'var(--surface-2)', color: 'var(--ink-mute)' }}>SG-1 EDGE · 5 nodes</span>
      </div>

      <div style={{ flex: 1 }} />

      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
        <span style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 11, color: 'var(--ink-mute)' }}>
          <span className="led ok" /> Healthy
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
function StatusBar({ tick }) {
  return (
    <div className="statusbar">
      <span><span className="led ok"></span> SSE connected</span>
      <span className="dim">|</span>
      <span>Cluster <span className="num">5/5</span></span>
      <span className="dim">|</span>
      <span>Last config sync <span className="num">14s</span></span>
      <span className="dim">|</span>
      <span>Audit chain <span className="pill ok">verified</span></span>
      <span className="dim">|</span>
      <span>GitOps <span className="pill ok">in-sync</span></span>
      <span style={{ marginLeft: 'auto' }}>Build <span className="num">1.4.2-3a8f</span> · {tick}s</span>
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
    case 'blacklist': page = <window.ListPage kind="blacklist" />; break;
    case 'whitelist': page = <window.ListPage kind="whitelist" />; break;
    case 'settings':  page = <window.PageSettings />; break;
    case 'tracking':  page = <window.PageTracking />; break;
    case 'help':      page = <window.PageHelp />; break;
    default:          page = <window.PageOverview />;
  }

  return (
    <div className="app density-compact">
      <TopBar env="prod" />
      <Sidebar active={route} onNav={nav} />
      <main className="content">{page}</main>
      <StatusBar tick={tick} />
    </div>
  );
}

ReactDOM.createRoot(document.getElementById('root')).render(<App />);
