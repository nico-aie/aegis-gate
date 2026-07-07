/* global React, ReactDOM */
const { useState, useEffect, useRef } = React;

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
    // 2026-07-07 — the standalone Incidents page was retired. Its
    // read-only twin already lived on Health & SLOs ("Active alerts",
    // same /api/incidents source); the actionable ack/snooze/resolve
    // queue moved there too. `#/incidents` now redirects to `#/health`.
    { id: 'investigation', label: 'Investigation',    icon: <window.I.Search />,   badge: null },
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
    { id: 'traffic-gates', label: 'Traffic Gates',    icon: <window.I.Shield />,   badge: null },
    { id: 'access-lists',  label: 'Access Lists',     icon: <window.I.Ban />,      badge: null },
    { id: 'detectors',     label: 'Detectors & Tiers', icon: <window.I.Cluster />, badge: null },
    { id: 'rules',         label: 'Rules',            icon: <window.I.Layers />,   badge: 'Beta', tone: 'warn' },
    { id: 'zero-trust',    label: 'Zero Trust',       icon: <window.I.Shield />,   badge: 'Beta', tone: 'warn' },
  ]},
  { group: 'Observability', items: [
    // 2026-06-05 — Copilot is no longer a page; it's a global chat widget
    // (floating launcher, bottom-right) reachable from anywhere, including
    // the Overview "Open Copilot" button. Old #/copilot links redirect to
    // Overview (see ROUTE_REDIRECTS).
    { id: 'performance',   label: 'Performance',      icon: <window.I.Gauge />,    badge: null },
    { id: 'health',        label: 'Health & SLOs',    icon: <window.I.Heart />,    badge: 'SLO', tone: 'warn' },
    { id: 'audit',         label: 'Audit Trail',      icon: <window.I.Book />,     badge: null },
    { id: 'scaling',       label: 'Scaling',          icon: <window.I.Cluster />,  badge: null },
  ]},
  { group: 'Admin', items: [
    { id: 'users',         label: 'Users',            icon: <window.I.Shield />,   badge: null },
    { id: 'settings',      label: 'Settings',         icon: <window.I.Settings />, badge: null },
    { id: 'reports',       label: 'Reports',          icon: <window.I.Download />, badge: null },
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
  // 2026-06-05 — Copilot page removed; it's a global chat widget now.
  // Old bookmarks / the prior sidebar route land on Overview, where the
  // "Open Copilot" button pops the widget.
  'copilot': 'overview',
  // 2026-07-07 — Incidents page retired; its actionable queue folded
  // into Health & SLOs. Old bookmarks + the notification bell land on
  // the "Active alerts" card there (#/health).
  'incidents': 'health',
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

// ============== Account password modal ==============
//
// AM-P2d follow-up — self-service password change lifted out of the
// Settings "My Account" card into a modal reachable from the topbar
// account menu (the discoverable, GitHub/Google-style home). Shares the
// exact server contract as the Settings card: `window.selfChangePassword`
// verifies the CURRENT password server-side (unlike an admin reset) and
// signs out your other sessions on success. The Settings card stays as a
// deep-linkable fallback (`#/settings`) — both call the same endpoint.
function AccountPasswordModal({ onClose }) {
  const [cur, setCur] = useState('');
  const [next, setNext] = useState('');
  const [confirm, setConfirm] = useState('');
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState(null); // { ok, text }

  const newOk = next.length >= 12;
  const matchOk = next === confirm;
  const canSubmit = cur.length > 0 && newOk && matchOk && next !== cur && !busy;

  async function submit(e) {
    e.preventDefault();
    if (!canSubmit) return;
    setBusy(true); setNotice(null);
    const res = await window.selfChangePassword(cur, next);
    setBusy(false);
    const ok = res.status >= 200 && res.status < 300;
    const text = ok
      ? (res.message || 'Password changed. Your other sessions were signed out.')
      : (res.message || res.reason || `Change failed (HTTP ${res.status})`);
    setNotice({ ok, text });
    if (window.aegisToast) window.aegisToast(text, ok ? 'ok' : 'err');
    if (ok) { setCur(''); setNext(''); setConfirm(''); }
  }

  const hint = next && !newOk ? 'New password must be ≥ 12 characters'
    : confirm && !matchOk ? 'Passwords don’t match'
      : next && next === cur ? 'New password must differ from current' : '';

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal" onClick={e => e.stopPropagation()} style={{ maxWidth: 440 }}>
        <div className="modal-head">
          <div className="modal-title">
            <span style={{ display: 'inline-flex', verticalAlign: 'middle', marginRight: 6 }}><window.I.Shield /></span>
            Change password
          </div>
          <button className="btn btn-sm" onClick={onClose} aria-label="Close">×</button>
        </div>
        <form onSubmit={submit}>
          <div className="modal-body">
            {notice && (
              <div style={{
                padding: '8px 10px', marginBottom: 12, fontSize: 12, borderRadius: 6,
                display: 'flex', alignItems: 'center', gap: 8,
                border: `1px solid var(--${notice.ok ? 'ok' : 'danger'})`,
                background: 'var(--surface-2)',
              }}>
                <span style={{ color: `var(--${notice.ok ? 'ok' : 'danger'})`, display: 'inline-flex' }}>
                  {notice.ok ? <window.I.Check /> : <window.I.Ban />}
                </span>
                <span style={{ color: 'var(--ink)' }}>{notice.text}</span>
              </div>
            )}
            <div className="form-row">
              <label>Current password</label>
              <input className="ip" type="password" value={cur} autoComplete="current-password"
                onChange={e => setCur(e.target.value)} autoFocus />
            </div>
            <div className="form-row">
              <label>New password</label>
              <input className="ip" type="password" value={next} autoComplete="new-password"
                placeholder="≥ 12 characters" onChange={e => setNext(e.target.value)} />
            </div>
            <div className="form-row">
              <label>Confirm new password</label>
              <input className="ip" type="password" value={confirm} autoComplete="new-password"
                onChange={e => setConfirm(e.target.value)} />
            </div>
            {hint && <div className="form-hint warn">{hint}</div>}
          </div>
          <div className="modal-foot">
            <button type="button" className="btn" onClick={onClose}>Cancel</button>
            <button type="submit" className="btn primary" disabled={!canSubmit}>
              {busy ? 'Changing…' : 'Change password'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

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
  // FIX-topbar-drain (2026-07-02) — live drain state so the button is a
  // truthful toggle (Pause=drain / Play=resume), matching the Scaling
  // page's reversible-drain UX (PR #113). Survives reloads + reflects
  // drains triggered by SIGTERM/automation.
  const drainState = window.useNodeDrainApi ? window.useNodeDrainApi() : { data: null, reload: null };
  const isDraining = drainState.data?.draining === true;
  // Two-click arm replaces the native confirm() — window.confirm stalls
  // Chrome's message pump under some extensions (M007 precedent) and is
  // inconsistent with the rest of the console. Auto-disarms after 5 s.
  const [drainArmed, setDrainArmed] = useState(false);
  const [drainBusy, setDrainBusy] = useState(false);
  useEffect(() => {
    if (!drainArmed) return;
    const t = setTimeout(() => setDrainArmed(false), 5000);
    return () => clearTimeout(t);
  }, [drainArmed]);
  // Account menu — the topbar chip is now a clickable popover (identity,
  // My Account, Sign out). Close on outside-click or Esc so it behaves like
  // every other app's account menu.
  const [acctMenu, setAcctMenu] = useState(false);
  const [pwModal, setPwModal] = useState(false);
  const acctRef = useRef(null);
  useEffect(() => {
    if (!acctMenu) return;
    const onDoc = (ev) => { if (acctRef.current && !acctRef.current.contains(ev.target)) setAcctMenu(false); };
    const onKey = (ev) => { if (ev.key === 'Escape') setAcctMenu(false); };
    document.addEventListener('mousedown', onDoc);
    document.addEventListener('keydown', onKey);
    return () => { document.removeEventListener('mousedown', onDoc); document.removeEventListener('keydown', onKey); };
  }, [acctMenu]);
  async function doLogout() {
    // CQF-T1 — POSTs /admin/logout with CSRF; handler returns 204 + Set-Cookie
    // clearing aegis_session + aegis_csrf. Always navigate away afterwards —
    // even on network failure, abandoning the session UI is the safe move.
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
      location.href = '/admin/login';
    }
  }
  const version = status.data?.version || '—';
  const env = (status.data?.environment || 'unknown').toLowerCase();
  const peers = cluster.data?.peers || [];
  const peerCount = peers.length;
  // Health rollup: green when we know we have at least one node and
  // /api/about is reachable; warn when /api/about is up but cluster
  // has no peer info yet; err when /api/about itself is failing.
  // Leaderless — every node is equal, so no leader badge.
  const healthTone = status.error ? 'err' : (peerCount === 0 ? 'warn' : 'ok');
  const healthLabel = status.error
    ? 'API unreachable'
    : peerCount === 0
      ? 'Standalone'
      : `Cluster ${peerCount} node${peerCount === 1 ? '' : 's'}`;

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
        {status.data?.zero_trust_break_glass_active && (
          <span
            className="pill down"
            title="AEGIS_ZERO_TRUST_BREAK_GLASS=1 was set at boot — mTLS `required` is downgraded to `optional`. Unset env + restart to return to enforced mode."
            style={{ marginLeft: 4, animation: 'pulse 2s ease-in-out infinite' }}
          >
            ⚠ MTLS BREAK-GLASS
          </span>
        )}
      </div>

      <div style={{ flex: 1 }} />

      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
        {window.FleetNodeSelector && <window.FleetNodeSelector />}
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
          // badge in lock-step with the Active-alerts card. Falls back to
          // `raw_alerts.firing` when the SLO engine isn't wired (tests).
          // 2026-07-07 — the bell now deep-links to Health & SLOs
          // (#/health#active-alerts) where the actionable queue lives.
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
              onClick={() => {
                location.hash = '#/health';
                // Best-effort scroll to the Active-alerts card once the
                // Health page mounts. Hash routing can't carry a second
                // fragment, so nudge the element into view after a tick.
                setTimeout(() => {
                  const el = document.getElementById('active-alerts');
                  if (el) el.scrollIntoView({ behavior: 'smooth', block: 'start' });
                }, 60);
              }}
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
        <div className="account-wrap" ref={acctRef}>
          <button
            type="button"
            className={`user-chip${acctMenu ? ' open' : ''}`}
            aria-haspopup="menu"
            aria-expanded={acctMenu}
            title="Account"
            onClick={() => setAcctMenu(v => !v)}
          >
            <div className="avatar">AD</div>
            <div style={{ display: 'flex', flexDirection: 'column' }}>
              <span style={{ fontSize: 12, color: 'var(--ink)', fontWeight: 600, lineHeight: 1.2 }}>admin</span>
              <span style={{ fontSize: 10, color: 'var(--ink-dim)' }}>SUPER · TOTP</span>
            </div>
          </button>
          {acctMenu && (
            <div className="account-menu" role="menu">
              <div className="account-menu-head">
                <div style={{ fontSize: 12, color: 'var(--ink)', fontWeight: 600 }}>admin</div>
                <div style={{ fontSize: 10, color: 'var(--ink-dim)', marginTop: 2 }}>SUPER · TOTP enrolled</div>
              </div>
              <button type="button" className="account-menu-item" role="menuitem"
                onClick={() => { setAcctMenu(false); setPwModal(true); }}>
                <window.I.Shield /> Change password
              </button>
              <button type="button" className="account-menu-item danger" role="menuitem"
                onClick={() => { setAcctMenu(false); doLogout(); }}>
                <window.I.LogOut /> Sign out
              </button>
            </div>
          )}
        </div>
        {/* CQF-T14 → FIX-topbar-drain (2026-07-02) — TopBar drain toggle.
            The old button had two defects: (1) it treated the raw fetch
            Response as parsed JSON (`r.status === 'draining'` compared the
            HTTP code 200 to a string), so the drain SUCCEEDED server-side
            while the toast always said "Drain failed: unknown response";
            (2) it used the native confirm() the console dropped in M007.
            Now: state-aware (Pause=drain when serving, Play=resume when
            draining), two-click arm with 5 s auto-disarm, and proper
            Response handling. Mirrors the Scaling page's reversible drain
            (PR #113) for quick incident response from any page. */}
        {isDraining && (
          <span
            className="pill warn"
            title="This node's /healthz/ready returns 503 — the LB is not routing new traffic here. Click ▶ to resume."
            style={{ fontSize: 10 }}
          >
            draining
          </span>
        )}
        <button
          className="icon-btn"
          disabled={drainBusy}
          title={isDraining
            ? 'Resume serving — clears the drain so the LB routes traffic back'
            : drainArmed
              ? 'Click again to CONFIRM drain — /healthz/ready flips to 503 and the LB stops sending new traffic (in-flight requests finish; reversible)'
              : 'Drain this node (readiness → 503; click twice to confirm)'}
          style={{ color: isDraining ? 'var(--up)' : drainArmed ? 'var(--down)' : 'var(--warn)' }}
          onClick={async () => {
            if (drainBusy) return;
            if (!isDraining && !drainArmed) {
              setDrainArmed(true);
              window.aegisToast && window.aegisToast('Click the drain button again to confirm — this pulls the node from the LB pool', 'warn');
              return;
            }
            setDrainArmed(false);
            setDrainBusy(true);
            try {
              const resp = isDraining
                ? await window.adminUndrainPost()
                : await window.adminDrainPost();
              if (resp && resp.status < 300) {
                // Wrappers return the raw Response — parse the JSON body.
                const j = await resp.json().catch(() => ({}));
                window.aegisToast(
                  isDraining
                    ? `Resumed serving · node ${j.node || 'unknown'} back in LB rotation`
                    : `Drain initiated · node ${j.node || 'unknown'}${j.already ? ' (was already draining)' : ''} — /healthz/ready now 503`,
                  'ok',
                );
              } else {
                let msg = `HTTP ${resp ? resp.status : '—'}`;
                try {
                  const j = await resp.json();
                  msg = j.error || j.message || msg;
                } catch (_) { /* non-JSON error body */ }
                window.aegisToast(`${isDraining ? 'Resume' : 'Drain'} failed: ${msg}`, 'err');
              }
            } catch (e) {
              window.aegisToast(`${isDraining ? 'Resume' : 'Drain'} error: ${e.message || e}`, 'err');
            } finally {
              setDrainBusy(false);
              if (drainState.reload) drainState.reload();
            }
          }}
        >
          {isDraining ? <window.I.Play /> : <window.I.Pause />}
        </button>
        {/* CQF-T1 — operator logout folded into the account menu (Sign out).
            The POST /admin/logout + redirect logic now lives in `doLogout`,
            shared by that menu item. */}
      </div>
      {pwModal && <AccountPasswordModal onClose={() => setPwModal(false)} />}
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
// Theme toggle — cycles the `data-theme` attribute on <html> through the
// four palettes and persists the choice to localStorage. The pre-paint
// script in index.html reads localStorage on next page load so the choice
// sticks. 2026-06-04: added "Dim" (softer dark) + "Paper" (softer light)
// so operators can pick a comfortable contrast level.
const THEME_ORDER = ['dark', 'dim', 'light', 'paper'];
const THEME_LABELS = { dark: 'Midnight', dim: 'Dim', light: 'Daylight', paper: 'Paper' };
function ThemeToggle() {
  const [theme, setTheme] = useState(() => {
    try { return document.documentElement.dataset.theme || 'dim'; }
    catch (_) { return 'dim'; }
  });
  const cycle = () => {
    const idx = THEME_ORDER.indexOf(theme);
    const next = THEME_ORDER[(idx + 1) % THEME_ORDER.length] || 'dim';
    document.documentElement.dataset.theme = next;
    try { localStorage.setItem('aegis_theme', next); } catch (_) {}
    setTheme(next);
  };
  const isDarkFamily = theme === 'dark' || theme === 'dim';
  const label = THEME_LABELS[theme] || theme;
  return (
    <button
      className="icon-btn"
      onClick={cycle}
      title={`Theme: ${label} — click to cycle (Midnight → Dim → Daylight → Paper)`}
      style={{ marginRight: 4, display: 'inline-flex', alignItems: 'center', gap: 6, width: 'auto', padding: '0 8px' }}
    >
      {isDarkFamily ? (
        // Sun — currently a dark-family theme
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
          <circle cx="12" cy="12" r="4" />
          <path d="M12 2v2M12 20v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41M2 12h2M20 12h2M4.93 19.07l1.41-1.41M17.66 6.34l1.41-1.41" />
        </svg>
      ) : (
        // Moon — currently a light-family theme
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
          <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z" />
        </svg>
      )}
      <span style={{ fontSize: 11 }}>{label}</span>
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
//   - Build SHA + ver  ← /api/about
//   - Tick (uptime in current page session)
// PE-1 (2026-07-04): GitOps pill removed with the /api/gitops/status
// placeholder endpoint (gitops module deleted 2026-05-17).
function StatusBar({ tick }) {
  const cluster = window.useClusterApi();
  const status = window.useStatusApi();
  const peers = cluster.data?.peers || [];
  const healthy = peers.filter(p => p.healthy !== false).length;
  const total = peers.length;
  const version = status.data?.version || '—';
  const buildSha = status.data?.build_sha;
  const buildLabel = buildSha ? `${version}-${String(buildSha).slice(0, 4)}` : version;

  return (
    <div className="statusbar">
      <span>Cluster <span className={`num ${total === 0 ? 'dim' : ''}`}>
        {total === 0 ? 'single-node' : `${healthy}/${total}`}
      </span></span>
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
    // 'incidents' route retired 2026-07-07 → redirected to 'health'.
    case 'investigation':    page = <window.PageInvestigation />; break;
    case 'top-attackers':    page = <window.PageTopAttackers />; break;
    // Attack-Analytics merged into Investigation (2026-05-03).
    // Old hash links keep working — redirect to Investigation.
    case 'attack-analytics': page = <window.PageInvestigation />; break;
    // Threat-intel + Compliance pages retired 2026-05-10. Stale
    // deep links fall through to the default `PageOverview` below.
    // Copilot page retired 2026-06-05 → global chat widget; #/copilot
    // redirects to overview (see ROUTE_REDIRECTS).
    case 'rules':            page = <window.PageRuleManager />; break;
    case 'detectors':        page = <window.PageTierConfig />; break;
    case 'zero-trust':       page = <window.PageZeroTrust />; break;
    case 'access-lists':     page = <window.PageAccessLists />; break;
    case 'upstreams':        page = <window.PageUpstreams />; break;
    case 'traffic-gates':    page = <window.PageTrafficGates />; break;
    case 'performance':      page = <window.PageAnalytics />; break;
    case 'health':           page = <window.PageTracking />; break;
    case 'audit':            page = <window.PageAuditLog />; break;
    case 'scaling':          page = <window.PageScaling />; break;
    case 'users':            page = <window.PageUsers />; break;
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
      {/* Floating Copilot chat widget — self-hides unless the copilot
          is enabled (probed for free on mount). Lives above the toast
          layer so it's reachable from every page. */}
      <window.CopilotWidget />
      <window.ToastContainer />
    </div>
  );
}

ReactDOM.createRoot(document.getElementById('root')).render(<App />);
