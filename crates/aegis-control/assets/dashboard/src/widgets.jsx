/* global React */
const { useState: useStateW, useEffect: useEffectW, useRef: useRefW, useMemo: useMemoW } = React;

// ============= Icons (Lucide-style inline SVG) =============
const I = {
  Shield: (p) => <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" {...p}><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>,
  Activity: (p) => <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" {...p}><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>,
  Siren: (p) => <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" {...p}><path d="M7 18v-6a5 5 0 0 1 10 0v6"/><path d="M5 21h14"/><path d="M21 12h1"/><path d="M2 12h1"/><path d="m4.93 4.93.7.7"/><path d="m18.36 4.93-.7.7"/></svg>,
  BarChart: (p) => <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" {...p}><line x1="12" y1="20" x2="12" y2="10"/><line x1="18" y1="20" x2="18" y2="4"/><line x1="6" y1="20" x2="6" y2="16"/></svg>,
  Book: (p) => <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" {...p}><path d="M4 19.5A2.5 2.5 0 0 1 6.5 17H20"/><path d="M6.5 2H20v20H6.5A2.5 2.5 0 0 1 4 19.5v-15A2.5 2.5 0 0 1 6.5 2z"/></svg>,
  Layers: (p) => <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" {...p}><polygon points="12 2 2 7 12 12 22 7 12 2"/><polyline points="2 17 12 22 22 17"/><polyline points="2 12 12 17 22 12"/></svg>,
  Ban: (p) => <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" {...p}><circle cx="12" cy="12" r="10"/><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/></svg>,
  Check: (p) => <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" {...p}><polyline points="20 6 9 17 4 12"/></svg>,
  Server: (p) => <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" {...p}><rect x="2" y="2" width="20" height="8" rx="2"/><rect x="2" y="14" width="20" height="8" rx="2"/><line x1="6" y1="6" x2="6.01" y2="6"/><line x1="6" y1="18" x2="6.01" y2="18"/></svg>,
  Settings: (p) => <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" {...p}><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>,
  Gauge: (p) => <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" {...p}><path d="m12 14 4-4"/><path d="M3.34 19a10 10 0 1 1 17.32 0"/></svg>,
  Globe: (p) => <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" {...p}><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>,
  Search: (p) => <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" {...p}><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>,
  X: (p) => <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" {...p}><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>,
  Plus: (p) => <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" {...p}><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>,
  Pause: (p) => <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" {...p}><rect x="6" y="4" width="4" height="16"/><rect x="14" y="4" width="4" height="16"/></svg>,
  Play: (p) => <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" {...p}><polygon points="6 4 20 12 6 20 6 4"/></svg>,
  Download: (p) => <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" {...p}><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>,
  Refresh: (p) => <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" {...p}><polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/></svg>,
  Edit: (p) => <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" {...p}><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>,
  Trash: (p) => <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" {...p}><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/></svg>,
  Bell: (p) => <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" {...p}><path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.73 21a2 2 0 0 1-3.46 0"/></svg>,
  Sparkles: (p) => <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" {...p}><path d="M9.937 15.5A2 2 0 0 0 8.5 14.063l-6.135-1.582a.5.5 0 0 1 0-.962L8.5 9.936A2 2 0 0 0 9.937 8.5l1.582-6.135a.5.5 0 0 1 .963 0L14.063 8.5A2 2 0 0 0 15.5 9.937l6.135 1.581a.5.5 0 0 1 0 .964L15.5 14.063a2 2 0 0 0-1.437 1.437l-1.582 6.135a.5.5 0 0 1-.963 0z"/></svg>,
  External: (p) => <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" {...p}><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/></svg>,
  ArrowUp: (p) => <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round" {...p}><line x1="12" y1="19" x2="12" y2="5"/><polyline points="5 12 12 5 19 12"/></svg>,
  ArrowDown: (p) => <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round" {...p}><line x1="12" y1="5" x2="12" y2="19"/><polyline points="19 12 12 19 5 12"/></svg>,
  Cluster: (p) => <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" {...p}><circle cx="6" cy="6" r="2"/><circle cx="18" cy="6" r="2"/><circle cx="6" cy="18" r="2"/><circle cx="18" cy="18" r="2"/><circle cx="12" cy="12" r="2"/><line x1="8" y1="6" x2="16" y2="6"/><line x1="8" y1="18" x2="16" y2="18"/><line x1="6" y1="8" x2="6" y2="16"/><line x1="18" y1="8" x2="18" y2="16"/></svg>,
  Heart: (p) => <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" {...p}><path d="M20.84 4.61a5.5 5.5 0 0 0-7.78 0L12 5.67l-1.06-1.06a5.5 5.5 0 0 0-7.78 7.78l1.06 1.06L12 21.23l7.78-7.78 1.06-1.06a5.5 5.5 0 0 0 0-7.78z"/></svg>,
  Info: (p) => <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" {...p}><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>,
  LogOut: (p) => <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" {...p}><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg>,
};

// ============= Sparkline =============
function Sparkline({ data, w = 80, h = 22, color = 'var(--brand-yellow)', fill = false, strokeWidth = 1.5 }) {
  if (!data || !data.length) return null;
  const max = Math.max(...data);
  const min = Math.min(...data);
  const range = max - min || 1;
  const step = w / Math.max(1, data.length - 1);
  const points = data.map((v, i) => {
    const x = i * step;
    const y = h - ((v - min) / range) * (h - 2) - 1;
    return [x, y];
  });
  const d = points.map((p, i) => (i === 0 ? `M${p[0]},${p[1]}` : `L${p[0]},${p[1]}`)).join(' ');
  const dFill = `${d} L${w},${h} L0,${h} Z`;
  return (
    <svg width={w} height={h} className="spark">
      {fill && <path d={dFill} fill={color} opacity="0.18" />}
      <path d={d} fill="none" stroke={color} strokeWidth={strokeWidth} strokeLinejoin="round" strokeLinecap="round" />
    </svg>
  );
}

// ============= Scope badge =============
// Labels a panel's data scope in a cluster: `fleet` ⇒ merged across all
// nodes, otherwise this node only. Renders nothing on single-node
// deployments (`cluster` false) where scope is moot.
function ScopeBadge({ cluster, fleet, node }) {
  if (!cluster) return null;
  // When scoped to a single node, a fleet-capable panel is showing THAT
  // node's data — badge the node id, not "Fleet".
  if (fleet && node && node !== 'all') {
    return (
      <span className="scope-badge scope-node" title={`Scoped to node ${node}`}>{node}</span>
    );
  }
  return fleet ? (
    <span className="scope-badge scope-fleet" title="Merged across all fleet nodes">Fleet</span>
  ) : (
    <span className="scope-badge scope-node" title="This node only — not merged across the fleet">This node</span>
  );
}

// Hook returning a `(capable) => <ScopeBadge/>` helper bound to the
// current fleet status, so each page wires scope badges in one line:
//   const scopeBadge = window.useScopeBadge();
//   ... scope={scopeBadge(true)}   // fleet-capable panel
// `capable` is whether the panel *can* be fleet-merged; the badge reads
// Fleet only when fleet view is also active.
function useScopeBadge() {
  const scope = window.useFleetScopeApi ? window.useFleetScopeApi() : { data: null };
  const [node] = window.useFleetNodeScope ? window.useFleetNodeScope() : ['all'];
  const cluster = !!scope.data?.configured;
  const active = !!scope.data?.active;
  return (capable) => <ScopeBadge cluster={cluster} fleet={active && !!capable} node={node} />;
}

// ============= Fleet node selector (SCOPE-P1b) =============
// Scopes fleet-capable panels to one node ('All nodes' = merged view).
// Hidden on single-node deployments. Node-local panels (Upstream,
// Incidents) are unaffected — they never carried the ?node= scope.
function FleetNodeSelector() {
  const nodesApi = window.useFleetNodesApi ? window.useFleetNodesApi() : { data: null };
  const [node, setNode] = window.useFleetNodeScope ? window.useFleetNodeScope() : ['all', () => {}];
  const nodes = nodesApi.data?.nodes || [];
  // If the selected node TTL'd out of the roster, fall back to All nodes
  // so the control never shows a stale/blank selection. (widgets.jsx
  // aliases the React hooks as *W — bare `useEffect` is undefined here.)
  useEffectW(() => {
    if (node !== 'all' && nodes.length > 0 && !nodes.includes(node)) setNode('all');
  }, [nodes, node]);
  if (nodes.length < 2) return null; // single node → nothing to pick
  return (
    <label className="fleet-node-select" title="Scope fleet panels to a single node">
      <span aria-hidden="true">🖧</span>
      <select value={node} onChange={e => setNode(e.target.value)} aria-label="Fleet node scope">
        <option value="all">All nodes ({nodes.length})</option>
        {nodes.map(n => <option key={n} value={n}>{n}</option>)}
      </select>
    </label>
  );
}

// ============= Stat tile =============
function StatTile({ title, value, sub, icon, tone, sparkData, sparkColor, scope }) {
  return (
    <div className={`stat ${tone || ''}`}>
      <div className="stat-head">
        <span>{title}</span>
        <span className="stat-head-right">
          {scope}
          <span className="stat-icon">{icon}</span>
        </span>
      </div>
      <div className="stat-value">{value}</div>
      <div className="stat-sub">{sub}</div>
      {sparkData && (
        <div className="stat-spark">
          <Sparkline data={sparkData} color={sparkColor || 'var(--brand-yellow)'} fill w={120} h={36} />
        </div>
      )}
    </div>
  );
}

// ============= Line/Area chart (traffic vs blocked) =============
function TrafficChart({ series, w = 800, h = 220 }) {
  if (!series || series.length < 2) return null;
  const padL = 36, padR = 12, padT = 12, padB = 22;
  const innerW = w - padL - padR;
  const innerH = h - padT - padB;
  const max = Math.max(...series.map(s => s.total), 10);
  const xs = i => padL + (i / (series.length - 1)) * innerW;
  const ys = v => padT + innerH - (v / max) * innerH;

  const totalPath = series.map((s, i) => `${i === 0 ? 'M' : 'L'}${xs(i)},${ys(s.total)}`).join(' ');
  const blockPath = series.map((s, i) => `${i === 0 ? 'M' : 'L'}${xs(i)},${ys(s.blocked)}`).join(' ');
  const totalFill = `${totalPath} L${xs(series.length - 1)},${ys(0)} L${xs(0)},${ys(0)} Z`;

  const yTicks = [0, max * 0.5, max].map(v => Math.round(v));
  return (
    <svg viewBox={`0 0 ${w} ${h}`} width="100%" height={h} preserveAspectRatio="none">
      {yTicks.map((t, i) => (
        <g key={i}>
          <line x1={padL} x2={w - padR} y1={ys(t)} y2={ys(t)} className="gridline" strokeDasharray="2 4" />
          <text x={padL - 6} y={ys(t) + 3} textAnchor="end" className="axis-label">{t}</text>
        </g>
      ))}
      <path d={totalFill} fill="#3B82F6" opacity="0.12" />
      <path d={totalPath} fill="none" stroke="#3B82F6" strokeWidth="1.6" />
      <path d={blockPath} fill="none" stroke="#F6465D" strokeWidth="1.6" />
      {series.length > 0 && (
        <circle cx={xs(series.length - 1)} cy={ys(series[series.length - 1].total)} r="3" fill="#3B82F6" stroke="#0B0E11" strokeWidth="1.5">
          <animate attributeName="r" values="3;5;3" dur="1.6s" repeatCount="indefinite" />
        </circle>
      )}
      {/* legend */}
      <g transform={`translate(${padL},${padT - 2})`}>
        <circle cx="4" cy="6" r="3" fill="#3B82F6" />
        <text x="12" y="9" className="axis-label" fill="#B7BDC6">Total req/s</text>
        <circle cx="80" cy="6" r="3" fill="#F6465D" />
        <text x="88" y="9" className="axis-label" fill="#B7BDC6">Blocked</text>
      </g>
    </svg>
  );
}

// ============= TimeseriesChart (PR-C P2, 2026-07-02) =============
// The Performance page's replacement for the fixed-460px Sparkline:
// responsive viewBox, ZERO y-baseline (min-max normalisation amplified
// noise and made windows incomparable), y-gridlines, x time labels, and
// a hover crosshair + tooltip. Two modes:
//   'area' — total request area + blocked overlay line (per bucket)
//   'bars' — per-bucket block ratio %; buckets with NO traffic render
//            as gaps (not 0%), and buckets below `minSample` requests
//            are dimmed (a 1/1 bucket is not a 100% attack wave).
//   'line' — SLO-P6b: caller-supplied `{ts, value, count}` series (the
//            Health page's availability-% timeline). `yDomain: [min,
//            max]` clips the y-axis so a 99.9%-vs-100% dip is visible
//            (a zero baseline renders availability as a flat line);
//            `gapMs` breaks the stroke across missing buckets — the
//            backend omits no-traffic minutes, and drawing through the
//            gap would invent uptime.
// Sparkline itself is untouched — stat tiles still use it.
function TimeseriesChart({ points, mode = 'area', h = 200, minSample = 5, yDomain = null, gapMs = null }) {
  const [hover, setHover] = useStateW(null); // hovered bucket index | null
  const svgRef = useRefW(null);
  if (!points || points.length < 2) return null;

  const w = 800;
  const padL = 40, padR = 12, padT = 16, padB = 24;
  const innerW = w - padL - padR;
  const innerH = h - padT - padB;
  const n = points.length;
  const isBars = mode === 'bars';
  const isLine = mode === 'line';

  // Bars: per-bucket ratio, null = no traffic (gap). Line: the caller's
  // value series. Area: totals.
  const values = isBars
    ? points.map(p => (p.total > 0 ? (p.blocked * 100) / p.total : null))
    : isLine
      ? points.map(p => p.value)
      : points.map(p => p.total);
  const yMin = isLine && yDomain ? yDomain[0] : 0;
  const max = isBars
    ? 100
    : isLine && yDomain
      ? yDomain[1]
      : Math.max(...values.map(v => v ?? 0), 10);
  const xs = i => padL + (n > 1 ? (i / (n - 1)) * innerW : 0);
  // Clamp into the (possibly clipped) domain so an outlier below the
  // line-mode floor pins to the plot edge instead of escaping the axes.
  // No-op for area/bars, whose values are within [0, max] by build.
  const ys = v => padT + innerH
    - ((Math.min(Math.max(v, yMin), max) - yMin) / ((max - yMin) || 1)) * innerH;

  const fmtTime = (ts) => {
    const d = new Date(ts);
    return Number.isFinite(d.getTime())
      ? d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', hour12: false })
      : '';
  };

  const onMove = (e) => {
    const el = svgRef.current;
    if (!el) return;
    const rect = el.getBoundingClientRect();
    // Fraction across the PLOT area (viewBox scales with CSS width).
    const plotLeft = (padL / w) * rect.width;
    const plotWidth = (innerW / w) * rect.width;
    const frac = (e.clientX - rect.left - plotLeft) / plotWidth;
    const idx = Math.round(frac * (n - 1));
    setHover(idx >= 0 && idx < n ? idx : null);
  };

  const yTicks = isBars
    ? [0, 50, 100]
    : isLine
      ? [yMin, (yMin + max) / 2, max]
      : [0, Math.round(max * 0.5), Math.round(max)];
  const xLabelIdx = [0, Math.floor((n - 1) / 2), n - 1];

  // Line mode — one path, broken (fresh `M`) wherever two consecutive
  // buckets are further apart than `gapMs`.
  const linePath = isLine
    ? points.map((p, i) => {
        const brk = i === 0 || (gapMs != null && (p.ts - points[i - 1].ts) > gapMs);
        return `${brk ? 'M' : 'L'}${xs(i)},${ys(values[i] ?? yMin)}`;
      }).join(' ')
    : null;

  // Tooltip content for the hovered bucket.
  const hoverBox = (() => {
    if (hover == null || !points[hover]) return null;
    const p = points[hover];
    const v = values[hover];
    const label = isBars
      ? (v == null ? `${fmtTime(p.ts)} · no traffic` : `${fmtTime(p.ts)} · ${v.toFixed(1)}% (${p.blocked}/${p.total})`)
      : isLine
        ? `${fmtTime(p.ts)} · ${v == null ? 'no data' : `${v.toFixed(3)}%`}${p.count != null ? ` (n=${p.count})` : ''}`
        : `${fmtTime(p.ts)} · ${p.total.toLocaleString()} req · ${p.blocked.toLocaleString()} blocked`;
    const boxW = Math.max(120, label.length * 6.2);
    // Clamp so the box stays inside the plot.
    const bx = Math.min(Math.max(xs(hover) - boxW / 2, padL), w - padR - boxW);
    return { label, bx, x: xs(hover) };
  })();

  return (
    <svg
      ref={svgRef}
      viewBox={`0 0 ${w} ${h}`}
      width="100%"
      height={h}
      preserveAspectRatio="none"
      onMouseMove={onMove}
      onMouseLeave={() => setHover(null)}
      style={{ display: 'block' }}
    >
      {yTicks.map((t, i) => (
        <g key={i}>
          <line x1={padL} x2={w - padR} y1={ys(t)} y2={ys(t)} className="gridline" strokeDasharray="2 4" />
          <text x={padL - 6} y={ys(t) + 3} textAnchor="end" className="axis-label">{isBars ? `${t}%` : isLine ? `${t.toFixed(2)}%` : t.toLocaleString()}</text>
        </g>
      ))}
      {xLabelIdx.map((i, k) => (
        <text
          key={`x${k}`}
          x={xs(i)}
          y={h - 8}
          textAnchor={k === 0 ? 'start' : k === xLabelIdx.length - 1 ? 'end' : 'middle'}
          className="axis-label"
        >
          {fmtTime(points[i]?.ts)}
        </text>
      ))}
      {isBars ? (
        // Ratio bars — a bucket ratio is a discrete quantity; bars don't
        // imply continuity between unrelated buckets the way a line does.
        points.map((p, i) => {
          const v = values[i];
          if (v == null) return null; // no traffic = gap, not 0%
          const bw = Math.max(innerW / n - 1, 1);
          const bx = padL + (i / n) * innerW;
          const by = ys(v);
          const lowSample = p.total < minSample;
          return (
            <rect
              key={i}
              x={bx}
              y={by}
              width={bw}
              height={Math.max(padT + innerH - by, 1)}
              fill="#F6465D"
              opacity={lowSample ? 0.3 : 0.85}
            >
              {lowSample && <title>{`low sample (n=${p.total}) — ratio unreliable`}</title>}
            </rect>
          );
        })
      ) : isLine ? (
        <path d={linePath} fill="none" stroke="var(--up)" strokeWidth="1.6" strokeLinejoin="round" strokeLinecap="round" />
      ) : (
        <>
          <path
            d={`${points.map((p, i) => `${i === 0 ? 'M' : 'L'}${xs(i)},${ys(p.total)}`).join(' ')} L${xs(n - 1)},${ys(0)} L${xs(0)},${ys(0)} Z`}
            fill="#3B82F6"
            opacity="0.12"
          />
          <path
            d={points.map((p, i) => `${i === 0 ? 'M' : 'L'}${xs(i)},${ys(p.total)}`).join(' ')}
            fill="none" stroke="#3B82F6" strokeWidth="1.6"
          />
          <path
            d={points.map((p, i) => `${i === 0 ? 'M' : 'L'}${xs(i)},${ys(p.blocked)}`).join(' ')}
            fill="none" stroke="#F6465D" strokeWidth="1.6"
          />
          <g transform={`translate(${padL},${padT - 4})`}>
            <circle cx="4" cy="0" r="3" fill="#3B82F6" />
            <text x="12" y="3" className="axis-label" fill="#B7BDC6">Total</text>
            <circle cx="56" cy="0" r="3" fill="#F6465D" />
            <text x="64" y="3" className="axis-label" fill="#B7BDC6">Blocked</text>
          </g>
        </>
      )}
      {hoverBox && (
        <g pointerEvents="none">
          <line x1={hoverBox.x} x2={hoverBox.x} y1={padT} y2={padT + innerH} stroke="var(--ink-faint, #5E6673)" strokeWidth="1" strokeDasharray="3 3" />
          <rect x={hoverBox.bx} y={padT} width={Math.max(120, hoverBox.label.length * 6.2)} height={16} rx="3" fill="#0B0E11" opacity="0.92" stroke="#2B3139" />
          <text x={hoverBox.bx + 6} y={padT + 11.5} className="axis-label" fill="#EAECEF">{hoverBox.label}</text>
        </g>
      )}
    </svg>
  );
}

// ============= Donut =============
function Donut({ slices, size = 180 }) {
  const total = slices.reduce((s, x) => s + x.value, 0) || 1;
  const r = size / 2 - 8;
  const inner = r * 0.6;
  const cx = size / 2, cy = size / 2;
  let acc = 0;
  return (
    <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`}>
      {slices.map((s, i) => {
        const a0 = (acc / total) * Math.PI * 2 - Math.PI / 2;
        acc += s.value;
        const a1 = (acc / total) * Math.PI * 2 - Math.PI / 2;
        const large = a1 - a0 > Math.PI ? 1 : 0;
        const x0 = cx + r * Math.cos(a0), y0 = cy + r * Math.sin(a0);
        const x1 = cx + r * Math.cos(a1), y1 = cy + r * Math.sin(a1);
        const xi0 = cx + inner * Math.cos(a0), yi0 = cy + inner * Math.sin(a0);
        const xi1 = cx + inner * Math.cos(a1), yi1 = cy + inner * Math.sin(a1);
        const d = `M${x0},${y0} A${r},${r} 0 ${large} 1 ${x1},${y1} L${xi1},${yi1} A${inner},${inner} 0 ${large} 0 ${xi0},${yi0} Z`;
        return <path key={i} d={d} fill={s.color} />;
      })}
      <text x={cx} y={cy - 4} textAnchor="middle" fill="#EAECEF" fontSize="22" fontWeight="700" fontFamily="JetBrains Mono">{total.toLocaleString()}</text>
      <text x={cx} y={cy + 12} textAnchor="middle" fill="#707A8A" fontSize="9" letterSpacing="1.4" style={{ textTransform: 'uppercase' }}>DETECTIONS · 15m</text>
    </svg>
  );
}

// ============= World Map (rough simplified continents) =============
// Equirectangular projection: lon -180..180 -> 0..w; lat 90..-90 -> 0..h
function project(lat, lon, w, h) {
  return [(lon + 180) * (w / 360), (90 - lat) * (h / 180)];
}

// FIX 2026-05-04 — when the operator's GeoIP only resolves to
// country (no City DB), the backend returns `country` but no
// lat/lon, so every blip fell on (0,0) — the Atlantic off the
// coast of Africa. The previous code hard-coded lat/lon to 0.
//
// Replace with a country-centroid lookup. Coordinates are rough
// population-weighted centroids — good enough for a "blip
// somewhere on this country" tile, which is all the WorldMap
// shows. Operators who need city-level pins ship a GeoLite2-
// City.mmdb and let the backend fill in the real coords.
//
// Top ~50 countries by likely-attacker traffic (covers > 95 %
// of what `/api/attacks/top` will surface in practice). Anything
// not in the table falls back to (0,0) so it doesn't crash —
// but the operator will see all unmapped traffic stack on one
// pixel, which is the cue to either extend the table or ship
// the city DB.
const COUNTRY_CENTROIDS = {
  // North America
  US: [39.5, -98.4], CA: [56.1, -106.3], MX: [23.6, -102.5],
  // South America
  BR: [-14.2, -51.9], AR: [-38.4, -63.6], CO: [4.6, -74.3], CL: [-35.7, -71.5],
  PE: [-9.2, -75.0], VE: [6.4, -66.6],
  // Europe
  GB: [55.4, -3.4], DE: [51.2, 10.5], FR: [46.6, 2.2], NL: [52.1, 5.3],
  ES: [40.5, -3.7], IT: [41.9, 12.6], SE: [60.1, 18.6], FI: [61.9, 25.7],
  PL: [51.9, 19.1], RO: [45.9, 24.9], CH: [46.8, 8.2], BE: [50.5, 4.5],
  CZ: [49.8, 15.5], DK: [56.3, 9.5], NO: [60.5, 8.5], AT: [47.5, 14.6],
  IE: [53.4, -8.2], PT: [39.4, -8.2], GR: [39.1, 21.8], TR: [38.9, 35.2],
  HU: [47.2, 19.5], BG: [42.7, 25.5], UA: [48.4, 31.2], RU: [61.5, 105.3],
  // Middle East
  AE: [23.4, 53.8], SA: [23.9, 45.1], IL: [31.0, 34.9], IR: [32.4, 53.7],
  EG: [26.8, 30.8], QA: [25.4, 51.2],
  // Asia
  CN: [35.9, 104.2], JP: [36.2, 138.3], KR: [35.9, 127.8], IN: [20.6, 78.9],
  ID: [-0.8, 113.9], TH: [15.9, 100.9], VN: [14.1, 108.3], MY: [4.2, 101.9],
  SG: [1.4, 103.8], HK: [22.4, 114.1], TW: [23.7, 121.0], PH: [12.9, 121.8],
  PK: [30.4, 69.3], BD: [23.7, 90.4],
  // Oceania
  AU: [-25.3, 133.8], NZ: [-40.9, 174.9],
  // Africa
  ZA: [-30.6, 22.9], NG: [9.1, 8.7], KE: [-0.0, 37.9], MA: [31.8, -7.1],
  DZ: [28.0, 1.7], TN: [33.9, 9.6],
};

/// Resolve a country code to a `[lat, lon]` centroid. Returns
/// `null` when the code isn't in the table — the WorldMap caller
/// drops blips with null coords rather than stacking them on
/// (0, 0).
function centroidFor(cc) {
  if (!cc) return null;
  return COUNTRY_CENTROIDS[cc.toUpperCase()] || null;
}

function WorldMap({ blips = [], h = 320 }) {
  const w = 720;
  const [tick, setTick] = useStateW(0);
  useEffectW(() => {
    const id = setInterval(() => setTick(t => t + 1), 1500);
    return () => clearInterval(id);
  }, []);

  // Simple continent paths approximated as polygons
  const continents = [
    // North America
    "M85,68 L155,55 L195,68 L210,95 L195,120 L165,140 L130,158 L100,150 L85,125 Z",
    // Central / South America
    "M170,165 L195,160 L210,180 L210,225 L190,260 L170,275 L160,255 L155,210 L160,180 Z",
    // Europe
    "M345,68 L395,62 L420,80 L410,105 L375,115 L345,105 Z",
    // Africa
    "M345,125 L405,115 L435,150 L425,210 L385,245 L355,235 L340,195 Z",
    // Asia (broad)
    "M420,55 L555,50 L605,75 L620,110 L585,140 L515,145 L455,135 L420,110 Z",
    // South-east Asia / Indonesia
    "M540,150 L620,150 L640,170 L605,185 L555,180 Z",
    // Australia
    "M580,210 L645,205 L660,230 L630,255 L585,250 Z",
  ];

  return (
    <svg viewBox={`0 0 ${w} ${h}`} width="100%" height={h} style={{ display: 'block' }}>
      <defs>
        <radialGradient id="bg-glow" cx="50%" cy="50%" r="60%">
          <stop offset="0%" stopColor="#161A20" />
          <stop offset="100%" stopColor="#0B0E11" />
        </radialGradient>
        <radialGradient id="blip-gradient">
          <stop offset="0%" stopColor="#F6465D" stopOpacity="1" />
          <stop offset="100%" stopColor="#F6465D" stopOpacity="0" />
        </radialGradient>
      </defs>

      <rect x="0" y="0" width={w} height={h} fill="url(#bg-glow)" />
      {/* lat/lon graticule */}
      <g stroke="#1B2026" strokeWidth="0.5" fill="none">
        {[-60, -30, 0, 30, 60].map(l => {
          const [, y] = project(l, 0, w, h);
          return <line key={`la${l}`} x1="0" x2={w} y1={y} y2={y} />;
        })}
        {[-150, -120, -90, -60, -30, 0, 30, 60, 90, 120, 150].map(l => {
          const [x] = project(0, l, w, h);
          return <line key={`lo${l}`} x1={x} x2={x} y1="0" y2={h} />;
        })}
      </g>

      {/* continents */}
      <g fill="#1E2329" stroke="#2B3139" strokeWidth="0.6">
        {continents.map((d, i) => <path key={i} d={d} />)}
      </g>

      {/* origin (datacenter) */}
      <g>
        {(() => {
          const [ox, oy] = project(window.ORIGIN.lat, window.ORIGIN.lon, w, h);
          return (
            <g transform={`translate(${ox},${oy})`}>
              <circle r="14" fill="none" stroke="#FCD535" strokeWidth="0.8" opacity="0.4" />
              <circle r="6" fill="#FCD535" opacity="0.95" />
              <text y="-12" textAnchor="middle" fill="#FCD535" fontSize="9" fontWeight="700">SG-1 EDGE</text>
            </g>
          );
        })()}
      </g>

      {/* arcs from attacker to origin */}
      <g>
        {blips.map((b, i) => {
          const [sx, sy] = project(b.lat, b.lon, w, h);
          const [tx, ty] = project(window.ORIGIN.lat, window.ORIGIN.lon, w, h);
          const mx = (sx + tx) / 2;
          const my = (sy + ty) / 2 - 60;
          const animKey = (tick + i) % 4 === 0;
          return (
            <g key={i}>
              <path
                d={`M${sx},${sy} Q${mx},${my} ${tx},${ty}`}
                className="attack-arc"
                strokeDasharray="3 4"
                strokeDashoffset={(tick * 6) % 100}
              />
              <circle cx={sx} cy={sy} r="14" fill="url(#blip-gradient)" opacity={animKey ? 0.7 : 0.3} />
              <circle cx={sx} cy={sy} r="3" fill="#F6465D" />
              {b.show && <text x={sx + 6} y={sy - 4} fill="#FF8896" fontSize="9" fontFamily="JetBrains Mono">{b.label}</text>}
            </g>
          );
        })}
      </g>
    </svg>
  );
}

// ============= Risk Heatmap (route × time) =============
function RiskHeatmap({ rows, cols = 30, h = 220 }) {
  const w = 760;
  const padL = 140, padT = 16, padB = 22;
  const cellW = (w - padL - 8) / cols;
  const cellH = (h - padT - padB) / rows.length;

  const data = useMemoW(() => rows.map(r => {
    const arr = [];
    let seed = r.path.length;
    for (let c = 0; c < cols; c++) {
      seed = (seed * 9301 + 49297) % 233280;
      let v = (seed / 233280) * (r.intensity || 1);
      if (Math.random() < 0.04) v += 0.6;
      arr.push(Math.min(1, v));
    }
    return arr;
  }), [rows, cols]);

  const colorFor = v => {
    if (v < 0.18) return '#1E2329';
    if (v < 0.35) return '#3B2A1A';
    if (v < 0.55) return '#6B4710';
    if (v < 0.75) return '#A87715';
    if (v < 0.9)  return '#E0A415';
    return '#FCD535';
  };

  return (
    <svg viewBox={`0 0 ${w} ${h}`} width="100%" height={h} preserveAspectRatio="none">
      {rows.map((r, ri) => (
        <g key={ri}>
          <text x={padL - 8} y={padT + ri * cellH + cellH * 0.7} textAnchor="end" fontSize="10" fill="#B7BDC6" fontFamily="JetBrains Mono">{r.path}</text>
          {data[ri].map((v, ci) => (
            <rect key={ci} x={padL + ci * cellW} y={padT + ri * cellH} width={cellW - 1} height={cellH - 1} fill={colorFor(v)} className="heat-cell" />
          ))}
        </g>
      ))}
      {/* x axis (time) */}
      {[0, 0.25, 0.5, 0.75, 1].map((p, i) => {
        const ago = Math.round(60 * (1 - p));
        const x = padL + p * (cols * cellW);
        return <text key={i} x={x} y={h - 6} textAnchor="middle" fontSize="9" fill="#5E6673" fontFamily="JetBrains Mono">-{ago}m</text>;
      })}
    </svg>
  );
}

// ============= Risk meter (small bar in cells) =============
function RiskMeter({ value }) {
  const v = Math.max(0, Math.min(100, value));
  const color = v >= 75 ? 'var(--down)' : v >= 50 ? 'var(--warn)' : v >= 25 ? 'var(--info)' : 'var(--up)';
  return (
    <span className="risk-meter">
      <span className="risk-bar"><span style={{ width: `${v}%`, background: color }} /></span>
      <span className="num" style={{ fontSize: 11, color: 'var(--ink-mute)' }}>{v}</span>
    </span>
  );
}

// ============= Action / Tier pills =============
function ActionPill({ value }) { return <span className={`pill ${value}`}>{value}</span>; }
// `inferred` — the event carried no route tier, so this label was derived
// from the IP's cumulative risk score (see `tierForRisk`). Render it muted +
// dashed with a `~` so operators don't read it as an authoritative route tier.
function TierPill({ value, inferred }) {
  if (inferred) {
    return (
      <span
        className={`pill tier-${value} tier-inferred`}
        title="Tier inferred from this IP's cumulative risk score — the request carried no route tier. Not an authoritative route classification."
      >~{value}</span>
    );
  }
  return <span className={`pill tier-${value}`}>{value}</span>;
}

// ============= SLO-P6b — unified SLI labels =============
// The SLI name reaches the UI in two spellings: serde snake_case
// ("data_plane_availability" — /api/slo rows, /api/slo/config, the
// incident `sli` field) and the Rust enum's Debug PascalCase
// ("DataPlaneAvailability" — legacy alert ids parsed as
// `<sli>-<window>`). Normalise both to one operator-facing label so
// the SLO card, Active alerts and the Incidents table all read the
// same. Unknown SLIs pass through verbatim — never hide a new name.
const SLI_LABELS = {
  data_plane_availability: 'Availability',
};
function sliLabel(name) {
  if (!name) return '—';
  const key = String(name)
    .replace(/([a-z0-9])([A-Z])/g, '$1_$2')
    .toLowerCase();
  return SLI_LABELS[key] || String(name);
}

// ============= Drawer =============
function Drawer({ open, onClose, title, children, footer }) {
  if (!open) return null;
  return (
    <>
      <div className="drawer-backdrop" onClick={onClose} />
      <aside className="drawer">
        <div className="drawer-head">
          <div>
            <div style={{ fontSize: 12, color: 'var(--ink-dim)' }}>Request detail</div>
            <div style={{ fontSize: 14, fontWeight: 600 }}>{title}</div>
          </div>
          <button className="icon-btn" onClick={onClose}><I.X /></button>
        </div>
        <div className="drawer-body">{children}</div>
        {footer && <div className="drawer-foot">{footer}</div>}
      </aside>
    </>
  );
}

// ============= Stacked bar (bot mix) =============
function StackedBar({ segments, h = 24 }) {
  const total = segments.reduce((s, x) => s + x.value, 0) || 1;
  return (
    <div style={{ display: 'flex', height: h, borderRadius: 4, overflow: 'hidden', background: 'var(--surface-3)' }}>
      {segments.map((s, i) => (
        <div key={i} style={{ width: `${(s.value / total) * 100}%`, background: s.color }} title={`${s.name}: ${s.value}`} />
      ))}
    </div>
  );
}

// ============= Horizontal bar list =============
function BarList({ items, fmt = v => v.toLocaleString() }) {
  const max = Math.max(...items.map(i => i.value), 1);
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
      {items.map((it, i) => (
        <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 12 }}>
          <span style={{ width: 110, color: 'var(--ink-mute)', fontSize: 11 }}>{it.label}</span>
          <div style={{ flex: 1, height: 14, background: 'var(--surface-2)', borderRadius: 3, overflow: 'hidden' }}>
            <div style={{ width: `${(it.value / max) * 100}%`, height: '100%', background: it.color || 'var(--brand-yellow)' }} />
          </div>
          <span className="num" style={{ width: 70, textAlign: 'right', color: 'var(--ink)' }}>{fmt(it.value)}</span>
        </div>
      ))}
    </div>
  );
}

// ============= Section Header =============
function SectionHeader({ title, sub, actions }) {
  return (
    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 10 }}>
      <div>
        <div style={{ fontSize: 13, fontWeight: 600 }}>{title}</div>
        {sub && <div style={{ fontSize: 11, color: 'var(--ink-dim)' }}>{sub}</div>}
      </div>
      {actions}
    </div>
  );
}

// ============= DD-T7 — Toast container =============
//
// Single global queue, emitted via custom event so any page can
// fire one without prop-drilling. Pages call:
//
//   window.aegisToast('Applied in 1.2s', 'ok');
//
// Kinds: 'ok' (green), 'warn' (yellow), 'err' (red), 'info' (default).
function ToastContainer() {
  const [toasts, setToasts] = useStateW([]);
  useEffectW(() => {
    const onAdd = (e) => {
      const id = Math.random().toString(36).slice(2);
      const t = { id, ts: Date.now(), ...e.detail };
      setToasts(prev => [...prev.slice(-4), t]);
      // An explicit `ttl` (e.g. an undoable action that wants a longer
      // grace window) wins over the per-kind defaults below.
      const ttl = (typeof t.ttl === 'number' && t.ttl > 0)
        ? t.ttl
        : (t.kind === 'err' ? 8000 : t.kind === 'ok' ? 2500 : 5000);
      setTimeout(() => setToasts(prev => prev.filter(x => x.id !== id)), ttl);
    };
    window.addEventListener('aegis:toast', onAdd);
    return () => window.removeEventListener('aegis:toast', onAdd);
  }, []);
  return (
    <div style={{
      // bottom: 92 clears the Copilot FAB (52px @ bottom:24) so toasts
      // stack above it rather than landing under the launcher.
      position: 'fixed', bottom: 92, right: 16, zIndex: 9999,
      display: 'flex', flexDirection: 'column', gap: 6,
      pointerEvents: 'none',
    }}>
      {toasts.map(t => (
        <div key={t.id} style={{
          minWidth: 240, maxWidth: 360, padding: '8px 12px',
          background: 'var(--surface-2)',
          border: '1px solid ' + (
            t.kind === 'ok' ? 'var(--up)' :
            t.kind === 'warn' ? 'var(--warn)' :
            t.kind === 'err' ? 'var(--down)' :
            'var(--hairline-strong)'
          ),
          borderLeft: '3px solid ' + (
            t.kind === 'ok' ? 'var(--up)' :
            t.kind === 'warn' ? 'var(--warn)' :
            t.kind === 'err' ? 'var(--down)' :
            'var(--brand-yellow)'
          ),
          borderRadius: 'var(--radius)',
          color: 'var(--ink)',
          fontSize: 12,
          boxShadow: '0 4px 16px rgba(0,0,0,0.5)',
          display: 'flex', alignItems: 'center', gap: 8,
          pointerEvents: 'auto',
        }}>
          <div style={{ flex: 1 }}>{t.message}</div>
          {t.detail && <span className="dim mono" style={{ fontSize: 10 }}>{t.detail}</span>}
          {t.action && (
            <button
              type="button"
              className="btn"
              style={{ fontSize: 11, padding: '2px 10px', flexShrink: 0 }}
              onClick={() => {
                // Dismiss first so a slow handler can't double-fire,
                // then run the caller's action (e.g. revert a toggle).
                setToasts(prev => prev.filter(x => x.id !== t.id));
                try { t.action.onClick && t.action.onClick(); } catch (_) {}
              }}
            >
              {t.action.label || 'Undo'}
            </button>
          )}
        </div>
      ))}
    </div>
  );
}

// Pages call `window.aegisToast(message, kind, detail, opts)`.
// `opts` is optional and may carry:
//   - action: { label, onClick }  → renders an inline button (e.g. "Undo")
//   - ttl: number (ms)            → overrides the per-kind auto-dismiss
function aegisToast(message, kind = 'info', detail = null, opts = null) {
  window.dispatchEvent(new CustomEvent('aegis:toast', {
    detail: { message, kind, detail, ...(opts || {}) },
  }));
}

// P9 (2026-05-11) — page-title-anchored Refresh button. Operators
// hit Refresh far more often than the destructive top-right
// actions ("+ New rule", "+ Add route", etc.); putting them in the
// same cluster meant a "Refresh" muscle-memory move was one
// careful click away from a creation flow. This icon-only
// circular button sits next to the page title so it's the natural
// first click on a page load, leaving top-right for primary
// actions.
function PageTitleRefresh({ onClick, label }) {
  return React.createElement(
    'button',
    {
      type: 'button',
      onClick,
      className: 'refresh-icon',
      title: label || 'Refresh this page',
      'aria-label': 'Refresh',
    },
    React.createElement(window.I.Refresh, null),
  );
}

Object.assign(window, {
  I, Sparkline, StatTile, ScopeBadge, useScopeBadge, FleetNodeSelector, TrafficChart, TimeseriesChart, Donut, WorldMap, RiskHeatmap,
  RiskMeter, ActionPill, TierPill, sliLabel, Drawer, StackedBar, BarList, SectionHeader,
  ToastContainer, aegisToast, PageTitleRefresh,
  // FIX 2026-05-04 — exposed so PageOverview can resolve country
  // codes to centroid coords before passing blips to WorldMap.
  centroidFor,
});
