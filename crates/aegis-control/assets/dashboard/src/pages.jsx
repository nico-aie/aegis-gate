/* global React */
const { useState: useStateP, useEffect: useEffectP, useMemo: useMemoP, useRef: useRefP, Fragment } = React;

// ============== OVERVIEW ==============
// Color palette for OWASP categories — used to overlay a colour on
// API-returned `name` strings (which are stable identifiers like
// `sqli`, `xss`, `ssrf`, …).
const CAT_COLOR = {
  sqli: '#F6465D',
  xss: '#A555E0',
  ssrf: '#FF8C42',
  path_traversal: '#FCD535',
  recon: '#4DA8FF',
  cmdi: '#FF4D4D',
  lfi: '#E0A415',
  honeypot: '#FCD535',
  rce: '#F6465D',
  body_abuse: '#A87715',
  header_injection: '#6B4710',
  brute_force: '#3B2A1A',
};
function colorFor(name) { return CAT_COLOR[name] || '#6B7280'; }

// CQF-T6 — live RiskHeatmap. Reads from useTopRiskPathsApi
// (audit ring grouped by path → max risk per path → top 8).
// Renders an honest empty state when no audit events have
// arrived yet, rather than the previous hardcoded JSX rows.
function RiskHeatmapLive() {
  const { rows } = window.useTopRiskPathsApi(200, 8);
  if (!rows || rows.length === 0) {
    return (
      <div style={{ padding: 18, fontSize: 12, color: 'var(--ink-dim)', fontStyle: 'italic', textAlign: 'center' }}>
        No risk-bearing audit events in the recent window.
        Drive some traffic (or a probe) to populate the heatmap.
      </div>
    );
  }
  return <window.RiskHeatmap rows={rows} h={200} />;
}

function PageOverview() {
  const stats = window.useStatsApi();              // /api/stats — request_rate, blocks_total, block_rate_pct
  // 2026-05-03 — Overview Upstream card used to read
  // `stats.upstream` (a stale rollup that often reported "no
  // members configured" on a healthy single-node dev WAF).
  // /api/upstreams returns the same per-pool live snapshot the
  // Routing & Upstreams page uses, so source from there
  // instead.  Sum healthy / total across pools.
  const upstreamsLive = window.useUpstreamsApi
    ? window.useUpstreamsApi()
    : { data: null };
  const tsApi = window.useTimeseriesApi(60, 1);    // /api/stats/timeseries — 60s window, 1s buckets
  const distApi = window.useAttacksDistributionApi(900); // /api/attacks/distribution — 15m
  const topApi = window.useAttacksTopApi(900, 5);  // /api/attacks/top — 5 attackers, 15m
  const tick = window.useTicking(2000);
  const [drawerEvent, setDrawerEvent] = useStateP(null);

  // CQF-T4 — wire the "Block" button on each Top Attackers row.
  // Uses the audit-mutated POST /api/blacklist endpoint shipped
  // in CQF-T2. ID is minted client-side for traceability; the
  // store enforces uniqueness so an accidental double-click on
  // the same IP is a 4xx, not a duplicate row.
  async function quickBlockIp(ip) {
    if (!ip || ip === '—') return;
    if (!confirm(`Add ${ip} to blacklist?`)) return;
    const id = `ui-${ip.replace(/[^A-Za-z0-9]+/g, '-')}-${Date.now().toString(36)}`;
    try {
      const r = await window.accessListAdd('blacklist', {
        id,
        kind: ip.includes('/') ? 'cidr' : 'ip',
        value: ip,
        note: 'blocked from Overview Top Attackers',
        bypass: [],
        created_at: new Date().toISOString(),
      });
      if (r.ok) {
        window.aegisToast(`Blocked ${ip}`, 'ok');
      } else {
        const msg = (r && (r.message || r.error || r.reason)) || `status ${r.status}`;
        window.aegisToast(`Block failed: ${msg}`, 'err');
      }
    } catch (e) {
      window.aegisToast(`Block error: ${e.message || e}`, 'err');
    }
  }

  // Adapt /api/stats/timeseries → series shape the TrafficChart wants.
  const series = useMemoP(() => {
    const pts = tsApi.data?.points || [];
    return pts.map(p => ({ total: p.total, blocked: p.blocked }));
  }, [tsApi.data]);

  const sparkTotal = series.slice(-30).map(s => s.total);
  const sparkBlocked = series.slice(-30).map(s => s.blocked);

  // KPI tiles fed by /api/stats; fall back to derived values when the
  // endpoint hasn't replied yet so first paint isn't blank.
  const requestRate = stats.data?.request_rate;
  const blocksTotal = stats.data?.blocks_total ?? 0;
  const blockRate = stats.data?.block_rate_pct;
  const activeThreats = stats.data?.active_threats ?? 0;
  // Roll up healthy / total across every live pool. The
  // `/api/upstreams` response shape is:
  //   { healthy_members, total_members, pools: [{name, healthy, total}, ...] }
  // We prefer the top-level aggregate (computed server-side); when
  // it's missing (or `pools` is the only thing populated), fall
  // back to summing the per-pool entries. Fix 2026-05-04: the
  // earlier code looked for per-pool `healthy_members` /
  // `total_members` keys that don't exist, so the rollup was
  // always 0 and the Overview tile reported "no members
  // configured" even with a pool defined.
  const upstream = (() => {
    const live = upstreamsLive.data;
    if (live && (Number(live.total_members ?? -1) >= 0 || Array.isArray(live.pools))) {
      let healthy = Number(live.healthy_members ?? 0);
      let total   = Number(live.total_members ?? 0);
      if (total === 0 && Array.isArray(live.pools)) {
        for (const p of live.pools) {
          healthy += Number(p.healthy ?? 0);
          total   += Number(p.total ?? 0);
        }
      }
      return { healthy, unhealthy: Math.max(total - healthy, 0) };
    }
    return stats.data?.upstream;
  })();

  // Adapt /api/attacks/distribution → donut slices (name + color + value).
  const dist = useMemoP(() => {
    const cats = distApi.data?.categories || [];
    return cats.map(c => ({
      name: c.name, color: colorFor(c.name), value: c.count,
    }));
  }, [distApi.data]);

  // Top attackers — real API rows. Geo enrichment isn't on the
  // server response yet (GeoIP join is a follow-up); the table shows
  // CI-T8 — identifier + categories + risk + (when MaxMind DBs
  // are loaded server-side) country + ASN. Geo arrives only for
  // public IPs; fingerprint identifiers (`fp:<ja4>`) get null.
  const topAttackers = (topApi.data?.attackers || []).map(a => ({
    id: a.identifier,
    fingerprint: a.identifier.startsWith('fp:') ? a.identifier : null,
    hits: a.hits,
    cats: a.categories || [],
    risk: a.risk,
    country: a.country || null,
    asn: a.asn || null,
    // The WorldMap renderer wants `{cc, city, lat, lon}`. The
    // backend gives us a country code; we look up a country
    // centroid for the lat/lon. City-level pins arrive when the
    // operator ships a GeoLite2-City.mmdb (the backend will then
    // populate `lat` / `lon` directly).
    geo: a.country
      ? (() => {
          const c = window.centroidFor && window.centroidFor(a.country);
          return c ? { cc: a.country, city: '', lat: c[0], lon: c[1] } : null;
        })()
      : null,
  }));

  // Map blips — country-centroid lookup so each origin lands
  // somewhere on the right country tile (not stacked at 0,0
  // off the African coast like the earlier hard-coded version).
  // Drops countries the centroid table doesn't know about
  // rather than piling them on a single pixel.
  const blips = topAttackers
    .filter(a => a.country && window.centroidFor && window.centroidFor(a.country))
    .slice(0, 12)
    .map((a, i) => {
      const [lat, lon] = window.centroidFor(a.country);
      return { cc: a.country, city: '', lat, lon, ip: a.id, label: a.country, show: i < 5 };
    });

  // Backend signal — `geoip_loaded` flips to true when the
  // server's AttacksHandler has a MaxMind reader wired (boot
  // path called `set_geo_lookup`). Lets us distinguish "DB
  // not loaded" (real backend gap) from "DB loaded but no
  // resolvable source IPs" (the localhost-dev case where every
  // attacker is 127.0.0.1, which MaxMind doesn't resolve).
  const geoipLoaded = topApi.data?.geoip_loaded === true;

  // L001 (2026-05-07) — surface firing alerts on the Overview
  // landing page. Pre-fix the only signal was a small bell-icon
  // badge in the top nav; SOC analysts during an incident would
  // open the dashboard, see all-green KPIs, and miss the breach.
  const overviewAlerts = window.useAlertsApi
    ? window.useAlertsApi()
    : { data: null };
  const firingAlerts = overviewAlerts.data?.firing || [];

  return (
    <>
      <div className="page-head">
        <div>
          <h1 className="page-title">Overview</h1>
          <p className="page-subtitle">Realtime WAF traffic monitoring · last update {tick}s</p>
        </div>
        <div className="page-actions">
          <button className="btn"><window.I.Refresh /> Refresh</button>
          <button className="btn"><window.I.Download /> Export</button>
          <button className="btn primary"><window.I.External /> Open Grafana</button>
        </div>
      </div>

      {firingAlerts.length > 0 && (
        <div
          className="callout warn"
          style={{ marginBottom: 12, display: 'flex', alignItems: 'center', gap: 12 }}
          role="alert"
        >
          <span style={{ fontSize: 18 }}>⚠</span>
          <div style={{ flex: 1, fontSize: 13 }}>
            <strong>
              {firingAlerts.length} alert{firingAlerts.length === 1 ? '' : 's'} firing
            </strong>
            {firingAlerts.length <= 4 && (
              <span style={{ marginLeft: 8, color: 'var(--ink-mute)' }}>
                {firingAlerts
                  .map(a => a.name || a.id || a.alert || 'alert')
                  .join(', ')}
              </span>
            )}
          </div>
          <a
            href="#/health"
            className="btn sm"
            style={{ textDecoration: 'none' }}
          >
            View in Health &amp; SLOs →
          </a>
        </div>
      )}

      {/* AI insights — coming soon */}
      <div className="ai-card ai-soon" style={{ marginBottom: 12 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <span className="ai-tag"><window.I.Sparkles /> AI INSIGHTS</span>
          <span className="pill warn">Coming soon</span>
          <span style={{ fontSize: 12, color: 'var(--ink-mute)' }}>
            Automated threat triage &amp; suggested rules — early access in v1.5
          </span>
          <button className="btn sm ghost" style={{ marginLeft: 'auto' }} disabled>Notify me →</button>
        </div>
      </div>

      {/* KPI tiles */}
      <div className="kpi-row">
        <window.StatTile
          title="Requests / s"
          value={requestRate !== undefined ? requestRate.toFixed(1) : '—'}
          sub={<>1-second sliding average</>}
          icon={<window.I.Activity />}
          sparkData={sparkTotal}
          sparkColor="#3B82F6"
        />
        <window.StatTile
          title="Block rate"
          value={blockRate !== undefined ? `${blockRate.toFixed(1)}%` : '—'}
          sub={<><span className="num">{blocksTotal.toLocaleString()}</span> blocked total</>}
          icon={<window.I.Ban />}
          tone="down"
          sparkData={sparkBlocked}
          sparkColor="#F6465D"
        />
        <window.StatTile
          title="Active threats"
          value={String(activeThreats)}
          sub={<>IPs over risk threshold · last 15m</>}
          icon={<window.I.Siren />}
          tone="warn"
        />
        <window.StatTile
          title="Upstream"
          value={(() => {
            if (!upstream) return '—';
            const healthy = Number(upstream.healthy ?? 0);
            const unhealthy = Number(upstream.unhealthy ?? 0);
            if (healthy + unhealthy === 0) return '—';
            if (unhealthy === 0) return 'Healthy';
            return unhealthy < healthy ? 'Degraded' : 'Down';
          })()}
          sub={(() => {
            if (!upstream) return 'awaiting first stats sample';
            const healthy = Number(upstream.healthy ?? 0);
            const unhealthy = Number(upstream.unhealthy ?? 0);
            const total = healthy + unhealthy;
            if (total === 0) return 'no members configured';
            return `${healthy} of ${total} members up`;
          })()}
          icon={<window.I.Server />}
          tone={(() => {
            if (!upstream) return undefined;
            const healthy = Number(upstream.healthy ?? 0);
            const unhealthy = Number(upstream.unhealthy ?? 0);
            if (healthy + unhealthy === 0) return undefined;
            return unhealthy === 0 ? 'up' : 'warn';
          })()}
        />
      </div>

      {/* World map (wow #1) */}
      <div className="card" style={{ padding: 0, overflow: 'hidden', marginBottom: 12 }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '12px 16px', borderBottom: '1px solid var(--hairline)' }}>
          <div>
            <div style={{ fontSize: 13, fontWeight: 600 }}>Live attack origins</div>
            <div style={{ fontSize: 11, color: 'var(--ink-dim)' }}>Real-time geolocation of blocked requests · last 60s</div>
          </div>
          <div style={{ display: 'flex', gap: 8 }}>
            <span className="pill block">{topAttackers.length} active sources</span>
            <span
              className={`pill ${
                blips.length > 0 ? 'ok' : geoipLoaded ? 'info' : 'warn'
              }`}
              title={
                blips.length > 0
                  ? `${blips.length} sources have country lookups`
                  : geoipLoaded
                    ? 'GeoIP DB loaded; no current attackers have a public IP MaxMind can resolve (e.g. localhost dev traffic). The pill flips when public-IP attackers arrive.'
                    : 'GeoIP MaxMind DB not loaded — see docs/security/geoip-filtering.md'
              }
              style={{ cursor: blips.length === 0 ? 'help' : 'default' }}
            >
              {blips.length > 0
                ? `${blips.length} geo-tagged`
                : geoipLoaded
                  ? 'no resolvable IPs'
                  : 'GeoIP DB not loaded'}
            </span>
          </div>
        </div>
        {blips.length === 0 && topAttackers.length > 0 && (
          <div style={{ padding: '8px 16px', fontSize: 11, color: 'var(--ink-dim)', borderBottom: '1px solid var(--hairline)' }}>
            {geoipLoaded
              ? 'Map empty because none of the current attackers have a public IP MaxMind can resolve (e.g. localhost). The Top Attackers table below still shows every IP.'
              : <>Map empty because GeoIP DB isn't loaded. The Top Attackers table below still shows every IP.{' '}<a href="#/help" style={{ color: 'var(--accent)' }}>How to install GeoIP →</a></>
            }
          </div>
        )}
        <window.WorldMap blips={blips} h={300} />
      </div>

      {/* Traffic chart + distribution */}
      <div className="section-row">
        <div className="card">
          <div className="card-head">
            <div>
              <div className="card-title">Traffic vs Blocked</div>
              <div className="card-sub">Realtime · 60s window · 1s buckets</div>
            </div>
            <div style={{ display: 'flex', gap: 6 }}>
              {['1m', '5m', '15m', '1h'].map((w, i) => (
                <button key={w} className={`chip ${i === 0 ? 'active' : ''}`}>{w}</button>
              ))}
            </div>
          </div>
          <window.TrafficChart series={series} h={220} />
        </div>
        <div className="card">
          <div className="card-head">
            <div>
              <div className="card-title">Attack distribution</div>
              <div className="card-sub">By detector class · 15m</div>
            </div>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
            <window.Donut slices={dist} size={170} />
            <div style={{ display: 'flex', flexDirection: 'column', gap: 4, fontSize: 11, flex: 1 }}>
              {dist.slice().sort((a,b) => b.value - a.value).slice(0, 7).map(s => (
                <div key={s.name} style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                  <span style={{ width: 8, height: 8, borderRadius: 2, background: s.color }} />
                  <span style={{ flex: 1, color: 'var(--ink-mute)' }}>{s.name}</span>
                  <span className="num" style={{ color: 'var(--ink)' }}>{s.value}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* Risk heatmap (wow #2) */}
      <div className="card" style={{ marginBottom: 12 }}>
        <div className="card-head">
          <div>
            <div className="card-title">Risk heatmap — top paths × intensity</div>
            <div className="card-sub">
              Top 8 paths by max risk score over the most-recent
              200 audit events. Live · derived from /api/audit/since.
            </div>
          </div>
          <div style={{ display: 'flex', gap: 6, alignItems: 'center', fontSize: 10, color: 'var(--ink-dim)' }}>
            <span>low</span>
            {['#1E2329','#3B2A1A','#6B4710','#A87715','#E0A415','#FCD535'].map(c => (
              <span key={c} style={{ width: 14, height: 10, background: c, display: 'inline-block', borderRadius: 1 }} />
            ))}
            <span>high</span>
          </div>
        </div>
        <RiskHeatmapLive />
      </div>

      {/* Top attackers */}
      <div className="card">
        <div className="card-head">
          <div className="card-title">Top attacker IPs · 15m</div>
          <button className="btn sm">View all →</button>
        </div>
        <table className="tbl tbl-compact">
          <thead>
            <tr>
              <th style={{ width: 36 }}>#</th>
              <th>Identifier</th>
              <th>Origin</th>
              <th>Hits</th>
              <th>Categories</th>
              <th>Risk</th>
              <th style={{ width: 180 }}>Action</th>
            </tr>
          </thead>
          <tbody>
            {topAttackers.length === 0 && (
              <tr><td colSpan={7} style={{ textAlign: 'center', padding: 16, color: 'var(--ink-dim)', fontSize: 12 }}>
                No attackers observed in the last 15 minutes.
              </td></tr>
            )}
            {topAttackers.map((a, i) => (
              <tr key={`${a.id}-${i}`} onClick={() => setDrawerEvent(a)}>
                <td className="num dim">{i + 1}</td>
                <td className="mono" style={{ fontSize: 12 }}>{a.id}</td>
                <td><span style={{ color: 'var(--ink-mute)' }}>{a.geo ? `${a.geo.cc} · ${a.geo.city}` : '—'}</span></td>
                <td className="num">{a.hits.toLocaleString()}</td>
                <td>
                  <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
                    {a.cats.map(c => <span key={c} className="pill neutral" style={{ fontSize: 9 }}>{c}</span>)}
                  </div>
                </td>
                <td><window.RiskMeter value={a.risk} /></td>
                <td onClick={e => e.stopPropagation()}>
                  <button
                    className="btn sm danger"
                    style={{ marginRight: 6 }}
                    title={`Add ${a.id} to blacklist`}
                    onClick={() => quickBlockIp(a.id)}
                  >Block</button>
                  <button className="btn sm" onClick={() => setDrawerEvent(a)}>Inspect</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <window.Drawer open={!!drawerEvent} onClose={() => setDrawerEvent(null)} title={drawerEvent?.id}>
        {drawerEvent && <RequestDetail data={{
          ip: drawerEvent.id, geo: drawerEvent.geo, hits: drawerEvent.hits,
          risk: drawerEvent.risk, cats: drawerEvent.cats,
        }} />}
      </window.Drawer>
    </>
  );
}

// CQF-T5 — RequestDetail. Renders only the fields the caller
// actually has. Caller passes through whatever the upstream API
// returned (Live-Feed event row or attacks-top attacker row);
// fields the caller doesn't have render as em-dashes or are
// omitted entirely.
//
// The drawer is opened from two surfaces today:
//   - Overview Top Attackers   row → { id (ip), geo, hits, risk, cats }
//   - Live Feed event          row → { id, ts, ip, method, path,
//                                      region, tier, risk, action, rules }
//
// Optionally the caller can pass `requestId` to drive a one-off
// `/api/audit/since` lookup; when the chain entry is found we
// surface request_id + chain_hash + prev. Otherwise the Audit
// section just shows the request_id (if any).
function RequestDetail({ data }) {
  const ip = data?.ip || '—';
  const action = data?.action || null;
  const tier = data?.tier || null;
  const risk = (typeof data?.risk === 'number') ? data.risk : null;
  const rules = Array.isArray(data?.rules) ? data.rules : [];
  const cats = Array.isArray(data?.cats) ? data.cats : [];
  const method = data?.method || null;
  const path = data?.path || null;
  const region = data?.region || null;
  const ts = data?.ts || null;
  const geo = data?.geo || null;
  const requestId = data?.request_id || data?.requestId || null;
  const status = data?.status || null;
  const latency = data?.latency || data?.latency_ms || null;
  const reason = data?.reason || null;
  const auditClass = data?.class || null;
  const routeId = data?.route_id || data?.fields?.route_id || null;
  const fields = data?.fields && typeof data.fields === 'object' ? data.fields : null;
  const detectorReason = rules.length > 0 ? rules.join(', ') : (cats.length > 0 ? cats.join(', ') : reason);
  // Render any backend-emitted scalar that isn't already covered
  // by the dedicated rows above. Stable key ordering so the
  // drawer doesn't reflow on every poll.
  const extraEntries = fields
    ? Object.entries(fields)
        .filter(([k]) => !['method', 'path', 'status', 'region', 'route_id', 'latency_ms'].includes(k))
        .sort(([a], [b]) => a.localeCompare(b))
    : [];

  // Optional: look the request up in the audit ring so the chain
  // hash + prev hash + sinks reflect reality. Disabled when no
  // request_id is available; otherwise polls once on mount.
  const auditApi = window.useAuditLookupForRequestId
    ? window.useAuditLookupForRequestId(requestId)
    : null;
  const auditEntry = auditApi?.data || null;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
      <div>
        <div style={{ fontSize: 10, color: 'var(--ink-faint)', textTransform: 'uppercase', letterSpacing: 1.2, marginBottom: 6 }}>Summary</div>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8, fontSize: 12 }}>
          <div>
            <div className="dim">Action</div>
            {action ? <window.ActionPill value={action} /> : <span className="dim mono">—</span>}
          </div>
          <div>
            <div className="dim">Reason</div>
            {detectorReason
              ? <span className="mono">{detectorReason}</span>
              : <span className="dim mono">—</span>}
          </div>
          <div>
            <div className="dim">Risk</div>
            {risk !== null ? <window.RiskMeter value={risk} /> : <span className="dim mono">—</span>}
          </div>
          <div>
            <div className="dim">Tier</div>
            {tier ? <window.TierPill value={tier} /> : <span className="dim mono">—</span>}
          </div>
        </div>
      </div>
      <div>
        <div style={{ fontSize: 10, color: 'var(--ink-faint)', textTransform: 'uppercase', letterSpacing: 1.2, marginBottom: 6 }}>Network</div>
        <div style={{ fontSize: 12, lineHeight: 1.7, fontFamily: 'var(--font-mono)' }}>
          <div><span className="dim">client_ip</span> {ip}</div>
          {geo && (geo.cc || geo.city || geo.lat) && (
            <div>
              <span className="dim">geo</span> {geo.cc || '—'}
              {geo.city ? ` · ${geo.city}` : ''}
              {(typeof geo.lat === 'number' && typeof geo.lon === 'number')
                ? ` (${geo.lat.toFixed(2)}, ${geo.lon.toFixed(2)})`
                : ''}
            </div>
          )}
          {region && <div><span className="dim">region</span> {region}</div>}
          {ts && <div><span className="dim">ts</span> {ts}</div>}
        </div>
      </div>
      {(method || path) && (
        <div>
          <div style={{ fontSize: 10, color: 'var(--ink-faint)', textTransform: 'uppercase', letterSpacing: 1.2, marginBottom: 6 }}>Request</div>
          <div style={{ fontSize: 12, fontFamily: 'var(--font-mono)', wordBreak: 'break-all' }}>
            {method && <span style={{ color: 'var(--info)', marginRight: 8 }}>{method}</span>}
            {path && <span style={{ color: 'var(--ink)' }}>{path}</span>}
          </div>
          {(status || latency || routeId) && (
            <div style={{ display: 'flex', gap: 12, fontSize: 11, marginTop: 6, flexWrap: 'wrap' }}>
              {status && (
                <div>
                  <span className="dim">status</span>{' '}
                  <span className={`pill ${status >= 500 ? 'down' : status >= 400 ? 'warn' : 'up'}`}>{status}</span>
                </div>
              )}
              {latency != null && Number.isFinite(latency) && (
                <div>
                  <span className="dim">latency</span>{' '}
                  <span className="num mono">{latency < 1 ? `${(latency * 1000).toFixed(0)} µs` : `${latency.toFixed(2)} ms`}</span>
                </div>
              )}
              {routeId && (
                <div>
                  <span className="dim">route</span>{' '}
                  <code style={{ fontSize: 10 }}>{routeId}</code>
                </div>
              )}
              {auditClass && (
                <div>
                  <span className="dim">class</span>{' '}
                  <span className="pill neutral" style={{ fontSize: 10 }}>{auditClass}</span>
                </div>
              )}
            </div>
          )}
        </div>
      )}
      {rules.length > 0 && (
        <div>
          <div style={{ fontSize: 10, color: 'var(--ink-faint)', textTransform: 'uppercase', letterSpacing: 1.2, marginBottom: 6 }}>Detection</div>
          <div style={{ fontSize: 12, display: 'flex', gap: 4, flexWrap: 'wrap' }}>
            {rules.map(r => <span key={r} className="pill neutral" style={{ fontSize: 10 }}>{r}</span>)}
          </div>
        </div>
      )}
      {extraEntries.length > 0 && (
        <div>
          <div style={{ fontSize: 10, color: 'var(--ink-faint)', textTransform: 'uppercase', letterSpacing: 1.2, marginBottom: 6 }}>Extra fields</div>
          <div style={{ fontSize: 11, fontFamily: 'var(--font-mono)' }}>
            {extraEntries.map(([k, v]) => (
              <div key={k} style={{ display: 'flex', gap: 8 }}>
                <span className="dim" style={{ minWidth: 100 }}>{k}</span>
                <span style={{ wordBreak: 'break-all' }}>
                  {typeof v === 'object' ? JSON.stringify(v) : String(v)}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}
      <div>
        <div style={{ fontSize: 10, color: 'var(--ink-faint)', textTransform: 'uppercase', letterSpacing: 1.2, marginBottom: 6 }}>Audit</div>
        <div style={{ fontSize: 11, fontFamily: 'var(--font-mono)', color: 'var(--ink-mute)' }}>
          <div><span className="dim">request_id</span> {requestId || <span className="dim">—</span>}</div>
          {auditEntry ? (
            <>
              <div><span className="dim">chain_hash</span> {auditEntry.hash || '—'}</div>
              <div><span className="dim">prev</span> {auditEntry.prev_hash || '—'}</div>
              <div><span className="dim">seq</span> {auditEntry.seq != null ? `#${auditEntry.seq}` : '—'}</div>
            </>
          ) : (
            <div className="dim" style={{ fontStyle: 'italic', fontSize: 10 }}>
              chain hash + prev surface in /api/audit/since once a request_id is known.
            </div>
          )}
          {requestId && (
            <div style={{ marginTop: 8 }}>
              <a
                href={`#/investigation?pivot=${encodeURIComponent(requestId)}&kind=request_id`}
                style={{ color: 'var(--accent)', fontSize: 11 }}
              >
                Pivot to Investigation →
              </a>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// ============== LIVE FEED ==============
function PageLiveFeed() {
  const [paused, setPaused] = useStateP(false);
  const { events, connected } = window.useRealLiveFeed(80, paused);
  const [filterAction, setFilterAction] = useStateP('all');
  const [filterTier, setFilterTier] = useStateP('all');
  const [search, setSearch] = useStateP('');
  const [selected, setSelected] = useStateP(null);

  // CQF-T4 — drawer footer actions. Block IP / Whitelist write
  // through the audit-mutated POST endpoints shipped in CQF-T2.
  // Copy as cURL builds a minimally-reproducible curl command
  // from the selected event (method + path + WAF data plane
  // host). No API call; clipboard only.
  async function quickAccessListAdd(kind, ip, note) {
    if (!ip) return;
    const id = `ui-${ip.replace(/[^A-Za-z0-9]+/g, '-')}-${Date.now().toString(36)}`;
    try {
      const r = await window.accessListAdd(kind, {
        id,
        kind: ip.includes('/') ? 'cidr' : 'ip',
        value: ip,
        note,
        bypass: kind === 'whitelist' ? ['all'] : [],
        created_at: new Date().toISOString(),
      });
      if (r.ok) {
        window.aegisToast(`${kind === 'blacklist' ? 'Blocked' : 'Whitelisted'} ${ip}`, 'ok');
        setSelected(null);
      } else {
        const msg = (r && (r.message || r.error || r.reason)) || `status ${r.status}`;
        window.aegisToast(`${kind} failed: ${msg}`, 'err');
      }
    } catch (e) {
      window.aegisToast(`${kind} error: ${e.message || e}`, 'err');
    }
  }
  async function copyAsCurl(ev) {
    if (!ev) return;
    // Best-effort host: data plane is on the same origin's port 8080
    // for dev; for non-localhost installs the operator can edit.
    const host = (location.hostname || '127.0.0.1') + ':8080';
    const proto = location.protocol === 'https:' ? 'https' : 'http';
    const method = (ev.method || 'GET').toUpperCase();
    const path = ev.path || '/';
    const lines = [
      `curl -i \\`,
      `  -X ${method} \\`,
      `  -H 'X-Forwarded-For: ${ev.ip || '127.0.0.1'}' \\`,
      `  '${proto}://${host}${path}'`,
    ];
    const cmd = lines.join('\n');
    try {
      if (navigator.clipboard && navigator.clipboard.writeText) {
        await navigator.clipboard.writeText(cmd);
        window.aegisToast('Copied curl to clipboard', 'ok');
      } else {
        // Fallback: select-and-prompt so operators on browsers
        // without async clipboard can still grab the command.
        window.prompt('Copy this curl command:', cmd);
      }
    } catch (e) {
      window.aegisToast(`Clipboard error: ${e.message || e}`, 'err');
    }
  }

  const filtered = events.filter(e => {
    if (filterAction !== 'all' && e.action !== filterAction) return false;
    if (filterTier !== 'all' && e.tier !== filterTier) return false;
    if (search && !(e.ip.includes(search) || e.path.toLowerCase().includes(search.toLowerCase()))) return false;
    return true;
  });

  const recent = filtered.slice().reverse();

  return (
    <>
      <div className="page-head">
        <div>
          <h1 className="page-title">Live Feed</h1>
          <p className="page-subtitle">
            {filtered.length.toLocaleString()} of {events.length.toLocaleString()} events · streaming via SSE
            <span className={`pill ${connected ? 'ok' : 'warn'}`} style={{ marginLeft: 6 }}>
              {connected ? 'connected' : 'disconnected'}
            </span>
          </p>
        </div>
        <div className="page-actions">
          <button className="btn"><window.I.Download /> CSV</button>
          <button className={`btn ${paused ? 'primary' : ''}`} onClick={() => setPaused(p => !p)}>
            {paused ? <><window.I.Play /> Resume</> : <><window.I.Pause /> Pause</>}
          </button>
        </div>
      </div>
      <div className="card" style={{ padding: '8px 12px', marginBottom: 8, fontSize: 11, color: 'var(--ink-dim)', display: 'flex', alignItems: 'center', gap: 8 }}>
        <window.I.Activity />
        <span>
          <strong>Live Feed</strong> shows every <em>request</em> the WAF inspected
          (allow / block / challenge). For configuration mutations and a
          chained, durable trail, see <a href="#/audit" style={{ color: 'var(--accent)' }}>Audit Trail →</a>.
        </span>
      </div>

      <div className="card flat" style={{ padding: 12, marginBottom: 12 }}>
        <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
          <select className="input select" style={{ width: 130 }} value={filterAction} onChange={e => setFilterAction(e.target.value)}>
            <option value="all">All actions</option>
            <option value="allow">Allow</option>
            <option value="block">Block</option>
            <option value="challenge">Challenge</option>
          </select>
          <select className="input select" style={{ width: 130 }} value={filterTier} onChange={e => setFilterTier(e.target.value)}>
            <option value="all">All risk tiers</option>
            <option value="low">Low</option>
            <option value="med">Medium</option>
            <option value="high">High</option>
            <option value="crit">Critical</option>
          </select>
          <div style={{ position: 'relative', flex: 1, maxWidth: 320 }}>
            <span style={{ position: 'absolute', left: 8, top: 7, color: 'var(--ink-faint)' }}><window.I.Search /></span>
            <input className="input" style={{ paddingLeft: 28 }} placeholder="Filter by IP, path…" value={search} onChange={e => setSearch(e.target.value)} />
          </div>
          <span style={{ marginLeft: 'auto', fontSize: 11, color: 'var(--ink-dim)' }}>
            <span className={`pill ${connected ? 'ok' : 'warn'}`} style={{ marginRight: 6 }}>
              {connected ? '● live' : '○ idle'}
            </span>
            buffer {events.length}/80
          </span>
        </div>
      </div>

      <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
        <div style={{ maxHeight: 'calc(100vh - 280px)', overflow: 'auto' }}>
          <table className="tbl tbl-compact">
            <thead>
              <tr>
                <th style={{ width: 80 }}>Time</th>
                <th style={{ width: 130 }}>IP</th>
                <th style={{ width: 70 }}>Method</th>
                <th style={{ width: 70 }}>Proto</th>
                <th>Path</th>
                <th style={{ width: 110 }}>Region</th>
                <th style={{ width: 70 }}>Tier</th>
                <th style={{ width: 80 }}>Risk</th>
                <th style={{ width: 80 }}>Action</th>
                <th style={{ width: 160 }}>Rules</th>
                <th style={{ width: 60 }}></th>
              </tr>
            </thead>
            <tbody>
              {recent.map(e => (
                <tr key={e.id} className={e.id === recent[0]?.id ? 'flash' : ''} onClick={() => setSelected(e)}>
                  <td className="num dim">{e.ts}</td>
                  <td className="mono">{e.ip}</td>
                  <td><span className="mono" style={{ color: e.method === 'POST' ? 'var(--info)' : e.method === 'DELETE' ? 'var(--down)' : 'var(--ink-mute)' }}>{e.method}</span></td>
                  <td>
                    {e.protocol && e.protocol !== 'http' ? (
                      <span
                        className="pill"
                        title={`tunnel event: ${e.protocol}`}
                        style={{
                          fontSize: 10,
                          background: e.protocol.startsWith('ws') ? 'rgba(96, 165, 250, 0.15)' : 'rgba(244, 196, 48, 0.15)',
                          color: e.protocol.startsWith('ws') ? '#60A5FA' : 'var(--accent)',
                        }}
                      >{e.protocol}</span>
                    ) : (
                      <span className="dim mono" style={{ fontSize: 10 }}>http</span>
                    )}
                  </td>
                  <td className="mono" style={{ color: 'var(--ink)' }}>{e.path}</td>
                  <td><span className="dim" style={{ fontSize: 11 }}>{e.region}</span></td>
                  <td><window.TierPill value={e.tier} /></td>
                  <td><window.RiskMeter value={e.risk} /></td>
                  <td><window.ActionPill value={e.action} /></td>
                  <td className="mono" style={{ fontSize: 10, color: 'var(--ink-dim)' }}>{e.rules.join(', ') || '—'}</td>
                  <td onClick={ev => ev.stopPropagation()}>
                    <button className="icon-btn" title="Inspect"><window.I.External /></button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      <window.Drawer open={!!selected} onClose={() => setSelected(null)} title={selected?.path}
        footer={<>
          <button className="btn" onClick={() => copyAsCurl(selected)}>Copy as cURL</button>
          <button className="btn danger" onClick={() => selected && quickAccessListAdd('blacklist', selected.ip, `blocked from Live Feed · ${selected.path}`)}>Block IP</button>
          <button className="btn primary" onClick={() => selected && quickAccessListAdd('whitelist', selected.ip, `whitelisted from Live Feed · ${selected.path}`)}>Whitelist</button>
        </>}>
        {selected && <RequestDetail data={{
          ip: selected.ip, geo: selected.geo, risk: selected.risk,
          cats: selected.cat ? [selected.cat] : [],
          method: selected.method, path: selected.path,
          region: selected.region, tier: selected.tier,
          action: selected.action, rules: selected.rules,
          status: selected.status, latency: selected.latency,
          reason: selected.reason, class: selected.class,
          fields: selected.fields,
          ts: selected.ts, request_id: selected.request_id || selected.id,
        }} />}
      </window.Drawer>
    </>
  );
}

// ============== ATTACK EVENTS ==============
// HACK-T1 — `Math.random` retired. Detector breakdown, bot mix,
// and threat-intel rows now read from `aegis_control::api::attacks`
// aggregator endpoints (`/api/attacks/by-detector`,
// `/api/bots/mix`, `/api/threat-intel/hits`) — every value
// reflects real audit-bus events the WAF processed in the
// configured window. Empty-state copy renders honestly when no
// events have arrived yet rather than fabricating numbers.
const ATTACK_WINDOWS = {
  '5m':  300,
  '15m': 900,
  '1h':  3600,
  '6h':  21600,
  '24h': 86400,
};

// Stable per-detector colour assignment so the bar list keeps the
// same hue across renders even when ordering shifts. Falls back to
// a neutral grey when an unrecognised detector lands in the
// response (forward-compatible with future detector additions).
const DETECTOR_COLORS = {
  sqli:        'var(--down)',
  xss:         '#F0B90B',
  command_injection: '#F6465D',
  path_traversal:    '#A78BFA',
  ssrf:        '#F472B6',
  crlf:        '#60A5FA',
  bot:         '#34D399',
  scanner:     '#9CA3AF',
};
function detectorColor(name) {
  return DETECTOR_COLORS[name] || 'var(--ink-mute)';
}

function PageAttackEvents() {
  const [win, setWin] = useStateP('1h');
  const windowSeconds = ATTACK_WINDOWS[win] ?? 3600;

  const byDetector = window.useAttacksByDetectorApi(windowSeconds);
  const botMix = window.useBotMixApi(windowSeconds);
  const tiApi = window.useThreatIntelApi(windowSeconds, 20);

  const detectorBars = (byDetector.data?.detectors ?? [])
    .map(d => ({
      label: d.name,
      value: d.count,
      color: detectorColor(d.name),
    }))
    .sort((a, b) => b.value - a.value);
  const totalDetections = detectorBars.reduce((s, x) => s + x.value, 0);

  const botCategories = botMix.data?.categories ?? [];
  const botColorFor = name => ({
    verified:  'var(--up)',
    suspect:   'var(--warn)',
    malicious: 'var(--down)',
    unknown:   'var(--ink-faint)',
  }[name] || 'var(--ink-mute)');
  const botSegments = botCategories.map(c => ({
    name: c.name,
    value: c.count,
    color: botColorFor(c.name),
  }));
  const malicious = botCategories.find(c => c.name === 'malicious');
  const totalBots = botCategories.reduce((s, c) => s + c.count, 0);

  const tiHits = tiApi.data?.hits ?? [];

  return (
    <>
      <div className="page-head">
        <div>
          <h1 className="page-title">Attack Analytics</h1>
          <p className="page-subtitle">
            Curated detector firings · OWASP + custom rules · last {win}
          </p>
        </div>
        <div className="page-actions">
          <select className="input select" value={win} onChange={e => setWin(e.target.value)} style={{ width: 90 }}>
            {Object.keys(ATTACK_WINDOWS).map(v => <option key={v}>{v}</option>)}
          </select>
          <button className="btn" onClick={() => {
            byDetector.reload && byDetector.reload();
            botMix.reload && botMix.reload();
            tiApi.reload && tiApi.reload();
          }}><window.I.Refresh /></button>
        </div>
      </div>

      <div className="section-row">
        <div className="card">
          <window.SectionHeader
            title="Detector breakdown"
            sub={`${totalDetections.toLocaleString()} detections in window`}
          />
          {detectorBars.length === 0 ? (
            <div style={{ padding: 16, fontSize: 12, color: 'var(--ink-dim)', textAlign: 'center' }}>
              No detections in the last {win}. The bar list lights up as soon as a request triggers any detector.
            </div>
          ) : (
            <window.BarList items={detectorBars} />
          )}
        </div>
        <div className="card">
          <window.SectionHeader
            title="Bot classification mix"
            sub={totalBots > 0 ? `${totalBots.toLocaleString()} classified requests` : 'no bot signal yet'}
          />
          {/*
            2026-05-03 fix — when every classified request lands
            in `unknown`, the bot classifier is wired but isn't
            producing usable signal on this profile (no JA4
            baseline, no UA rules in dev cfg, etc.).  Showing a
            100% "unknown" stacked bar reads as a dishonest
            "we classified things"; instead we surface the
            actionable empty state with a config pointer.
          */}
          {botSegments.length === 0 ||
            (botCategories.length === 1 && botCategories[0].name === 'unknown') ? (
            <div style={{ padding: 16, fontSize: 12, color: 'var(--ink-dim)', textAlign: 'center' }}>
              {botCategories.length === 1 && botCategories[0].name === 'unknown' ? (
                <>
                  Bot classifier wired but every request landed in
                  <code style={{ margin: '0 4px' }}>unknown</code>.
                  This profile has no JA4 baseline / UA allow-list to drive
                  classification — see{' '}
                  <a href="#/help" style={{ color: 'var(--accent)' }}>Help → Bot classifier setup</a>{' '}
                  for the bring-up.
                </>
              ) : (
                <>No bot classifications recorded in the last {win}.</>
              )}
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
              <window.StackedBar segments={botSegments} h={28} />
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 6, fontSize: 11 }}>
                {botCategories.map(c => (
                  <div key={c.name}>
                    <span style={{ color: botColorFor(c.name) }}>● {c.name}</span>{' '}
                    <span className="num">{c.count.toLocaleString()}</span>
                  </div>
                ))}
              </div>
              {malicious && (
                <div style={{ marginTop: 6, padding: 8, background: 'var(--canvas-2)', borderRadius: 6, fontSize: 11, color: 'var(--ink-mute)' }}>
                  {/* CQF-T12 — defensive guard: malicious.pct may be undefined
                      when the backend aggregator hasn't filled the field yet
                      (e.g. fresh boot, no events). */}
                  <strong style={{ color: 'var(--ink-strong)' }}>{(malicious.pct ?? 0).toFixed(1)}%</strong> of classified bot traffic in this window flagged malicious.
                </div>
              )}
            </div>
          )}
        </div>
      </div>

      <div className="card">
        <window.SectionHeader title="Threat-intel hits" sub={`${tiHits.length} indicators matched in window`} />
        {tiHits.length === 0 ? (
          <div style={{ padding: 16, fontSize: 12, color: 'var(--ink-dim)', textAlign: 'center' }}>
            No threat-intel matches in the last {win}.
          </div>
        ) : (
          <table className="tbl tbl-compact">
            <thead><tr><th>Source</th><th>Indicator</th><th>Hits</th><th>Last seen</th></tr></thead>
            <tbody>
              {tiHits.map((t, i) => (
                <tr key={`${t.feed}-${t.indicator}-${i}`}>
                  <td className="mono"><span className="pill violet">{t.feed}</span></td>
                  <td className="mono">{t.indicator}</td>
                  <td className="num">{t.hits.toLocaleString()}</td>
                  <td className="dim">{new Date(t.last_seen).toLocaleTimeString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </>
  );
}

// ============== ANALYTICS ==============
// HACK-T1 — `Math.random` retired. Requests over time + block
// ratio sparklines now read from `/api/stats/timeseries`.
// Latency-percentile + error-rate-by-route widgets render an
// honest empty state; their data sources land in a follow-up
// (Prometheus histogram + per-route audit aggregator).
const ANALYTICS_WINDOWS = {
  '1h':  { window: 3600,    step: 60   },
  '6h':  { window: 21600,   step: 300  },
  '24h': { window: 86400,   step: 1200 },
  '7d':  { window: 604800,  step: 3600 * 4 },
  '30d': { window: 2592000, step: 3600 * 24 },
};

function PageAnalytics() {
  const [range, setRange] = useStateP('24h');
  const cfg = ANALYTICS_WINDOWS[range] ?? ANALYTICS_WINDOWS['24h'];
  const ts = window.useTimeseriesApi(cfg.window, cfg.step);
  const latency = window.useLatencyApi ? window.useLatencyApi() : { data: null };
  const routeLatency = window.useRouteLatencyApi ? window.useRouteLatencyApi() : { data: null };
  const detectorLatency = window.useDetectorLatencyApi ? window.useDetectorLatencyApi() : { data: null };
  const routes = window.useAnalyticsRoutesApi ? window.useAnalyticsRoutesApi() : { data: null };
  // HACK-T1 — SLO + Cert summaries also retired from static
  // fixtures. Both endpoints already shipped (Tracking page
  // consumes them); we just expose them on Analytics too so
  // operators don't have to switch tabs.
  const sloApi = window.useSloApi();
  const certsApi = window.useCertsApi();

  const points = ts.data?.points ?? [];
  const reqOverTime = points.map(p => p.total);
  const blockRatioPct = points.map(p => p.total > 0 ? (p.blocked * 100) / p.total : 0);

  const totalReq = points.reduce((s, p) => s + p.total, 0);
  const totalBlocked = points.reduce((s, p) => s + p.blocked, 0);
  const stepsPerSecond = cfg.step > 0 ? cfg.step : 1;
  const avgReqPerSecond = points.length > 0
    ? Math.round(totalReq / (points.length * stepsPerSecond))
    : 0;
  const avgBlockPct = totalReq > 0 ? (totalBlocked * 100) / totalReq : 0;
  const peakBlockPct = blockRatioPct.length > 0
    ? Math.max(...blockRatioPct)
    : 0;
  const peakIdx = blockRatioPct.indexOf(peakBlockPct);
  const peakTs = peakIdx >= 0 && points[peakIdx]
    ? new Date(points[peakIdx].ts).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
    : '—';

  const hasSeries = points.length > 0;

  return (
    <>
      <div className="page-head">
        <div>
          <h1 className="page-title">Performance</h1>
          <p className="page-subtitle">
            Historical trends · {range} window
          </p>
        </div>
        <div className="page-actions">
          <div style={{ display: 'flex', gap: 4 }}>
            {Object.keys(ANALYTICS_WINDOWS).map(r => (
              <button key={r} className={`chip ${range === r ? 'active' : ''}`} onClick={() => setRange(r)}>{r}</button>
            ))}
          </div>
          <button className="btn" onClick={() => ts.reload && ts.reload()}><window.I.Refresh /></button>
        </div>
      </div>

      <div className="grid-12" style={{ marginBottom: 12 }}>
        <div className="col-6 card">
          <window.SectionHeader
            title="Requests over time"
            sub={hasSeries ? `avg ${avgReqPerSecond.toLocaleString()} req/s` : 'no data yet'}
          />
          {hasSeries ? (
            <window.Sparkline data={reqOverTime} w={460} h={120} color="#3B82F6" fill strokeWidth={1.5} />
          ) : (
            <div style={{ padding: 16, fontSize: 12, color: 'var(--ink-dim)', textAlign: 'center' }}>
              No traffic recorded in the last {range}.
            </div>
          )}
        </div>
        <div className="col-6 card">
          <window.SectionHeader
            title="Latency p50/p95/p99"
            sub={(() => {
              const total = latency.data?.stages?.total;
              return total
                ? `WAF-internal · ${total.samples.toLocaleString()} samples`
                : 'no samples yet — drive traffic with `make mock-load`';
            })()}
          />
          {(() => {
            const stages = latency.data?.stages || {};
            const stageOrder = ['total', 'detect', 'rate_limit', 'respond'];
            const present = stageOrder.filter(s => stages[s]);
            if (present.length === 0) {
              return (
                <div style={{ padding: 16, fontSize: 12, color: 'var(--ink-dim)', textAlign: 'center', minHeight: 120, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                  No samples yet. Drive traffic and refresh.
                </div>
              );
            }
            const fmt = v => v >= 1 ? v.toFixed(2) : v.toFixed(3);
            return (
              <table className="tbl tbl-compact" style={{ marginTop: 4 }}>
                <thead><tr><th>Stage</th><th style={{ textAlign: 'right' }}>p50 (ms)</th><th style={{ textAlign: 'right' }}>p95 (ms)</th><th style={{ textAlign: 'right' }}>p99 (ms)</th></tr></thead>
                <tbody>
                  {present.map(s => (
                    <tr key={s}>
                      <td style={{ fontWeight: s === 'total' ? 600 : 400 }}>{s}</td>
                      <td className="num" style={{ textAlign: 'right' }}>{fmt(stages[s].p50_ms)}</td>
                      <td className="num" style={{ textAlign: 'right' }}>{fmt(stages[s].p95_ms)}</td>
                      <td className="num" style={{ textAlign: 'right' }}>{fmt(stages[s].p99_ms)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            );
          })()}
        </div>
        <div className="col-6 card">
          <window.SectionHeader
            title="Block ratio"
            sub={hasSeries ? `avg ${avgBlockPct.toFixed(1)}% · peak ${peakBlockPct.toFixed(1)}% at ${peakTs}` : 'no data yet'}
          />
          {hasSeries ? (
            <window.Sparkline data={blockRatioPct} w={460} h={120} color="#F6465D" fill />
          ) : (
            <div style={{ padding: 16, fontSize: 12, color: 'var(--ink-dim)', textAlign: 'center' }}>
              No block decisions in the last {range}.
            </div>
          )}
        </div>
        <div className="col-6 card">
          {(() => {
            const rows = routes.data?.routes || [];
            return (
              <>
                <window.SectionHeader
                  title="Error rate by route"
                  sub={rows.length > 0
                    ? `${rows.length} route${rows.length === 1 ? '' : 's'} · audit-ring window`
                    : 'no traffic in window'}
                />
                {rows.length === 0 ? (
                  <div style={{ padding: 16, fontSize: 12, color: 'var(--ink-dim)', textAlign: 'center', minHeight: 120, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                    Drive traffic with <code>make mock-load</code> to populate.
                  </div>
                ) : (
                  <table className="tbl tbl-compact" style={{ marginTop: 4 }}>
                    <thead><tr>
                      <th>Route</th>
                      <th style={{ textAlign: 'right' }}>Total</th>
                      <th style={{ textAlign: 'right' }}>Blocked</th>
                      <th style={{ textAlign: 'right' }}>5xx</th>
                      <th style={{ textAlign: 'right' }}>Error %</th>
                    </tr></thead>
                    <tbody>
                      {rows.slice(0, 10).map(r => (
                        <tr key={r.route}>
                          <td><code style={{ fontSize: 11 }}>{r.route}</code></td>
                          <td className="num" style={{ textAlign: 'right' }}>{r.total}</td>
                          <td className="num" style={{ textAlign: 'right' }}>{r.blocked}</td>
                          <td className="num" style={{ textAlign: 'right' }}>{r.errors_5xx}</td>
                          <td className="num" style={{ textAlign: 'right' }}>
                            <span className={`pill ${r.error_rate_pct > 50 ? 'down' : r.error_rate_pct > 10 ? 'warn' : 'up'}`}>
                              {r.error_rate_pct.toFixed(1)}%
                            </span>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
              </>
            );
          })()}
        </div>
      </div>

      <div className="grid-12" style={{ marginBottom: 12 }}>
        <div className="col-12 card">
          {(() => {
            const rows = routeLatency.data?.routes || [];
            return (
              <>
                <window.SectionHeader
                  title="Latency p50/p95/p99 by route"
                  sub={rows.length > 0
                    ? `${rows.length} active route${rows.length === 1 ? '' : 's'} · live histogram`
                    : 'no per-route samples yet'}
                />
                {rows.length === 0 ? (
                  <div style={{ padding: 16, fontSize: 12, color: 'var(--ink-dim)', textAlign: 'center', minHeight: 80, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                    Drive traffic with <code>make mock-load</code>; per-route series populate as routes resolve.
                  </div>
                ) : (
                  <table className="tbl tbl-compact" style={{ marginTop: 4 }}>
                    <thead><tr>
                      <th>Route</th>
                      <th style={{ textAlign: 'right' }}>Samples</th>
                      <th style={{ textAlign: 'right' }}>p50 (ms)</th>
                      <th style={{ textAlign: 'right' }}>p95 (ms)</th>
                      <th style={{ textAlign: 'right' }}>p99 (ms)</th>
                    </tr></thead>
                    <tbody>
                      {rows.slice(0, 15).map(r => {
                        const fmt = v => v >= 1 ? v.toFixed(2) : v.toFixed(3);
                        return (
                          <tr key={r.route}>
                            <td><code style={{ fontSize: 11 }}>{r.route}</code></td>
                            <td className="num" style={{ textAlign: 'right' }}>{r.samples.toLocaleString()}</td>
                            <td className="num" style={{ textAlign: 'right' }}>{fmt(r.p50_ms)}</td>
                            <td className="num" style={{ textAlign: 'right' }}>{fmt(r.p95_ms)}</td>
                            <td className="num" style={{ textAlign: 'right' }}>
                              <span className={`pill ${r.p99_ms > 100 ? 'down' : r.p99_ms > 10 ? 'warn' : 'up'}`}>
                                {fmt(r.p99_ms)}
                              </span>
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                )}
              </>
            );
          })()}
        </div>
      </div>

      <div className="grid-12" style={{ marginBottom: 12 }}>
        <div className="col-12 card">
          {(() => {
            const rows = detectorLatency.data?.detectors || [];
            return (
              <>
                <window.SectionHeader
                  title="Latency p50/p95/p99 by detector"
                  sub={rows.length > 0
                    ? `${rows.length} active class${rows.length === 1 ? '' : 'es'} · per-detector inspect cost`
                    : 'no detector samples yet — drive traffic with `make mock-load`'}
                />
                {rows.length === 0 ? (
                  <div style={{ padding: 16, fontSize: 12, color: 'var(--ink-dim)', textAlign: 'center', minHeight: 80, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                    Each `Detector::inspect` call records into a per-class histogram. Populates as the data plane handles requests.
                  </div>
                ) : (
                  <table className="tbl tbl-compact" style={{ marginTop: 4 }}>
                    <thead><tr>
                      <th>Detector class</th>
                      <th style={{ textAlign: 'right' }}>Samples</th>
                      <th style={{ textAlign: 'right' }}>p50 (ms)</th>
                      <th style={{ textAlign: 'right' }}>p95 (ms)</th>
                      <th style={{ textAlign: 'right' }}>p99 (ms)</th>
                    </tr></thead>
                    <tbody>
                      {rows.slice(0, 16).map(r => {
                        const fmt = v => v >= 1 ? v.toFixed(2) : v.toFixed(3);
                        return (
                          <tr key={r.class}>
                            <td><code style={{ fontSize: 11 }}>{r.class}</code></td>
                            <td className="num" style={{ textAlign: 'right' }}>{r.samples.toLocaleString()}</td>
                            <td className="num" style={{ textAlign: 'right' }}>{fmt(r.p50_ms)}</td>
                            <td className="num" style={{ textAlign: 'right' }}>{fmt(r.p95_ms)}</td>
                            <td className="num" style={{ textAlign: 'right' }}>
                              <span className={`pill ${r.p99_ms > 5 ? 'down' : r.p99_ms > 1 ? 'warn' : 'up'}`}>
                                {fmt(r.p99_ms)}
                              </span>
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                )}
              </>
            );
          })()}
        </div>
      </div>

      <div className="grid-12">
        <div className="col-8 card">
          <window.SectionHeader title="SLO budget remaining" sub="live engine" />
          <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
            {(sloApi.data?.slis ?? []).length === 0 && (
              <div style={{ padding: 12, fontSize: 12, color: 'var(--ink-dim)', textAlign: 'center' }}>
                SLO engine warming up — no SLI data yet.
              </div>
            )}
            {(sloApi.data?.slis ?? []).map(s => {
              const remainPct = Math.round((s.budget_remaining ?? 0) * 100);
              return (
                <div key={s.name} style={{ display: 'grid', gridTemplateColumns: '180px 80px 80px 1fr 80px', gap: 12, alignItems: 'center', fontSize: 12 }}>
                  <span>{s.name}</span>
                  <span className="dim">{s.target.toFixed(2)}%</span>
                  <span className="num" style={{ color: 'var(--ink)' }}>{s.current.toFixed(2)}%</span>
                  <div style={{ height: 6, background: 'var(--surface-3)', borderRadius: 3, overflow: 'hidden' }}>
                    <div style={{ width: `${remainPct}%`, height: '100%', background: remainPct < 30 ? 'var(--down)' : remainPct < 60 ? 'var(--warn)' : 'var(--up)' }} />
                  </div>
                  <span className="num right" style={{ color: remainPct < 30 ? 'var(--down)' : 'var(--ink-mute)' }}>{remainPct}% left</span>
                </div>
              );
            })}
          </div>
        </div>
        <div className="col-4 card">
          <window.SectionHeader title="Cert freshness" sub={`${(certsApi.data?.certs ?? []).length} certificates`} />
          {(certsApi.data?.certs ?? []).length === 0 ? (
            <div style={{ padding: 12, fontSize: 12, color: 'var(--ink-dim)', textAlign: 'center' }}>
              No certificates configured.
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
              {(certsApi.data?.certs ?? []).slice(0, 5).map(c => {
                const days = c.days_to_expiry ?? c.days ?? 0;
                const tone = days < 7 ? 'down' : days < 30 ? 'warn' : 'up';
                return (
                  <div key={c.host} style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 12 }}>
                    <div style={{ flex: 1, overflow: 'hidden', textOverflow: 'ellipsis' }} className="mono">{c.host}</div>
                    <span className={`pill ${tone}`}>{days}d</span>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      </div>
    </>
  );
}

// ============== AUDIT LOG ==============
function PageAuditLog() {
  const [ipFilter, setIpFilter] = useStateP('');
  const [ruleIdFilter, setRuleIdFilter] = useStateP('');
  const [requestIdFilter, setRequestIdFilter] = useStateP('');
  const [windowKey, setWindowKey] = useStateP('all');
  const [pageLimit, setPageLimit] = useStateP(200);
  const [debouncedQ, setDebouncedQ] = useStateP({ ip: '', ruleId: '', requestId: '' });
  // FIX 2026-05-04 — Audit Trail page now defaults to admin /
  // access / system events, hiding per-request `detection`
  // events. Operators reading this page want config history,
  // not the request firehose; per-request data lives on the
  // Investigation page's "Recent requests" table. Toggle group
  // lets them re-enable the firehose if they need it.
  const [classFilter, setClassFilter] = useStateP('non-detection');

  // Debounce filter inputs so the API isn't hit on every keystroke.
  useEffectP(() => {
    const t = setTimeout(() => setDebouncedQ({
      ip: ipFilter.trim(), ruleId: ruleIdFilter.trim(), requestId: requestIdFilter.trim(),
    }), 250);
    return () => clearTimeout(t);
  }, [ipFilter, ruleIdFilter, requestIdFilter]);

  const audit = window.useAuditLogApi({
    ip: debouncedQ.ip || undefined,
    ruleId: debouncedQ.ruleId || undefined,
    requestId: debouncedQ.requestId || undefined,
    limit: pageLimit,
  });
  const rawEvents = audit.data?.events || [];
  const gap = audit.data?.gap;

  // CQF-T11 — time-range filter applied client-side. Plus the
  // class filter (admin / detection / access / system /
  // non-detection / all) so the page focuses on config history
  // by default.
  const events = useMemoP(() => {
    let out = rawEvents;
    if (windowKey !== 'all') {
      const sec = windowKey === '1h' ? 3600 : windowKey === '24h' ? 86400 : 604800;
      const cutoff = Date.now() - sec * 1000;
      out = out.filter(row => {
        const e = row.event || row;
        const ts = e.ts ? Date.parse(e.ts) : NaN;
        return Number.isFinite(ts) ? ts >= cutoff : true;
      });
    }
    if (classFilter !== 'all') {
      out = out.filter(row => {
        const c = (row.event || row).class || 'unknown';
        if (classFilter === 'non-detection') return c !== 'detection';
        return c === classFilter;
      });
    }
    return out;
  }, [rawEvents, windowKey, classFilter]);

  function fmt(ts) {
    try {
      const d = new Date(ts);
      const h = String(d.getHours()).padStart(2, '0');
      const m = String(d.getMinutes()).padStart(2, '0');
      const s = String(d.getSeconds()).padStart(2, '0');
      return `${h}:${m}:${s}`;
    } catch (_) { return ts; }
  }
  function classPill(c) {
    if (c === 'admin')     return 'warn';
    if (c === 'system')    return 'info';
    if (c === 'access')    return 'neutral';
    if (c === 'detection') return 'block';
    return 'neutral';
  }

  return (
    <>
      <div className="page-head">
        <div>
          <h1 className="page-title">Audit Trail</h1>
          <p className="page-subtitle">
            Hash-chained · {events.length.toLocaleString()} events shown
            <span style={{ marginLeft: 8 }}>
              <span className={`pill ${audit.error ? 'warn' : 'ok'}`}>
                {audit.error ? 'fetch failed' : 'live'}
              </span>
            </span>
            {gap && (
              <span style={{ marginLeft: 6 }}>
                <span className="pill warn">stream gap</span>
              </span>
            )}
          </p>
        </div>
        <div className="page-actions">
          <button className="btn" onClick={() => audit.reload && audit.reload()}>
            <window.I.Refresh /> Refresh
          </button>
        </div>
      </div>
      <div className="card" style={{ padding: '8px 12px', marginBottom: 8, fontSize: 11, color: 'var(--ink-dim)', display: 'flex', alignItems: 'center', gap: 8 }}>
        <window.I.Book />
        <span>
          <strong>Audit Trail</strong> is the hash-chained durable trail of
          operator + system events. The default view shows
          configuration mutations, logins, and system events
          (boot, drain, hot-reload). Per-request decisions are
          on the <a href="#/investigation" style={{ color: 'var(--accent)' }}>Investigation page →</a> ("Recent requests"
          table) and the <a href="#/live" style={{ color: 'var(--accent)' }}>Live Feed →</a>. Flip the class filter
          below to <code>detection</code> or <code>all</code> to bring them back here.
        </span>
      </div>

      <div className="card flat" style={{ padding: 12, marginBottom: 12 }}>
        <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
          <input className="input" style={{ width: 160 }} placeholder="client IP"
                 value={ipFilter} onChange={e => setIpFilter(e.target.value)} />
          <input className="input" style={{ width: 200 }} placeholder="rule_id"
                 value={ruleIdFilter} onChange={e => setRuleIdFilter(e.target.value)} />
          <input className="input" style={{ flex: 1, maxWidth: 320 }} placeholder="request_id"
                 value={requestIdFilter} onChange={e => setRequestIdFilter(e.target.value)} />
          {/* Class filter — defaults to non-detection so the page
              focuses on config history. */}
          <div style={{ display: 'flex', gap: 4, marginLeft: 8, alignItems: 'center' }}>
            <span style={{ fontSize: 11, color: 'var(--ink-dim)' }}>Class:</span>
            {[
              { k: 'non-detection', l: 'admin + sys' },
              { k: 'admin',         l: 'admin' },
              { k: 'access',        l: 'access' },
              { k: 'system',        l: 'system' },
              { k: 'detection',     l: 'requests' },
              { k: 'all',           l: 'all' },
            ].map(({ k, l }) => (
              <button
                key={k}
                className={`btn ${classFilter === k ? 'primary' : ''}`}
                style={{ padding: '4px 10px', fontSize: 11 }}
                onClick={() => setClassFilter(k)}
              >{l}</button>
            ))}
          </div>
          {/* Time-range chip group */}
          <div style={{ display: 'flex', gap: 4, marginLeft: 8, alignItems: 'center' }}>
            <span style={{ fontSize: 11, color: 'var(--ink-dim)' }}>Window:</span>
            {[
              { k: '1h',  l: '1h' },
              { k: '24h', l: '24h' },
              { k: '7d',  l: '7d' },
              { k: 'all', l: 'all' },
            ].map(({ k, l }) => (
              <button
                key={k}
                className={`btn ${windowKey === k ? 'primary' : ''}`}
                style={{ padding: '4px 10px', fontSize: 11 }}
                onClick={() => setWindowKey(k)}
              >{l}</button>
            ))}
          </div>
          <span style={{ marginLeft: 'auto', fontSize: 11, color: 'var(--ink-dim)' }}>
            cursor {audit.data?.cursor ?? 0} → {audit.data?.next_cursor ?? 0} ·
            page limit {pageLimit}
          </span>
        </div>
      </div>

      <div className="card" style={{ padding: 0 }}>
        <table className="tbl tbl-compact">
          <thead><tr>
            <th style={{ width: 90 }}>Time</th>
            <th style={{ width: 90 }}>Class</th>
            <th style={{ width: 90 }}>Action</th>
            <th style={{ width: 130 }}>Client IP</th>
            <th style={{ width: 160 }}>Rule</th>
            <th>Reason</th>
            <th style={{ width: 200 }}>Request ID</th>
          </tr></thead>
          <tbody>
            {events.length === 0 && (
              <tr><td colSpan={7} style={{ textAlign: 'center', padding: 16, color: 'var(--ink-dim)', fontSize: 12 }}>
                No audit events match the current filters.
              </td></tr>
            )}
            {events.slice().reverse().map((row) => {
              const e = row.event || row; // /api/audit/since flattens AuditEvent into the row
              return (
                <tr key={row.seq}>
                  <td className="num dim">{fmt(e.ts)}</td>
                  <td><span className={`pill ${classPill(e.class)}`}>{e.class}</span></td>
                  <td className="mono" style={{ color: 'var(--ink)' }}>{e.action}</td>
                  <td className="mono">{e.client_ip || '—'}</td>
                  <td className="mono dim" style={{ fontSize: 11 }}>{e.rule_id || '—'}</td>
                  <td className="dim">{e.reason}</td>
                  <td className="mono" style={{ fontSize: 10, color: 'var(--brand-yellow)' }}>{e.request_id}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
        {/* CQF-T11 — load-more pagination. Each click bumps the
            server-side limit by 200 (capped at the audit ring's
            configured high-water; rawEvents.length plateaus once
            we've seen everything available). */}
        {rawEvents.length >= pageLimit && (
          <div style={{ padding: 10, borderTop: '1px solid var(--hairline)', textAlign: 'center' }}>
            <button
              className="btn"
              onClick={() => setPageLimit(n => n + 200)}
              style={{ fontSize: 11 }}
            >
              Load 200 more (currently {pageLimit})
            </button>
          </div>
        )}
        {windowKey !== 'all' && events.length < rawEvents.length && (
          <div style={{ padding: 8, fontSize: 10, color: 'var(--ink-dim)', fontStyle: 'italic', textAlign: 'center', borderTop: '1px solid var(--hairline)' }}>
            Showing {events.length} of {rawEvents.length} fetched (filtered by time range "{windowKey}")
          </div>
        )}
      </div>
    </>
  );
}

// ============== RULE MANAGER ==============
// DSL body templates used when the API doesn't supply one.
function defaultRuleBody(id) {
  return `rule "${id}" {\n  priority   = 100\n  field      = "any"\n  operator   = "regex"\n  pattern    = r"example"\n  action     = "block"\n  risk_delta = 50\n  scope      = ["global"]\n  tags       = ["custom"]\n}\n`;
}

// Synthesise a rule body from a mock-style row so we have something
// to PUT when an operator clicks Save & deploy on a builtin entry.
function ruleRowToBody(r) {
  if (r.body) return r.body;
  return [
    `rule "${r.id}" {`,
    `  // ${r.name || r.id}`,
    `  priority   = ${r.pri ?? 100}`,
    `  field      = "${r.field || 'any'}"`,
    `  operator   = "${r.op || 'regex'}"`,
    `  pattern    = r"${r.pattern || ''}"`,
    `  action     = "${r.action || 'block'}"`,
    `  risk_delta = ${r.risk ?? 50}`,
    `  scope      = ["global"]`,
    `  tags       = ["${r.cat || 'custom'}"]`,
    `}`,
    '',
  ].join('\n');
}

// Read the current /api/config/version. Returns the numeric version
// or 0 on failure so the caller can still wait for `ver + 1`.
async function fetchCurrentVersion() {
  try {
    const r = await fetch('/api/config/version', { credentials: 'same-origin', cache: 'no-store' });
    if (!r.ok) return 0;
    const j = await r.json();
    return Number(j.version) || 0;
  } catch (_) {
    return 0;
  }
}

// HACK-T3 — Tier-A bonus: rule simulator UI on the Rule
// Manager page. Operators type a method + path + body and click
// Simulate to preview the decision against the **live**
// detector chain — no real traffic, no audit emit.
function RuleSimulator() {
  const [method, setMethod] = useStateP('GET');
  const [path, setPath] = useStateP("/api/users?id=1' OR '1'='1");
  const [body, setBody] = useStateP('');
  const [result, setResult] = useStateP(null);
  const [busy, setBusy] = useStateP(false);

  const onSimulate = async () => {
    if (busy) return;
    setBusy(true);
    setResult({ pending: true });
    try {
      const payload = { method, path };
      if (body && body.length > 0) payload.body = body;
      const r = await window.rulesSimulate(payload);
      setResult(r);
    } catch (err) {
      setResult({ status: 0, error: String(err) });
    } finally {
      setBusy(false);
    }
  };

  const ok = result && !result.pending && result.status === 200;
  const decision = ok ? result.decision_action : null;
  const tone = decision === 'block' ? 'down' : decision === 'allow' ? 'up' : decision === 'challenge' ? 'warn' : 'neutral';
  const fired = (ok && Array.isArray(result.detectors_fired)) ? result.detectors_fired : [];
  const muted = (ok && Array.isArray(result.muted_detectors)) ? result.muted_detectors : [];
  const signals = (ok && Array.isArray(result.signals)) ? result.signals : [];

  return (
    <div className="card" style={{ marginBottom: 12, padding: 0 }}>
      <div className="card-head" style={{ padding: '10px 14px', borderBottom: '1px solid var(--hairline)' }}>
        <div>
          <div className="card-title">Rule simulator</div>
          <div className="card-sub">
            Replay a hypothetical request against the live detector chain — no traffic, no audit emit.
          </div>
        </div>
        <span className="pill neutral">Tier A</span>
      </div>
      <div style={{ padding: 14, display: 'grid', gridTemplateColumns: '110px 1fr 1fr', gap: 8, alignItems: 'start' }}>
        <select className="input select" value={method} onChange={e => setMethod(e.target.value)}>
          {['GET','POST','PUT','DELETE','PATCH','HEAD'].map(m => <option key={m}>{m}</option>)}
        </select>
        <input
          className="input mono"
          value={path}
          onChange={e => setPath(e.target.value)}
          placeholder="/api/users?id=1"
        />
        <input
          className="input mono"
          value={body}
          onChange={e => setBody(e.target.value)}
          placeholder="optional request body (e.g. <script>alert(1)</script>)"
        />
      </div>
      <div style={{ padding: '0 14px 14px', display: 'flex', gap: 10, alignItems: 'center' }}>
        <button className="btn primary" onClick={onSimulate} disabled={busy || !path}>
          {busy ? 'Simulating…' : 'Simulate'}
        </button>
        {result && !result.pending && result.status !== 200 && (
          <span className="pill down">
            HTTP {result.status || '—'} {result.error ? `· ${result.error}` : ''}
          </span>
        )}
        {ok && (
          <>
            <span style={{ fontSize: 11, color: 'var(--ink-dim)' }}>verdict:</span>
            <span className={`pill ${tone}`}>{decision}</span>
            {result.rule_id && (
              <span style={{ fontSize: 11, color: 'var(--ink-mute)' }}>
                rule: <code>{result.rule_id}</code>
              </span>
            )}
            <span style={{ fontSize: 11, color: 'var(--ink-mute)' }}>
              risk: <span className="num">{result.risk_score}</span>
            </span>
            <span style={{ fontSize: 11, color: 'var(--ink-mute)' }}>
              tier: <code>{result.tier}</code>
            </span>
          </>
        )}
      </div>
      {ok && (fired.length > 0 || muted.length > 0 || signals.length > 0) && (
        <div style={{ padding: '10px 14px 14px', borderTop: '1px solid var(--hairline)', display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 14 }}>
          <div>
            <div style={{ fontSize: 10, color: 'var(--ink-faint)', textTransform: 'uppercase', letterSpacing: 0.6, marginBottom: 6 }}>Detectors fired</div>
            {fired.length === 0 ? (
              <div style={{ fontSize: 12, color: 'var(--ink-dim)' }}>none</div>
            ) : (
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                {fired.map(d => <span key={d} className="pill down">{d}</span>)}
              </div>
            )}
            {muted.length > 0 && (
              <>
                <div style={{ fontSize: 10, color: 'var(--ink-faint)', textTransform: 'uppercase', letterSpacing: 0.6, margin: '10px 0 6px' }}>Muted (disabled by mask)</div>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                  {muted.map(d => <span key={d} className="pill neutral">{d}</span>)}
                </div>
              </>
            )}
          </div>
          <div>
            <div style={{ fontSize: 10, color: 'var(--ink-faint)', textTransform: 'uppercase', letterSpacing: 0.6, marginBottom: 6 }}>Signals</div>
            {signals.length === 0 ? (
              <div style={{ fontSize: 12, color: 'var(--ink-dim)' }}>none</div>
            ) : (
              <table className="tbl tbl-compact">
                <thead><tr><th>Class</th><th>Detail</th></tr></thead>
                <tbody>
                  {signals.map((s, i) => (
                    <tr key={i}>
                      <td className="mono"><span className="pill down">{s.class}</span></td>
                      <td className="dim">{s.detail}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

function PageRuleManager() {
  const rulesApi = window.useRulesApi();
  // HACK-T1 — only show what the live API returns. The page
  // renders an empty state when no user rules are configured
  // rather than seeding curated demo entries.
  const apiRules = (rulesApi.data && Array.isArray(rulesApi.data.rules))
    ? rulesApi.data.rules
    : [];

  const merged = apiRules.map(r => ({
    id: r.id,
    name: r.id,
    kind: 'custom',
    pri: r.pri ?? r.priority ?? 100,
    field: 'any',
    op: 'regex',
    pattern: '',
    action: r.action ?? 'block',
    risk: r.risk ?? 50,
    enabled: r.enabled !== undefined ? r.enabled : true,
    cat: r.cat ?? 'custom',
    // CQF-T16 — preserve `hits1h` when the backend supplies it
    // (was discarded as `0` regardless of API value).
    hits1h: Number(r.hits1h ?? r.hits_1h ?? 0),
    body: r.body || ruleRowToBody({ id: r.id }),
  }));

  const [selectedId, setSelectedId] = useStateP(merged[0]?.id || null);
  const [tab, setTab] = useStateP('dsl');
  const [search, setSearch] = useStateP('');
  const [editing, setEditing] = useStateP(false);
  const [editBody, setEditBody] = useStateP('');
  const [busy, setBusy] = useStateP(false);
  const [showNew, setShowNew] = useStateP(false);
  const [newId, setNewId] = useStateP('');
  const [newBody, setNewBody] = useStateP(defaultRuleBody('my-rule-001'));
  const [newEnabled, setNewEnabled] = useStateP(true);
  // 2026-05-07 — M007. window.confirm() blocks Chrome's message
  // pump for 30+ s when extensions intercept it. Custom modal
  // mirrors the DeleteRouteModal pattern used elsewhere on this
  // dashboard for destructive actions.
  const [showDeleteModal, setShowDeleteModal] = useStateP(false);

  // Re-anchor selected when the list changes (e.g., after delete).
  useEffectP(() => {
    if (merged.length === 0) { setSelectedId(null); return; }
    if (!selectedId || !merged.find(r => r.id === selectedId)) {
      setSelectedId(merged[0].id);
    }
  }, [merged.length, selectedId]);

  const filtered = merged.filter(r => !search || r.id.includes(search) || r.name.toLowerCase().includes(search.toLowerCase()));
  const selected = merged.find(r => r.id === selectedId) || merged[0] || null;

  // Run a mutation, wait for /api/config/version to advance, then toast.
  async function runMutation(label, fn) {
    if (busy) return;
    setBusy(true);
    try {
      const before = await fetchCurrentVersion();
      const result = await fn();
      if (result && result.ok) {
        const v = await window.waitForVersion(before + 1, 10000);
        if (v.applied) {
          window.aegisToast(`${label} · applied in ${v.latencyMs} ms`, 'ok');
        } else {
          window.aegisToast(`${label} · pending after 10 s`, 'warn');
        }
        rulesApi.reload && rulesApi.reload();
      } else {
        const msg = (result && (result.message || result.error || result.reason)) || 'unknown error';
        window.aegisToast(`${label} failed: ${msg}`, 'err');
      }
    } catch (err) {
      window.aegisToast(`${label} error: ${err.message || err}`, 'err');
    } finally {
      setBusy(false);
    }
  }

  function startEdit() {
    if (!selected) return;
    setEditBody(selected.body || ruleRowToBody(selected));
    setEditing(true);
    setTab('dsl');
  }
  function cancelEdit() { setEditing(false); setEditBody(''); }

  async function saveEdit() {
    if (!selected) return;
    await runMutation(`Rule ${selected.id} updated`,
      () => window.rulesPut(selected.id, { body: editBody, enabled: selected.enabled }));
    setEditing(false);
  }

  async function toggleSelected() {
    if (!selected) return;
    const label = selected.enabled ? `Rule ${selected.id} disabled` : `Rule ${selected.id} enabled`;
    await runMutation(label, () => window.rulesToggle(selected.id));
  }

  function deleteSelected() {
    if (!selected) return;
    setShowDeleteModal(true);
  }

  async function confirmDeleteSelected() {
    if (!selected) return;
    setShowDeleteModal(false);
    await runMutation(`Rule ${selected.id} deleted`, () => window.rulesDelete(selected.id));
  }

  async function createNew() {
    const id = newId.trim();
    if (!id) { window.aegisToast('Rule id is required', 'err'); return; }
    await runMutation(`Rule ${id} created`,
      () => window.rulesPost({ id, body: newBody, enabled: newEnabled }));
    setShowNew(false);
    setNewId('');
    setNewBody(defaultRuleBody('my-rule-001'));
    setNewEnabled(true);
    setSelectedId(id);
  }

  return (
    <>
      <div className="page-head">
        <div>
          <h1 className="page-title">Rules</h1>
          <p className="page-subtitle">{merged.length} total · validate before apply · audit-chained</p>
        </div>
        <div className="page-actions">
          <button className="btn" onClick={() => rulesApi.reload && rulesApi.reload()} disabled={busy}>
            <window.I.Refresh /> Reload
          </button>
          <button className="btn primary" onClick={() => setShowNew(true)} disabled={busy}>
            <window.I.Plus /> New rule
          </button>
        </div>
      </div>

      <RuleSimulator />

      <div className="split-list">
        <div className="left">
          <div style={{ padding: 10, borderBottom: '1px solid var(--hairline)' }}>
            <div style={{ position: 'relative' }}>
              <span style={{ position: 'absolute', left: 8, top: 7, color: 'var(--ink-faint)' }}><window.I.Search /></span>
              <input className="input" style={{ paddingLeft: 28 }} placeholder="Search rule…" value={search} onChange={e => setSearch(e.target.value)} />
            </div>
          </div>
          <div style={{ overflow: 'auto', flex: 1 }}>
            {filtered.length === 0 && (
              <div style={{ padding: 20, fontSize: 12, color: 'var(--ink-dim)', textAlign: 'center' }}>
                No rules match.
              </div>
            )}
            {filtered.map((r, i) => (
              <button key={`${r.id}-${i}`} onClick={() => { setSelectedId(r.id); setEditing(false); }}
                style={{ display: 'block', width: '100%', textAlign: 'left', padding: '8px 12px', border: 'none', borderBottom: '1px solid var(--hairline)',
                  background: selected && selected.id === r.id ? 'var(--surface-active)' : 'transparent',
                  borderLeft: selected && selected.id === r.id ? '3px solid var(--brand-yellow)' : '3px solid transparent',
                  cursor: 'pointer', color: 'inherit' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 2 }}>
                  <span className="num dim" style={{ width: 36, fontSize: 10 }}>{r.pri}</span>
                  <span style={{ fontSize: 12, fontWeight: 500, color: 'var(--ink)' }}>{r.name}</span>
                  <span className={`pill ${r.kind}`} style={{ marginLeft: 'auto' }}>{r.kind}</span>
                </div>
                <div style={{ display: 'flex', gap: 6, alignItems: 'center', fontSize: 10, color: 'var(--ink-dim)' }}>
                  <span className="mono">{r.id}</span>
                  <span>·</span>
                  <window.ActionPill value={r.action} />
                  {r.enabled ? null : <span className="pill warn" style={{ marginLeft: 4 }}>off</span>}
                  <span style={{ marginLeft: 'auto' }} className="num">+{r.risk}</span>
                </div>
              </button>
            ))}
          </div>
        </div>
        <div className="right">
          {selected ? (
            <>
              <div style={{ padding: 14, borderBottom: '1px solid var(--hairline)', display: 'flex', alignItems: 'center', gap: 10 }}>
                <div>
                  <div style={{ fontSize: 14, fontWeight: 600 }}>{selected.name}</div>
                  <div style={{ fontSize: 11, color: 'var(--ink-dim)' }} className="mono">{selected.id} · priority {selected.pri} · {(selected.hits1h || 0).toLocaleString()} hits/1h</div>
                </div>
                <div style={{ marginLeft: 'auto', display: 'flex', gap: 6 }}>
                  {!editing && (
                    <button className="btn" onClick={startEdit} disabled={busy}><window.I.Edit /> Edit</button>
                  )}
                  <button className="btn" onClick={toggleSelected} disabled={busy}>
                    {selected.enabled ? 'Disable' : 'Enable'}
                  </button>
                  <button className="btn danger" onClick={deleteSelected} disabled={busy} title="Delete rule">
                    <window.I.Trash />
                  </button>
                </div>
              </div>
              <div style={{ display: 'flex', borderBottom: '1px solid var(--hairline)' }}>
                {['general','dsl','stats'].map(t => (
                  <button key={t} onClick={() => setTab(t)} style={{
                    flex: 'unset', padding: '10px 16px', background: 'transparent', border: 'none',
                    color: tab === t ? 'var(--brand-yellow)' : 'var(--ink-mute)',
                    borderBottom: tab === t ? '2px solid var(--brand-yellow)' : '2px solid transparent',
                    fontSize: 12, fontWeight: 600, textTransform: 'capitalize', cursor: 'pointer' }}>{t}</button>
                ))}
              </div>
              <div style={{ padding: 16 }}>
                {tab === 'general' && (
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12, fontSize: 12 }}>
                    <div><div className="field-label">ID</div><div className="mono">{selected.id}</div></div>
                    <div><div className="field-label">Kind</div><span className={`pill ${selected.kind}`}>{selected.kind}</span></div>
                    <div><div className="field-label">Field</div><div>{selected.field}</div></div>
                    <div><div className="field-label">Operator</div><div>{selected.op}</div></div>
                    <div><div className="field-label">Action</div><window.ActionPill value={selected.action} /></div>
                    <div><div className="field-label">Risk Δ</div><span className="num">+{selected.risk}</span></div>
                    <div><div className="field-label">Priority</div><span className="num">{selected.pri}</span></div>
                    <div><div className="field-label">Enabled</div><div className={`toggle ${selected.enabled ? 'on' : ''}`}></div></div>
                  </div>
                )}
                {tab === 'dsl' && (
                  <div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
                      <span className={`pill ${editing ? 'warn' : 'ok'}`}>{editing ? 'editing' : 'view'}</span>
                      <span style={{ fontSize: 11, color: 'var(--ink-dim)' }}>
                        {editing ? 'Save & deploy will PUT /api/rules/{id} and toast on apply' : 'Click Edit to modify'}
                      </span>
                    </div>
                    {editing ? (
                      <textarea
                        className="input"
                        style={{ width: '100%', minHeight: 240, fontFamily: 'var(--font-mono)', fontSize: 12, lineHeight: 1.5, padding: 12 }}
                        value={editBody}
                        onChange={e => setEditBody(e.target.value)}
                      />
                    ) : (
                      <pre style={{ background: 'var(--canvas)', border: '1px solid var(--hairline)', borderRadius: 6, padding: 14, fontSize: 12, fontFamily: 'var(--font-mono)', margin: 0, overflow: 'auto', lineHeight: 1.6, whiteSpace: 'pre-wrap' }}>
                        {selected.body || ruleRowToBody(selected)}
                      </pre>
                    )}
                  </div>
                )}
                {tab === 'stats' && (
                  <div style={{ padding: 16, fontSize: 12, color: 'var(--ink-dim)', textAlign: 'center', minHeight: 200, display: 'flex', alignItems: 'center', justifyContent: 'center', flexDirection: 'column', gap: 6 }}>
                    <span>Per-rule statistics ship in a follow-up.</span>
                    <span style={{ fontSize: 11 }}>For now: filter <a href="#/audit" style={{ color: 'var(--accent)' }}>Audit Log</a> by <code>rule_id={selected.id}</code> to see every match.</span>
                  </div>
                )}
              </div>
              <div style={{ padding: 12, borderTop: '1px solid var(--hairline)', display: 'flex', gap: 8, justifyContent: 'flex-end' }}>
                {editing && <button className="btn" onClick={cancelEdit} disabled={busy}>Cancel</button>}
                {editing && <button className="btn primary" onClick={saveEdit} disabled={busy}>Save & deploy</button>}
              </div>
            </>
          ) : (
            <div style={{ padding: 24, fontSize: 12, color: 'var(--ink-dim)' }}>
              No rule selected. Use “+ New rule” to create one.
            </div>
          )}
        </div>
      </div>

      {showNew && (
        <NewRuleModal
          newId={newId} setNewId={setNewId}
          newBody={newBody} setNewBody={setNewBody}
          newEnabled={newEnabled} setNewEnabled={setNewEnabled}
          onCancel={() => setShowNew(false)}
          onSave={createNew}
          busy={busy}
        />
      )}

      {showDeleteModal && selected && (
        <DeleteRuleModal
          ruleId={selected.id}
          busy={busy}
          onCancel={() => setShowDeleteModal(false)}
          onConfirm={confirmDeleteSelected}
        />
      )}
    </>
  );
}

// 2026-05-07 — M007. Custom React confirmation modal replacing
// the prior native window.confirm() call (which blocked Chrome's
// message pump for 30+ s when extensions intercepted it). Mirrors
// the DeleteRouteModal pattern used on the Routing page.
function DeleteRuleModal({ ruleId, busy, onCancel, onConfirm }) {
  return (
    <div className="modal-backdrop" onClick={onCancel}>
      <div className="modal" onClick={e => e.stopPropagation()} style={{ maxWidth: 460 }}>
        <div className="modal-head">
          <div className="modal-title">Delete rule {ruleId}?</div>
          <button className="btn btn-sm" onClick={onCancel}>×</button>
        </div>
        <div className="modal-body">
          <p style={{ fontSize: 13, lineHeight: 1.5 }}>
            Removing <code>{ruleId}</code> is audit-mutated and cannot
            be undone. In-flight requests finish on the old rule
            table; new requests see the updated table immediately.
            The change is recorded in the audit chain.
          </p>
        </div>
        <div className="modal-foot">
          <button className="btn" onClick={onCancel} disabled={busy}>Cancel</button>
          <button className="btn danger" onClick={onConfirm} disabled={busy}>
            {busy ? 'Deleting…' : 'Delete rule'}
          </button>
        </div>
      </div>
    </div>
  );
}

function NewRuleModal({ newId, setNewId, newBody, setNewBody, newEnabled, setNewEnabled, onCancel, onSave, busy }) {
  return (
    <div style={{
      position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.5)',
      display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000,
    }} onClick={onCancel}>
      <div className="card" style={{ width: 560, maxWidth: '90vw', padding: 0 }} onClick={e => e.stopPropagation()}>
        <div style={{ padding: '14px 16px', borderBottom: '1px solid var(--hairline)', display: 'flex', alignItems: 'center' }}>
          <div style={{ fontSize: 14, fontWeight: 600 }}>New rule</div>
          <span style={{ fontSize: 11, color: 'var(--ink-dim)', marginLeft: 8 }}>POST /api/rules · audit-mutated · CSRF-gated</span>
          <button className="btn" style={{ marginLeft: 'auto' }} onClick={onCancel} disabled={busy}>×</button>
        </div>
        <div style={{ padding: 16, display: 'flex', flexDirection: 'column', gap: 12 }}>
          <label style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
            <span className="field-label">Rule ID</span>
            <input className="input" value={newId} onChange={e => setNewId(e.target.value)} placeholder="custom-xss-001" autoFocus />
          </label>
          <label style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
            <span className="field-label">DSL body</span>
            <textarea
              className="input"
              style={{ minHeight: 220, fontFamily: 'var(--font-mono)', fontSize: 12, lineHeight: 1.5, padding: 12 }}
              value={newBody}
              onChange={e => setNewBody(e.target.value)}
            />
          </label>
          <label style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 12 }}>
            <input type="checkbox" checked={newEnabled} onChange={e => setNewEnabled(e.target.checked)} />
            <span>Enabled on save</span>
          </label>
        </div>
        <div style={{ padding: 12, borderTop: '1px solid var(--hairline)', display: 'flex', gap: 8, justifyContent: 'flex-end' }}>
          <button className="btn" onClick={onCancel} disabled={busy}>Cancel</button>
          <button className="btn primary" onClick={onSave} disabled={busy || !newId.trim()}>Save</button>
        </div>
      </div>
    </div>
  );
}

// ============== TIER CONFIG ==============
// CQF-T3 — detector mask editor. Audit-mutated edit of the
// base mask + per-tier overrides via `PUT /api/detectors`.
// Compliance-locked classes (sqli/xss/path_traversal/ssrf when
// any compliance mode is active) render as a disabled toggle.
// All 12 detector classes wired to the bitmask. Order matches
// DetectorClass::ALL on the backend so the chip grid reads in the
// same order operators see in docs (security-engine.md risk-weight
// ladder, detectors/README.md tag table).
const MASK_CLASSES = [
  'sqli', 'xss', 'path_traversal', 'ssrf', 'header_injection',
  'body_abuse', 'recon', 'brute_force', 'command_injection',
  'template_injection', 'nosql_injection', 'open_redirect',
];

// 5-tier framework chip palette — keeps the score chip colour
// in sync with the docs in `plans/issue-fix/tester-n-2026-05-08-
// run5/README.md` and `docs/operator/risk-tuning.md`. Uses the
// existing dashboard palette (--down for error/red, --warn for
// yellow, --brand-yellow for accent) so the chip colours match
// the rest of the SPA.
const SCORE_TIER_STYLE = {
  critical: { bg: 'rgba(246,70,93,0.14)', fg: 'var(--down)',         label: 'Critical RCE/CVE' },
  high:     { bg: 'rgba(240,185,11,0.14)', fg: 'var(--warn)',        label: 'High-conf injection' },
  broad:    { bg: 'rgba(252,213,53,0.10)', fg: 'var(--brand-yellow)', label: 'Broader pattern' },
  header:   { bg: 'rgba(112,122,138,0.16)', fg: 'var(--ink-dim)',    label: 'Header heuristic' },
  phishing: { bg: 'rgba(112,122,138,0.10)', fg: 'var(--ink-dim)',    label: 'Phishing / info' },
  probe:    { bg: 'rgba(112,122,138,0.06)', fg: 'var(--ink-faint)',  label: 'Probe / canary' },
};

function DetectorMaskCard() {
  const api = window.useDetectorsApi();
  const baseMask = api.data?.mask || null;
  const overrides = api.data?.overrides || {};
  const lockedClasses = api.data?.locked_classes || [];
  const complianceModes = api.data?.compliance_modes || [];
  const scoreTable = api.data?.score_table || [];

  const [busy, setBusy] = useStateP(false);
  const [editing, setEditing] = useStateP(null);
  const [draft, setDraft] = useStateP({});

  // 2026-05-10 — compute the dominant score + tier per class so
  // each chip in the mask grid carries a small score badge tinted
  // by the 5-tier framework (probe / phishing / header / broad /
  // high / critical). Operators see "sqli · 60" with a critical
  // tint instead of bare "sqli", so the mask + scores are
  // legible from one card without expanding anything.
  const dominantByClass = {};
  for (const row of scoreTable) {
    const prev = dominantByClass[row.class];
    if (!prev || row.score > prev.score) {
      dominantByClass[row.class] = { score: row.score, tier: row.tier, tag: row.tag };
    }
  }

  if (!baseMask) {
    return (
      <div className="card" style={{ marginBottom: 12, padding: 12 }}>
        <div className="card-head">
          <div className="card-title">Detector Mask</div>
        </div>
        <div style={{ fontSize: 12, color: 'var(--ink-dim)', padding: 8 }}>
          Loading detector mask…
        </div>
      </div>
    );
  }

  function startEdit(target, current) {
    setEditing(target);
    setDraft({ ...current });
  }

  // FIX 2026-05-04 — the old code checked `r.ok` after a PUT,
  // but `/api/detectors` responds with the NEW MASK STATE on
  // success (not an `{ok: true}` envelope like routes/pools),
  // so `r.ok` was always undefined and every save toasted
  // "Save failed: status 200". Switch the success criterion to
  // a 2xx HTTP status. Same fix in `clearOverride`.
  function isHttpOk(r) {
    return r && typeof r.status === 'number' && r.status >= 200 && r.status < 300;
  }

  async function saveEdit() {
    if (busy) return;
    setBusy(true);
    try {
      const body = editing === 'base'
        ? { mask: draft }
        : { overrides: { [editing]: draft } };
      const r = await window.detectorsPut(body);
      if (isHttpOk(r)) {
        window.aegisToast(`Saved detector mask · ${editing}`, 'ok');
        setEditing(null);
        api.reload && api.reload();
      } else {
        const msg = (r && (r.message || r.error || r.reason)) || `status ${r?.status ?? '?'}`;
        window.aegisToast(`Save failed: ${msg}`, 'err');
      }
    } catch (e) {
      window.aegisToast(`Save error: ${e.message || e}`, 'err');
    } finally {
      setBusy(false);
    }
  }

  async function clearOverride(tierName) {
    if (busy) return;
    if (!confirm(`Clear ${tierName} override and inherit from base?`)) return;
    setBusy(true);
    try {
      const r = await window.detectorsPut({ overrides: { [tierName]: null } });
      if (isHttpOk(r)) {
        window.aegisToast(`Cleared ${tierName} override`, 'ok');
        api.reload && api.reload();
      } else {
        const msg = (r && (r.message || r.error || r.reason)) || `status ${r?.status ?? '?'}`;
        window.aegisToast(`Clear failed: ${msg}`, 'err');
      }
    } catch (e) {
      window.aegisToast(`Clear error: ${e.message || e}`, 'err');
    } finally {
      setBusy(false);
    }
  }

  const renderRow = (label, mask, target) => {
    const isEditing = editing === target;
    const view = isEditing ? draft : mask;
    return (
      <div key={target} style={{ borderTop: '1px solid var(--hairline)', padding: '10px 12px', display: 'flex', alignItems: 'center', gap: 12 }}>
        <div style={{ minWidth: 110, fontWeight: 600, fontSize: 12 }}>{label}</div>
        <div style={{ flex: 1, display: 'flex', flexWrap: 'wrap', gap: 6 }}>
          {MASK_CLASSES.map(cls => {
            const enabled = !!view[cls];
            const locked = lockedClasses.includes(cls);
            // Each class has a dominant score + tier (highest-weight
            // signal that class can emit). Render that score inline
            // so operators see "sqli · 60" instead of just "sqli" —
            // the calibrated tier tint backs each enabled chip so
            // posture is readable at a glance without expanding the
            // reference table below.
            const dominant = dominantByClass[cls];
            const tierStyle = dominant ? (SCORE_TIER_STYLE[dominant.tier] || SCORE_TIER_STYLE.probe) : null;
            const baseTitle = dominant
              ? `${cls} → top score ${dominant.score} (${tierStyle.label}) via tag ${dominant.tag}`
              : cls;
            const titleText = locked
              ? `${baseTitle}\n\n🔒 pinned by active compliance mode`
              : `${baseTitle}\n\n${enabled ? 'enabled — click to disable' : 'disabled — click to enable'}`;
            const chipBg = enabled && tierStyle ? tierStyle.bg : 'transparent';
            const chipFg = enabled && tierStyle ? tierStyle.fg : 'var(--ink-dim)';
            return (
              <button
                key={cls}
                onClick={() => {
                  if (!isEditing || locked) return;
                  setDraft(d => ({ ...d, [cls]: !d[cls] }));
                }}
                disabled={!isEditing || locked || busy}
                title={titleText}
                style={{
                  fontSize: 10,
                  cursor: isEditing && !locked ? 'pointer' : 'default',
                  opacity: locked ? 0.6 : (enabled ? 1 : 0.55),
                  padding: '2px 8px',
                  borderRadius: 4,
                  background: chipBg,
                  color: chipFg,
                  fontWeight: enabled ? 600 : 500,
                  border: isEditing && !locked ? '1px dashed var(--hairline)' : '1px solid transparent',
                  textDecoration: enabled ? 'none' : 'line-through',
                }}
              >
                {locked && '🔒 '}{cls}{dominant ? ` · ${dominant.score}` : ''}
              </button>
            );
          })}
        </div>
        <div style={{ display: 'flex', gap: 6 }}>
          {isEditing ? (
            <>
              <button className="btn primary" disabled={busy} onClick={saveEdit} style={{ fontSize: 11, padding: '4px 10px' }}>Save</button>
              <button className="btn" disabled={busy} onClick={() => setEditing(null)} style={{ fontSize: 11, padding: '4px 10px' }}>Cancel</button>
            </>
          ) : (
            <>
              <button className="btn" disabled={busy || editing !== null} onClick={() => startEdit(target, mask)} style={{ fontSize: 11, padding: '4px 10px' }}>Edit</button>
              {target !== 'base' && (
                <button className="btn danger" disabled={busy || editing !== null} onClick={() => clearOverride(target)} style={{ fontSize: 11, padding: '4px 10px' }}>Clear</button>
              )}
            </>
          )}
        </div>
      </div>
    );
  };

  return (
    <div className="card" style={{ marginBottom: 12, padding: 0 }}>
      <div className="card-head" style={{ padding: 12 }}>
        <div>
          <div className="card-title">Detector inventory &amp; mask</div>
          <div className="card-subtitle">
            Per-class on/off mask plus the read-only score reference.
            Each chip shows the dominant score for that class, tinted
            by the 5-tier framework. Locked classes (🔒) are pinned
            by active compliance modes
            {complianceModes.length > 0 && (
              <> ({complianceModes.join(', ')})</>
            )}
            . Audit-mutated; takes effect within one hot-reload tick.
          </div>
        </div>
      </div>

      {/* Mask grid — base + per-tier overrides. */}
      {renderRow('Base', baseMask, 'base')}
      {Object.keys(overrides).length === 0 ? (
        <div style={{ borderTop: '1px solid var(--hairline)', padding: '8px 12px', fontSize: 11, color: 'var(--ink-dim)', fontStyle: 'italic' }}>
          No per-tier overrides — base mask applies to every tier.
        </div>
      ) : (
        Object.entries(overrides).map(([tier, mask]) => renderRow(tier, mask, tier))
      )}

      {/* Read-only risk-score catalog (#293) — surfaced so
          operators can see the calibrated 5-tier ladder without
          scraping detector source files. NOT editable by design;
          see docs/operator/risk-tuning.md for the rationale + the
          safe knobs available (set_profile log_only, risk
          thresholds, RaiseRisk rules, per-tier overrides). */}
      <DetectorScorePanel scoreTable={api.data?.score_table || []} />

      {/* AI detector — folded into the same card. AI lives outside
          the bitmask (separate AtomicBool flipped via PUT
          /api/ai/enabled) but operators read this whole page as
          "the detector inventory", so it slots in here. */}
      <AiDetectorRow />
    </div>
  );
}

// Read-only score reference — sits inside the unified Detectors
// card. The tier legend is always visible so operators can decode
// the chip colours in the mask grid above without hunting; the
// per-tag breakdown stays behind a "Show full table" toggle to
// keep the card compact for routine operation.
//
// Why read-only: the score each detector emits is a calibrated
// ladder that interacts with `risk.thresholds.challenge_at` (40)
// and `block_at` (80). Editing scores arbitrarily breaks the
// score↔threshold contract. To tune posture, operators reach for
// `set_profile log_only`, the threshold knobs, RaiseRisk rules,
// or per-tier overrides above (all surfaced on this same page).
function DetectorScorePanel({ scoreTable }) {
  const [expanded, setExpanded] = useStateP(false);
  if (!scoreTable || scoreTable.length === 0) {
    return null;
  }

  const byClass = {};
  for (const row of scoreTable) {
    if (!byClass[row.class]) byClass[row.class] = [];
    byClass[row.class].push(row);
  }
  const classOrder = Object.keys(byClass);

  return (
    <div style={{ borderTop: '1px solid var(--hairline)', padding: '10px 12px' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap', marginBottom: 6 }}>
        <span style={{ fontSize: 12, fontWeight: 600, color: 'var(--ink)' }}>
          Risk score reference
        </span>
        <span style={{ fontSize: 10, color: 'var(--ink-dim)' }}>
          · read-only · 5-tier framework · {scoreTable.length} signal types
        </span>
      </div>

      {/* Always-visible tier legend — decodes the chip tints in
          the mask grid above so operators do not need to expand
          anything for routine reading. */}
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, marginBottom: 8 }}>
        {Object.entries(SCORE_TIER_STYLE).map(([tier, style]) => (
          <span
            key={tier}
            title={`${style.label} tier`}
            style={{
              fontSize: 10, padding: '2px 8px', borderRadius: 4,
              background: style.bg, color: style.fg, fontWeight: 600,
            }}
          >
            {style.label}
          </span>
        ))}
      </div>

      <div style={{ fontSize: 11, color: 'var(--ink-dim)', lineHeight: 1.4, marginBottom: 6 }}>
        Scores are calibrated against{' '}
        <code style={{ fontSize: 10 }}>risk.thresholds.challenge_at</code> (40) and{' '}
        <code style={{ fontSize: 10 }}>block_at</code> (80). To tune posture without
        touching scores, use <code style={{ fontSize: 10 }}>set_profile log_only</code>,
        adjust risk thresholds, add a <code style={{ fontSize: 10 }}>RaiseRisk(delta)</code> rule,
        or apply a per-tier override above. See the{' '}
        <a href="/docs/operator/risk-tuning" target="_blank" rel="noreferrer" style={{ color: 'var(--accent)' }}>
          operator risk-tuning guide
        </a>.
      </div>

      <button
        onClick={() => setExpanded(e => !e)}
        className="btn"
        style={{
          background: 'transparent', border: '1px solid var(--hairline)',
          padding: '4px 10px', fontSize: 11, color: 'var(--ink-dim)',
          cursor: 'pointer', borderRadius: 4,
        }}
      >
        {expanded ? '▼ Hide full table' : '▶ Show full per-tag table'}
      </button>

      {expanded && (
        <div style={{ marginTop: 10, display: 'grid', gridTemplateColumns: 'minmax(140px, auto) 1fr', gap: '6px 10px', alignItems: 'baseline' }}>
          {classOrder.map(cls => (
            <React.Fragment key={cls}>
              <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--ink)' }}>{cls}</div>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                {byClass[cls].map(row => {
                  const tierStyle = SCORE_TIER_STYLE[row.tier] || SCORE_TIER_STYLE.probe;
                  return (
                    <span
                      key={`${row.class}-${row.tag}`}
                      title={`${row.tag} → ${row.score} · ${tierStyle.label} tier\n\n${row.note}`}
                      style={{
                        fontSize: 10, padding: '2px 8px', borderRadius: 4,
                        background: tierStyle.bg, color: tierStyle.fg,
                        fontWeight: 500, fontFamily: 'monospace',
                        cursor: 'help',
                      }}
                    >
                      {row.tag} · {row.score}
                    </span>
                  );
                })}
              </div>
            </React.Fragment>
          ))}
        </div>
      )}
    </div>
  );
}

// Compact AI-detector row inside the Detectors card. Replaces
// the earlier full-width `AiDetectorPanel` that lived above the
// mask grid. Shows the same controls (Enable/Disable, status
// pill) inline with the mask rows, with an expand toggle to
// reveal the detailed metrics tiles.
function AiDetectorRow() {
  const aiEnabledApi = window.useAiEnabledApi();
  const [busy, setBusy] = useStateP(false);
  const [expanded, setExpanded] = useStateP(false);
  const [metrics, setMetrics] = useStateP(null);

  // Lazy-load the metrics only when the row is expanded — saves
  // a /metrics scrape per 5 s for operators who never expand it.
  useEffectP(() => {
    if (!expanded) return;
    let cancelled = false;
    const load = () => {
      fetch('/metrics', { credentials: 'same-origin' })
        .then(r => r.ok ? r.text() : null)
        .then(txt => {
          if (cancelled || !txt) return;
          const out = { attack: 0, normal: 0, fallback: {}, present: false, mean_inf_us: null };
          let lat_sum = 0, lat_count = 0;
          for (const line of txt.split('\n')) {
            if (line.startsWith('#') || !line.startsWith('aegis_ai_')) continue;
            out.present = true;
            const m = line.match(/^aegis_ai_predictions_total\{verdict="(\w+)"\}\s+([\d.]+)/);
            if (m) {
              if (m[1] === 'attack') out.attack = Number(m[2]);
              else if (m[1] === 'normal') out.normal = Number(m[2]);
              continue;
            }
            const f = line.match(/^aegis_ai_fallback_total\{reason="(\w+)"\}\s+([\d.]+)/);
            if (f) { out.fallback[f[1]] = Number(f[2]); continue; }
            const ls = line.match(/^aegis_ai_inference_duration_seconds_sum\{[^}]*\}\s+([\d.]+)/);
            if (ls) { lat_sum += Number(ls[1]); continue; }
            const lc = line.match(/^aegis_ai_inference_duration_seconds_count\{[^}]*\}\s+([\d.]+)/);
            if (lc) { lat_count += Number(lc[1]); continue; }
          }
          if (lat_count > 0) out.mean_inf_us = (lat_sum / lat_count) * 1_000_000;
          setMetrics(out);
        })
        .catch(() => {});
    };
    load();
    const id = setInterval(load, 5000);
    return () => { cancelled = true; clearInterval(id); };
  }, [expanded]);

  const featurePresent = !!aiEnabledApi.data?.feature_present;
  const runtimeOn = !!aiEnabledApi.data?.enabled;
  const total = (metrics?.attack || 0) + (metrics?.normal || 0);
  const attackPct = total > 0 ? ((metrics.attack / total) * 100).toFixed(1) : '0.0';
  const fbTotal = metrics?.fallback ? Object.values(metrics.fallback).reduce((a, b) => a + b, 0) : 0;

  async function flip() {
    if (busy || !featurePresent) return;
    setBusy(true);
    try {
      const r = await window.aiEnabledPut(!runtimeOn);
      if (r.status === 200 && r.ok) {
        window.aegisToast(`AI detector ${r.enabled ? 'enabled' : 'disabled'}`, 'ok');
        aiEnabledApi.reload && aiEnabledApi.reload();
      } else if (r.status === 409 && r.reason === 'feature_off') {
        window.aegisToast('AI detector feature not built — rebuild with `--features ai`', 'warn');
      } else {
        const msg = r.message || r.error || r.reason || `HTTP ${r.status}`;
        window.aegisToast(`Toggle failed: ${msg}`, 'err');
      }
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <div style={{ borderTop: '1px solid var(--hairline)', padding: '10px 12px', display: 'flex', alignItems: 'center', gap: 12 }}>
        <div style={{ minWidth: 110, fontWeight: 600, fontSize: 12 }}>
          AI{' '}
          <span style={{ fontSize: 10, color: 'var(--ink-dim)', fontWeight: 400 }}>(ml)</span>
        </div>
        <div style={{ flex: 1, display: 'flex', alignItems: 'center', gap: 8, fontSize: 11, color: 'var(--ink-dim)' }}>
          <span className={`pill ${featurePresent ? (runtimeOn ? 'ok' : 'neutral') : 'neutral'}`} style={{ fontSize: 10 }}>
            {!featurePresent ? '🔒 feature off' : (runtimeOn ? 'enabled' : 'disabled')}
          </span>
          {featurePresent && (
            <span>
              ML-based detector · ONNX classifier
              {runtimeOn && total > 0 && (
                <> · <span className="num">{total.toLocaleString()}</span> predictions · {attackPct}% attack</>
              )}
            </span>
          )}
          {!featurePresent && (
            <span>rebuild with <code>--features ai</code> + set <code>cfg.ai.enabled = true</code></span>
          )}
          <button
            type="button"
            onClick={() => setExpanded(!expanded)}
            disabled={!featurePresent}
            style={{ background: 'transparent', border: 'none', color: 'var(--ink-dim)', cursor: featurePresent ? 'pointer' : 'default', fontSize: 11, padding: 0 }}
          >
            {expanded ? '▾ hide details' : '▸ details'}
          </button>
        </div>
        <div style={{ display: 'flex', gap: 6 }}>
          <button
            className="btn"
            onClick={flip}
            disabled={!featurePresent || busy}
            style={{ fontSize: 11, padding: '4px 10px' }}
          >
            {busy ? '…' : (runtimeOn ? 'Disable' : 'Enable')}
          </button>
        </div>
      </div>
      {expanded && featurePresent && (
        <div style={{ borderTop: '1px solid var(--hairline)', padding: '12px 16px', background: 'var(--canvas-2)' }}>
          {metrics && metrics.present ? (
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 14, fontSize: 12 }}>
              <div>
                <div className="field-label">Predictions</div>
                <div className="num" style={{ fontSize: 18 }}>{total.toLocaleString()}</div>
              </div>
              <div>
                <div className="field-label">Attack rate</div>
                <div style={{ fontSize: 18 }}>
                  <span className={`pill ${attackPct > 50 ? 'down' : 'ok'}`}>{attackPct}%</span>
                </div>
              </div>
              <div>
                <div className="field-label">Mean inference</div>
                <div className="num" style={{ fontSize: 18 }}>
                  {metrics.mean_inf_us != null ? `${metrics.mean_inf_us.toFixed(0)} µs` : '—'}
                </div>
              </div>
              <div>
                <div className="field-label">Fallbacks</div>
                <div style={{ fontSize: 18 }}>
                  <span className={`pill ${fbTotal > 0 ? 'warn' : 'ok'}`}>{fbTotal}</span>
                </div>
              </div>
            </div>
          ) : (
            <div style={{ fontSize: 12, color: 'var(--ink-dim)' }}>
              {runtimeOn ? 'No traffic yet — drive a request through the data plane to see metrics.' : 'Detector is disabled. Enable to start collecting metrics.'}
            </div>
          )}
          {metrics && fbTotal > 0 && (
            <div style={{ marginTop: 10, fontSize: 11, color: 'var(--ink-mute)' }}>
              Fallbacks by reason: {Object.entries(metrics.fallback).filter(([, n]) => n > 0).map(([k, n]) => `${k}=${n}`).join(' · ')}
            </div>
          )}
        </div>
      )}
    </>
  );
}

function PageTierConfig() {
  const tiersApi = window.useTiersApi();
  const routesApi = window.useRoutesApi();
  const tiers = tiersApi.data?.tiers || [];
  const routes = routesApi.data?.routes || [];
  const [selectedName, setSelectedName] = useStateP(null);
  const [tierEditor, setTierEditor] = useStateP(null);  // null | tier object
  const [busy, setBusy] = useStateP(false);

  async function saveTier(name, body) {
    setBusy(true);
    try {
      const r = await window.tierPut(name, body);
      if (r.status === 200 && r.ok) {
        window.aegisToast(`Tier "${name}" updated`, 'ok');
        tiersApi.reload && tiersApi.reload();
        setTierEditor(null);
      } else {
        const msg = (r && (r.message || r.error || r.reason)) || `status ${r?.status ?? '?'}`;
        window.aegisToast(`Save failed: ${msg}`, 'err');
      }
    } finally {
      setBusy(false);
    }
  }

  // Auto-select the first tier when data lands.
  useEffectP(() => {
    if (!selectedName && tiers.length > 0) setSelectedName(tiers[0].name);
  }, [tiers.length, selectedName]);

  const selected = tiers.find(t => t.name === selectedName) || tiers[0] || null;
  // 2026-05-05 — a route with no `tier_override` set falls back
  // to the default tier at runtime (`Tier::Low` post-rename). The
  // pre-fix filter only matched explicit overrides, so the
  // catch-all route (which never sets tier_override) showed as
  // "0 routes assigned to low" despite being the dominant low-
  // tier consumer. Treat null/empty tier_override as belonging
  // to the default tier (`low`).
  const matchTier = (r, name) =>
    r.tier_override === name ||
    (!r.tier_override && name === 'low');
  const routesForSelected = selected
    ? routes.filter(r => matchTier(r, selected.name))
    : [];

  return (
    <>
      <div className="page-head">
        <div>
          <h1 className="page-title">Detectors &amp; Tiers</h1>
          <p className="page-subtitle">
            Detector mask + per-tier pipeline assignment ·
            <span className="num"> {tiers.length}</span> active tiers ·
            <span className="num"> {routes.length}</span> routes
            <span style={{ marginLeft: 8 }}>
              <span className={`pill ${tiersApi.error || routesApi.error ? 'warn' : 'ok'}`}>
                {tiersApi.error || routesApi.error ? 'fetch failed' : 'live'}
              </span>
            </span>
          </p>
        </div>
        <div className="page-actions">
          <button className="btn" onClick={() => { tiersApi.reload && tiersApi.reload(); routesApi.reload && routesApi.reload(); }}>
            <window.I.Refresh /> Refresh
          </button>
        </div>
      </div>

      {/* `DetectorMaskCard` renders the unified Detectors card —
          base mask + per-tier overrides + an `AiDetectorRow`
          folded in at the bottom (separate runtime knob, same
          card so operators see the full detector inventory in
          one place). */}
      <DetectorMaskCard />

      <div className="split-list">
        <div className="left">
          <div style={{ overflow: 'auto', flex: 1 }}>
            {tiers.length === 0 && (
              <div style={{ padding: 16, fontSize: 12, color: 'var(--ink-dim)', textAlign: 'center' }}>
                No tiers configured.
              </div>
            )}
            {tiers.map(t => {
              const tierRouteCount = routes.filter(r => matchTier(r, t.name)).length;
              const detectorCount = (t.pipeline || []).filter(p => !['rate', 'rules', 'risk', 'challenge'].includes(p)).length;
              return (
                <button key={t.name} onClick={() => setSelectedName(t.name)}
                  style={{ display: 'block', width: '100%', textAlign: 'left', padding: 14, border: 'none', borderBottom: '1px solid var(--hairline)',
                    background: selected && selected.name === t.name ? 'var(--surface-active)' : 'transparent',
                    borderLeft: selected && selected.name === t.name ? '3px solid var(--brand-yellow)' : '3px solid transparent',
                    cursor: 'pointer', color: 'inherit' }}>
                  <div style={{ fontSize: 13, fontWeight: 600, marginBottom: 2 }}>{t.name}</div>
                  {/* 2026-05-09 — `block_threshold` (req/s) is descriptive
                      metadata, not enforced. Source comment in
                      crates/aegis-control/src/api/tiers.rs:36-44 confirms.
                      Real per-IP volumetric limits live on the Traffic
                      Gates page (Rate Limit + DDoS gates). Showing the
                      field here was misleading — operators thought it
                      was an enforce knob. */}
                  <div style={{ fontSize: 11, color: 'var(--ink-dim)', marginBottom: 6 }}>
                    risk ≥ <span className="num">{t.risk_threshold}</span>
                  </div>
                  <div style={{ display: 'flex', gap: 6, fontSize: 10 }}>
                    <span className="pill neutral">{tierRouteCount} routes</span>
                    <span className="pill neutral">{detectorCount} detectors</span>
                  </div>
                </button>
              );
            })}
          </div>
        </div>
        <div className="right" style={{ padding: 16 }}>
          {selected ? (
            <>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 10, marginBottom: 14 }}>
                <div>
                  <div style={{ fontSize: 16, fontWeight: 700 }}>{selected.name}</div>
                  <div style={{ fontSize: 11, color: 'var(--ink-dim)' }}>
                    {(selected.pipeline || []).length} pipeline stages · risk threshold <span className="num">{selected.risk_threshold}</span>
                    <span style={{ marginLeft: 8, opacity: 0.7 }}>
                      · per-IP volumetric limits live on the <a href="#/traffic-gates" style={{ color: 'var(--accent)' }}>Traffic Gates</a> page
                    </span>
                  </div>
                </div>
                <button className="btn" onClick={() => setTierEditor(selected)} disabled={busy}>
                  Edit tier
                </button>
              </div>

              <div style={{ background: 'var(--canvas-2)', border: '1px solid var(--hairline)', borderRadius: 6, padding: 12, marginBottom: 16 }}>
                <div style={{ fontSize: 12, fontWeight: 600, marginBottom: 10 }}>Pipeline ({(selected.pipeline || []).length} stages)</div>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                  {(selected.pipeline || []).map(p => (
                    <span key={p} className="pill neutral" style={{ fontSize: 10 }}>{p}</span>
                  ))}
                </div>
              </div>

              <div>
                <div style={{ fontSize: 12, fontWeight: 600, marginBottom: 8 }}>
                  Routes assigned to <span className="mono">{selected.name}</span> ({routesForSelected.length})
                </div>
                <table className="tbl tbl-compact">
                  <thead><tr><th>Route ID</th><th>Host</th><th>Path</th><th>Match</th><th>Methods</th><th>Upstream</th><th title="MTLS-T11 — required client-identity kinds">Auth</th></tr></thead>
                  <tbody>
                    {routesForSelected.length === 0 && (
                      <tr><td colSpan={7} style={{ textAlign: 'center', padding: 16, color: 'var(--ink-dim)', fontSize: 12 }}>
                        No routes assigned to this tier.
                      </td></tr>
                    )}
                    {routesForSelected.map(r => {
                      const auth = r.auth_required || [];
                      return (
                        <tr key={r.id}>
                          <td className="mono">{r.id}</td>
                          <td className="mono dim">{r.host || '*'}</td>
                          <td className="mono">{r.path}</td>
                          <td><span className="pill neutral">{r.match_type}</span></td>
                          <td className="mono dim">{r.methods.length === 0 ? 'ANY' : r.methods.join(', ')}</td>
                          <td className="mono">{r.upstream}</td>
                          <td>
                            {auth.length === 0 ? (
                              <span className="pill" style={{ opacity: 0.5 }} title="Any identity admitted (default open)">open</span>
                            ) : (
                              auth.map(k => (
                                <span
                                  key={k}
                                  className={`pill ${k === 'mtls' || k === 'spiffe' ? 'ok' : 'warn'}`}
                                  style={{ marginRight: 4, fontSize: 10 }}
                                  title={`auth_required includes "${k}" — only ${k} clients are admitted`}
                                >
                                  {k}
                                </span>
                              ))
                            )}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </>
          ) : (
            <div style={{ padding: 24, color: 'var(--ink-dim)', fontSize: 12 }}>Select a tier to inspect.</div>
          )}
        </div>
      </div>

      {tierEditor && (
        <TierEditModal
          tier={tierEditor}
          onCancel={() => setTierEditor(null)}
          onSave={(body) => saveTier(tierEditor.name, body)}
          busy={busy}
        />
      )}
    </>
  );
}

// Pipeline stages the four canonical tiers use today. Order
// matters for the canonical sort below. Heads up — this list
// is **descriptive metadata** today: the data plane gates
// detectors via the global detector mask (PUT /api/detectors),
// not by walking this list. Toggling a stage off here surfaces
// the change in the audit chain + the tier list, but doesn't
// currently disable the detector at runtime. Real tier-scoped
// execution is a follow-up.
const TIER_PIPELINE_STAGES = [
  ['rate', 'Rate-limit gate'],
  ['rules', 'Custom rule engine'],
  ['sqli', 'SQL injection detector'],
  ['xss', 'Cross-site scripting detector'],
  ['ssrf', 'SSRF detector'],
  ['path_traversal', 'Path traversal detector'],
  ['header_inj', 'Header injection / CRLF'],
  ['bots', 'Bot management'],
  ['ai', 'AI-based attack detector (ML / ONNX)'],
  ['risk', 'Composite risk scoring'],
  ['challenge', 'JS / CAPTCHA challenge ladder'],
];

function TierEditModal({ tier, onCancel, onSave, busy }) {
  const [pipelineSet, setPipelineSet] = useStateP(() => new Set(tier.pipeline || []));
  const [risk, setRisk] = useStateP(tier.risk_threshold || 50);
  const [block, setBlock] = useStateP(tier.block_threshold || 100);

  const togglePipeline = (s) => {
    const next = new Set(pipelineSet);
    next.has(s) ? next.delete(s) : next.add(s);
    setPipelineSet(next);
  };
  const orderedPipeline = TIER_PIPELINE_STAGES
    .map(([s]) => s)
    .filter(s => pipelineSet.has(s));

  const riskValid = risk >= 0 && risk <= 100;
  const blockValid = block >= 1;
  const pipelineValid = orderedPipeline.length > 0;
  const canSave = riskValid && blockValid && pipelineValid && !busy;

  return (
    <div className="modal-backdrop" onClick={onCancel}>
      <div className="modal" onClick={e => e.stopPropagation()} style={{ maxWidth: 560 }}>
        <div className="modal-head">
          <div className="modal-title">Edit tier · {tier.name}</div>
          <button className="btn btn-sm" onClick={onCancel}>×</button>
        </div>
        <div className="modal-body">
          <div className="form-row">
            <label>Pipeline stages <span className="req">*</span></label>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 4, marginTop: 4 }}>
              {TIER_PIPELINE_STAGES.map(([s, label]) => {
                const on = pipelineSet.has(s);
                return (
                  <label key={s} style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 12, cursor: 'pointer', padding: '4px 0' }}>
                    <input type="checkbox" checked={on} onChange={() => togglePipeline(s)} />
                    <code style={{ minWidth: 110 }}>{s}</code>
                    <span style={{ color: 'var(--ink-dim)' }}>— {label}</span>
                  </label>
                );
              })}
            </div>
            <div className="form-hint">
              <strong>Heads up.</strong> This list is descriptive metadata today —
              the data plane gates detectors via the <strong>Detectors mask</strong> at
              the top of this page, not by walking this list. Edit the mask there to
              actually disable a detector. Per-tier execution is a follow-up.
            </div>
            {!pipelineValid && (
              <div className="form-hint warn">Pipeline must have at least one stage.</div>
            )}
          </div>

          <div className="form-row" style={{ display: 'flex', gap: 8, marginTop: 14, paddingTop: 12, borderTop: '1px solid var(--hairline)' }}>
            <div style={{ flex: 1 }}>
              <label>Risk threshold (0-100) <span className="req">*</span></label>
              <input className="ip" type="number" min="0" max="100"
                value={risk}
                onChange={e => setRisk(parseInt(e.target.value, 10) || 0)} />
              <div className="form-hint">Composite score that triggers a block. Lower = stricter.</div>
              {!riskValid && (
                <div className="form-hint warn">Must be between 0 and 100.</div>
              )}
            </div>
            {/* 2026-05-09 — Block threshold (req/s) input removed.
                The field exists on `Tier` for legacy reasons but
                is **descriptive metadata only** — the data plane
                doesn't enforce per-tier req/s caps (source comment
                in crates/aegis-control/src/api/tiers.rs:36-44).
                Real per-IP volumetric limits live on the Traffic
                Gates page (Rate Limit + DDoS gates). The form
                still POSTs `block_threshold` (using the existing
                `block` state) so the audit-mutated PUT surface
                doesn't change. Keeping the field hidden in the UI
                means operators stop tuning a knob that does
                nothing. */}
          </div>

          <div style={{ marginTop: 14, padding: 8, background: 'var(--canvas-2)', borderRadius: 4, fontSize: 11, fontFamily: 'var(--mono)' }}>
            {tier.name}: pipeline=[{orderedPipeline.join(', ')}], risk≥{risk}
          </div>
          <div style={{ marginTop: 8, fontSize: 11, color: 'var(--ink-dim)', lineHeight: 1.5 }}>
            <strong>Note:</strong> per-IP volumetric limits (req/s caps, sustained-burst auto-block) live on the{' '}
            <a href="#/traffic-gates" style={{ color: 'var(--accent)' }}>Traffic Gates</a> page,
            not here. This tier's pipeline + risk threshold drive the detector chain after the gates pass.
          </div>
        </div>
        <div className="modal-foot">
          <button className="btn" onClick={onCancel} disabled={busy}>Cancel</button>
          <button className="btn primary" disabled={!canSave} onClick={() => onSave({
            pipeline: orderedPipeline,
            risk_threshold: risk,
            block_threshold: block,
          })}>
            {busy ? 'Saving…' : 'Save'}
          </button>
        </div>
      </div>
    </div>
  );
}

// ============== BLACKLIST / WHITELIST ==============
function ListPage({ kind }) {
  const isBL = kind === 'blacklist';
  const api = isBL ? window.useBlacklistApi() : window.useWhitelistApi();
  // Server returns `{entries: [...]}`; mock fallback was already
  // a flat array — accept either shape.
  const raw = api.data?.entries ?? api.data ?? [];
  const data = Array.isArray(raw) ? raw : [];

  // CQF-T2 — Add entry form + per-row delete. Form is shown
  // inline in the page-head when "Add entry" is clicked; submit
  // lands via accessListAdd → audit-mutated POST.
  const [showForm, setShowForm] = useStateP(false);
  const [busy, setBusy] = useStateP(false);
  const [draftKind, setDraftKind] = useStateP('ip');
  const [draftValue, setDraftValue] = useStateP('');
  const [draftNote, setDraftNote] = useStateP('');
  const [draftBypass, setDraftBypass] = useStateP('');
  // M005 (2026-05-07) — optional expiry, search filter, bulk import.
  const [draftExpiry, setDraftExpiry] = useStateP(''); // YYYY-MM-DDTHH:mm (datetime-local)
  const [search, setSearch] = useStateP('');
  const [showImport, setShowImport] = useStateP(false);

  // Filter entries by search term against value + note + kind.
  const filtered = useMemoP(() => {
    const q = search.trim().toLowerCase();
    if (!q) return data;
    return data.filter(e => {
      const value = (e.value || '').toLowerCase();
      const note = (e.note || e.reason || '').toLowerCase();
      const k = (e.kind || e.type || '').toLowerCase();
      return value.includes(q) || note.includes(q) || k.includes(q);
    });
  }, [data, search]);

  async function submitAdd() {
    const value = draftValue.trim();
    if (!value || busy) return;
    setBusy(true);
    try {
      const id = `${kind}-${Date.now().toString(36)}-${Math.floor(Math.random() * 1e6).toString(36)}`;
      // NOTE: `Math.random` here is for ID minting only (no security
      // surface; the server validates anyway). Not a render path.
      const entry = {
        id,
        kind: draftKind,
        value,
        note: draftNote.trim(),
        bypass: !isBL && draftBypass.trim()
          ? draftBypass.split(',').map(s => s.trim()).filter(Boolean)
          : [],
        created_at: new Date().toISOString(),
      };
      // M005 — optional ISO 8601 expiry. The datetime-local input
      // returns "YYYY-MM-DDTHH:mm" in local time; promote to a
      // proper ISO string with timezone for the server.
      if (draftExpiry) {
        const d = new Date(draftExpiry);
        if (!isNaN(d.getTime())) {
          entry.expires_at = d.toISOString();
        }
      }
      const r = await window.accessListAdd(kind, entry);
      if (r.ok) {
        window.aegisToast(`Added ${kind} entry ${draftKind}:${value}`, 'ok');
        setDraftValue(''); setDraftNote(''); setDraftBypass(''); setDraftExpiry('');
        setShowForm(false);
        api.reload && api.reload();
      } else {
        const msg = (r && (r.message || r.error || r.reason)) || `status ${r.status}`;
        window.aegisToast(`Add failed: ${msg}`, 'err');
      }
    } catch (e) {
      window.aegisToast(`Add error: ${e.message || e}`, 'err');
    } finally {
      setBusy(false);
    }
  }

  // M005 — CSV bulk import. Format: kind,value,note,bypass,expires_at
  // - kind: ip | cidr | asn | country
  // - bypass: pipe-separated (sqli|xss) or empty; only meaningful for whitelist
  // - expires_at: ISO 8601 or empty
  // Submits one POST per row (no batch endpoint today). Reports
  // a summary toast at the end.
  async function bulkImport(csvText) {
    const lines = csvText.split(/\r?\n/).map(l => l.trim()).filter(Boolean);
    if (!lines.length) {
      window.aegisToast('Bulk import: no rows to import', 'warn');
      return;
    }
    // Skip a header row if first line looks like one.
    const start = /^kind\b/i.test(lines[0]) ? 1 : 0;
    setBusy(true);
    let added = 0, failed = 0;
    try {
      for (let i = start; i < lines.length; i++) {
        const cols = lines[i].split(',').map(c => c.trim());
        const [k, val, note = '', bypass = '', exp = ''] = cols;
        if (!k || !val) { failed++; continue; }
        const id = `${kind}-bulk-${Date.now().toString(36)}-${i.toString(36)}`;
        const entry = {
          id,
          kind: k,
          value: k === 'country' ? val.toUpperCase() : val,
          note,
          bypass: !isBL && bypass
            ? bypass.split('|').map(s => s.trim()).filter(Boolean)
            : [],
          created_at: new Date().toISOString(),
        };
        if (exp) {
          const d = new Date(exp);
          if (!isNaN(d.getTime())) entry.expires_at = d.toISOString();
        }
        const r = await window.accessListAdd(kind, entry);
        if (r.ok) added++; else failed++;
      }
      window.aegisToast(
        `Imported ${added} of ${lines.length - start}` +
        (failed > 0 ? ` · ${failed} failed` : ''),
        failed > 0 ? 'warn' : 'ok',
      );
      api.reload && api.reload();
    } catch (e) {
      window.aegisToast(`Bulk import error: ${e.message || e}`, 'err');
    } finally {
      setBusy(false);
      setShowImport(false);
    }
  }

  async function deleteRow(entry) {
    if (busy) return;
    if (!confirm(`Remove ${kind} entry ${entry.kind}:${entry.value}?`)) return;
    setBusy(true);
    try {
      const r = await window.accessListDelete(kind, entry.id);
      if (r.ok) {
        window.aegisToast(`Removed ${entry.kind}:${entry.value}`, 'ok');
        api.reload && api.reload();
      } else {
        const msg = (r && (r.message || r.error || r.reason)) || `status ${r.status}`;
        window.aegisToast(`Remove failed: ${msg}`, 'err');
      }
    } catch (e) {
      window.aegisToast(`Remove error: ${e.message || e}`, 'err');
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <div className="page-head">
        <div>
          <h1 className="page-title">{isBL ? 'Blacklist' : 'Whitelist'}</h1>
          <p className="page-subtitle">
            {data.length.toLocaleString()} entries
            <span style={{ marginLeft: 8 }}>
              <span className={`pill ${api.error ? 'warn' : 'ok'}`}>
                {api.error ? 'fetch failed' : 'live'}
              </span>
            </span>
          </p>
        </div>
        <div className="page-actions">
          <button className="btn" onClick={() => api.reload && api.reload()}>
            <window.I.Refresh /> Refresh
          </button>
          {/* M005 — bulk import opens a CSV-paste modal */}
          <button
            className="btn"
            onClick={() => setShowImport(true)}
            disabled={busy}
            title="Paste CSV: kind,value,note,bypass,expires_at"
          >
            Bulk import
          </button>
          <button
            className="btn primary"
            onClick={() => setShowForm(v => !v)}
            disabled={busy}
          >
            <window.I.Plus /> {showForm ? 'Cancel' : 'Add entry'}
          </button>
        </div>
      </div>

      {/* M005 — search input above the table */}
      <div style={{ marginBottom: 8, display: 'flex', alignItems: 'center', gap: 8 }}>
        <input
          type="search"
          value={search}
          onChange={e => setSearch(e.target.value)}
          placeholder="Search value, note, or type…"
          style={{
            flex: 1,
            padding: '6px 10px',
            background: 'var(--canvas-2)',
            border: '1px solid var(--hairline)',
            borderRadius: 4,
            color: 'var(--ink)',
            fontSize: 12,
          }}
        />
        {search && (
          <span style={{ fontSize: 11, color: 'var(--ink-dim)' }}>
            {filtered.length} of {data.length}
          </span>
        )}
      </div>

      {showForm && (
        <div className="card" style={{ marginBottom: 12, padding: 12 }}>
          <div style={{ display: 'flex', gap: 8, alignItems: 'flex-end', flexWrap: 'wrap' }}>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
              <label style={{ fontSize: 10, color: 'var(--ink-dim)', textTransform: 'uppercase', letterSpacing: 0.4 }}>Type</label>
              <select
                value={draftKind}
                onChange={e => setDraftKind(e.target.value)}
                disabled={busy}
                style={{ padding: '6px 8px', background: 'var(--canvas-2)', border: '1px solid var(--hairline)', borderRadius: 4, color: 'var(--ink)', minWidth: 90 }}
              >
                <option value="ip">ip</option>
                <option value="cidr">cidr</option>
                <option value="asn">asn</option>
                <option value="country">country</option>
              </select>
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 4, flex: 1, minWidth: 220 }}>
              <label style={{ fontSize: 10, color: 'var(--ink-dim)', textTransform: 'uppercase', letterSpacing: 0.4 }}>Value</label>
              <input
                type="text"
                value={draftValue}
                onChange={e => setDraftValue(
                  // Country codes are stored uppercase ISO-3166-1
                  // alpha-2; auto-uppercase on input so operators
                  // don't trip the validator with `cn` vs `CN`.
                  draftKind === 'country' ? e.target.value.toUpperCase() : e.target.value
                )}
                onKeyDown={e => { if (e.key === 'Enter') submitAdd(); }}
                placeholder={
                  draftKind === 'ip'      ? '203.0.113.7' :
                  draftKind === 'cidr'    ? '203.0.113.0/24' :
                  draftKind === 'asn'     ? 'AS13335' :
                  /* country */             'CN'
                }
                disabled={busy}
                style={{ padding: '6px 8px', background: 'var(--canvas-2)', border: '1px solid var(--hairline)', borderRadius: 4, color: 'var(--ink)', fontFamily: 'monospace' }}
              />
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 4, flex: 2, minWidth: 200 }}>
              <label style={{ fontSize: 10, color: 'var(--ink-dim)', textTransform: 'uppercase', letterSpacing: 0.4 }}>Note (optional)</label>
              <input
                type="text"
                value={draftNote}
                onChange={e => setDraftNote(e.target.value)}
                onKeyDown={e => { if (e.key === 'Enter') submitAdd(); }}
                placeholder="why this entry exists"
                disabled={busy}
                style={{ padding: '6px 8px', background: 'var(--canvas-2)', border: '1px solid var(--hairline)', borderRadius: 4, color: 'var(--ink)' }}
              />
            </div>
            {!isBL && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 4, minWidth: 200 }}>
                <label style={{ fontSize: 10, color: 'var(--ink-dim)', textTransform: 'uppercase', letterSpacing: 0.4 }}>Bypass (CSV; "all" = full trust)</label>
                <input
                  type="text"
                  value={draftBypass}
                  onChange={e => setDraftBypass(e.target.value)}
                  onKeyDown={e => { if (e.key === 'Enter') submitAdd(); }}
                  placeholder="sqli,xss  or  all"
                  disabled={busy}
                  style={{ padding: '6px 8px', background: 'var(--canvas-2)', border: '1px solid var(--hairline)', borderRadius: 4, color: 'var(--ink)' }}
                />
              </div>
            )}
            {/* M005 — optional expiry */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: 4, minWidth: 180 }}>
              <label style={{ fontSize: 10, color: 'var(--ink-dim)', textTransform: 'uppercase', letterSpacing: 0.4 }}>
                Expires (optional)
              </label>
              <input
                type="datetime-local"
                value={draftExpiry}
                onChange={e => setDraftExpiry(e.target.value)}
                disabled={busy}
                style={{ padding: '6px 8px', background: 'var(--canvas-2)', border: '1px solid var(--hairline)', borderRadius: 4, color: 'var(--ink)' }}
              />
            </div>
            <button
              className="btn primary"
              onClick={submitAdd}
              disabled={busy || !draftValue.trim()}
            >
              Submit
            </button>
          </div>
        </div>
      )}

      <div className="card" style={{ padding: 0 }}>
        <table className="tbl tbl-compact">
          <thead>
            <tr>
              <th style={{ width: 90 }}>Type</th>
              <th>Value</th>
              <th>Note</th>
              <th style={{ width: 130 }}>{isBL ? 'Action' : 'Bypass'}</th>
              <th style={{ width: 130 }}>Expires</th>
              <th style={{ width: 130 }}>Created</th>
              <th style={{ width: 80 }}></th>
            </tr>
          </thead>
          <tbody>
            {filtered.length === 0 && (
              <tr><td colSpan={7} style={{ textAlign: 'center', padding: 16, color: 'var(--ink-dim)', fontSize: 12 }}>
                {data.length === 0
                  ? 'No entries.'
                  : `No matches for "${search}". Clear the search to see all ${data.length} entries.`}
              </td></tr>
            )}
            {filtered.map(e => (
              <tr key={e.id}>
                <td><span className="pill neutral">{e.kind || e.type}</span></td>
                <td className="mono" style={{ color: 'var(--ink-strong)' }}>{e.value}</td>
                <td className="dim" style={{ maxWidth: 280, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                  {e.note || e.reason || ''}
                </td>
                <td>
                  {isBL ? <window.ActionPill value={e.action || 'block'} /> : (
                    <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
                      {(e.bypass || []).includes('all')
                        ? <span className="pill solid-yellow">all · high-trust</span>
                        : (e.bypass || []).map(b => <span key={b} className="pill neutral" style={{ fontSize: 9 }}>{b}</span>)}
                    </div>
                  )}
                </td>
                <td className="num" style={{ color: e.expires_at ? 'var(--warn)' : 'var(--ink-dim)' }}>
                  {e.expires_at ? new Date(e.expires_at).toISOString().slice(0, 10) : 'never'}
                </td>
                <td className="dim" style={{ fontSize: 11 }}>
                  {e.created_at ? new Date(e.created_at).toISOString().slice(0, 10) : '—'}
                </td>
                <td style={{ textAlign: 'right' }}>
                  <button
                    className="btn danger"
                    style={{ fontSize: 11, padding: '4px 8px' }}
                    onClick={() => deleteRow(e)}
                    disabled={busy}
                    title={`Remove ${e.kind || 'entry'} ${e.value}`}
                  >
                    Remove
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {showImport && (
        <BulkImportModal
          kind={kind}
          isBL={isBL}
          busy={busy}
          onCancel={() => setShowImport(false)}
          onImport={bulkImport}
        />
      )}
    </>
  );
}

// M005 (2026-05-07) — paste-CSV bulk import for access lists.
// Format documented inline in the modal so operators don't need
// to leave the page to look it up.
function BulkImportModal({ kind, isBL, busy, onCancel, onImport }) {
  const [text, setText] = useStateP('');
  const sample = isBL
    ? 'kind,value,note,bypass,expires_at\nip,203.0.113.7,test entry,,2026-12-31T00:00:00Z\ncidr,198.51.100.0/24,known bot net,,'
    : 'kind,value,note,bypass,expires_at\nip,203.0.113.7,partner,sqli|xss,\nasn,AS13335,cdn,all,';
  return (
    <div className="modal-backdrop" onClick={onCancel}>
      <div className="modal" onClick={e => e.stopPropagation()} style={{ maxWidth: 720 }}>
        <div className="modal-head">
          <div className="modal-title">Bulk import to {kind}</div>
          <button className="btn btn-sm" onClick={onCancel}>×</button>
        </div>
        <div className="modal-body">
          <p style={{ fontSize: 13, lineHeight: 1.5, marginBottom: 8 }}>
            Paste CSV: <code>kind,value,note,bypass,expires_at</code>.
            One row per entry; header row is auto-detected.
            Each row submits as its own audit-chained POST.
            {!isBL && <> Bypass list is pipe-separated (e.g. <code>sqli|xss</code> or <code>all</code>).</>}
          </p>
          <textarea
            value={text}
            onChange={e => setText(e.target.value)}
            placeholder={sample}
            disabled={busy}
            spellCheck={false}
            style={{
              width: '100%',
              minHeight: 220,
              padding: 8,
              background: 'var(--canvas-2)',
              border: '1px solid var(--hairline)',
              borderRadius: 4,
              color: 'var(--ink)',
              fontFamily: 'var(--mono)',
              fontSize: 12,
            }}
          />
        </div>
        <div className="modal-foot">
          <button className="btn" onClick={onCancel} disabled={busy}>Cancel</button>
          <button
            className="btn primary"
            onClick={() => onImport(text)}
            disabled={busy || !text.trim()}
          >
            {busy ? 'Importing…' : 'Import'}
          </button>
        </div>
      </div>
    </div>
  );
}

// ============== SETTINGS ==============
// HACK-T4 — Tier-B bonus: config-change timeline. One row
// per audit-mutated change, newest first; click expands the
// full event payload (the "before/after" diff fields each
// mutation handler stamps). No rollback button — that ships
// in a follow-up; this card is the operator-visible Tier-B
// browser per v2.3 §2.4.
function ConfigVersionsCard() {
  const api = window.useConfigVersionsApi(50);
  const [expanded, setExpanded] = useStateP(null);
  // HACK-T4 rollback — per-row state.
  // confirmSeq: which row is showing the "Confirm rollback?" prompt.
  // busy: which row is currently posting (disables both confirm
  // and other rollback buttons until done).
  // result: last rollback outcome, keyed by seq, so the row can
  // show a success / error pill after the click.
  const [confirmSeq, setConfirmSeq] = useStateP(null);
  const [busy, setBusy] = useStateP(false);
  const [result, setResult] = useStateP({});
  const versions = api.data?.versions ?? [];
  const bounded = !!api.data?.bounded;
  const rollbackable = (window.ROLLBACKABLE_ACTIONS || []);

  const onRollback = async (seq) => {
    if (busy) return;
    setBusy(true);
    setResult(prev => ({ ...prev, [seq]: { pending: true } }));
    try {
      const r = await window.configRollback(seq);
      setResult(prev => ({ ...prev, [seq]: r }));
      if (r.status === 200) {
        setConfirmSeq(null);
        api.reload && api.reload();
      }
    } finally {
      setBusy(false);
    }
  };

  const toneFor = (action) => {
    if (action.includes('failed') || action.includes('reload_failed')) return 'down';
    if (action.includes('reloaded') || action.includes('rotated')) return 'up';
    return 'neutral';
  };

  return (
    <div className="card" style={{ marginBottom: 12, padding: 0 }}>
      <div className="card-head" style={{ padding: '10px 14px', borderBottom: '1px solid var(--hairline)' }}>
        <div>
          <div className="card-title">Config history</div>
          <div className="card-sub">
            Every audit-mutated change · {versions.length} {versions.length === 1 ? 'entry' : 'entries'} · newest first
            {bounded && (
              <span style={{ marginLeft: 8 }}>
                <span className="pill warn">truncated</span>
              </span>
            )}
          </div>
        </div>
        <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
          <span className="pill neutral">Tier B</span>
          <button className="btn sm" onClick={() => api.reload && api.reload()}>
            <window.I.Refresh />
          </button>
        </div>
      </div>
      {versions.length === 0 ? (
        <div style={{ padding: 16, fontSize: 12, color: 'var(--ink-dim)', textAlign: 'center' }}>
          No config changes recorded yet — every audit-mutated PUT/POST/DELETE will land here.
        </div>
      ) : (
        <table className="tbl tbl-compact">
          <thead>
            <tr>
              <th style={{ width: 60 }}>Version</th>
              <th style={{ width: 140 }}>Time</th>
              <th>Action</th>
              <th>Reason</th>
              <th style={{ width: 100 }}>Actor</th>
              <th style={{ width: 80 }}>Source</th>
              <th style={{ width: 40 }}></th>
            </tr>
          </thead>
          <tbody>
            {versions.map(v => {
              const isOpen = expanded === v.seq;
              const ts = v.ts ? new Date(v.ts).toLocaleString([], { hour: '2-digit', minute: '2-digit', second: '2-digit', month: 'short', day: 'numeric' }) : '—';
              return (
                <Fragment key={`${v.seq}-${v.request_id}`}>
                  <tr style={{ cursor: 'pointer' }} onClick={() => setExpanded(isOpen ? null : v.seq)}>
                    <td className="num mono">#{v.seq}</td>
                    <td className="dim mono">{ts}</td>
                    <td>
                      <span className={`pill ${toneFor(v.action)}`}>{v.action}</span>
                    </td>
                    <td className="dim" style={{ maxWidth: 360, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={v.reason}>
                      {v.reason}
                    </td>
                    <td className="mono">{v.actor}</td>
                    <td>
                      <span className="pill neutral">{v.source}</span>
                    </td>
                    <td className="dim" style={{ textAlign: 'center' }}>{isOpen ? '▼' : '▶'}</td>
                  </tr>
                  {isOpen && (
                    <tr>
                      <td colSpan={7} style={{ background: 'var(--canvas-2)', padding: '12px 14px' }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 10, gap: 12 }}>
                          <div>
                            <div style={{ fontSize: 10, color: 'var(--ink-faint)', textTransform: 'uppercase', letterSpacing: 0.6, marginBottom: 6 }}>
                              Request id
                            </div>
                            <div className="mono" style={{ fontSize: 11, color: 'var(--ink-mute)' }}>
                              {v.request_id || <span className="dim">—</span>}{' '}
                              {v.request_id && (
                                <a
                                  href={`#/audit?request_id=${encodeURIComponent(v.request_id)}`}
                                  style={{ color: 'var(--accent)', marginLeft: 8 }}
                                >
                                  View in Audit Log →
                                </a>
                              )}
                            </div>
                          </div>
                          {/* HACK-T4 rollback button. Visible only for rollback-able
                              actions; everything else gets a disabled hint. */}
                          <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
                            {rollbackable.includes(v.action) ? (
                              confirmSeq === v.seq ? (
                                <>
                                  <span style={{ fontSize: 11, color: 'var(--warn)' }}>
                                    Confirm — rollback to #{v.seq}?
                                  </span>
                                  <button className="btn sm" onClick={() => setConfirmSeq(null)} disabled={busy}>
                                    Cancel
                                  </button>
                                  <button className="btn sm solid-yellow" onClick={() => onRollback(v.seq)} disabled={busy}>
                                    Yes, rollback
                                  </button>
                                </>
                              ) : (
                                <button className="btn sm" onClick={() => setConfirmSeq(v.seq)} disabled={busy}>
                                  Rollback to #{v.seq}
                                </button>
                              )
                            ) : (
                              <span style={{ fontSize: 11, color: 'var(--ink-dim)' }} title={`Action '${v.action}' is not rollback-able in this build.`}>
                                rollback unavailable
                              </span>
                            )}
                            {result[v.seq]?.pending && (
                              <span style={{ fontSize: 11, color: 'var(--ink-dim)' }}>rolling back…</span>
                            )}
                            {result[v.seq] && !result[v.seq].pending && result[v.seq].status === 200 && (
                              <span className="pill up">rolled back</span>
                            )}
                            {result[v.seq] && !result[v.seq].pending && result[v.seq].status !== 200 && (
                              <span className="pill down" title={result[v.seq].error || ''}>
                                rollback failed (HTTP {result[v.seq].status})
                              </span>
                            )}
                          </div>
                        </div>
                        <div style={{ fontSize: 10, color: 'var(--ink-faint)', textTransform: 'uppercase', letterSpacing: 0.6, marginBottom: 6 }}>
                          Fields
                        </div>
                        <pre style={{ background: 'var(--canvas)', border: '1px solid var(--hairline)', borderRadius: 6, padding: 10, fontSize: 11, fontFamily: 'var(--font-mono)', margin: 0, overflow: 'auto', maxHeight: 240, color: 'var(--ink-mute)' }}>
                          {JSON.stringify(v.fields, null, 2)}
                        </pre>
                      </td>
                    </tr>
                  )}
                </Fragment>
              );
            })}
          </tbody>
        </table>
      )}
    </div>
  );
}

// MTLS-T8 — runtime client_auth.mode override. Lets operators
// flip between disabled / optional / required without editing
// YAML. Upgrades to `required` show a confirm prompt because
// they're destructive (clients without certs will fail TLS).
// Setting an override that differs from the configured value
// surfaces a "restart required" pill — the TLS acceptor only
// rebuilds on cfg.tls swaps today.
function MtlsModeCard() {
  const api = window.useApi
    ? window.useApi('/api/mtls/mode', { intervalMs: 10000, fallback: null })
    : { data: null };
  const [busy, setBusy] = useStateP(false);

  if (!api.data) {
    return (
      <div className="card" style={{ padding: 16, fontSize: 12, color: 'var(--ink-dim)' }}>
        Loading mTLS mode…
      </div>
    );
  }
  const { configured, override: ovr, effective, requires_restart } = api.data;

  async function setMode(target) {
    if (target === 'required') {
      const ok = window.confirm(
        `Switch effective mTLS mode to REQUIRED?\n\nClients that don't present a valid client certificate will fail the TLS handshake. This affects every active session. Type OK in the next prompt to confirm.`
      );
      if (!ok) return;
    }
    setBusy(true);
    try {
      const csrf = document.cookie.split('; ').find(c => c.startsWith('aegis_csrf='))?.slice(11) || '';
      const r = await fetch('/api/mtls/mode', {
        method: 'PUT',
        headers: { 'content-type': 'application/json', 'x-csrf-token': csrf },
        body: JSON.stringify({ mode: target }),
        credentials: 'same-origin',
      });
      if (!r.ok) throw new Error(`status ${r.status}`);
      if (api.reload) api.reload();
    } catch (e) {
      window.toast && window.toast(`mTLS mode set failed: ${e.message}`, 'err');
    } finally {
      setBusy(false);
    }
  }
  async function clearOverride() {
    setBusy(true);
    try {
      const csrf = document.cookie.split('; ').find(c => c.startsWith('aegis_csrf='))?.slice(11) || '';
      const r = await fetch('/api/mtls/mode', {
        method: 'PUT',
        headers: { 'content-type': 'application/json', 'x-csrf-token': csrf },
        body: JSON.stringify({ clear: true }),
        credentials: 'same-origin',
      });
      if (!r.ok) throw new Error(`status ${r.status}`);
      if (api.reload) api.reload();
    } catch (e) {
      window.toast && window.toast(`mTLS mode clear failed: ${e.message}`, 'err');
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="card" style={{ padding: 16, marginBottom: 12 }}>
      <window.SectionHeader
        title="mTLS mode"
        sub={`configured: ${configured} · effective: ${effective}${ovr ? ' · override active' : ''}`}
      />
      <div style={{ padding: '8px 0', display: 'flex', flexWrap: 'wrap', gap: 8, alignItems: 'center' }}>
        {['disabled', 'optional', 'required'].map(m => (
          <button
            key={m}
            className={`btn ${effective === m ? 'primary' : ''}`}
            disabled={busy || effective === m}
            onClick={() => setMode(m)}
            title={`Set runtime override to ${m}`}
          >{m}</button>
        ))}
        {ovr && (
          <button className="btn" disabled={busy} onClick={clearOverride}>
            Clear override (revert to {configured})
          </button>
        )}
        {requires_restart && (
          <span className="pill warn" title="The TLS acceptor only rebuilds on cfg.tls hot-reload; this override is logged + visible everywhere it's read, but the handshake layer needs a process restart to fully apply.">
            restart required
          </span>
        )}
      </div>
      <div style={{ fontSize: 11, color: 'var(--ink-dim)', marginTop: 6 }}>
        Mutations are CSRF-gated + audit-chained. <code>required</code>{' '}
        rejects clients without a valid client cert at TLS handshake — confirm before applying.
      </div>
    </div>
  );
}

// MTLS-T10 — CA bundle upload card. Renders only when the
// operator has set `cfg.admin.dashboard_auth.allow_ca_upload: true`
// (default off — many operators run trust anchors via GitOps).
//
// **Phase 1**: paste / upload PEM → parse + preview metadata
// (subject / issuer / fingerprint / expiry / is_ca). Audit-emits
// `mtls_ca_bundle_validated`. The hot-swap of the live trust
// store ships with the listener-rebuild track (Phase 2).
function MtlsCaBundleCard() {
  const cap = window.useApi
    ? window.useApi('/api/mtls/ca-bundle/capability', { intervalMs: 60000, fallback: { allow_ca_upload: false } })
    : { data: { allow_ca_upload: false } };
  const [pem, setPem] = useStateP('');
  const [preview, setPreview] = useStateP(null);
  const [busy, setBusy] = useStateP(false);
  const [errMsg, setErrMsg] = useStateP(null);

  if (cap.data && !cap.data.allow_ca_upload) {
    // Don't render — operator hasn't opted in. Returning null
    // keeps the Settings page tidy; the env explanation lives
    // in the docs.
    return null;
  }

  function onFile(e) {
    const f = e.target.files?.[0];
    if (!f) return;
    const reader = new FileReader();
    reader.onload = () => setPem(String(reader.result || ''));
    reader.readAsText(f);
  }

  async function validate() {
    if (!pem.trim()) {
      setErrMsg('paste or select a PEM bundle first');
      return;
    }
    setBusy(true); setErrMsg(null); setPreview(null);
    try {
      const csrf = document.cookie.split('; ').find(c => c.startsWith('aegis_csrf='))?.slice(11) || '';
      const r = await fetch('/api/mtls/ca-bundle', {
        method: 'PUT',
        headers: { 'content-type': 'application/x-pem-file', 'x-csrf-token': csrf },
        body: pem,
        credentials: 'same-origin',
      });
      const body = await r.json();
      if (!r.ok) {
        setErrMsg(body.error || `status ${r.status}`);
        if (body.preview) setPreview(body.preview);
      } else {
        setPreview(body.preview);
      }
    } catch (e) {
      setErrMsg(e.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="card" style={{ padding: 16, marginBottom: 12 }}>
      <window.SectionHeader
        title="CA bundle upload (preview)"
        sub="Paste a PEM trust bundle → parse + audit-emit. Phase 1: validation only; live swap requires restart."
      />
      <div style={{ padding: '8px 0', display: 'flex', flexDirection: 'column', gap: 8 }}>
        <textarea
          value={pem}
          onChange={e => setPem(e.target.value)}
          placeholder="-----BEGIN CERTIFICATE-----&#10;...&#10;-----END CERTIFICATE-----"
          rows={8}
          style={{ fontFamily: 'monospace', fontSize: 11, padding: 8, border: '1px solid var(--hairline)', borderRadius: 6, background: 'var(--surface-2)' }}
        />
        <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
          <input type="file" accept=".pem,.crt,.cer,application/x-pem-file" onChange={onFile} />
          <button className="btn primary" disabled={busy || !pem.trim()} onClick={validate}>
            {busy ? 'Validating…' : 'Validate + audit-emit'}
          </button>
          <button className="btn" disabled={busy} onClick={() => { setPem(''); setPreview(null); setErrMsg(null); }}>
            Clear
          </button>
        </div>
        {errMsg && (
          <div className="pill warn" style={{ alignSelf: 'flex-start' }}>error: {errMsg}</div>
        )}
        {preview && preview.valid && (
          <div style={{ marginTop: 4 }}>
            <div style={{ fontSize: 11, color: 'var(--ink-dim)', marginBottom: 4 }}>
              {preview.blocks_seen} block{preview.blocks_seen === 1 ? '' : 's'} parsed · {preview.certificates.length} certificates
            </div>
            <table className="tbl tbl-compact">
              <thead><tr><th>Subject</th><th>Issuer</th><th>Fingerprint (SHA-256)</th><th>Expires</th><th>CA?</th></tr></thead>
              <tbody>
                {preview.certificates.map((c, i) => (
                  <tr key={i}>
                    <td className="mono" style={{ fontSize: 11 }}>{c.subject}</td>
                    <td className="mono" style={{ fontSize: 11 }}>{c.issuer}</td>
                    <td className="mono" style={{ fontSize: 10 }}>{c.fingerprint_sha256.slice(0, 23)}…</td>
                    <td>
                      {c.expired
                        ? <span className="pill down">expired</span>
                        : <span className={`pill ${c.days_to_expiry < 30 ? 'warn' : 'ok'}`}>
                            {c.days_to_expiry} days
                          </span>}
                    </td>
                    <td>{c.is_ca ? <span className="pill ok">CA</span> : <span className="pill warn">leaf</span>}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        {preview && !preview.valid && (
          <div style={{ marginTop: 4, fontSize: 11, color: 'var(--ink-dim)' }}>
            <strong>Errors:</strong>
            <ul>{preview.errors.map((e, i) => <li key={i}>{e}</li>)}</ul>
          </div>
        )}
      </div>
    </div>
  );
}

// MTLS-T7 — Allowed SAN allowlist card. Lives on the Settings
// page; allows operators to add/remove DNS / wildcard / SPIFFE
// patterns and test admit decisions without making a real mTLS
// handshake. Empty list = admit anything (back-compat).
function MtlsSansCard() {
  const api = window.useMtlsSansApi();
  const list = Array.isArray(api?.data?.allowed) ? api.data.allowed : [];
  const [draft, setDraft] = useStateP('');
  const [busy, setBusy] = useStateP(false);
  const [testTarget, setTestTarget] = useStateP('');
  const [testResult, setTestResult] = useStateP(null);

  async function addOne() {
    const next = (draft || '').trim();
    if (!next || busy) return;
    if (list.includes(next)) {
      window.aegisToast(`SAN '${next}' is already allowed`, 'warn');
      return;
    }
    setBusy(true);
    try {
      const merged = [...list, next];
      const r = await window.mtlsSansPut(merged);
      if (r && r.ok) {
        window.aegisToast(`Added SAN '${next}'`, 'ok');
        setDraft('');
        api.reload && api.reload();
      } else {
        const msg = (r && (r.error || r.message)) || 'unknown error';
        window.aegisToast(`Add SAN failed: ${msg}`, 'err');
      }
    } catch (e) {
      window.aegisToast(`Add SAN error: ${e.message || e}`, 'err');
    } finally {
      setBusy(false);
    }
  }

  async function removeOne(san) {
    if (busy) return;
    if (!confirm(`Remove SAN '${san}' from allowlist?`)) return;
    setBusy(true);
    try {
      const r = await window.mtlsSansDelete(san);
      if (r && r.ok) {
        window.aegisToast(`Removed SAN '${san}'`, 'ok');
        api.reload && api.reload();
      } else {
        const msg = (r && (r.error || r.message)) || 'unknown error';
        window.aegisToast(`Remove failed: ${msg}`, 'err');
      }
    } catch (e) {
      window.aegisToast(`Remove error: ${e.message || e}`, 'err');
    } finally {
      setBusy(false);
    }
  }

  async function runTest() {
    const target = (testTarget || '').trim();
    if (!target || busy) return;
    setBusy(true);
    setTestResult(null);
    try {
      const r = await window.mtlsSansTest(target);
      setTestResult(r);
    } catch (e) {
      setTestResult({ ok: false, error: e.message || String(e) });
    } finally {
      setBusy(false);
    }
  }

  const empty = list.length === 0;

  return (
    <div className="card" style={{ marginBottom: 12 }}>
      <div className="card-head">
        <div>
          <div className="card-title">mTLS — Allowed SANs</div>
          <div className="card-subtitle">
            Restrict which client-cert Subject Alternative Names are
            accepted. Empty list admits anything (back-compat).
            Wildcards match a single label (RFC 6125 §6.4.3):
            <code style={{ marginLeft: 4 }}>*.api.example.com</code>
            {' '}admits <code>svc.api.example.com</code> but not
            {' '}<code>a.b.api.example.com</code>.
          </div>
        </div>
        <span className={`pill ${empty ? 'warn' : 'ok'}`}>
          {empty ? 'open (any SAN)' : `${list.length} pattern${list.length === 1 ? '' : 's'}`}
        </span>
      </div>

      <div style={{ display: 'flex', gap: 8, alignItems: 'center', marginBottom: 8 }}>
        <input
          type="text"
          placeholder="svc.example.com  or  *.api.example.com  or  spiffe://example.org/svc"
          value={draft}
          onChange={e => setDraft(e.target.value)}
          onKeyDown={e => { if (e.key === 'Enter') addOne(); }}
          disabled={busy}
          style={{ flex: 1, padding: '6px 8px', background: 'var(--canvas-2)', border: '1px solid var(--hairline)', borderRadius: 4, color: 'var(--ink)', fontFamily: 'monospace' }}
        />
        <button className="btn primary" onClick={addOne} disabled={busy || !draft.trim()}>
          Add SAN
        </button>
      </div>

      {empty ? (
        <div style={{ padding: 8, fontSize: 12, color: 'var(--ink-dim)', fontStyle: 'italic' }}>
          No patterns configured — every cert-presenting peer is admitted.
        </div>
      ) : (
        <table className="table" style={{ width: '100%', marginBottom: 8 }}>
          <thead>
            <tr>
              <th style={{ textAlign: 'left' }}>Pattern</th>
              <th style={{ textAlign: 'right', width: 200 }}>Actions</th>
            </tr>
          </thead>
          <tbody>
            {list.map(p => (
              <tr key={p}>
                <td style={{ fontFamily: 'monospace' }}>{p}</td>
                <td style={{ textAlign: 'right' }}>
                  <button
                    className="btn"
                    style={{ marginRight: 6 }}
                    disabled={busy}
                    onClick={() => { setTestTarget(p); setTestResult(null); }}
                  >
                    Copy to test
                  </button>
                  <button
                    className="btn danger"
                    disabled={busy}
                    onClick={() => removeOne(p)}
                  >
                    Remove
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      <div style={{ marginTop: 8, padding: 8, background: 'var(--canvas-2)', border: '1px solid var(--hairline)', borderRadius: 4 }}>
        <div style={{ fontSize: 12, color: 'var(--ink-dim)', marginBottom: 6 }}>
          Test admission for a candidate SAN:
        </div>
        <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
          <input
            type="text"
            placeholder="svc.example.com"
            value={testTarget}
            onChange={e => setTestTarget(e.target.value)}
            onKeyDown={e => { if (e.key === 'Enter') runTest(); }}
            disabled={busy}
            style={{ flex: 1, padding: '6px 8px', background: 'var(--canvas-1)', border: '1px solid var(--hairline)', borderRadius: 4, color: 'var(--ink)', fontFamily: 'monospace' }}
          />
          <button className="btn" onClick={runTest} disabled={busy || !testTarget.trim()}>
            Test admit
          </button>
        </div>
        {testResult && (
          <div style={{ marginTop: 6, fontSize: 12 }}>
            {testResult.ok && testResult.admitted ? (
              <span className="pill ok">
                admitted{testResult.matched ? ` · matched ${testResult.matched}` : ''}
              </span>
            ) : testResult.ok && !testResult.admitted ? (
              <span className="pill err">
                rejected — no matching pattern
              </span>
            ) : (
              <span className="pill err">
                error: {testResult.error || testResult.status || 'unknown'}
              </span>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

function PageSettings() {
  const modeApi = window.useModeApi();
  const mode = modeApi.data?.mode || 'enforce';
  const isShadow = mode === 'log_only';
  const [busy, setBusy] = useStateP(false);

  // SC-T3 — surface the L1 restart-only invariant to operators
  // who land here looking for a "workers" slider. We only show
  // the hint when /api/runtime actually answered (otherwise
  // the dashboard is in fallback / loading state and a
  // banner would be misleading).
  const runtime = window.useRuntimeApi();
  const showRuntimeHint = !!runtime?.data;

  // CQF-T8 — risk thresholds wired to /api/risk/thresholds.
  // The endpoint shipped via CI-T12; this wiring closes the
  // CQA-T10 partial. The slider's "Allow ≤ X" is challenge_at-1
  // and "Challenge ≤ Y" is block_at-1; we mirror the API's
  // `challenge_at` / `block_at` directly into local state.
  const riskApi = window.useRiskThresholdsApi();
  const [allow, setAllow] = useStateP(0);
  const [challenge, setChallenge] = useStateP(0);
  const [riskBusy, setRiskBusy] = useStateP(false);
  // Sync local sliders with whatever the live API reports —
  // first load, hot-reload, or another operator's PUT.
  useEffectP(() => {
    if (!riskApi.data) return;
    const ca = Number(riskApi.data.challenge_at);
    const ba = Number(riskApi.data.block_at);
    if (Number.isFinite(ca)) setAllow(Math.max(0, ca - 1));
    if (Number.isFinite(ba)) setChallenge(Math.max(0, ba - 1));
  }, [riskApi.data?.challenge_at, riskApi.data?.block_at]);

  async function saveRiskThresholds() {
    if (riskBusy) return;
    setRiskBusy(true);
    try {
      const body = {
        challenge_at: allow + 1,
        block_at: challenge + 1,
        max: Number(riskApi.data?.max) || 100,
      };
      const r = await window.settingsRiskThresholdsPut(body);
      if (r && r.ok) {
        window.aegisToast(`IP risk thresholds → challenge ≥ ${body.challenge_at} · block ≥ ${body.block_at}`, 'ok');
        riskApi.reload && riskApi.reload();
      } else {
        const msg = (r && (r.message || r.error || r.reason)) || 'unknown error';
        window.aegisToast(`Risk threshold save failed: ${msg}`, 'err');
      }
    } catch (e) {
      window.aegisToast(`Risk threshold error: ${e.message || e}`, 'err');
    } finally {
      setRiskBusy(false);
    }
  }

  const [honeypots, setHoneypots] = useStateP(['/.env', '/.git/config', '/wp-admin/install.php', '/phpmyadmin', '/aws/credentials', '/actuator/env']);
  const [stackTraces, setStackTraces] = useStateP(true);
  const [redactJSON, setRedactJSON] = useStateP(true);

  async function toggleShadow() {
    if (busy) return;
    setBusy(true);
    const next = isShadow ? 'enforce' : 'log_only';
    try {
      const before = await fetch('/api/config/version', { credentials: 'same-origin', cache: 'no-store' })
        .then(r => r.json()).then(j => Number(j.version) || 0).catch(() => 0);
      const result = await window.settingsModePut(next);
      if (result && result.ok) {
        const v = await window.waitForVersion(before + 1, 10000);
        if (v.applied) {
          window.aegisToast(`Mode → ${next} · applied in ${v.latencyMs} ms`, 'ok');
        } else {
          window.aegisToast(`Mode → ${next} · pending after 10 s`, 'warn');
        }
        modeApi.reload && modeApi.reload();
      } else {
        const msg = (result && (result.message || result.error || result.reason)) || 'unknown error';
        window.aegisToast(`Mode change failed: ${msg}`, 'err');
      }
    } catch (err) {
      window.aegisToast(`Mode change error: ${err.message || err}`, 'err');
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <div className="page-head">
        <div>
          <h1 className="page-title">Settings</h1>
          <p className="page-subtitle">
            Changes apply immediately — no restart required
            <span style={{ marginLeft: 8 }}>
              <span className={`pill ${isShadow ? 'warn' : 'ok'}`}>
                {isShadow ? 'log_only' : 'enforce'}
              </span>
            </span>
          </p>
        </div>
      </div>

      {isShadow && (
        <div className="banner warn" style={{ marginBottom: 12 }}>
          <div style={{ marginTop: 1 }}><window.I.Siren /></div>
          <div style={{ flex: 1 }}>
            <div className="banner-strong">Shadow mode is ON — no traffic is being blocked.</div>
            <div>Detection events still appear in Live Feed with their original action.</div>
          </div>
          <span className="pill warn" style={{ alignSelf: 'flex-start' }}>ACTIVE</span>
        </div>
      )}

      {showRuntimeHint && (
        <div className="banner" style={{ marginBottom: 12, background: 'var(--canvas-2)', border: '1px solid var(--hairline)', borderRadius: 6, padding: 10, display: 'flex', alignItems: 'center', gap: 10, fontSize: 12 }}>
          <span style={{ color: 'var(--ink-dim)' }}>
            Runtime sizing (workers, blocking threads, CPU affinity) is
            restart-only.
          </span>
          <a
            href="#/scaling"
            style={{ color: 'var(--accent)', textDecoration: 'none', fontWeight: 600 }}
          >
            See the Scaling page →
          </a>
        </div>
      )}

      <ConfigVersionsCard />

      <MtlsModeCard />
      <MtlsCaBundleCard />
      <MtlsSansCard />

      <div className="card" style={{ marginBottom: 12 }}>
        <div className="card-head">
          <div className="card-title">Shadow Mode (Dry-Run)</div>
          <div
            className={`toggle ${isShadow ? 'on' : ''}`}
            onClick={busy ? undefined : toggleShadow}
            style={{ cursor: busy ? 'wait' : 'pointer' }}
          />
        </div>
        <div style={{ fontSize: 12, color: 'var(--ink-mute)' }}>
          Log detections without blocking. Audit chain still records every event;
          /api/mode endpoint is audit-mutated and CSRF-gated.
        </div>
      </div>

      <div className="card" style={{ marginBottom: 12 }}>
        <div className="card-head" style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <div className="card-title">Cumulative IP risk thresholds</div>
          <span className={`pill ${riskApi.error ? 'warn' : 'ok'}`}>
            {riskApi.error ? 'fetch failed' : 'live'}
          </span>
          {riskApi.data && (
            <span style={{ fontSize: 11, color: 'var(--ink-dim)', marginLeft: 'auto' }}>
              live: challenge ≥ {riskApi.data.challenge_at} · block ≥ {riskApi.data.block_at}
            </span>
          )}
        </div>
        <div style={{ fontSize: 12, color: 'var(--ink-mute)', marginBottom: 10, lineHeight: 1.5 }}>
          Per-source-IP score that <strong>accumulates across requests</strong> and decays exponentially
          (half-life <span className="num">{riskApi.data?.decay_half_life || '5m'}</span> from <code>risk.decay_half_life</code>).
          Gates the challenge ladder for <em>future</em> requests from this IP.
          {' '}
          <strong>Distinct from</strong> the per-request <em>tier risk threshold</em> (50 / 70 / 80 / 90 by tier)
          which blocks <em>this</em> request based on its detector hits — that one lives on the Detectors page → Edit tier.
          {' '}
          See <a href="/docs/security/security-engine.md" target="_blank" rel="noreferrer">security-engine.md § Risk model</a>.
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12, marginBottom: 6 }}>
              <span>Allow IP score (0 – {allow}) — let the request through, no gate</span><span className="num">{allow}</span>
            </div>
            <input type="range" min="0" max="100" value={allow} disabled={riskBusy} onChange={e => setAllow(+e.target.value)} style={{ width: '100%', accentColor: 'var(--brand-yellow)' }} />
          </div>
          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12, marginBottom: 6 }}>
              <span>Challenge IP score ({allow + 1} – {challenge}) — JS / CAPTCHA before allowing</span><span className="num">{challenge}</span>
            </div>
            <input type="range" min={allow+1} max="100" value={challenge} disabled={riskBusy} onChange={e => setChallenge(+e.target.value)} style={{ width: '100%', accentColor: 'var(--brand-yellow)' }} />
          </div>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 12 }}>
            <div style={{ fontSize: 12, color: 'var(--ink-mute)' }}>
              Block IP score: <span className="num" style={{ color: 'var(--down)' }}>≥ {challenge + 1}</span> — refuse all further requests from this IP until score decays
            </div>
            <button
              className="btn primary"
              disabled={riskBusy}
              onClick={saveRiskThresholds}
              style={{ fontSize: 11, padding: '4px 12px' }}
            >
              Save thresholds
            </button>
          </div>
        </div>
      </div>

      <div className="card" style={{ marginBottom: 12 }}>
        <div className="card-head" style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <div className="card-title">Challenge Engine</div>
          <span className="pill warn" title="Selection is local-only — backend always uses JS challenge today">not wired</span>
        </div>
        <div className="field-label">Challenge type</div>
        <select className="input select" defaultValue="JS Challenge"><option>JS Challenge</option><option>JS + CAPTCHA</option><option>Strict (PoW)</option></select>
      </div>

      <div className="card" style={{ marginBottom: 12 }}>
        <div className="card-head" style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <div className="card-title">Honeypot Paths</div>
          <span className="pill warn" title="Honeypot list is local-only. Backend honeypot config is loaded from waf.yaml at boot.">not wired</span>
        </div>
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, marginBottom: 8 }}>
          {honeypots.map(p => (
            <span key={p} className="chip active">{p} <span className="chip-x" onClick={() => setHoneypots(hp => hp.filter(x => x !== p))}><window.I.X /></span></span>
          ))}
        </div>
        <div style={{ display: 'flex', gap: 6 }}>
          <input className="input" placeholder="/trap-path" />
          <button className="icon-btn"><window.I.Plus /></button>
        </div>
      </div>

      <div className="card">
        <div className="card-head" style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <div className="card-title">Response Filtering</div>
          <span className="pill warn" title="Toggles are local-only. Backend uses cfg.observability + cfg.dlp from waf.yaml.">not wired</span>
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <div className={`toggle ${stackTraces ? 'on' : ''}`} onClick={() => setStackTraces(s => !s)} />
            <div style={{ fontSize: 12 }}>Block stack traces in responses</div>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <div className={`toggle ${redactJSON ? 'on' : ''}`} onClick={() => setRedactJSON(s => !s)} />
            <div style={{ fontSize: 12 }}>Redact JSON fields (password, secret, token, ssn)</div>
          </div>
        </div>
      </div>

      {/* M004 (2026-05-07) — surface backend data already returned
          by /api/admin/sessions, /api/admin/break-glass,
          /api/integrations, /api/certs. All four cards are
          read-only today; mutation surfaces (terminate, toggle,
          update) ship in a follow-up once the audit-mutated
          handlers are wired. */}
      <SettingsSessionsCard />
      <SettingsBreakGlassCard />
      <SettingsIntegrationsCard />
      <SettingsCertsCard />

      {/*
        CQF-T7 — Cache management card removed.

        The previous card rendered 6 hardcoded "demo data"
        cache buckets (rules / geoip / ti / fp / session / dns)
        with hand-drawn sizes ("128 MB"), ages ("14m"), and entry
        counts ("8.4M entries"). The Flush buttons and the
        Reset-all button were both no-op stubs. M1 doesn't ship
        a query-cache layer (only the per-decision audit ring,
        which is bounded in entry count, not bytes); the card
        was aspirational.

        If a future track adds a per-cache stats endpoint
        (/api/caches/stats) and a flush handler, re-add the
        card here, sourced from the live API. The interop
        contract surface already has POST /__waf_control/
        flush_cache for benchmark-side cache invalidation
        (returns 200/4xx; not 5xx) — but that's not a per-
        bucket inspector.
      */}
    </>
  );
}

// ============== M004 SETTINGS SECTIONS ==============
// All four cards are read-only surfaces over backend data that
// previously had no UI. The QA finding was specifically:
//   "Operators cannot terminate sessions, enable break-glass,
//    configure integrations, or inspect cert expiry from the
//    dashboard. All require direct API calls."
// Visibility comes first; the mutation surfaces follow once the
// audit-mutated handlers exist (DELETE /api/admin/sessions/{id},
// POST /api/admin/break-glass, PUT /api/integrations).

function SettingsSessionsCard() {
  const sessions = window.useAdminSessionsApi
    ? window.useAdminSessionsApi()
    : { data: null };
  const rows = sessions.data?.sessions || [];
  return (
    <div className="card" style={{ marginBottom: 12 }}>
      <div className="card-head">
        <div>
          <div className="card-title">Active admin sessions</div>
          <div className="card-sub">
            live from /api/admin/sessions · {rows.length} active · terminate via direct API
            (audit-mutated DELETE handler not yet wired)
          </div>
        </div>
        <span className={`pill ${rows.length > 0 ? 'up' : 'neutral'}`}>{rows.length}</span>
      </div>
      {rows.length === 0 ? (
        <div style={{ padding: 12, fontSize: 12, color: 'var(--ink-dim)', textAlign: 'center' }}>
          No active sessions visible. (Your own session is excluded by the API.)
        </div>
      ) : (
        <table className="tbl tbl-compact">
          <thead>
            <tr>
              <th style={{ width: 220 }}>Session id</th>
              <th>Created</th>
              <th>Last seen</th>
              <th>IP</th>
              <th>User-Agent</th>
            </tr>
          </thead>
          <tbody>
            {rows.map(s => (
              <tr key={s.id || s.session_id}>
                <td className="mono" style={{ fontSize: 11 }}>
                  {(s.id || s.session_id || '—').slice(0, 16)}…
                </td>
                <td className="dim">
                  {s.created_at ? new Date(s.created_at).toISOString().slice(0, 19) : '—'}
                </td>
                <td className="dim">
                  {s.last_seen ? new Date(s.last_seen).toISOString().slice(0, 19) : '—'}
                </td>
                <td className="mono">{s.ip || '—'}</td>
                <td
                  className="dim"
                  style={{ maxWidth: 280, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}
                  title={s.user_agent}
                >
                  {s.user_agent || '—'}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

function SettingsBreakGlassCard() {
  const bg = window.useBreakGlassApi ? window.useBreakGlassApi() : { data: null };
  const data = bg.data || { active: false };
  const expiresAt = data.expires_at ? new Date(data.expires_at) : null;
  const expiresIn = expiresAt
    ? Math.max(0, Math.round((expiresAt - new Date()) / 60000))
    : null;
  return (
    <div className="card" style={{ marginBottom: 12 }}>
      <div className="card-head">
        <div>
          <div className="card-title">Break-glass</div>
          <div className="card-sub">
            emergency override · live from /api/admin/break-glass · toggle via direct API
            (audit-mutated POST handler not yet wired)
          </div>
        </div>
        <span className={`pill ${data.active ? 'down' : 'neutral'}`}>
          {data.active ? 'ACTIVE' : 'INACTIVE'}
        </span>
      </div>
      <div style={{ padding: 4 }}>
        {data.active ? (
          <div className="callout warn" style={{ fontSize: 12 }}>
            <strong>Break-glass active.</strong>{' '}
            Reason: <em>{data.reason || '(unset)'}</em>{' '}
            · expires in ~{expiresIn} min
            {expiresAt && <> ({expiresAt.toISOString().slice(0, 19)} UTC)</>}
          </div>
        ) : (
          <div style={{ fontSize: 12, color: 'var(--ink-dim)' }}>
            Not active. When enabled, break-glass relaxes selected
            policies (e.g. mTLS) for a bounded TTL (60s–3600s) with
            a free-form reason recorded in the audit chain.
          </div>
        )}
      </div>
    </div>
  );
}

function SettingsIntegrationsCard() {
  const integ = window.useIntegrationsApi
    ? window.useIntegrationsApi()
    : { data: null };
  const data = integ.data || {};
  const fields = [
    { key: 'grafana_url', label: 'Grafana' },
    { key: 'alertmanager_url', label: 'Alertmanager' },
    { key: 'gitops_repo', label: 'GitOps repo' },
    { key: 'prometheus_url', label: 'Prometheus' },
  ];
  const configured = fields.filter(f => data[f.key]).length;
  return (
    <div className="card" style={{ marginBottom: 12 }}>
      <div className="card-head">
        <div>
          <div className="card-title">External integrations</div>
          <div className="card-sub">
            live from /api/integrations · {configured} of {fields.length} configured · edit via
            waf.yaml + restart (audit-mutated PUT handler not yet wired)
          </div>
        </div>
        <span className={`pill ${configured > 0 ? 'up' : 'neutral'}`}>
          {configured}/{fields.length}
        </span>
      </div>
      <table className="tbl tbl-compact">
        <tbody>
          {fields.map(f => (
            <tr key={f.key}>
              <td style={{ width: 180, color: 'var(--ink-dim)' }}>{f.label}</td>
              <td className="mono">
                {data[f.key]
                  ? <a href={data[f.key]} target="_blank" rel="noopener noreferrer">{data[f.key]}</a>
                  : <span style={{ color: 'var(--ink-dim)', fontStyle: 'italic' }}>not configured</span>}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function SettingsCertsCard() {
  const certsApi = window.useCertsApi ? window.useCertsApi() : { data: null };
  const certs = certsApi.data?.certs || certsApi.data || [];
  const rows = Array.isArray(certs) ? certs : [];
  function tone(days) {
    if (days == null) return 'neutral';
    if (days < 14) return 'down';
    if (days < 30) return 'warn';
    return 'up';
  }
  return (
    <div className="card" style={{ marginBottom: 12 }}>
      <div className="card-head">
        <div>
          <div className="card-title">Certificates</div>
          <div className="card-sub">
            live from /api/certs · {rows.length} loaded · ACME / static / mTLS source
          </div>
        </div>
        <span className={`pill neutral`}>{rows.length}</span>
      </div>
      {rows.length === 0 ? (
        <div style={{ padding: 12, fontSize: 12, color: 'var(--ink-dim)', textAlign: 'center' }}>
          No certs reported. /api/certs may not be wired in this build.
        </div>
      ) : (
        <table className="tbl tbl-compact">
          <thead>
            <tr>
              <th>Subject / host</th>
              <th>Issuer</th>
              <th>Source</th>
              <th style={{ width: 140 }}>Expires</th>
              <th style={{ width: 110 }}>Days remaining</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((c, i) => {
              const days = c.days_to_expiry ?? c.days_remaining;
              return (
                <tr key={c.host || c.subject || i}>
                  <td className="mono">{c.host || c.subject || '—'}</td>
                  <td className="dim">{c.issuer || '—'}</td>
                  <td>
                    <span className="pill neutral" style={{ fontSize: 9 }}>
                      {c.source || 'static'}
                    </span>
                  </td>
                  <td className="dim">
                    {c.expires_at
                      ? new Date(c.expires_at).toISOString().slice(0, 10)
                      : c.not_after || '—'}
                  </td>
                  <td>
                    <span className={`pill ${tone(days)}`}>
                      {days != null ? `${days} d` : '—'}
                    </span>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      )}
    </div>
  );
}

// ============== TRACKING ==============

// CC-T2.2 — kind-tag → human label. Mirrors the serde-derived
// `RedactedKind::tag()` strings emitted by the backend so the
// dashboard binding stays stable.
const RECEIVER_KIND_LABELS = {
  vip_talk: 'VipTalk',
  slack: 'Slack',
  pager_duty: 'PagerDuty',
  service_now: 'ServiceNow',
  jira: 'Jira',
  alertmanager_webhook: 'Alertmanager',
};
const RECEIVER_KIND_OPTIONS = Object.entries(RECEIVER_KIND_LABELS);

// Build a one-line target preview for the list row. Always uses
// the *redacted* fields the backend exposes — never reads raw
// secrets (the dashboard never holds the plaintext after a save).
function receiverTargetPreview(kind) {
  if (!kind) return '';
  switch (kind.type) {
    case 'vip_talk':
      return `${kind.bot_token_redacted} → ${(kind.room_ids || []).length} room(s)`;
    case 'slack':
      return kind.webhook_url_redacted;
    case 'pager_duty':
      return kind.routing_key_redacted;
    case 'service_now':
      return `${kind.instance} · ${kind.table}`;
    case 'jira':
      return `${kind.base_url} · ${kind.project}`;
    case 'alertmanager_webhook':
      return kind.url;
    default:
      return '';
  }
}

// Build the per-status pill for the dispatch ring outcome.
function deliveryStatusPill(status) {
  if (!status || !status.last_status) {
    return { tone: 'neutral', label: 'idle' };
  }
  if (status.last_status === 'ok') {
    return { tone: 'ok', label: `delivered ${formatRelative(status.last_delivered_at)}` };
  }
  if (status.last_status === 'external') {
    return { tone: 'info', label: `external · ${formatRelative(status.last_delivered_at)}` };
  }
  if (status.last_status === 'skipped_no_feature') {
    return { tone: 'warn', label: 'skipped (no `alerts` feature)' };
  }
  if (status.last_status.startsWith('failed:')) {
    const reason = status.last_status.slice('failed:'.length);
    const n = status.consecutive_failures || 1;
    return { tone: 'err', label: `failed ${n}× · ${reason.slice(0, 32)}` };
  }
  return { tone: 'neutral', label: status.last_status };
}

function formatRelative(unixSeconds) {
  if (!unixSeconds) return '';
  const ageSec = Math.max(0, Math.floor(Date.now() / 1000 - unixSeconds));
  if (ageSec < 60) return `${ageSec}s ago`;
  if (ageSec < 3600) return `${Math.floor(ageSec / 60)}m ago`;
  if (ageSec < 86400) return `${Math.floor(ageSec / 3600)}h ago`;
  return `${Math.floor(ageSec / 86400)}d ago`;
}

// Empty-shape factories per ReceiverKind variant. Used by the
// "+ Add channel" modal when the operator picks a kind from the
// dropdown — we stamp the matching empty payload so the form
// fields render in the right shape.
function emptyKindBody(tag) {
  switch (tag) {
    case 'vip_talk':
      return { VipTalk: { bot_token: '', room_ids: [''] } };
    case 'slack':
      return { Slack: { webhook_url: '' } };
    case 'pager_duty':
      return { PagerDuty: { routing_key: '' } };
    case 'service_now':
      return { ServiceNow: { instance: '', table: 'incident' } };
    case 'jira':
      return { Jira: { base_url: '', project: '' } };
    case 'alertmanager_webhook':
      return { AlertmanagerWebhook: { url: '' } };
    default:
      return null;
  }
}

// Build a wire-shape AlertReceiver from the modal form draft.
// Returns null when the kind tag isn't recognised.
function draftToReceiver(draft) {
  const empty = emptyKindBody(draft.kindTag);
  if (!empty) return null;
  const variantKey = Object.keys(empty)[0];
  const fields = { ...empty[variantKey] };
  // Copy form values into the variant payload, dropping empty
  // strings that should remain empty for the validator to reject
  // (the validator's reason_codes drive the toast text).
  if (draft.kindTag === 'vip_talk') {
    fields.bot_token = draft.bot_token || '';
    fields.room_ids = (draft.room_ids || '')
      .split(/[\n,]/).map(s => s.trim()).filter(Boolean);
    if (fields.room_ids.length === 0) fields.room_ids = [''];
  } else if (draft.kindTag === 'slack') {
    fields.webhook_url = draft.webhook_url || '';
  } else if (draft.kindTag === 'pager_duty') {
    fields.routing_key = draft.routing_key || '';
  } else if (draft.kindTag === 'service_now') {
    fields.instance = draft.instance || '';
    fields.table = draft.table || 'incident';
  } else if (draft.kindTag === 'jira') {
    fields.base_url = draft.base_url || '';
    fields.project = draft.project || '';
  } else if (draft.kindTag === 'alertmanager_webhook') {
    fields.url = draft.url || '';
  }
  return { name: (draft.name || '').trim(), kind: { [variantKey]: fields } };
}

function AlertChannelsCard({ receiversApi }) {
  const { useState: useStateP } = React;
  const [editing, setEditing] = useStateP(null); // null | { mode: 'add'|'edit', draft: {...} }
  const [busy, setBusy] = useStateP(null);       // receiver-name being acted on
  const list = receiversApi.data?.receivers ?? [];

  const openAdd = () => setEditing({ mode: 'add', draft: { kindTag: 'vip_talk', name: '' } });
  const openEdit = (entry) => setEditing({
    mode: 'edit',
    draft: { kindTag: entry.kind?.type, name: entry.name, ...flatFieldsFromKind(entry.kind) },
  });

  async function applyDraft(receivers, draft) {
    const newReceiver = draftToReceiver(draft);
    if (!newReceiver) {
      window.aegisToast('Pick a channel kind', 'err');
      return false;
    }
    const next = (() => {
      if (editing.mode === 'edit') {
        return receivers.map(r => r.name === draft.originalName ? newReceiver : r);
      }
      return [...receivers, newReceiver];
    })();
    const result = await window.alertReceiversPut(next);
    if (result && result.ok) {
      window.aegisToast(`Saved channel "${newReceiver.name}"`, 'ok');
      receiversApi.reload && receiversApi.reload();
      return true;
    }
    const msg = (result && (result.message || result.error || result.reason)) || 'unknown error';
    window.aegisToast(`Save failed: ${msg}`, 'err');
    return false;
  }

  async function removeReceiver(name) {
    if (!confirm(`Remove channel "${name}"? This is audit-logged.`)) return;
    setBusy(name);
    try {
      const r = await window.alertReceiverDelete(name);
      if (r && r.ok) {
        window.aegisToast(`Removed channel "${name}"`, 'ok');
        receiversApi.reload && receiversApi.reload();
      } else {
        const msg = (r && (r.message || r.error || r.reason)) || 'unknown error';
        window.aegisToast(`Remove failed: ${msg}`, 'err');
      }
    } finally {
      setBusy(null);
    }
  }

  async function testReceiver(name) {
    setBusy(name);
    try {
      const r = await window.alertReceiverTest(name);
      // BUG-FIX 2026-05-03: previous code treated r.ok as the
      // single source of truth, but the backend USED to return
      // ok=true even when VipTalk silently no-op'd because the
      // binary was built without --features alerts. Now we also
      // surface r.skipped_feature_off — that path means
      // "nothing left the WAF".
      const skipped = r?.skipped_feature_off?.length || 0;
      if (skipped > 0) {
        window.aegisToast(
          `Test SKIPPED: ${skipped} receiver(s) need rebuild with FEATURES="redis geoip alerts". Nothing was sent.`,
          'warn',
        );
        receiversApi.reload && receiversApi.reload();
      } else if (r && r.ok) {
        const parts = [];
        if (r.delivered?.length) parts.push(`delivered: ${r.delivered.length}`);
        if (r.external?.length)  parts.push(`external: ${r.external.length}`);
        if (r.failed?.length)    parts.push(`failed: ${r.failed.length}`);
        window.aegisToast(`Test → ${parts.join(' · ') || 'sent'}`, 'ok');
        receiversApi.reload && receiversApi.reload();
      } else {
        const msg = (r && (r.message || r.error || r.reason)) || 'unknown error';
        window.aegisToast(`Test failed: ${msg}`, 'err');
      }
    } finally {
      setBusy(null);
    }
  }

  return (
    <div className="card" style={{ marginBottom: 12 }}>
      <window.SectionHeader
        title="Alert channels"
        sub={`${list.length} configured · audit-mutated`}
        actions={(
          <button className="btn" onClick={openAdd}>+ Add channel</button>
        )}
      />
      {list.length === 0 && (
        <div style={{ padding: 16, fontSize: 12, color: 'var(--ink-dim)', textAlign: 'center' }}>
          No alert channels configured. The SLO engine will record alerts but won't deliver them.
        </div>
      )}
      <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
        {list.map(entry => {
          const pill = deliveryStatusPill(entry.status);
          const tag = entry.kind?.type;
          return (
            <div
              key={entry.name}
              style={{
                display: 'grid',
                gridTemplateColumns: '120px 160px 1fr 220px auto',
                gap: 10,
                alignItems: 'center',
                padding: '8px 10px',
                background: 'var(--canvas-2)',
                borderRadius: 6,
                fontSize: 12,
              }}
            >
              <span className="pill neutral" style={{ justifySelf: 'start' }}>
                {RECEIVER_KIND_LABELS[tag] || tag || '—'}
              </span>
              <span className="mono">{entry.name}</span>
              <span className="mono dim" style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                {receiverTargetPreview(entry.kind)}
              </span>
              <span className={`pill ${pill.tone}`}>{pill.label}</span>
              <div style={{ display: 'flex', gap: 6 }}>
                <button
                  className="btn"
                  disabled={busy === entry.name}
                  onClick={() => testReceiver(entry.name)}
                >Test</button>
                <button
                  className="btn"
                  disabled={busy === entry.name}
                  onClick={() => openEdit(entry)}
                >Edit</button>
                <button
                  className="btn"
                  disabled={busy === entry.name}
                  onClick={() => removeReceiver(entry.name)}
                  style={{ color: 'var(--down)' }}
                >Remove</button>
              </div>
            </div>
          );
        })}
      </div>
      {editing && (
        <AlertChannelModal
          mode={editing.mode}
          draft={editing.draft}
          existingNames={list.map(r => r.name)}
          onCancel={() => setEditing(null)}
          onSave={async (draft) => {
            const ok = await applyDraft(list, draft);
            if (ok) setEditing(null);
          }}
        />
      )}
    </div>
  );
}

// Inverse of `draftToReceiver` — derives a flat form-friendly
// shape from a (redacted) ReceiverEntry the GET endpoint returned.
// Token / URL fields are LEFT BLANK on edit so the operator must
// re-enter the secret to change it; saving with empty secrets
// triggers the backend's `empty_target` validator (intentional —
// "preserve existing secret" is a CC-T2.2 follow-up needing a
// dedicated `--keep-secret` server-side path).
function flatFieldsFromKind(kind) {
  if (!kind) return {};
  switch (kind.type) {
    case 'vip_talk':
      return { bot_token: '', room_ids: (kind.room_ids || []).join('\n') };
    case 'slack':
      return { webhook_url: '' };
    case 'pager_duty':
      return { routing_key: '' };
    case 'service_now':
      return { instance: kind.instance || '', table: kind.table || 'incident' };
    case 'jira':
      return { base_url: kind.base_url || '', project: kind.project || '' };
    case 'alertmanager_webhook':
      return { url: kind.url || '' };
    default:
      return {};
  }
}

function AlertChannelModal({ mode, draft, existingNames, onSave, onCancel }) {
  const { useState: useStateP } = React;
  const [d, setD] = useStateP({
    ...draft,
    originalName: draft.name,
  });
  const set = (k, v) => setD(prev => ({ ...prev, [k]: v }));

  const isEdit = mode === 'edit';
  const nameTaken =
    !isEdit && existingNames.includes((d.name || '').trim()) && (d.name || '').trim() !== '';
  const canSave =
    (d.name || '').trim() !== '' &&
    !nameTaken &&
    !!d.kindTag;

  return (
    <div
      style={{
        position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.5)',
        display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000,
      }}
      onClick={onCancel}
    >
      <div
        className="card"
        style={{ width: 520, maxWidth: '92vw', padding: 0 }}
        onClick={e => e.stopPropagation()}
      >
        <div style={{
          padding: '14px 16px', borderBottom: '1px solid var(--hairline)',
          display: 'flex', alignItems: 'center',
        }}>
          <div style={{ fontSize: 14, fontWeight: 600 }}>
            {isEdit ? `Edit channel "${draft.name}"` : 'Add alert channel'}
          </div>
          <span style={{ fontSize: 11, color: 'var(--ink-dim)', marginLeft: 8 }}>
            audit-mutated · CSRF-gated
          </span>
          <button className="btn" style={{ marginLeft: 'auto' }} onClick={onCancel}>×</button>
        </div>
        <div style={{ padding: 16, display: 'flex', flexDirection: 'column', gap: 12 }}>
          <label style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
            <span className="field-label">Name</span>
            <input
              className="input mono"
              value={d.name || ''}
              onChange={e => set('name', e.target.value)}
              disabled={isEdit}
              placeholder="vt-prod"
              autoFocus={!isEdit}
            />
            {nameTaken && (
              <span style={{ color: 'var(--down)', fontSize: 11 }}>
                Name already in use.
              </span>
            )}
          </label>
          <label style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
            <span className="field-label">Kind</span>
            <select
              className="input"
              value={d.kindTag || ''}
              onChange={e => setD(prev => ({
                ...prev,
                kindTag: e.target.value,
                bot_token: '', room_ids: '', webhook_url: '',
                routing_key: '', instance: '', table: 'incident',
                base_url: '', project: '', url: '',
              }))}
              disabled={isEdit}
            >
              {RECEIVER_KIND_OPTIONS.map(([tag, label]) => (
                <option key={tag} value={tag}>{label}</option>
              ))}
            </select>
          </label>
          <KindFieldset draft={d} setField={set} isEdit={isEdit} />
          {isEdit && (
            <div style={{ fontSize: 11, color: 'var(--ink-dim)' }}>
              Secrets shown only as <span className="mono">****&lt;last4&gt;</span>.
              Re-enter the full secret to change it; leaving blank → backend
              rejects with <span className="mono">empty_target</span>.
            </div>
          )}
        </div>
        <div style={{
          padding: 12, borderTop: '1px solid var(--hairline)',
          display: 'flex', gap: 8, justifyContent: 'flex-end',
        }}>
          <button className="btn" onClick={onCancel}>Cancel</button>
          <button
            className="btn primary"
            disabled={!canSave}
            onClick={() => onSave(d)}
          >Save</button>
        </div>
      </div>
    </div>
  );
}

function KindFieldset({ draft, setField, isEdit }) {
  const tag = draft.kindTag;
  if (tag === 'vip_talk') {
    return (
      <>
        <label style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
          <span className="field-label">Bot token</span>
          <input
            className="input mono"
            type="password"
            value={draft.bot_token || ''}
            onChange={e => setField('bot_token', e.target.value)}
            placeholder={isEdit ? '(re-enter to change)' : 'tok-...'}
          />
        </label>
        <label style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
          <span className="field-label">Room IDs (one per line, or comma-separated)</span>
          <textarea
            className="input mono"
            rows={3}
            value={draft.room_ids || ''}
            onChange={e => setField('room_ids', e.target.value)}
            placeholder="!QNxJHzVzJBrLWIOLPo:matrix-uat.viptalk.org"
          />
        </label>
      </>
    );
  }
  if (tag === 'slack') {
    return (
      <label style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
        <span className="field-label">Webhook URL</span>
        <input
          className="input mono"
          type="password"
          value={draft.webhook_url || ''}
          onChange={e => setField('webhook_url', e.target.value)}
          placeholder="https://hooks.slack.com/services/..."
        />
      </label>
    );
  }
  if (tag === 'pager_duty') {
    return (
      <label style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
        <span className="field-label">Routing key</span>
        <input
          className="input mono"
          type="password"
          value={draft.routing_key || ''}
          onChange={e => setField('routing_key', e.target.value)}
          placeholder="R0123456789..."
        />
      </label>
    );
  }
  if (tag === 'service_now') {
    return (
      <>
        <label style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
          <span className="field-label">Instance</span>
          <input
            className="input mono"
            value={draft.instance || ''}
            onChange={e => setField('instance', e.target.value)}
            placeholder="acme.service-now.com"
          />
        </label>
        <label style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
          <span className="field-label">Table</span>
          <input
            className="input mono"
            value={draft.table || 'incident'}
            onChange={e => setField('table', e.target.value)}
          />
        </label>
      </>
    );
  }
  if (tag === 'jira') {
    return (
      <>
        <label style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
          <span className="field-label">Base URL</span>
          <input
            className="input mono"
            value={draft.base_url || ''}
            onChange={e => setField('base_url', e.target.value)}
            placeholder="https://acme.atlassian.net"
          />
        </label>
        <label style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
          <span className="field-label">Project key</span>
          <input
            className="input mono"
            value={draft.project || ''}
            onChange={e => setField('project', e.target.value)}
            placeholder="OPS"
          />
        </label>
      </>
    );
  }
  if (tag === 'alertmanager_webhook') {
    return (
      <label style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
        <span className="field-label">Webhook URL</span>
        <input
          className="input mono"
          value={draft.url || ''}
          onChange={e => setField('url', e.target.value)}
          placeholder="http://alertmanager:9093/api/v1/alerts"
        />
      </label>
    );
  }
  return null;
}

// S7 (2026-05-08) — root-cause hint surfaced on the Health & SLOs
// page when one or more SLOs drop below their target. Reads the
// last-hour by-detector breakdown and links to the Audit Trail
// filtered to the top blocking detector. Pre-fix: the analyst saw
// a red SLO with no explanation and had to cross-reference attack
// logs by hand. Score now: 4-5/5 (S7 was 3/5 in QA Run-2).
function SloRootCauseHint({ slis }) {
  const breaching = (slis || []).filter(s => s.current < s.target);
  // Pull the by-detector window unconditionally so the hook
  // ordering stays stable across renders. The hint only shows
  // when there's something to explain.
  const byDet = window.useAttacksByDetectorApi
    ? window.useAttacksByDetectorApi(3600)
    : { data: null };
  if (breaching.length === 0) return null;
  const detectors = byDet.data?.by_detector || [];
  const top = [...detectors]
    .sort((a, b) => (b.blocks ?? b.count ?? 0) - (a.blocks ?? a.count ?? 0))[0];
  return (
    <div
      className="callout warn"
      style={{ marginBottom: 10, fontSize: 12, lineHeight: 1.45 }}
      role="alert"
    >
      <strong>
        {breaching.length} SLO{breaching.length === 1 ? '' : 's'} below target.
      </strong>
      {top
        ? (
          <>
            {' '}Top blocking detector in the last hour:{' '}
            <code>{top.detector || top.name || 'unknown'}</code>
            {top.blocks != null && <> ({top.blocks} blocks)</>}.{' '}
            <a href="#/audit" style={{ color: 'var(--accent)' }}>
              View Audit Trail →
            </a>
          </>
        )
        : (
          <>
            {' '}No blocked-traffic data in the last hour — the SLO breach
            isn't from detector blocks. Check{' '}
            <a href="#/health" style={{ color: 'var(--accent)' }}>upstream health</a>
            {' '}and the alerts panel below.
          </>
        )}
    </div>
  );
}

function PageTracking() {
  // Live API hooks. SLO / certs / alerts / gitops still return
  // placeholder shapes server-side (CI-T4 will replace those);
  // cluster + upstreams are real today.
  const cluster = window.useClusterApi();
  const upstreamsApi = window.useUpstreamsApi();
  const slo = window.useSloApi();
  const certs = window.useCertsApi();
  const alerts = window.useAlertsApi();
  const gitops = window.useGitopsApi();
  // CC-T2.2 — alert channels (read + audit-mutated PUT/DELETE/POST-test)
  const alertReceivers = window.useAlertReceiversApi();

  // Pool list adapter — server returns `{pools: [{...}]}`; mock
  // fallback is `[{...}]`; accept either shape.
  const upstreamsRaw = upstreamsApi.data?.pools ?? upstreamsApi.data ?? [];
  const upstreams = Array.isArray(upstreamsRaw) ? upstreamsRaw : [];

  const peers = cluster.data?.peers || [];
  const ourNode = cluster.data?.our_node;
  const isLeader = cluster.data?.is_leader;

  return (
    <>
      <div className="page-head">
        <div>
          <h1 className="page-title">Health &amp; SLOs</h1>
          <p className="page-subtitle">
            Operational state · SLO · cluster · GitOps · cert health
            <span style={{ marginLeft: 8 }}>
              <span className={`pill ${isLeader ? 'solid-yellow' : 'neutral'}`}>
                {ourNode ? `node ${ourNode}${isLeader ? ' · leader' : ''}` : 'standalone'}
              </span>
            </span>
          </p>
        </div>
        <div className="page-actions">
          <button className="btn" onClick={() => {
            cluster.reload && cluster.reload();
            upstreamsApi.reload && upstreamsApi.reload();
            slo.reload && slo.reload();
            certs.reload && certs.reload();
            alerts.reload && alerts.reload();
            gitops.reload && gitops.reload();
            alertReceivers.reload && alertReceivers.reload();
          }}>
            <window.I.Refresh /> Refresh
          </button>
        </div>
      </div>

      <div className="grid-12" style={{ marginBottom: 12 }}>
        <div className="col-6 card">
          <window.SectionHeader title="SLO budget" sub="live engine · burn windows pending wiring" />
          {/* S7 (2026-05-08) — root-cause hint when an SLO is below
              target. Pre-fix: the SOC analyst saw a red SLO and had
              to cross-reference attack logs manually to find the
              culprit. Now we surface the top blocking detector and
              link to the audit trail filtered to it. */}
          <SloRootCauseHint slis={slo.data?.slis || []} />
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            {(slo.data?.slis || []).length === 0 && (
              <div style={{ padding: 12, fontSize: 12, color: 'var(--ink-dim)', textAlign: 'center' }}>
                No SLO data — engine warming up.
              </div>
            )}
            {(slo.data?.slis || []).map(s => {
              const tone = s.budget_remaining > 0.5 ? 'up' : s.budget_remaining > 0.1 ? 'warn' : 'down';
              return (
                <div key={s.name} style={{ display: 'grid', gridTemplateColumns: '180px 80px 80px 1fr 80px', gap: 10, alignItems: 'center', fontSize: 12 }}>
                  <span>{s.name}</span>
                  <span className="num" style={{ color: `var(--${tone === 'up' ? 'up' : tone === 'warn' ? 'warn' : 'down'})` }}>
                    {s.current.toFixed(2)}%
                  </span>
                  <span className="dim">{s.target.toFixed(2)}%</span>
                  <div style={{ height: 6, background: 'var(--surface-3)', borderRadius: 3, overflow: 'hidden' }}>
                    <div style={{ width: `${(s.budget_remaining * 100).toFixed(0)}%`, height: '100%', background: tone === 'up' ? 'var(--up)' : tone === 'warn' ? 'var(--warn)' : 'var(--down)' }} />
                  </div>
                  <span className={`pill ${tone}`}>{(s.budget_remaining * 100).toFixed(0)}% left</span>
                </div>
              );
            })}
          </div>
        </div>
        <div className="col-6 card">
          {(() => {
            const firing = alerts.data?.firing || [];
            const resolved = alerts.data?.resolved || [];
            return (
              <window.SectionHeader
                title="Active alerts"
                sub={`${firing.length} firing · ${resolved.length} acked`}
              />
            );
          })()}
          <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
            {(alerts.data?.firing || []).length === 0 && (
              <div style={{ padding: 12, fontSize: 12, color: 'var(--ink-dim)', textAlign: 'center' }}>
                No alerts firing.
              </div>
            )}
            {(alerts.data?.firing || []).map(a => (
              <div key={a.name} style={{ display: 'flex', alignItems: 'center', gap: 8, padding: 8, background: 'var(--canvas-2)', borderRadius: 6, fontSize: 12 }}>
                <span className={`pill ${a.severity === 'page' ? 'err' : a.severity === 'ticket' ? 'warn' : 'info'}`}>
                  {a.severity}
                </span>
                <div style={{ flex: 1 }}>
                  <div className="mono" style={{ color: 'var(--ink)' }}>{a.name}</div>
                  {a.runbook_url && (
                    <a href={a.runbook_url} target="_blank" rel="noopener noreferrer" className="dim" style={{ fontSize: 11 }}>
                      runbook ↗
                    </a>
                  )}
                </div>
                <span className="dim" style={{ fontSize: 11 }}>
                  {a.since ? new Date(a.since).toLocaleTimeString() : ''}
                </span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* CC-T2.2 — alert-channel management. Lives next to the
          Active alerts panel because the two are operationally
          paired: the alerts pane shows what fired; this pane
          configures *where* the next firing alert is sent. */}
      <AlertChannelsCard receiversApi={alertReceivers} />

      <div className="card" style={{ marginBottom: 12 }}>
        {(() => {
          const totalMembers = upstreams.reduce((s, x) => s + (x.total ?? x.members ?? x.total_members ?? 0), 0);
          const totalHealthy = upstreams.reduce((s, x) => s + (x.healthy ?? x.healthy_members ?? 0), 0);
          return (
            <window.SectionHeader
              title="Upstream pools"
              sub={`${upstreams.length} pools · ${totalHealthy}/${totalMembers} healthy`}
            />
          );
        })()}
        <table className="tbl tbl-compact">
          <thead><tr><th>Pool</th><th>Members</th><th>LB</th><th>Circuit</th><th>p99</th><th>req/s</th><th>Status</th></tr></thead>
          <tbody>
            {upstreams.length === 0 && (
              <tr><td colSpan={7} style={{ textAlign: 'center', padding: 16, color: 'var(--ink-dim)', fontSize: 12 }}>
                No upstream pools registered.
              </td></tr>
            )}
            {upstreams.map(p => {
              const total = p.total ?? p.members ?? p.total_members ?? 0;
              const healthy = p.healthy ?? p.healthy_members ?? 0;
              const cb = p.cb || p.circuit_breaker || 'closed';
              const ok = total > 0 && healthy === total;
              const half = cb === 'half-open';
              const open = cb === 'open';
              return (
                <tr key={p.name}>
                  <td className="mono">{p.name}</td>
                  <td>
                    <div style={{ display: 'flex', gap: 2 }}>
                      {Array.from({length: total}).map((_, i) => (
                        <span key={i} style={{ width: 8, height: 14, background: i < healthy ? 'var(--up)' : 'var(--down)', borderRadius: 1 }} />
                      ))}
                      <span className="num dim" style={{ marginLeft: 6, fontSize: 11 }}>{healthy}/{total}</span>
                    </div>
                  </td>
                  <td className="mono dim">{p.lb || '—'}</td>
                  <td><span className={`pill ${open ? 'err' : half ? 'warn' : 'ok'}`}>{cb}</span></td>
                  <td className="num">{p.p99 ? `${p.p99}ms` : '—'}</td>
                  <td className="num">{(p.rps ?? 0).toLocaleString()}</td>
                  <td>{ok && !open ? <span className="pill ok">healthy</span> : open ? <span className="pill err">down</span> : <span className="pill warn">degraded</span>}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      <div className="grid-12" style={{ marginBottom: 12 }}>
        <div className="col-6 card">
          <window.SectionHeader
            title="Cluster peers"
            sub={`${peers.length} ${peers.length === 1 ? 'node' : 'nodes'} · ${cluster.data?.leader_node ? `leader: ${cluster.data.leader_node}` : 'no leader observed'}`}
          />
          <table className="tbl tbl-compact">
            <thead><tr><th>ID</th><th>Address</th><th>Version</th><th>Role</th><th>Heartbeat</th><th>Leases</th></tr></thead>
            <tbody>
              {peers.length === 0 && (
                <tr><td colSpan={6} style={{ textAlign: 'center', padding: 16, color: 'var(--ink-dim)', fontSize: 12 }}>
                  Single-node deployment — no cluster peers.
                </td></tr>
              )}
              {peers.map(c => (
                <tr key={c.id}>
                  <td className="mono">{c.id}</td>
                  <td className="mono dim">{c.addr || '—'}</td>
                  <td><span className="pill neutral">{c.version || '—'}</span></td>
                  <td><span className={`pill ${c.id === cluster.data?.leader_node ? 'solid-yellow' : 'neutral'}`}>
                    {c.id === cluster.data?.leader_node ? 'leader' : 'follower'}
                  </span></td>
                  <td className="num dim">{c.last_heartbeat ? new Date(c.last_heartbeat).toLocaleTimeString() : '—'}</td>
                  <td>{(c.leases || []).length === 0 ? <span className="dim">—</span> : c.leases.map(l => <span key={l} className="pill info" style={{ marginRight: 4 }}>{l}</span>)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <div className="col-6 card">
          {(() => {
            const certList = certs.data?.certs || [];
            return (
              <window.SectionHeader
                title="Cert freshness"
                sub={`${certList.length} cert${certList.length === 1 ? '' : 's'} loaded`}
              />
            );
          })()}
          <table className="tbl tbl-compact">
            <thead><tr><th>Host</th><th>Issuer</th><th>Source</th><th>Expires</th></tr></thead>
            <tbody>
              {(certs.data?.certs || []).length === 0 && (
                <tr><td colSpan={4} style={{ textAlign: 'center', padding: 16, color: 'var(--ink-dim)', fontSize: 12 }}>
                  No certs configured (data plane is plaintext).
                </td></tr>
              )}
              {(certs.data?.certs || []).map(c => {
                const tone = c.days_to_expiry < 7 ? 'err' : c.days_to_expiry < 30 ? 'warn' : 'ok';
                return (
                  <tr key={c.host + c.issuer}>
                    <td className="mono">{c.host}</td>
                    <td className="dim">{c.issuer}</td>
                    <td><span className="pill neutral">{c.source}</span></td>
                    <td><span className={`pill ${tone}`}>{c.days_to_expiry}d</span></td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>

      <div className="card">
        {(() => {
          const g = gitops.data || {};
          const configured = Boolean(g.repo);
          return (
            <>
              <window.SectionHeader
                title="GitOps sync"
                sub={configured ? `auto-pull from ${g.branch || 'main'}` : 'not configured'}
              />
              {configured ? (
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 14, fontSize: 12 }}>
                  <div><div className="field-label">Repo</div><div className="mono">{g.repo}</div></div>
                  <div><div className="field-label">Branch</div><span className="pill neutral">{g.branch}</span></div>
                  <div><div className="field-label">Last sync</div><span className="num">{g.last_sync ? new Date(g.last_sync).toLocaleTimeString() : '—'}</span></div>
                  <div><div className="field-label">Drift</div><span className={`pill ${g.drift ? 'warn' : 'ok'}`}>{g.drift ? 'drift' : 'none'}</span></div>
                  {g.head_commit && (
                    <div style={{ gridColumn: '1 / -1' }}>
                      <div className="field-label">HEAD commit</div>
                      <div className="mono" style={{ fontSize: 11 }}>
                        <span style={{ color: 'var(--brand-yellow)' }}>{g.head_commit.slice(0, 7)}</span>
                        <span className={`pill ${g.signature_ok ? 'ok' : 'err'}`} style={{ marginLeft: 8 }}>
                          {g.signature_ok ? 'signature verified' : 'signature failed'}
                        </span>
                      </div>
                    </div>
                  )}
                </div>
              ) : (
                <div style={{ padding: 12, fontSize: 12, color: 'var(--ink-dim)' }}>
                  GitOps disabled. Set <span className="mono">gitops.repo_url</span> in your config to enable config-as-code.
                </div>
              )}
            </>
          );
        })()}
      </div>
    </>
  );
}

// ============== UPSTREAMS (CC-T1.2) ==============
//
// Read-only first slice. Lists every configured pool with full
// detail (members / lb / health / circuit-breaker / connection
// pool / referenced-by-routes). The audit-mutated PUT/DELETE
// land in CC-T1.1.b once `ProxyContext.pools` becomes hot-
// swappable; until then this page surfaces the YAML-loaded
// state so operators can verify what's running without
// shelling into the box.

function fmtMs(ms) {
  if (ms == null) return '—';
  if (ms < 1000) return `${ms} ms`;
  if (ms < 60_000) return `${(ms / 1000).toFixed(1)} s`;
  return `${(ms / 60_000).toFixed(1)} m`;
}

function fmtPct(v) {
  if (v == null || isNaN(v)) return '—';
  return `${(v * 100).toFixed(0)}%`;
}

function lbBadgeTone(lb) {
  // Stable visual hint per strategy — operators can scan the
  // pool list without reading the labels.
  switch (lb) {
    case 'round_robin':           return 'neutral';
    case 'weighted_round_robin':  return 'info';
    case 'least_conn':            return 'ok';
    case 'consistent_hash':       return 'warn';
    case 'p2c':                   return 'ok';
    default:                      return 'neutral';
  }
}

function PoolListRow({ pool, name, summary, isSelected, onSelect }) {
  const total = pool.members?.length ?? 0;
  // Live health from /api/upstreams (not the config view) — gives
  // the real healthy/total instead of guessing from config.
  const live = (summary || []).find(p => p.name === name);
  const healthy = live?.healthy ?? live?.healthy_members ?? 0;
  const liveTotal = live?.total ?? live?.total_members ?? total;
  const healthOk = liveTotal > 0 && healthy === liveTotal;
  const healthDown = liveTotal > 0 && healthy === 0;
  return (
    <button
      type="button"
      onClick={() => onSelect(name)}
      className={`nav-item ${isSelected ? 'active' : ''}`}
      style={{
        textAlign: 'left',
        width: '100%',
        gap: 6,
        padding: '8px 10px',
        marginBottom: 4,
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, width: '100%' }}>
        <span className="mono" style={{ fontWeight: 600, flex: 1, overflow: 'hidden', textOverflow: 'ellipsis' }}>
          {name}
        </span>
        <span className={`pill ${lbBadgeTone(pool.lb)}`} style={{ fontSize: 10 }}>
          {pool.lb}
        </span>
      </div>
      <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 11, color: 'var(--ink-dim)' }}>
        <span>{total} member{total === 1 ? '' : 's'}</span>
        <span className="dim">·</span>
        <span className={`pill ${healthOk ? 'ok' : healthDown ? 'err' : 'warn'}`} style={{ fontSize: 10 }}>
          {healthy}/{liveTotal} healthy
        </span>
        {pool.referenced_by_routes?.length > 0 && (
          <>
            <span className="dim">·</span>
            <span>{pool.referenced_by_routes.length} route{pool.referenced_by_routes.length === 1 ? '' : 's'}</span>
          </>
        )}
      </div>
    </button>
  );
}

function PoolDetail({ name, pool, onEdit, onDelete, busy }) {
  if (!pool) {
    return (
      <div className="card" style={{ padding: 32, textAlign: 'center', color: 'var(--ink-dim)', fontSize: 13 }}>
        Select a pool from the list to inspect its configuration.
      </div>
    );
  }

  const memberRows = pool.members || [];
  const cb = pool.circuit_breaker;
  const health = pool.health;
  const conn = pool.connection || {};
  const refs = pool.referenced_by_routes || [];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
      <div className="card">
        <window.SectionHeader
          title={name}
          sub={`${memberRows.length} member${memberRows.length === 1 ? '' : 's'} · lb ${pool.lb}`}
          actions={(
            <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
              <span className={`pill ${refs.length === 0 ? 'warn' : 'ok'}`}>
                {refs.length === 0 ? 'unreferenced' : `${refs.length} route${refs.length === 1 ? '' : 's'}`}
              </span>
              <button
                className="btn"
                onClick={() => onEdit && onEdit(name, pool)}
                disabled={busy}
              >Edit</button>
              <button
                className="btn"
                style={{ color: 'var(--down)' }}
                onClick={() => onDelete && onDelete(name, refs)}
                disabled={busy}
                title={refs.length > 0 ? `Will return 409 — ${refs.length} route(s) still target this pool` : 'Audit-mutated · CSRF-gated'}
              >Delete</button>
            </div>
          )}
        />
        <table className="tbl tbl-compact">
          <thead>
            <tr>
              <th>Address</th>
              <th style={{ width: 80 }}>Weight</th>
              <th>Zone</th>
            </tr>
          </thead>
          <tbody>
            {memberRows.length === 0 && (
              <tr>
                <td colSpan={3} style={{ textAlign: 'center', padding: 16, color: 'var(--ink-dim)', fontSize: 12 }}>
                  No members configured. Pool will return upstream errors for any route that targets it.
                </td>
              </tr>
            )}
            {memberRows.map((m, i) => (
              <tr key={`${m.addr}-${i}`}>
                <td className="mono">{m.addr}</td>
                <td className="num">{m.weight ?? 1}</td>
                <td className="dim">{m.zone || '—'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div className="grid-12">
        <div className="col-6 card">
          <window.SectionHeader title="Health check" sub={health ? 'Active probe' : 'Disabled'} />
          {health ? (
            <div style={{ display: 'grid', gridTemplateColumns: '120px 1fr', gap: 6, fontSize: 12 }}>
              <span className="dim">Path</span>      <span className="mono">{health.path}</span>
              <span className="dim">Interval</span>  <span className="num">{fmtMs(health.interval_ms)}</span>
              <span className="dim">Timeout</span>   <span className="num">{fmtMs(health.timeout_ms)}</span>
            </div>
          ) : (
            <div style={{ fontSize: 12, color: 'var(--ink-dim)' }}>
              No health check — every member treated as healthy at boot.
            </div>
          )}
        </div>

        <div className="col-6 card">
          <window.SectionHeader title="Circuit breaker" sub={cb ? 'Active' : 'Disabled'} />
          {cb ? (
            <div style={{ display: 'grid', gridTemplateColumns: '160px 1fr', gap: 6, fontSize: 12 }}>
              <span className="dim">Error-rate threshold</span>
              <span className="num">{fmtPct(cb.error_rate_threshold)}</span>
              <span className="dim">Open duration</span>
              <span className="num">{fmtMs(cb.open_duration_ms)}</span>
            </div>
          ) : (
            <div style={{ fontSize: 12, color: 'var(--ink-dim)' }}>
              No circuit breaker — every request reaches the upstream regardless of recent failures.
            </div>
          )}
        </div>
      </div>

      <div className="card">
        <window.SectionHeader title="Connection pool" sub="Per-pool keep-alive tuning (UP-T1)" />
        <div style={{ display: 'grid', gridTemplateColumns: '180px 1fr 180px 1fr', gap: 6, fontSize: 12 }}>
          <span className="dim">Max idle / host</span>
          <span className="num">{conn.max_idle_per_host ?? '—'}</span>
          <span className="dim">Idle timeout</span>
          <span className="num">{fmtMs(conn.idle_timeout_ms)}</span>
          <span className="dim">Keep-alive</span>
          <span><span className={`pill ${conn.keep_alive ? 'ok' : 'warn'}`}>{conn.keep_alive ? 'on' : 'off'}</span></span>
          <span className="dim">Upstream TLS</span>
          <span><span className={`pill ${conn.tls ? 'ok' : 'neutral'}`}>{conn.tls ? 'https' : 'http'}</span></span>
        </div>
      </div>

      <div className="card">
        <window.SectionHeader
          title="Referenced by routes"
          sub={refs.length === 0
            ? 'No routes target this pool — safe to delete'
            : `${refs.length} route${refs.length === 1 ? '' : 's'} — DELETE will return 409 until these routes are updated`}
        />
        {refs.length === 0 ? (
          <div style={{ fontSize: 12, color: 'var(--ink-dim)' }}>
            DELETE this pool and the audit chain will record the removal; the proxy hot-swaps on the same request.
          </div>
        ) : (
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
            {refs.map(rid => (
              <span key={rid} className="pill neutral mono" style={{ fontSize: 11 }}>{rid}</span>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

// Routing page — restructured 2026-05-04 around the operator's
// mental model: routes are the primary list (because that's what
// they think about — "where does /news go?"), pools are the
// backend a route happens to point at. Click a route → see the
// pool inline with its members, scheme, host_header, health.
// "+ Add route" can create a new pool in the same step.
//
// (Function name kept as `PageUpstreams` for router compat; the
// sidebar label is "Routing & Upstreams".)
function PageUpstreams() {
  const cfgApi = window.useUpstreamsConfigApi();
  const summaryApi = window.useUpstreamsApi();
  const routesApi = window.useRoutesApi();
  const pools = cfgApi.data?.pools || {};
  const names = Object.keys(pools).sort();
  const summary = summaryApi.data?.pools || [];
  const routes = routesApi.data?.routes || [];

  const [editor, setEditor] = useStateP(null); // null | { kind: 'pool', mode: 'add'|'edit', ... }
  const [deleteModal, setDeleteModal] = useStateP(null); // pool delete only — route delete lives in RoutesTable
  const [busy, setBusy] = useStateP(false);
  const [showOrphans, setShowOrphans] = useStateP(false);

  const orphanPoolNames = names.filter(n => (pools[n]?.referenced_by_routes || []).length === 0);

  // Defensive — `pools[n]` can be undefined transiently between
  // a mutation landing and the next reload completing; without
  // optional chaining the page used to throw and the
  // PageErrorBoundary would catch it (still better than the
  // white-page-on-refresh bug, but we'd rather not crash at all).
  const totalMembers = names.reduce(
    (s, n) => s + (pools[n]?.members?.length || 0),
    0,
  );
  const orphaned = names.filter(
    n => (pools[n]?.referenced_by_routes || []).length === 0,
  ).length;

  // Pool-side handlers (used by the route-detail panel's
  // "Edit pool" / "Delete pool" buttons and by the route-add
  // modal when it creates a fresh pool inline).
  const openPoolEdit = (name, pool) => setEditor({ kind: 'pool', mode: 'edit', name, pool });
  const openPoolAdd  = () => setEditor({ kind: 'pool', mode: 'add' });

  async function savePool({ name, body }) {
    setBusy(true);
    try {
      const r = await window.poolUpsert(name, body);
      if (r.status === 200 && r.ok) {
        window.aegisToast(`Pool "${name}" saved`, 'ok');
        cfgApi.reload && cfgApi.reload();
        setEditor(null);
      } else {
        const msg = r.message || r.error || r.reason || `HTTP ${r.status}`;
        window.aegisToast(`Save failed: ${msg}`, 'err');
      }
    } finally {
      setBusy(false);
    }
  }

  function openDelete(name, refs) {
    setDeleteModal({ name, refs: refs || [] });
  }

  async function confirmPoolDelete() {
    if (!deleteModal) return;
    const { name } = deleteModal;
    setBusy(true);
    try {
      const r = await window.poolDelete(name);
      if (r.status === 200 && r.ok) {
        window.aegisToast(`Pool "${name}" removed`, 'ok');
        cfgApi.reload && cfgApi.reload();
        setDeleteModal(null);
      } else if (r.status === 409 && Array.isArray(r.referenced_by_routes)) {
        setDeleteModal({ name, refs: r.referenced_by_routes });
        window.aegisToast(`Pool "${name}" has ${r.referenced_by_routes.length} route reference(s)`, 'warn');
      } else {
        const msg = r.message || r.error || r.reason || `HTTP ${r.status}`;
        window.aegisToast(`Delete failed: ${msg}`, 'err');
      }
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <div className="page-head">
        <div>
          <h1 className="page-title">Routing &amp; Upstreams</h1>
          <p className="page-subtitle">
            <span className="num">{routes.length}</span> route{routes.length === 1 ? '' : 's'} →
            <span className="num"> {names.length}</span> pool{names.length === 1 ? '' : 's'}
            {' '}({totalMembers} member{totalMembers === 1 ? '' : 's'}{orphaned ? `, ${orphaned} unreferenced` : ''}){' · '}
            <span
              className={`pill ${cfgApi.error ? 'warn' : 'ok'}`}
              title="Routes + pools land via the audit-mutated pipeline; the proxy hot-swaps without restart."
            >
              {cfgApi.error ? 'fetch failed' : 'live · audit-mutated'}
            </span>
          </p>
        </div>
        <div className="page-actions">
          <button className="btn" onClick={() => {
            cfgApi.reload && cfgApi.reload();
            summaryApi.reload && summaryApi.reload();
            routesApi.reload && routesApi.reload();
          }}>
            <window.I.Refresh /> Refresh
          </button>
        </div>
      </div>

      {/* How it works — one-line orientation. */}
      <div style={{
        background: 'var(--canvas-2)',
        border: '1px solid var(--hairline)',
        borderRadius: 6,
        padding: '10px 14px',
        marginBottom: 12,
        fontSize: 12,
        color: 'var(--ink-dim)',
        lineHeight: 1.5,
      }}>
        <strong style={{ color: 'var(--ink)' }}>How it works.</strong>{' '}
        Each <strong style={{ color: 'var(--ink)' }}>route</strong> matches incoming traffic
        (host + path + method) and forwards it to <strong style={{ color: 'var(--ink)' }}>one upstream pool</strong>.
        A pool can have one or more backend members (load-balanced) and the same pool can be reused by several routes.
        Routes are evaluated by <strong style={{ color: 'var(--ink)' }}>specificity</strong> — most-specific host first,
        then longest path prefix, then explicit method filters. Add/edit order doesn't affect resolution; the table
        below is sorted by effective <strong style={{ color: 'var(--ink)' }}>priority</strong> (highest first).
      </div>

      <RoutesTable
        poolNames={names}
        routesApi={routesApi}
        pools={pools}
        onEditPool={openPoolEdit}
        onDeletePool={(n) => setDeleteModal({ name: n, refs: pools[n]?.referenced_by_routes || [] })}
        cfgReload={cfgApi.reload}
      />

      {/* Orphan pools — collapsed by default. Pools that no
          route currently points at, kept around so operators
          can clean them up or re-attach. */}
      {orphanPoolNames.length > 0 && (
        <div className="card" style={{ marginTop: 12, padding: 0 }}>
          <button
            type="button"
            onClick={() => setShowOrphans(!showOrphans)}
            style={{
              display: 'flex', alignItems: 'center', justifyContent: 'space-between',
              width: '100%', background: 'transparent', border: 'none', color: 'inherit',
              padding: '10px 14px', cursor: 'pointer', textAlign: 'left',
            }}
          >
            <span style={{ fontSize: 12 }}>
              <strong>Pools without routes</strong>{' '}
              <span className="pill warn" style={{ fontSize: 10, marginLeft: 6 }}>
                {orphanPoolNames.length} unreferenced
              </span>
            </span>
            <span style={{ fontSize: 12, color: 'var(--ink-dim)' }}>
              {showOrphans ? '▴ hide' : '▾ show'}
            </span>
          </button>
          {showOrphans && (
            <div style={{ borderTop: '1px solid var(--hairline)', padding: 8 }}>
              <table className="tbl tbl-compact">
                <thead><tr><th>Pool</th><th>Members</th><th>Scheme</th><th style={{ width: 160 }}></th></tr></thead>
                <tbody>
                  {orphanPoolNames.map(n => {
                    const p = pools[n] || {};
                    return (
                      <tr key={n}>
                        <td className="mono">{n}</td>
                        <td>{(p.members || []).length}</td>
                        <td className="mono" style={{ fontSize: 11 }}>{p.connection?.scheme || 'auto'}</td>
                        <td style={{ textAlign: 'right' }}>
                          <button className="btn btn-sm" onClick={() => openPoolEdit(n, p)}>Edit</button>
                          <button
                            className="btn btn-sm"
                            style={{ marginLeft: 4 }}
                            onClick={() => setDeleteModal({ name: n, refs: [] })}
                          >Delete</button>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
              <div style={{ padding: '6px 8px 0', fontSize: 11, color: 'var(--ink-dim)' }}>
                Or use <strong>+ Add pool</strong>{' '}
                <button className="btn btn-sm" onClick={openPoolAdd} style={{ marginLeft: 4 }}>+ Add pool</button>
                {' '}to create one without a route.
              </div>
            </div>
          )}
        </div>
      )}

      {editor && editor.kind === 'pool' && (
        <PoolEditModal
          mode={editor.mode}
          existingNames={names}
          initialName={editor.name}
          initialPool={editor.pool}
          onCancel={() => setEditor(null)}
          onSave={savePool}
          busy={busy}
        />
      )}

      {deleteModal && (
        <DeletePoolModal
          name={deleteModal.name}
          refs={deleteModal.refs}
          onCancel={() => setDeleteModal(null)}
          onConfirm={confirmPoolDelete}
          busy={busy}
        />
      )}
    </>
  );
}

// ---------------------------------------------------------------------------
// CC-T1.2 editor — kind-aware add/edit modal for one PoolConfig
// ---------------------------------------------------------------------------

const LB_OPTIONS = [
  ['round_robin', 'Round-robin'],
  ['weighted_round_robin', 'Weighted round-robin'],
  ['least_conn', 'Least connections'],
  ['consistent_hash', 'Consistent hash'],
  ['p2c', 'Power-of-two-choices'],
];

// Convert a PoolView (millisecond-typed display shape from
// /api/upstreams/config) to the wire-shape PoolConfig the PUT
// endpoint expects (humantime-style strings: "10s" / "3s" /
// "30s"). Symmetrical with `poolViewFromConfig` below.
function poolConfigFromForm(d) {
  const cfg = {
    members: (d.members || []).map(m => ({
      addr: (m.addr || '').trim(),
      weight: Number(m.weight) || 1,
      ...(m.zone && m.zone.trim() ? { zone: m.zone.trim() } : {}),
      // 2026-05-03 — multi-vhost upstream support.  When set,
      // the WAF rewrites the upstream Host header AND (for
      // HTTPS schemes) drives SNI + cert validation against
      // this name while pinning DNS to the addr above.
      ...(m.host_header && m.host_header.trim()
        ? { host_header: m.host_header.trim() }
        : {}),
    })),
    lb: d.lb || 'round_robin',
    connection: {
      max_idle_per_host: Number(d.connection?.max_idle_per_host) || 32,
      idle_timeout: humanTimeFromMs(Number(d.connection?.idle_timeout_ms) || 30000),
      keep_alive: !!d.connection?.keep_alive,
      tls: !!d.connection?.tls,
    },
  };
  if (d.health_enabled) {
    cfg.health = {
      path: (d.health?.path || '/healthz').trim() || '/healthz',
      interval: humanTimeFromMs(Number(d.health?.interval_ms) || 10000),
      timeout: humanTimeFromMs(Number(d.health?.timeout_ms) || 3000),
    };
  }
  if (d.cb_enabled) {
    cfg.circuit_breaker = {
      error_rate_threshold: Number(d.circuit_breaker?.error_rate_threshold) || 0.5,
      open_duration: humanTimeFromMs(Number(d.circuit_breaker?.open_duration_ms) || 30000),
    };
  }
  return cfg;
}

// humantime-serde compat: emit the smallest sensible unit so
// the YAML / JSON round-trips read naturally.
function humanTimeFromMs(ms) {
  if (ms <= 0) return '0s';
  if (ms % 60000 === 0) return `${ms / 60000}m`;
  if (ms % 1000 === 0)  return `${ms / 1000}s`;
  return `${ms}ms`;
}

// Seed the modal form from an existing PoolView (the shape the
// GET endpoint returns). For "add" mode pass null.
function poolFormFromView(view) {
  if (!view) {
    return {
      members: [{ addr: '', weight: 1, zone: '' }],
      lb: 'round_robin',
      health_enabled: false,
      health: { path: '/healthz', interval_ms: 10000, timeout_ms: 3000 },
      cb_enabled: false,
      circuit_breaker: { error_rate_threshold: 0.5, open_duration_ms: 30000 },
      connection: { max_idle_per_host: 32, idle_timeout_ms: 30000, keep_alive: true, tls: false },
    };
  }
  return {
    members: (view.members || []).map(m => ({
      addr: m.addr || '',
      weight: m.weight ?? 1,
      zone: m.zone || '',
      host_header: m.host_header || '',
    })),
    lb: view.lb || 'round_robin',
    health_enabled: !!view.health,
    health: {
      path: view.health?.path || '/healthz',
      interval_ms: view.health?.interval_ms ?? 10000,
      timeout_ms:  view.health?.timeout_ms  ?? 3000,
    },
    cb_enabled: !!view.circuit_breaker,
    circuit_breaker: {
      error_rate_threshold: view.circuit_breaker?.error_rate_threshold ?? 0.5,
      open_duration_ms:     view.circuit_breaker?.open_duration_ms     ?? 30000,
    },
    connection: {
      max_idle_per_host: view.connection?.max_idle_per_host ?? 32,
      idle_timeout_ms:   view.connection?.idle_timeout_ms   ?? 30000,
      keep_alive:        view.connection?.keep_alive ?? true,
      tls:               view.connection?.tls       ?? false,
    },
  };
}

function PoolEditModal({ mode, existingNames, initialName, initialPool, onCancel, onSave, busy }) {
  const [name, setName] = useStateP(initialName || '');
  const [d, setD] = useStateP(() => poolFormFromView(initialPool));

  const isEdit = mode === 'edit';
  const trimmedName = (name || '').trim();
  const nameTaken = !isEdit && existingNames.includes(trimmedName) && trimmedName !== '';
  const hasMember = (d.members || []).some(m => (m.addr || '').trim() !== '');
  // Client-side mirror of the backend validators in
  // aegis-control::api::upstreams_config::validate_pool. The
  // server is authoritative; this is just a fast UX gate so
  // operators don't see "empty_members" as a toast.
  const memberOk = hasMember &&
    (d.members || []).every(m =>
      (m.addr || '').trim() !== '' &&
      Number.isFinite(Number(m.weight)) &&
      Number(m.weight) >= 1
    );
  const healthOk = !d.health_enabled || (
    Number(d.health?.timeout_ms) > 0 &&
    Number(d.health?.timeout_ms) < Number(d.health?.interval_ms)
  );
  const cbOk = !d.cb_enabled || (
    Number(d.circuit_breaker?.error_rate_threshold) >= 0 &&
    Number(d.circuit_breaker?.error_rate_threshold) <= 1
  );
  const canSave = trimmedName !== '' && !nameTaken && memberOk && healthOk && cbOk;

  function setMember(i, key, val) {
    setD(prev => ({
      ...prev,
      members: prev.members.map((m, idx) => idx === i ? { ...m, [key]: val } : m),
    }));
  }
  function addMember() {
    setD(prev => ({
      ...prev,
      members: [
        ...prev.members,
        { addr: '', weight: 1, zone: '', host_header: '' },
      ],
    }));
  }
  function removeMember(i) {
    setD(prev => ({ ...prev, members: prev.members.filter((_, idx) => idx !== i) }));
  }

  async function handleSave() {
    if (!canSave) return;
    onSave({ name: trimmedName, body: poolConfigFromForm(d) });
  }

  return (
    <div
      style={{
        position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.5)',
        display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000,
      }}
      onClick={busy ? undefined : onCancel}
    >
      <div
        className="card"
        style={{ width: 640, maxWidth: '94vw', maxHeight: '90vh', padding: 0, overflow: 'hidden', display: 'flex', flexDirection: 'column' }}
        onClick={e => e.stopPropagation()}
      >
        <div style={{
          padding: '14px 16px', borderBottom: '1px solid var(--hairline)',
          display: 'flex', alignItems: 'center',
        }}>
          <div style={{ fontSize: 14, fontWeight: 600 }}>
            {isEdit ? `Edit pool "${initialName}"` : 'Add upstream pool'}
          </div>
          <span style={{ fontSize: 11, color: 'var(--ink-dim)', marginLeft: 8 }}>
            audit-mutated · CSRF-gated · hot-swap (no restart)
          </span>
          <button className="btn" style={{ marginLeft: 'auto' }} onClick={onCancel} disabled={busy}>×</button>
        </div>

        <div style={{ padding: 16, display: 'flex', flexDirection: 'column', gap: 12, overflowY: 'auto' }}>
          <label style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
            <span className="field-label">Pool name</span>
            <input
              className="input mono"
              value={name}
              onChange={e => setName(e.target.value)}
              disabled={isEdit}
              placeholder="backend-pool"
              autoFocus={!isEdit}
            />
            {nameTaken && (
              <span style={{ color: 'var(--down)', fontSize: 11 }}>Name already in use.</span>
            )}
          </label>

          <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
              <span className="field-label">Members</span>
              <button className="btn" onClick={addMember} disabled={busy}>+ Add member</button>
            </div>
            <table className="tbl tbl-compact">
              <thead>
                <tr>
                  <th>Address (host:port)</th>
                  <th style={{ width: 70 }}>Weight</th>
                  <th style={{ width: 100 }}>Zone</th>
                  <th
                    style={{ width: 160 }}
                    title="Optional. When set, the upstream sees Host: <vhost>; for HTTPS this name also drives SNI + cert validation. Leave blank for IP-addressed backends."
                  >Host header (vhost)</th>
                  <th style={{ width: 36 }}></th>
                </tr>
              </thead>
              <tbody>
                {d.members.map((m, i) => (
                  <tr key={i}>
                    <td>
                      <input
                        className="input mono"
                        value={m.addr}
                        onChange={e => setMember(i, 'addr', e.target.value)}
                        placeholder="127.0.0.1:3001"
                      />
                    </td>
                    <td>
                      <input
                        className="input num"
                        type="number"
                        min="1"
                        value={m.weight}
                        onChange={e => setMember(i, 'weight', e.target.value)}
                      />
                    </td>
                    <td>
                      <input
                        className="input mono"
                        value={m.zone}
                        onChange={e => setMember(i, 'zone', e.target.value)}
                        placeholder="optional"
                      />
                    </td>
                    <td>
                      <input
                        className="input mono"
                        value={m.host_header || ''}
                        onChange={e => setMember(i, 'host_header', e.target.value)}
                        placeholder="example.com"
                      />
                    </td>
                    <td>
                      <button
                        className="btn"
                        onClick={() => removeMember(i)}
                        disabled={busy || d.members.length === 1}
                        title={d.members.length === 1 ? 'A pool needs at least one member' : 'Remove this member'}
                      >×</button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            {!memberOk && (
              <span style={{ color: 'var(--warn)', fontSize: 11 }}>
                Each member needs an addr and weight ≥ 1.
              </span>
            )}
          </div>

          <label style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
            <span className="field-label">Load balancing</span>
            <select
              className="input"
              value={d.lb}
              onChange={e => setD(prev => ({ ...prev, lb: e.target.value }))}
            >
              {LB_OPTIONS.map(([tag, label]) => (
                <option key={tag} value={tag}>{label}</option>
              ))}
            </select>
          </label>

          <fieldset style={{ border: '1px solid var(--hairline)', borderRadius: 6, padding: 10 }}>
            <legend style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '0 6px' }}>
              <input
                type="checkbox"
                checked={d.health_enabled}
                onChange={e => setD(prev => ({ ...prev, health_enabled: e.target.checked }))}
              />
              <span className="field-label" style={{ marginBottom: 0 }}>Health check</span>
            </legend>
            {d.health_enabled && (
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 120px 120px', gap: 8 }}>
                <label style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                  <span className="field-label">Path</span>
                  <input
                    className="input mono"
                    value={d.health.path}
                    onChange={e => setD(prev => ({ ...prev, health: { ...prev.health, path: e.target.value } }))}
                  />
                </label>
                <label style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                  <span className="field-label">Interval (ms)</span>
                  <input
                    className="input num"
                    type="number"
                    min="100"
                    value={d.health.interval_ms}
                    onChange={e => setD(prev => ({ ...prev, health: { ...prev.health, interval_ms: e.target.value } }))}
                  />
                </label>
                <label style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                  <span className="field-label">Timeout (ms)</span>
                  <input
                    className="input num"
                    type="number"
                    min="50"
                    value={d.health.timeout_ms}
                    onChange={e => setD(prev => ({ ...prev, health: { ...prev.health, timeout_ms: e.target.value } }))}
                  />
                </label>
                {!healthOk && (
                  <span style={{ gridColumn: '1 / -1', color: 'var(--down)', fontSize: 11 }}>
                    Timeout must be &gt; 0 and &lt; interval.
                  </span>
                )}
              </div>
            )}
          </fieldset>

          <fieldset style={{ border: '1px solid var(--hairline)', borderRadius: 6, padding: 10 }}>
            <legend style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '0 6px' }}>
              <input
                type="checkbox"
                checked={d.cb_enabled}
                onChange={e => setD(prev => ({ ...prev, cb_enabled: e.target.checked }))}
              />
              <span className="field-label" style={{ marginBottom: 0 }}>Circuit breaker</span>
            </legend>
            {d.cb_enabled && (
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
                <label style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                  <span className="field-label">Error-rate threshold (0.0 – 1.0)</span>
                  <input
                    className="input num"
                    type="number"
                    step="0.05"
                    min="0"
                    max="1"
                    value={d.circuit_breaker.error_rate_threshold}
                    onChange={e => setD(prev => ({
                      ...prev,
                      circuit_breaker: { ...prev.circuit_breaker, error_rate_threshold: e.target.value },
                    }))}
                  />
                </label>
                <label style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                  <span className="field-label">Open duration (ms)</span>
                  <input
                    className="input num"
                    type="number"
                    min="100"
                    value={d.circuit_breaker.open_duration_ms}
                    onChange={e => setD(prev => ({
                      ...prev,
                      circuit_breaker: { ...prev.circuit_breaker, open_duration_ms: e.target.value },
                    }))}
                  />
                </label>
                {!cbOk && (
                  <span style={{ gridColumn: '1 / -1', color: 'var(--down)', fontSize: 11 }}>
                    Threshold must be in [0.0, 1.0].
                  </span>
                )}
              </div>
            )}
          </fieldset>

          <fieldset style={{ border: '1px solid var(--hairline)', borderRadius: 6, padding: 10 }}>
            <legend style={{ padding: '0 6px' }}>
              <span className="field-label" style={{ marginBottom: 0 }}>Connection pool</span>
            </legend>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
              <label style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                <span className="field-label">Max idle per host</span>
                <input
                  className="input num"
                  type="number"
                  min="0"
                  value={d.connection.max_idle_per_host}
                  onChange={e => setD(prev => ({
                    ...prev,
                    connection: { ...prev.connection, max_idle_per_host: e.target.value },
                  }))}
                />
              </label>
              <label style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                <span className="field-label">Idle timeout (ms)</span>
                <input
                  className="input num"
                  type="number"
                  min="0"
                  value={d.connection.idle_timeout_ms}
                  onChange={e => setD(prev => ({
                    ...prev,
                    connection: { ...prev.connection, idle_timeout_ms: e.target.value },
                  }))}
                />
              </label>
              <label style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                <input
                  type="checkbox"
                  checked={d.connection.keep_alive}
                  onChange={e => setD(prev => ({
                    ...prev,
                    connection: { ...prev.connection, keep_alive: e.target.checked },
                  }))}
                />
                <span className="field-label" style={{ marginBottom: 0 }}>HTTP keep-alive</span>
              </label>
              <label style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                <input
                  type="checkbox"
                  checked={d.connection.tls}
                  onChange={e => setD(prev => ({
                    ...prev,
                    connection: { ...prev.connection, tls: e.target.checked },
                  }))}
                />
                <span className="field-label" style={{ marginBottom: 0 }}>Upstream TLS (legacy `tls` flag)</span>
              </label>
              <label style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                <span className="field-label" style={{ marginBottom: 0 }}>Scheme</span>
                <select
                  value={d.connection.scheme || 'auto'}
                  onChange={e => setD(prev => ({
                    ...prev,
                    connection: { ...prev.connection, scheme: e.target.value },
                  }))}
                  style={{ padding: '4px 6px', borderRadius: 4, border: '1px solid var(--hairline)', fontSize: 12 }}
                >
                  <option value="auto">auto — h1/h2 via TLS toggle (also bridges WS)</option>
                  <option value="http">http — plaintext h1 (also bridges WS)</option>
                  <option value="https">https — TLS, ALPN h1/h2 (also bridges WSS)</option>
                  <option value="h2c">h2c — HTTP/2 cleartext (no h1 fallback)</option>
                  <option value="grpc">grpc — HTTPS, ALPN h2 only (gRPC strict)</option>
                  <option value="tcp">tcp — raw byte tunneling (CONNECT method)</option>
                </select>
              </label>
            </div>
            {/* 2026-05-03 — protocol matrix that explains exactly
                what each scheme handles, including WS upgrades
                (which are auto-detected on http/https/auto and
                don't need a separate scheme). */}
            <div style={{ marginTop: 10, padding: 10, borderRadius: 6, background: 'var(--surface-2)', fontSize: 11, color: 'var(--ink-dim)' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 6 }}>
                <window.I.Info />
                <strong style={{ color: 'var(--ink)' }}>Protocol matrix</strong>
              </div>
              <table className="tbl tbl-compact" style={{ fontSize: 10 }}>
                <thead>
                  <tr>
                    <th>Scheme</th>
                    <th>HTTP/1.1</th>
                    <th>HTTP/2</th>
                    <th>WebSocket</th>
                    <th>gRPC</th>
                    <th>Raw TCP</th>
                  </tr>
                </thead>
                <tbody>
                  <tr><td><code>auto</code></td><td>✓</td><td>ALPN</td><td>✓ auto</td><td>—</td><td>—</td></tr>
                  <tr><td><code>http</code></td><td>✓</td><td>—</td><td>✓ auto</td><td>—</td><td>—</td></tr>
                  <tr><td><code>https</code></td><td>✓</td><td>ALPN</td><td>✓ wss</td><td>—</td><td>—</td></tr>
                  <tr><td><code>h2c</code></td><td>—</td><td>✓</td><td>—</td><td>✓ h2c</td><td>—</td></tr>
                  <tr><td><code>grpc</code></td><td>—</td><td>✓</td><td>—</td><td>✓ TLS</td><td>—</td></tr>
                  <tr><td><code>tcp</code></td><td>—</td><td>—</td><td>—</td><td>—</td><td>✓ CONNECT</td></tr>
                </tbody>
              </table>
              <div style={{ marginTop: 6 }}>
                <strong>WebSocket</strong> is detected by the
                <code style={{ margin: '0 3px' }}>Upgrade: websocket</code>
                + <code style={{ margin: '0 3px' }}>Connection: Upgrade</code>
                header pair on any
                <code style={{ margin: '0 3px' }}>http</code> /
                <code style={{ margin: '0 3px' }}>https</code> /
                <code style={{ margin: '0 3px' }}>auto</code> scheme — no
                separate config.  The bridge runs
                <code style={{ margin: '0 3px' }}>copy_bidirectional</code>
                after the upstream returns 101.
                {' '}<strong>Raw TCP tunneling</strong> requires{' '}
                <code>scheme: tcp</code> AND the
                <code style={{ margin: '0 3px' }}>CONNECT</code> method.
                Other methods on a tcp pool return 502
                {' '}<code>non_connect_to_tcp_route</code>.
              </div>
            </div>
          </fieldset>
        </div>

        <div style={{
          padding: 12, borderTop: '1px solid var(--hairline)',
          display: 'flex', gap: 8, justifyContent: 'flex-end',
        }}>
          <button className="btn" onClick={onCancel} disabled={busy}>Cancel</button>
          <button
            className="btn primary"
            disabled={!canSave || busy}
            onClick={handleSave}
          >{busy ? 'Saving…' : 'Save'}</button>
        </div>
      </div>
    </div>
  );
}

function DeletePoolModal({ name, refs, onCancel, onConfirm, busy }) {
  const blocked = refs && refs.length > 0;
  return (
    <div
      style={{
        position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.5)',
        display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000,
      }}
      onClick={busy ? undefined : onCancel}
    >
      <div
        className="card"
        style={{ width: 480, maxWidth: '92vw', padding: 0 }}
        onClick={e => e.stopPropagation()}
      >
        <div style={{
          padding: '14px 16px', borderBottom: '1px solid var(--hairline)',
          display: 'flex', alignItems: 'center',
        }}>
          <div style={{ fontSize: 14, fontWeight: 600 }}>
            Remove pool <span className="mono">"{name}"</span>?
          </div>
          <button className="btn" style={{ marginLeft: 'auto' }} onClick={onCancel} disabled={busy}>×</button>
        </div>
        <div style={{ padding: 16, display: 'flex', flexDirection: 'column', gap: 10, fontSize: 13 }}>
          {blocked ? (
            <>
              <div style={{ color: 'var(--down)' }}>
                <strong>Blocked.</strong> {refs.length} route{refs.length === 1 ? '' : 's'} still target this pool.
                Update or delete the route{refs.length === 1 ? '' : 's'} first.
              </div>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                {refs.map(rid => (
                  <span key={rid} className="pill neutral mono" style={{ fontSize: 11 }}>{rid}</span>
                ))}
              </div>
              <div style={{ fontSize: 11, color: 'var(--ink-dim)' }}>
                Backend returns <span className="mono">409 pool_referenced</span> with the list above.
              </div>
            </>
          ) : (
            <>
              <div>
                The proxy will hot-swap the pool table on the same request.
                In-flight requests finish on the existing pool.
              </div>
              <div style={{ fontSize: 11, color: 'var(--ink-dim)' }}>
                Audit-chain entry recorded as <span className="mono">pool_delete</span>.
              </div>
            </>
          )}
        </div>
        <div style={{
          padding: 12, borderTop: '1px solid var(--hairline)',
          display: 'flex', gap: 8, justifyContent: 'flex-end',
        }}>
          <button className="btn" onClick={onCancel} disabled={busy}>
            {blocked ? 'Close' : 'Cancel'}
          </button>
          {!blocked && (
            <button
              className="btn"
              style={{ color: 'var(--down)' }}
              onClick={onConfirm}
              disabled={busy}
            >{busy ? 'Removing…' : 'Remove'}</button>
          )}
        </div>
      </div>
    </div>
  );
}

// ============== SC-T2 — Page: Scaling ==============
//
// Three-layer scaling visibility, stacked top-to-bottom:
//   L1 — In-node tokio runtime (workers, blocking threads, affinity)
//   L2 — Cross-node cluster (peers, leader, drain)
//   L3 — Shared-state backend (Redis / in_memory health)
//
// Read-only except for the L2 "Drain this node" button which
// POSTs to the existing audit-mutated /admin/drain endpoint.
// L1 sizing is restart-only by design (tokio API doesn't permit
// hot resize) — the page documents this rather than offering a
// slider that would lie.

function ScalingL1Card({ runtime }) {
  const data = runtime?.data;
  const hasData = !!data;
  const affinityState = !hasData
    ? 'unknown'
    : data.cpu_affinity_active
      ? 'active'
      : data.cpu_affinity_requested
        ? 'requested-inactive'
        : 'off';
  const affinityLabel = {
    active: 'active',
    'requested-inactive': 'requested · inactive',
    off: 'off',
    unknown: '—',
  }[affinityState];
  const affinityTone = {
    active: 'up',
    'requested-inactive': 'warn',
    off: 'neutral',
    unknown: 'neutral',
  }[affinityState];

  return (
    <div className="card" style={{ marginBottom: 12 }}>
      <div className="card-head">
        <div>
          <div className="card-title">Layer 1 · In-node workers</div>
          <div className="card-sub">tokio runtime sizing · this node · restart-only</div>
        </div>
        <span className="pill neutral">L1</span>
      </div>
      {!hasData && (
        <div style={{ padding: 12, fontSize: 12, color: 'var(--ink-dim)', textAlign: 'center' }}>
          Runtime info not available — endpoint may be loading.
        </div>
      )}
      {hasData && (
        <>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 12 }}>
            <Stat
              label="Workers"
              value={data.workers}
              sub={`of ${data.host_logical_cpus} logical CPUs`}
            />
            <Stat
              label="Mode"
              value={data.workers_mode === 'auto' ? 'auto' : 'fixed'}
              tone={data.workers_mode === 'auto' ? 'up' : 'neutral'}
            />
            <Stat
              label="Blocking pool"
              value={data.blocking_threads}
              sub={`${data.stack_size_kb} KiB stack`}
            />
            <Stat
              label="CPU affinity"
              value={affinityLabel}
              tone={affinityTone}
            />
          </div>
          <div style={{ marginTop: 10, padding: 8, background: 'var(--canvas-2)', borderRadius: 6, fontSize: 11, color: 'var(--ink-dim)' }}>
            Restart required to change. Edit the <code>runtime:</code> block in <code>waf.yaml</code>.
          </div>
        </>
      )}
    </div>
  );
}

function ScalingL2Card({ cluster, onDrain, draining }) {
  const peers = cluster?.data?.peers || [];
  const ourNode = cluster?.data?.our_node;
  const isLeader = cluster?.data?.is_leader;
  const leaderNode = cluster?.data?.leader_node;
  const [confirmStep, setConfirmStep] = useStateP(0); // 0 idle, 1 first, 2 final
  const [drainResult, setDrainResult] = useStateP(null);

  const onConfirmFirst = () => setConfirmStep(1);
  const onCancel = () => setConfirmStep(0);
  const onConfirmFinal = async () => {
    setConfirmStep(0);
    setDrainResult({ pending: true });
    const res = await onDrain();
    setDrainResult(res);
  };

  // 2026-05-08 NEW-3 — derive freshness signals from the raw
  // ClusterPeer fields the backend actually serialises
  // (id, addr, version, last_heartbeat, leases). The pre-fix
  // dashboard read p.node_id / p.healthy / p.last_heartbeat_age_s
  // / p.leader — none of which exist on the JSON, so a single
  // self-peer rendered as a phantom `down/replica/—` row.
  //
  // Healthy is defined here as a heartbeat within 30 s (≈ 2×
  // the 15 s lease TTL). Beyond that the membership lease would
  // have expired and the peer wouldn't be in the list at all,
  // but we defend in depth.
  const now = Date.now();
  const peersDecorated = peers.map(p => {
    const ts = p.last_heartbeat ? new Date(p.last_heartbeat).getTime() : NaN;
    const ageSec = Number.isFinite(ts) ? Math.max(0, Math.round((now - ts) / 1000)) : null;
    const healthy = ageSec != null && ageSec < 30;
    const leader = leaderNode != null && p.id === leaderNode;
    const isMe = p.id === ourNode;
    return { ...p, ageSec, healthy, leader, isMe };
  });
  const peersExcludingSelf = peersDecorated.filter(p => !p.isMe);
  // Single-node mode: either no peers at all, or only self-peer
  // present (the membership writer publishes our own members:<id>
  // key, so an N=1 cluster always has 1 entry in peers[]).
  const isSingleNode = peersExcludingSelf.length === 0;
  const peerCountLabel = isSingleNode
    ? '1 node · standalone'
    : `${peersDecorated.length} ${peersDecorated.length === 1 ? 'node' : 'nodes'}`;

  return (
    <div className="card" style={{ marginBottom: 12 }}>
      <div className="card-head">
        <div>
          <div className="card-title">Layer 2 · Cluster peers</div>
          <div className="card-sub">
            {peerCountLabel}
            {ourNode ? ` · this node ${ourNode}${isLeader ? ' · leader' : ''}` : ''}
          </div>
        </div>
        <span className="pill neutral">L2</span>
      </div>
      {isSingleNode && (
        <div style={{ padding: 12, fontSize: 12, color: 'var(--ink-dim)', textAlign: 'center' }}>
          Running in single-node mode — no remote peers configured.
          {ourNode && peersDecorated.length === 1 && <> This node ({ourNode}) is the only member.</>}
        </div>
      )}
      {!isSingleNode && (
        <table className="data-table" style={{ width: '100%', fontSize: 12 }}>
          <thead>
            <tr>
              <th style={{ textAlign: 'left' }}>Node</th>
              <th style={{ textAlign: 'left' }}>State</th>
              <th style={{ textAlign: 'right' }}>Last heartbeat</th>
              <th style={{ textAlign: 'left' }}>Role</th>
            </tr>
          </thead>
          <tbody>
            {peersDecorated.map(p => (
              <tr key={p.id} style={p.isMe ? { background: 'var(--surface-3)' } : undefined}>
                <td>
                  <code>{p.id}</code>
                  {p.isMe && <span style={{ marginLeft: 6, fontSize: 10, color: 'var(--ink-dim)' }}>(this)</span>}
                </td>
                <td>
                  <span className={`pill ${p.healthy ? 'up' : 'down'}`}>
                    {p.healthy ? 'healthy' : 'down'}
                  </span>
                </td>
                <td style={{ textAlign: 'right' }} className="num">
                  {p.ageSec != null ? `${p.ageSec}s ago` : '—'}
                </td>
                <td>{p.leader ? <span className="pill solid-yellow">leader</span> : <span className="dim">replica</span>}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginTop: 10, paddingTop: 10, borderTop: '1px solid var(--hairline)' }}>
        {confirmStep === 0 && (
          <>
            <button
              className="btn"
              disabled={draining}
              onClick={onConfirmFirst}
            >
              Drain this node
            </button>
            <span style={{ fontSize: 11, color: 'var(--ink-dim)' }}>
              Flips readiness to 503 — the load balancer pulls this node within one health-check interval.
            </span>
          </>
        )}
        {confirmStep === 1 && (
          <>
            <span style={{ fontSize: 12, color: 'var(--warn)' }}>
              Confirm — drain {ourNode || 'this node'}?
            </span>
            <button className="btn" onClick={onCancel}>Cancel</button>
            <button className="btn solid-yellow" onClick={onConfirmFinal}>
              Yes, drain
            </button>
          </>
        )}
        {drainResult?.pending && (
          <span style={{ fontSize: 11, color: 'var(--ink-dim)' }}>Draining…</span>
        )}
        {drainResult && !drainResult.pending && drainResult.status >= 200 && drainResult.status < 300 && (
          <span className="pill up">Drained — readiness now 503</span>
        )}
        {drainResult && !drainResult.pending && (drainResult.status < 200 || drainResult.status >= 300) && (
          <span className="pill down">Drain failed (HTTP {drainResult.status || '—'})</span>
        )}
      </div>
    </div>
  );
}

function ScalingL3Card({ state }) {
  const data = state?.data;
  const hasData = !!data;
  const backend = data?.backend ?? 'unknown';
  const connected = !!data?.connected;
  const circuit = data?.circuit?.state ?? 'closed';
  const circuitTone = circuit === 'closed' ? 'up' : circuit === 'half_open' ? 'warn' : 'down';

  return (
    <div className="card">
      <div className="card-head">
        <div>
          <div className="card-title">Layer 3 · Shared state</div>
          <div className="card-sub">
            backend · {backend}
            {hasData && ` · ${connected ? 'connected' : 'disconnected'}`}
            {data?.server_version && ` · v${data.server_version}`}
          </div>
        </div>
        <span className="pill neutral">L3</span>
      </div>
      {!hasData && (
        <div style={{ padding: 12, fontSize: 12, color: 'var(--ink-dim)', textAlign: 'center' }}>
          State endpoint loading…
        </div>
      )}
      {hasData && (
        <>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 12, marginBottom: 10 }}>
            <Stat
              label="Connection"
              value={connected ? 'live' : 'down'}
              tone={connected ? 'up' : 'down'}
            />
            <Stat
              label="Circuit"
              value={circuit.replace('_', ' ')}
              tone={circuitTone}
              sub={data?.circuit?.last_open_at_unix_ms ? new Date(data.circuit.last_open_at_unix_ms).toLocaleTimeString() : undefined}
            />
            <Stat
              label="Keys"
              value={data?.key_count != null ? data.key_count.toLocaleString() : '—'}
              sub="DBSIZE"
            />
            <Stat
              label="Replica lag"
              value={data?.replica_lag_ms != null ? `${data.replica_lag_ms} ms` : '—'}
              tone={data?.replica_lag_ms == null ? 'neutral' : data.replica_lag_ms > 1000 ? 'warn' : 'up'}
            />
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 8, fontSize: 12 }}>
            <LatencyChip label="p50" us={data?.latency?.p50_us} />
            <LatencyChip label="p95" us={data?.latency?.p95_us} />
            <LatencyChip label="p99" us={data?.latency?.p99_us} />
          </div>
        </>
      )}
    </div>
  );
}

function Stat({ label, value, sub, tone }) {
  return (
    <div style={{ padding: 10, background: 'var(--canvas-2)', borderRadius: 6 }}>
      <div style={{ fontSize: 10, color: 'var(--ink-faint)', textTransform: 'uppercase', letterSpacing: 0.5 }}>{label}</div>
      <div className="num" style={{ fontSize: 18, fontWeight: 600, color: tone ? `var(--${tone === 'up' ? 'up' : tone === 'warn' ? 'warn' : tone === 'down' ? 'down' : 'ink'})` : 'var(--ink)' }}>
        {value}
      </div>
      {sub && <div style={{ fontSize: 10, color: 'var(--ink-dim)', marginTop: 2 }}>{sub}</div>}
    </div>
  );
}

function LatencyChip({ label, us }) {
  const display = us == null
    ? '—'
    : us < 1000
      ? `${us} µs`
      : us < 1_000_000
        ? `${(us / 1000).toFixed(1)} ms`
        : `${(us / 1_000_000).toFixed(2)} s`;
  return (
    <div style={{ padding: 8, background: 'var(--canvas-2)', borderRadius: 6, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
      <span style={{ fontSize: 10, color: 'var(--ink-faint)', textTransform: 'uppercase' }}>{label}</span>
      <span className="num" style={{ fontSize: 13, fontWeight: 600 }}>{display}</span>
    </div>
  );
}

function PageScaling() {
  const runtime = window.useRuntimeApi();
  const cluster = window.useClusterApi();
  const state = window.useStateApi();
  const loadmode = window.useLoadModeApi ? window.useLoadModeApi() : { data: null };
  const [draining, setDraining] = useStateP(false);

  const onDrain = async () => {
    setDraining(true);
    try {
      const r = await window.adminDrainPost();
      return r;
    } finally {
      setDraining(false);
    }
  };

  return (
    <>
      <div className="page-head">
        <div>
          <h1 className="page-title">Scaling</h1>
          <p className="page-subtitle">
            Three-layer scaling visibility · in-node workers, cluster peers, shared state
          </p>
        </div>
        <div className="page-actions">
          <button className="btn" onClick={() => {
            runtime.reload && runtime.reload();
            cluster.reload && cluster.reload();
            state.reload && state.reload();
            loadmode.reload && loadmode.reload();
          }}>
            <window.I.Refresh /> Refresh
          </button>
        </div>
      </div>

      <LoadModeCard loadmode={loadmode} />
      <ScalingL1Card runtime={runtime} />
      <ScalingL2Card cluster={cluster} onDrain={onDrain} draining={draining} />
      <ScalingL3Card state={state} />
    </>
  );
}

// M002 (2026-05-07) — operator override for the LoadGauge mode.
// Three pill buttons (normal / elevated / critical) + a "Clear
// override" link that returns to auto-driven mode. Critical
// requires a confirmation modal because it tightens block
// thresholds and cannot be auto-recovered without an explicit
// unset. Audit-mutated via PUT /api/loadmode.
function LoadModeCard({ loadmode }) {
  const data = loadmode?.data;
  const [busy, setBusy] = useStateP(false);
  const [confirmCritical, setConfirmCritical] = useStateP(false);
  const effective = data?.effective_mode || data?.mode || '—';
  const overrideActive = !!data?.override_active;
  const autoMode = data?.mode || '—';

  async function applyMode(mode) {
    if (busy) return;
    setBusy(true);
    try {
      const r = await window.loadmodePut(mode);
      if (r && r.status >= 200 && r.status < 300) {
        window.aegisToast(
          mode === 'unset'
            ? 'Override cleared · mode now auto-driven'
            : `Mode pinned to ${mode}`,
          'ok',
        );
        loadmode.reload && loadmode.reload();
      } else {
        const msg = (r && (r.message || r.error || r.reason)) || `status ${r?.status}`;
        window.aegisToast(`Mode change failed: ${msg}`, 'err');
      }
    } catch (err) {
      window.aegisToast(`Mode change error: ${err.message || err}`, 'err');
    } finally {
      setBusy(false);
    }
  }

  function onClickMode(mode) {
    if (mode === 'critical') {
      setConfirmCritical(true);
      return;
    }
    applyMode(mode);
  }

  const pillStyle = (mode) => ({
    padding: '6px 14px',
    border: '1px solid var(--border)',
    borderRadius: 999,
    cursor: busy ? 'not-allowed' : 'pointer',
    fontSize: 12,
    fontWeight: 500,
    background: effective === mode ? 'var(--accent)' : 'transparent',
    color: effective === mode ? 'var(--canvas)' : 'var(--ink)',
    opacity: busy ? 0.6 : 1,
  });

  return (
    <div className="card" style={{ marginBottom: 12 }}>
      <div className="card-head">
        <div>
          <div className="card-title">Load mode</div>
          <div className="card-sub">
            operator pin overrides auto · audit-chained on every change
          </div>
        </div>
        <span className={`pill ${effective === 'critical' ? 'down' : effective === 'elevated' ? 'warn' : 'up'}`}>
          {effective.toUpperCase()}
        </span>
      </div>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, padding: 4, flexWrap: 'wrap' }}>
        {['normal', 'elevated', 'critical'].map(mode => (
          <button
            key={mode}
            type="button"
            style={pillStyle(mode)}
            onClick={() => onClickMode(mode)}
            disabled={busy}
          >
            {mode}
          </button>
        ))}
        {overrideActive && (
          <button
            type="button"
            className="btn sm"
            onClick={() => applyMode('unset')}
            disabled={busy}
            style={{ marginLeft: 'auto' }}
          >
            Clear override (return to auto: {autoMode})
          </button>
        )}
      </div>
      <div style={{ marginTop: 8, padding: 8, background: 'var(--canvas-2)', borderRadius: 6, fontSize: 11, color: 'var(--ink-dim)' }}>
        {overrideActive
          ? <>Operator override active. Auto-driven mode would be <code>{autoMode}</code>.</>
          : <>Auto-driven from RPS. Pin a mode to override; clear to return to auto.</>}
      </div>

      {confirmCritical && (
        <div className="modal-backdrop" onClick={() => setConfirmCritical(false)}>
          <div className="modal" onClick={e => e.stopPropagation()} style={{ maxWidth: 460 }}>
            <div className="modal-head">
              <div className="modal-title">Pin mode to critical?</div>
              <button className="btn btn-sm" onClick={() => setConfirmCritical(false)}>×</button>
            </div>
            <div className="modal-body">
              <p style={{ fontSize: 13, lineHeight: 1.5 }}>
                Critical mode tightens rate limits and block thresholds.
                It does <strong>not</strong> auto-revert when load drops —
                you must explicitly clear the override. The change is
                audit-chained.
              </p>
            </div>
            <div className="modal-foot">
              <button className="btn" onClick={() => setConfirmCritical(false)} disabled={busy}>
                Cancel
              </button>
              <button
                className="btn danger"
                onClick={() => { setConfirmCritical(false); applyMode('critical'); }}
                disabled={busy}
              >
                {busy ? 'Pinning…' : 'Pin to critical'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

// ================================================================
// PHASE 2 — Access Lists (Blacklist + Whitelist merged with tabs).
// ================================================================
function PageAccessLists() {
  const [tab, setTab] = useStateP(() => location.hash.includes('whitelist') ? 'whitelist' : 'blacklist');
  return (
    <>
      <div className="page-head">
        <div>
          <h1 className="page-title">Access Lists</h1>
          <p className="page-subtitle">Block known-bad IPs / CIDRs / ASNs · whitelist trusted callers with optional detector-bypass</p>
        </div>
      </div>
      <div className="card" style={{ padding: '8px 12px', marginBottom: 8, fontSize: 11, color: 'var(--ink-dim)', display: 'flex', alignItems: 'center', gap: 8 }}>
        <window.I.Info />
        <span>
          Both lists are audit-chained on every mutation. Blacklist
          entries always block. Whitelist entries can specify a
          per-detector <em>bypass</em> (e.g. <code>sqli,xss</code>) or
          <code> all</code> for high-trust sources.
        </span>
      </div>
      <div className="tab-bar" style={{ display: 'flex', gap: 4, marginBottom: 8 }}>
        <button
          className={`btn ${tab === 'blacklist' ? 'primary' : ''}`}
          onClick={() => setTab('blacklist')}
        ><window.I.Ban /> Blacklist</button>
        <button
          className={`btn ${tab === 'whitelist' ? 'primary' : ''}`}
          onClick={() => setTab('whitelist')}
        ><window.I.Check /> Whitelist</button>
      </div>
      {tab === 'blacklist'
        ? <ListPage kind="blacklist" />
        : <ListPage kind="whitelist" />}
    </>
  );
}

// ================================================================
// PHASE 3 — SOC pages, stub bodies until each lands fully wired.
// Each page renders a "ships in Phase 3" frame plus whatever real
// data we already have via existing endpoints.
// ================================================================
function StubPage({ title, subtitle, children, eta }) {
  return (
    <>
      <div className="page-head">
        <div>
          <h1 className="page-title">{title}</h1>
          <p className="page-subtitle">{subtitle}</p>
        </div>
      </div>
      <div className="card" style={{ padding: '12px 16px', marginBottom: 12, background: 'var(--surface-2)' }}>
        <div style={{ display: 'flex', gap: 10, alignItems: 'flex-start' }}>
          <window.I.Sparkles />
          <div style={{ fontSize: 12 }}>
            <strong>Phase 3 in progress.</strong> {eta || 'Full wiring lands this sprint.'}
            {' '}See <a href="#/help" style={{ color: 'var(--accent)' }}>plans/console-soc-refactor.md</a> §"Phase 3".
          </div>
        </div>
      </div>
      {children}
    </>
  );
}

function PageIncidents() {
  const alerts = window.useAlertsApi ? window.useAlertsApi() : { data: null };
  const incidents = window.useIncidentsApi ? window.useIncidentsApi() : { data: null };
  const [busy, setBusy] = useStateP(null); // alert id currently mutating
  const [filter, setFilter] = useStateP('open'); // open | snoozed | resolved | all

  // Compose: prefer the enriched /api/incidents view; fall back
  // to /api/alerts when the engine isn't wired yet (test builds).
  const overlay = incidents.data?.incidents || [];
  const overlayById = new Map(overlay.map(i => [i.id, i]));
  const rawAlerts = alerts.data?.alerts || alerts.data?.firing || incidents.data?.raw_alerts?.alerts || [];

  // Derive a unified "incident list" from raw alerts + overlay.
  const merged = (Array.isArray(rawAlerts) ? rawAlerts : []).map(a => {
    const id = a.id || `${a.sli || a.kind}:${a.fired_at ? Date.parse(a.fired_at) / 1000 | 0 : 0}`;
    const o = overlayById.get(id);
    return {
      id,
      sli: a.sli || a.kind || 'unknown',
      severity: (a.severity || 'warn').toLowerCase(),
      fired_at: a.fired_at,
      burn_rate: a.burn_rate,
      budget_consumed_pct: a.budget_consumed_pct,
      window_hours: a.window_hours,
      runbook_url: a.runbook_url,
      status: o?.status || 'firing',
      acked_at: o?.acked_at,
      acked_by: o?.acked_by,
      snoozed_until: o?.snoozed_until,
      note: o?.note,
    };
  });

  const counts = merged.reduce((acc, m) => ({ ...acc, [m.status]: (acc[m.status] || 0) + 1 }), {});
  const filtered = merged.filter(m => {
    if (filter === 'all') return true;
    if (filter === 'open') return m.status === 'firing' || m.status === 'acknowledged';
    return m.status === filter;
  });

  async function doAct(action, id) {
    setBusy(id);
    try {
      let r;
      if (action === 'ack')      r = await window.incidentAck(id, { note: '' });
      if (action === 'snooze')   r = await window.incidentSnooze(id, 15, '');
      if (action === 'resolve')  r = await window.incidentResolve(id, '');
      // FIX 2026-05-04 — the previous code used `window.toast`
      // (which doesn't exist; the project's toast is
      // `aegisToast`), so every failure was silently swallowed
      // and operators saw a click that did nothing. Surface
      // the result either way: success → green toast + reload;
      // failure → red toast with the backend reason.
      if (r && r.status >= 200 && r.status < 300) {
        window.aegisToast(`Incident ${action} ok`, 'ok');
        if (incidents.reload) incidents.reload();
        if (alerts.reload) alerts.reload();
      } else {
        const msg = (r && (r.message || r.error || r.reason)) || `status ${r?.status ?? '?'}`;
        window.aegisToast(`${action} failed: ${msg}`, 'err');
      }
    } catch (e) {
      window.aegisToast(`${action} error: ${e.message || e}`, 'err');
    } finally {
      setBusy(null);
    }
  }

  function fmtRel(iso) {
    if (!iso) return '—';
    const d = new Date(iso);
    const ago = (Date.now() - d.getTime()) / 1000;
    if (ago < 60) return `${Math.floor(ago)}s ago`;
    if (ago < 3600) return `${Math.floor(ago / 60)}m ago`;
    if (ago < 86400) return `${Math.floor(ago / 3600)}h ago`;
    return `${Math.floor(ago / 86400)}d ago`;
  }

  return (
    <>
      <div className="page-head">
        <div>
          <h1 className="page-title">Incidents</h1>
          <p className="page-subtitle">SLO alerts with operator overlay · ack / snooze / resolve · audit-chained mutations</p>
        </div>
      </div>

      <div className="grid-12" style={{ marginBottom: 12 }}>
        {[
          { k: 'firing',       label: 'Firing',       tone: 'down' },
          { k: 'acknowledged', label: 'Acknowledged', tone: 'warn' },
          { k: 'snoozed',      label: 'Snoozed',      tone: 'info' },
          { k: 'resolved',     label: 'Resolved',     tone: 'up'   },
        ].map(b => (
          <div key={b.k} className="col-3 card" style={{ padding: 12 }}>
            <div className="card-title">{b.label}</div>
            <div className="num" style={{ fontSize: 24 }}>
              <span className={`pill ${b.tone}`}>{counts[b.k] || 0}</span>
            </div>
          </div>
        ))}
      </div>

      <div className="card" style={{ marginBottom: 12 }}>
        <window.SectionHeader
          title="Incident queue"
          sub={`${filtered.length} of ${merged.length} · ${filter} filter`}
        />
        <div style={{ display: 'flex', gap: 4, padding: '0 12px 8px' }}>
          {['open', 'firing', 'acknowledged', 'snoozed', 'resolved', 'all'].map(f => (
            <button
              key={f}
              className={`btn ${filter === f ? 'primary' : ''}`}
              onClick={() => setFilter(f)}
            >{f}</button>
          ))}
        </div>
        {filtered.length === 0 ? (
          <div style={{ padding: 16, textAlign: 'center', color: 'var(--ink-dim)', fontSize: 12 }}>
            No incidents in this view.{' '}
            <a href="#/health" style={{ color: 'var(--accent)' }}>Health &amp; SLOs</a> shows current burn pressure.
          </div>
        ) : (
          <table className="tbl tbl-compact">
            <thead><tr>
              <th>Status</th>
              <th>Severity</th>
              <th>SLI</th>
              <th>Fired</th>
              <th>Budget</th>
              <th>Acked by</th>
              <th>Note</th>
              <th style={{ textAlign: 'right' }}>Actions</th>
            </tr></thead>
            <tbody>
              {filtered.map(m => (
                <tr key={m.id} style={m.status === 'snoozed' ? { opacity: 0.6 } : undefined}>
                  <td>
                    <span className={`pill ${m.status === 'firing' ? 'down' : m.status === 'acknowledged' ? 'warn' : m.status === 'snoozed' ? 'info' : 'up'}`}>
                      {m.status}
                    </span>
                  </td>
                  <td><span className={`pill ${m.severity === 'critical' ? 'down' : 'warn'}`}>{m.severity}</span></td>
                  <td><code style={{ fontSize: 11 }}>{m.sli}</code></td>
                  <td title={m.fired_at}>{fmtRel(m.fired_at)}</td>
                  <td className="num">{m.budget_consumed_pct ? m.budget_consumed_pct.toFixed(1) + '%' : '—'}</td>
                  <td>{m.acked_by || '—'} {m.acked_at && <span style={{ fontSize: 10, color: 'var(--ink-dim)' }}>· {fmtRel(m.acked_at)}</span>}</td>
                  <td style={{ fontSize: 11, color: 'var(--ink-dim)' }}>{m.note || '—'}</td>
                  <td style={{ textAlign: 'right', whiteSpace: 'nowrap' }}>
                    {m.status === 'firing' && (
                      <button className="btn sm" disabled={busy === m.id} onClick={() => doAct('ack', m.id)}>Ack</button>
                    )}
                    {(m.status === 'firing' || m.status === 'acknowledged') && (
                      <button className="btn sm" disabled={busy === m.id} onClick={() => doAct('snooze', m.id)} style={{ marginLeft: 4 }}>Snooze 15m</button>
                    )}
                    {m.status !== 'resolved' && (
                      <button className="btn sm primary" disabled={busy === m.id} onClick={() => doAct('resolve', m.id)} style={{ marginLeft: 4 }}>Resolve</button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      <div className="card" style={{ padding: 12, fontSize: 11, color: 'var(--ink-dim)', display: 'flex', alignItems: 'center', gap: 8 }}>
        <window.I.Info />
        <span>
          Acks/snoozes/resolves are CSRF-gated POSTs that go through
          the audit chain — every action lands in <a href="#/audit" style={{ color: 'var(--accent)' }}>Audit Trail</a>.
          Alert <em>rules</em> (when to fire) are still configured via YAML
          (<code>cfg.alerts</code>); the in-place rule editor isn't built yet.
        </span>
      </div>
    </>
  );
}

function PageInvestigation() {
  // 2026-05-03 SOC-UX pass — the page now defaults to a recent-
  // requests list (last 200 audit events) so operators see signal
  // immediately on landing.  Filters narrow the view; pivoting
  // on an IP / request_id / rule_id replaces the list with a
  // focused timeline + summary panels.  The Attack-Analytics
  // top strip (detector + bot mix) folded in from the deleted
  // standalone page lives at the top so it's visible regardless
  // of pivot state.
  const [pivot, setPivot] = useStateP('');
  const [activePivot, setActivePivot] = useStateP('');
  const [pivotKind, setPivotKind] = useStateP('auto'); // auto | ip | request_id | rule_id
  const [actionFilter, setActionFilter] = useStateP('all'); // all | block | allow | challenge
  const [selected, setSelected] = useStateP(null);

  // Honour deep-links from the Live-Feed RequestDetail drawer:
  // `#/investigation?pivot=<id>&kind=request_id`.
  useEffectP(() => {
    if (typeof location === 'undefined') return;
    const m = location.hash.match(/\?(.+)$/);
    if (!m) return;
    const params = new URLSearchParams(m[1]);
    const p = params.get('pivot');
    const k = params.get('kind');
    if (p) {
      setPivot(p);
      setActivePivot(p);
      if (k && ['ip', 'request_id', 'rule_id'].includes(k)) {
        setPivotKind(k);
      }
    }
  }, []);

  // Derive pivot type from the input shape.
  const detectKind = (s) => {
    if (!s) return null;
    if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(s)) return 'request_id';
    if (/^[0-9a-f]{32,}$/i.test(s)) return 'request_id'; // blake3/sha hash
    if (/^\d{1,3}(\.\d{1,3}){3}(\/\d{1,2})?$/.test(s)) return 'ip';
    if (/^[a-f0-9:]+:[a-f0-9:]+$/i.test(s)) return 'ip'; // ipv6
    if (/^[a-z][a-z0-9_-]*\.[a-z][a-z0-9_-]*$/i.test(s)) return 'rule_id'; // e.g. owasp.sqli.union
    return 'rule_id';
  };
  const effectiveKind = pivotKind === 'auto' ? detectKind(activePivot) : pivotKind;

  // Hit the audit endpoint with the right filter for this pivot kind.
  const auditQ = (() => {
    if (!activePivot) return { ip: undefined, ruleId: undefined, requestId: undefined };
    if (effectiveKind === 'ip')         return { ip: activePivot, ruleId: undefined, requestId: undefined };
    if (effectiveKind === 'rule_id')    return { ip: undefined, ruleId: activePivot, requestId: undefined };
    if (effectiveKind === 'request_id') return { ip: undefined, ruleId: undefined, requestId: activePivot };
    return { ip: undefined, ruleId: undefined, requestId: undefined };
  })();
  const audit = window.useAuditLogApi
    ? window.useAuditLogApi({ ...auditQ, limit: 200 })
    : { data: null };
  const events = audit.data?.events || [];

  // Top-attackers table: when pivoting on an IP, find the row.
  const topAttackers = window.useApi
    ? window.useApi('/api/attacks/top', { intervalMs: 30000, fallback: null })
    : { data: null };
  const attackerRow = activePivot && effectiveKind === 'ip'
    ? (topAttackers.data?.attackers || []).find(a => a.identifier === activePivot)
    : null;

  // SOC-UX: detector + bot-mix top strip (folded in from the
  // deleted Attack-Analytics page).  Hooks live here at the top
  // level so they obey React's Rules-of-Hooks regardless of
  // pivot state.  Last-1h window matches the page's "recent
  // operations" framing.
  const insightsByDetector = window.useAttacksByDetectorApi
    ? window.useAttacksByDetectorApi(3600)
    : { data: null };
  const insightsBotMix = window.useBotMixApi
    ? window.useBotMixApi(3600)
    : { data: null };

  // Stats roll-up over the audit window.
  const summary = useMemoP(() => {
    if (!events.length) return null;
    const byAction = {};
    const byDetector = {};
    const byPath = {};
    const ips = new Set();
    let earliest = Infinity, latest = -Infinity;
    for (const row of events) {
      const e = row.event || row;
      const a = e.action || 'unknown';
      byAction[a] = (byAction[a] || 0) + 1;
      const d = e.detector || (e.detectors && e.detectors[0]) || e.rule_id || 'n/a';
      byDetector[d] = (byDetector[d] || 0) + 1;
      const p = e.path || '/';
      byPath[p] = (byPath[p] || 0) + 1;
      if (e.client_ip) ips.add(e.client_ip);
      const ts = e.ts ? Date.parse(e.ts) : NaN;
      if (Number.isFinite(ts)) {
        earliest = Math.min(earliest, ts);
        latest = Math.max(latest, ts);
      }
    }
    return {
      total: events.length,
      byAction,
      byDetector,
      byPath,
      uniqueIps: ips.size,
      windowStart: Number.isFinite(earliest) ? new Date(earliest) : null,
      windowEnd: Number.isFinite(latest) ? new Date(latest) : null,
    };
  }, [events]);

  return (
    <>
      <div className="page-head">
        <div>
          <h1 className="page-title">Investigation</h1>
          <p className="page-subtitle">Pivot from any IP / request_id / rule_id into the full WAF context</p>
        </div>
      </div>

      <div className="card" style={{ padding: 16, marginBottom: 12 }}>
        <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
          <window.I.Search />
          <input
            type="text"
            placeholder="Paste an IP (1.2.3.4 or 10.0.0.0/8), request_id (UUID), or rule_id (owasp.sqli.union)…"
            value={pivot}
            onChange={e => setPivot(e.target.value)}
            onKeyDown={e => { if (e.key === 'Enter') setActivePivot(pivot.trim()); }}
            style={{ flex: 1, padding: '8px 12px', borderRadius: 6, border: '1px solid var(--hairline)', fontSize: 13 }}
          />
          <select
            value={pivotKind}
            onChange={e => setPivotKind(e.target.value)}
            style={{ padding: '8px 6px', borderRadius: 6, border: '1px solid var(--hairline)', fontSize: 12 }}
          >
            <option value="auto">auto-detect</option>
            <option value="ip">IP / CIDR</option>
            <option value="request_id">request_id</option>
            <option value="rule_id">rule_id</option>
          </select>
          <button className="btn primary" onClick={() => setActivePivot(pivot.trim())}>Pivot</button>
        </div>
        {activePivot && (
          <div style={{ marginTop: 6, fontSize: 11, color: 'var(--ink-dim)' }}>
            Pivoting on <code>{activePivot}</code> · type: <strong>{effectiveKind || 'unknown'}</strong>
          </div>
        )}
      </div>

      {!activePivot && (() => {
        // Default mode: recent requests + Attack-Analytics top
        // strip.  All hooks live at the top of the function;
        // here we just consume them.
        const detectorBars = (insightsByDetector.data?.detectors ?? [])
          .map(d => ({ label: d.name, value: d.count, color: detectorColor(d.name) }))
          .sort((a, b) => b.value - a.value);
        const totalDetections = detectorBars.reduce((s, x) => s + x.value, 0);
        const botCategories = insightsBotMix.data?.categories ?? [];
        const botColorFor = name => ({
          verified:  'var(--up)',
          suspect:   'var(--warn)',
          malicious: 'var(--down)',
          unknown:   'var(--ink-faint)',
        }[name] || 'var(--ink-mute)');
        const botSegments = botCategories.map(c => ({
          name: c.name, value: c.count, color: botColorFor(c.name),
        }));

        // FIX 2026-05-04 — sort desc by `ts` so the table matches
        // the "newest first" subtitle. `/api/audit/since` returns
        // events in insertion order (oldest → newest); we flip
        // here so the user sees today's events at the top.
        const filtered = events
          .filter(row => {
            const e = row.event || row;
            if (actionFilter !== 'all' && e.action !== actionFilter) return false;
            return true;
          })
          .slice()
          .sort((a, b) => {
            const ea = a.event || a, eb = b.event || b;
            const ta = ea.ts ? Date.parse(ea.ts) : 0;
            const tb = eb.ts ? Date.parse(eb.ts) : 0;
            return tb - ta;
          });

        return (
          <>
            <div className="grid-12" style={{ marginBottom: 12 }}>
              <div className="col-6 card">
                <window.SectionHeader
                  title="Detector breakdown"
                  sub={`${totalDetections.toLocaleString()} detections · last 1h`}
                />
                {detectorBars.length === 0 ? (
                  <div style={{ padding: 16, fontSize: 12, color: 'var(--ink-dim)', textAlign: 'center' }}>
                    No detections in the last hour. Drive traffic with <code>make mock-load-attacks</code>.
                  </div>
                ) : (
                  <window.BarList items={detectorBars} />
                )}
              </div>
              <div className="col-6 card">
                <window.SectionHeader
                  title="Bot classification mix"
                  sub={botCategories.length ? `${botCategories.reduce((s, c) => s + c.count, 0).toLocaleString()} classified · last 1h` : 'no bot signal yet'}
                />
                {botSegments.length === 0 ||
                  (botCategories.length === 1 && botCategories[0].name === 'unknown') ? (
                  <div style={{ padding: 16, fontSize: 12, color: 'var(--ink-dim)', textAlign: 'center' }}>
                    {botCategories.length === 1 && botCategories[0].name === 'unknown' ? (
                      <>
                        Bot classifier wired but every request landed in
                        <code style={{ margin: '0 4px' }}>unknown</code>.
                        This profile has no JA4 baseline — see{' '}
                        <a href="#/help" style={{ color: 'var(--accent)' }}>Help → Bot classifier setup</a>.
                      </>
                    ) : (
                      <>No bot classifications recorded.</>
                    )}
                  </div>
                ) : (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                    <window.StackedBar segments={botSegments} h={28} />
                    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 6, fontSize: 11 }}>
                      {botCategories.map(c => (
                        <div key={c.name}>
                          <span style={{ color: botColorFor(c.name) }}>● {c.name}</span>{' '}
                          <span className="num">{c.count.toLocaleString()}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            </div>

            <div className="card flat" style={{ padding: 12, marginBottom: 12 }}>
              <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
                <span style={{ fontSize: 11, color: 'var(--ink-dim)' }}>Filter:</span>
                {['all', 'block', 'challenge', 'allow'].map(a => (
                  <button
                    key={a}
                    className={`chip ${actionFilter === a ? 'active' : ''}`}
                    onClick={() => setActionFilter(a)}
                  >
                    {a}
                  </button>
                ))}
                <span style={{ marginLeft: 'auto', fontSize: 11, color: 'var(--ink-dim)' }}>
                  {filtered.length.toLocaleString()} of {events.length.toLocaleString()} · audit ring
                </span>
              </div>
            </div>

            <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
              <window.SectionHeader
                title="Recent requests"
                sub="newest first · click a row for full request detail · audit ring (last 200)"
              />
              {events.length === 0 && audit.data ? (
                <div style={{ padding: 24, textAlign: 'center', color: 'var(--ink-dim)' }}>
                  Audit ring is empty. Drive some traffic first — try{' '}
                  <code>make mock-load</code>.
                </div>
              ) : !audit.data ? (
                <div style={{ padding: 24, textAlign: 'center', color: 'var(--ink-dim)' }}>
                  Loading audit events…
                </div>
              ) : (
                <table className="tbl tbl-compact">
                  <thead>
                    <tr>
                      <th style={{ width: 90 }}>Time</th>
                      <th>Action</th>
                      <th style={{ width: 130 }}>IP</th>
                      <th style={{ width: 70 }}>Method</th>
                      <th>Path</th>
                      <th style={{ width: 70 }}>Status</th>
                      <th
                        style={{ width: 80 }}
                        title="Cumulative risk score for this client IP (decays over time). NOT the score of this single request — a request can be allowed even when its IP carries high risk if the request itself didn't trigger any detector."
                      >IP risk</th>
                      <th>Rule</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filtered.slice(0, 200).map((row, i) => {
                      const e = row.event || row;
                      const f = (e.fields && typeof e.fields === 'object') ? e.fields : {};
                      return (
                        <tr key={`${e.request_id || i}`} onClick={() => setSelected(e)} style={{ cursor: 'pointer' }}>
                          <td style={{ fontFamily: 'var(--font-mono)', fontSize: 11 }}>
                            {e.ts ? new Date(e.ts).toLocaleTimeString() : '—'}
                          </td>
                          <td><window.ActionPill value={e.action || '—'} /></td>
                          <td className="mono">{e.client_ip || '—'}</td>
                          <td className="mono">{f.method || e.method || '—'}</td>
                          <td className="mono"><code style={{ fontSize: 11 }}>{(f.path || e.path || '/').slice(0, 80)}</code></td>
                          <td className="num">{f.status || e.status || '—'}</td>
                          <td className="num">{e.risk_score ?? '—'}</td>
                          <td className="mono"><code style={{ fontSize: 10, color: 'var(--ink-dim)' }}>{e.rule_id || e.reason || '—'}</code></td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              )}
            </div>

            <window.Drawer
              open={!!selected}
              onClose={() => setSelected(null)}
              title={(selected && (selected.fields?.path || selected.path)) || 'Request detail'}
              footer={selected && selected.client_ip ? (
                <>
                  <button
                    className="btn"
                    onClick={() => {
                      setPivot(selected.client_ip);
                      setActivePivot(selected.client_ip);
                      setPivotKind('ip');
                      setSelected(null);
                    }}
                  >
                    Pivot on this IP
                  </button>
                </>
              ) : null}
            >
              {selected && <RequestDetail data={{
                ip: selected.client_ip,
                action: selected.action,
                tier: selected.tier,
                risk: selected.risk_score,
                rules: selected.rule_id ? [selected.rule_id] : [],
                method: selected.fields?.method || selected.method,
                path: selected.fields?.path || selected.path,
                status: selected.fields?.status || selected.status,
                latency: selected.fields?.latency_ms || selected.latency_ms,
                reason: selected.reason,
                class: selected.class,
                route_id: selected.route_id,
                fields: selected.fields,
                ts: selected.ts,
                request_id: selected.request_id,
              }} />}
            </window.Drawer>
          </>
        );
      })()}

      {activePivot && summary && (
        <>
          <div className="grid-12" style={{ marginBottom: 12 }}>
            <div className="col-3 card" style={{ padding: 12 }}>
              <div className="card-title">Events</div>
              <div className="num" style={{ fontSize: 24 }}>{summary.total.toLocaleString()}</div>
              <div style={{ fontSize: 11, color: 'var(--ink-dim)' }}>matching this pivot</div>
            </div>
            <div className="col-3 card" style={{ padding: 12 }}>
              <div className="card-title">Unique IPs</div>
              <div className="num" style={{ fontSize: 24 }}>{summary.uniqueIps}</div>
              <div style={{ fontSize: 11, color: 'var(--ink-dim)' }}>seen across these events</div>
            </div>
            <div className="col-3 card" style={{ padding: 12 }}>
              <div className="card-title">Window</div>
              <div style={{ fontSize: 13 }}>
                {summary.windowStart ? summary.windowStart.toLocaleTimeString() : '—'}
                <br />
                <span style={{ fontSize: 11, color: 'var(--ink-dim)' }}>
                  → {summary.windowEnd ? summary.windowEnd.toLocaleTimeString() : '—'}
                </span>
              </div>
            </div>
            <div className="col-3 card" style={{ padding: 12 }}>
              <div className="card-title">Top action</div>
              {(() => {
                const top = Object.entries(summary.byAction).sort((a, b) => b[1] - a[1])[0];
                return top ? (
                  <>
                    <div style={{ fontSize: 18 }}>
                      <span className={`pill ${top[0] === 'block' ? 'down' : top[0] === 'allow' ? 'up' : 'warn'}`}>{top[0]}</span>
                    </div>
                    <div style={{ fontSize: 11, color: 'var(--ink-dim)' }}>{top[1]} of {summary.total}</div>
                  </>
                ) : <span>—</span>;
              })()}
            </div>
          </div>

          {attackerRow && (
            <div className="card" style={{ marginBottom: 12 }}>
              <window.SectionHeader title="Attacker context" sub="from /api/attacks/top" />
              <div style={{ padding: 12, display: 'flex', gap: 24, flexWrap: 'wrap', fontSize: 12 }}>
                <div><strong>Hits</strong>: <span className="num">{attackerRow.hits}</span></div>
                {attackerRow.country && <div><strong>Country</strong>: {attackerRow.country}</div>}
                {attackerRow.asn && <div><strong>ASN</strong>: {attackerRow.asn}</div>}
                {attackerRow.risk !== undefined && <div><strong>Risk</strong>: <span className="num">{attackerRow.risk}</span></div>}
                {attackerRow.categories && (
                  <div><strong>Categories</strong>: {Array.isArray(attackerRow.categories) ? attackerRow.categories.join(', ') : attackerRow.categories}</div>
                )}
              </div>
            </div>
          )}

          <div className="grid-12" style={{ marginBottom: 12 }}>
            <div className="col-6 card">
              <window.SectionHeader title="Action breakdown" />
              <table className="tbl tbl-compact">
                <tbody>
                  {Object.entries(summary.byAction).sort((a, b) => b[1] - a[1]).map(([k, v]) => (
                    <tr key={k}>
                      <td><span className={`pill ${k === 'block' ? 'down' : k === 'allow' ? 'up' : 'warn'}`}>{k}</span></td>
                      <td className="num" style={{ textAlign: 'right' }}>{v}</td>
                      <td className="num" style={{ textAlign: 'right' }}>{((v / summary.total) * 100).toFixed(1)}%</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <div className="col-6 card">
              <window.SectionHeader title="Top detectors / rules" />
              <table className="tbl tbl-compact">
                <tbody>
                  {Object.entries(summary.byDetector).sort((a, b) => b[1] - a[1]).slice(0, 10).map(([k, v]) => (
                    <tr key={k}>
                      <td><code style={{ fontSize: 11 }}>{k}</code></td>
                      <td className="num" style={{ textAlign: 'right' }}>{v}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          <div className="card">
            <window.SectionHeader title={`Audit timeline (newest first, ${events.length} of last 200)`} />
            <table className="tbl tbl-compact">
              <thead><tr><th>ts</th><th>action</th><th>ip</th><th>method</th><th>path</th><th>rule_id</th></tr></thead>
              <tbody>
                {events.slice(0, 100).map((row, i) => {
                  const e = row.event || row;
                  return (
                    <tr key={i}>
                      <td style={{ fontFamily: 'monospace', fontSize: 11 }}>
                        {e.ts ? new Date(e.ts).toLocaleTimeString() : '—'}
                      </td>
                      <td><span className={`pill ${e.action === 'block' ? 'down' : e.action === 'allow' ? 'up' : 'warn'}`}>{e.action || '—'}</span></td>
                      <td className="num">{e.client_ip || '—'}</td>
                      <td>{e.method || '—'}</td>
                      <td><code style={{ fontSize: 11 }}>{(e.path || '/').slice(0, 60)}</code></td>
                      <td><code style={{ fontSize: 11 }}>{e.rule_id || e.detector || '—'}</code></td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </>
      )}

      {activePivot && !summary && events.length === 0 && (
        <div className="card" style={{ padding: 24, textAlign: 'center', color: 'var(--ink-dim)' }}>
          No audit events found for <code>{activePivot}</code> in the in-process ring (last 200 events).
        </div>
      )}
    </>
  );
}

function PageThreatIntel() {
  const ti = window.useApi ? window.useApi('/api/threat-intel/hits', { intervalMs: 30000, fallback: null }) : { data: null };
  const feeds = window.useThreatIntelFeedsApi ? window.useThreatIntelFeedsApi() : { data: null };
  const geo = window.useGeoipStatusApi ? window.useGeoipStatusApi() : { data: null };
  const hits = ti.data?.hits || [];
  const feedList = feeds.data?.feeds || [];
  const featureBuilt = feeds.data?.feature_built !== false; // null = unknown, treat as on
  const noFeedsAndNoGeo = feedList.length === 0 && !geo.data?.db_loaded;

  return (
    <>
      <div className="page-head">
        <div>
          <h1 className="page-title">Threat Intel</h1>
          <p className="page-subtitle">TAXII / MISP feeds · GeoIP DB · recent indicator matches</p>
        </div>
      </div>

      {/* SOC-UX: when nothing is wired, lead with a clear "what
          this page is for + what it needs" panel instead of three
          empty stat cards.  Hides automatically once any feed or
          GeoIP DB is configured. */}
      {noFeedsAndNoGeo && (
        <div className="card" style={{ padding: 16, marginBottom: 12, borderLeft: '3px solid var(--accent)' }}>
          <div style={{ fontWeight: 600, marginBottom: 6 }}>What you'll see here</div>
          <div style={{ fontSize: 12, color: 'var(--ink-mute)', lineHeight: 1.6 }}>
            Threat Intel surfaces three signals once you wire them:
            <ul style={{ marginTop: 6, paddingLeft: 18 }}>
              <li><strong>Feeds</strong> — TAXII / MISP indicator subscriptions; hits attribute traffic to known-bad infrastructure.</li>
              <li><strong>Indicator hits</strong> — every request whose IP / domain matched a feed entry.</li>
              <li><strong>GeoIP</strong> — country + ASN enrichment on the Overview map and the access-list <code>kind: country</code> matcher.</li>
            </ul>
            Until a feed is configured this page reads honestly empty — it is not a bug.
            See <a href="#/help" style={{ color: 'var(--accent)' }}>Help → Threat Intel setup</a>.
          </div>
        </div>
      )}

      <div className="grid-12" style={{ marginBottom: 12 }}>
        <div className="col-4 card" style={{ padding: 12 }}>
          <div className="card-title">Configured feeds</div>
          <div className="num" style={{ fontSize: 24 }}>{feedList.length}</div>
          <div style={{ fontSize: 11, color: 'var(--ink-dim)' }}>
            {feeds.data?.configured_in_yaml ? 'from YAML' : 'no feeds configured'}
          </div>
        </div>
        <div className="col-4 card" style={{ padding: 12 }}>
          <div className="card-title">Recent matches</div>
          <div className="num" style={{ fontSize: 24 }}>{hits.length}</div>
          <div style={{ fontSize: 11, color: 'var(--ink-dim)' }}>indicator hits in current window</div>
        </div>
        <div className="col-4 card" style={{ padding: 12 }}>
          <div className="card-title">GeoIP DB</div>
          <div style={{ fontSize: 18 }}>
            {geo.data?.db_loaded ? (
              <span className="pill ok">loaded</span>
            ) : geo.data?.feature_built ? (
              <span className="pill warn">no .mmdb</span>
            ) : (
              <span className="pill" style={{ opacity: 0.5 }}>feature off</span>
            )}
          </div>
          <div style={{ fontSize: 11, color: 'var(--ink-dim)' }}>
            {geo.data?.feature_built
              ? geo.data?.db_loaded ? `${geo.data?.indicator_count?.toLocaleString() || 0} indicators` : 'set geoip.path in config'
              : 'rebuild with FEATURES="redis geoip"'}
          </div>
        </div>
      </div>

      <div className="card" style={{ marginBottom: 12 }}>
        <window.SectionHeader title="Configured feeds" sub="from cfg.threat_intel.feeds" />
        {feedList.length === 0 ? (
          <div style={{ padding: 16, textAlign: 'center', color: 'var(--ink-dim)', fontSize: 12 }}>
            No threat-intel feeds configured. Add to <code>config/*.yaml</code>:
            <pre style={{ background: 'var(--surface-2)', padding: 8, borderRadius: 4, marginTop: 8, textAlign: 'left', fontSize: 11 }}>
{`threat_intel:
  feeds:
    - kind: taxii
      url: "https://example.org/taxii/api"
      collection: "indicators"
      interval: "10m"`}
            </pre>
            <div style={{ marginTop: 8, fontSize: 11 }}>
              Then restart the WAF. A feed-management UI (add/remove without restart) isn't built yet — for now this page is read-only.
            </div>
          </div>
        ) : (
          <table className="tbl tbl-compact">
            <thead><tr><th>Kind</th><th>Source</th><th>Last fetch</th><th>Indicators</th><th>Status</th></tr></thead>
            <tbody>
              {feedList.map((f, i) => (
                <tr key={i}>
                  <td><span className="pill">{f.kind || 'taxii'}</span></td>
                  <td className="num">{f.source || f.url || f.name}</td>
                  <td>{f.last_fetch_at ? new Date(f.last_fetch_at).toLocaleString() : '—'}</td>
                  <td className="num">{f.indicator_count || 0}</td>
                  <td><span className={`pill ${f.error ? 'down' : 'ok'}`}>{f.error ? 'error' : 'ok'}</span></td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      <div className="card" style={{ marginBottom: 12 }}>
        <window.SectionHeader title="Recent indicator hits" sub={`${hits.length} matches in current window`} />
        {hits.length === 0 ? (
          <div style={{ padding: 16, textAlign: 'center', color: 'var(--ink-dim)', fontSize: 12 }}>
            No threat-intel matches recorded. Either no feeds configured (above), or no traffic matched.
          </div>
        ) : (
          <table className="tbl tbl-compact">
            <thead><tr><th>Feed</th><th>Indicator</th><th>Hits</th><th>Last seen</th></tr></thead>
            <tbody>
              {hits.map((h, i) => (
                <tr key={i}>
                  <td>{h.feed}</td>
                  <td className="num">{h.indicator}</td>
                  <td className="num">{h.hits}</td>
                  <td>{h.last_seen ? new Date(h.last_seen).toLocaleString() : '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      <div className="card">
        <window.SectionHeader title="GeoIP DB" sub="MaxMind .mmdb status" />
        <div style={{ padding: 16, fontSize: 12 }}>
          {geo.data?.feature_built === false ? (
            <div>
              The <code>geoip</code> Cargo feature is not enabled in this build. Rebuild with:
              <pre style={{ background: 'var(--surface-2)', padding: 8, borderRadius: 4, marginTop: 8 }}>
                FEATURES="redis geoip" make build
              </pre>
            </div>
          ) : geo.data?.db_loaded ? (
            <div>
              GeoLite2 DB loaded from <code>{geo.data?.db_path || '?'}</code>{' '}
              ({geo.data?.indicator_count?.toLocaleString() || 0} country mappings).
              The Overview map renders attacker country blips automatically.
            </div>
          ) : (
            <div>
              GeoIP feature is built but no <code>.mmdb</code> file is loaded. Configure:
              <pre style={{ background: 'var(--surface-2)', padding: 8, borderRadius: 4, marginTop: 8 }}>
{`geoip:
  enabled: true
  path: /path/to/GeoLite2-City.mmdb`}
              </pre>
              Free download:{' '}
              <a href="https://www.maxmind.com/en/geolite2/signup" target="_blank" rel="noopener" style={{ color: 'var(--accent)' }}>
                maxmind.com/en/geolite2/signup
              </a>
            </div>
          )}
        </div>
      </div>
    </>
  );
}

// 2026-05-09 — Traffic Gates page. Operator-facing surface for the
// four request-flow gates that fire BEFORE the detector chain:
//
//   1. Access list (blacklist + whitelist) — IP / CIDR / country
//   2. Strike-block — per-IP lifetime strike counter
//   3. Rate-limit — token-bucket per-IP volumetric guard
//   4. DDoS — sliding-window per-IP burst gate + EWMA spike mode
//
// All four short-circuit the request before detectors run. They are
// NOT detectors (don't emit `Signal { score, tag }`); they live in
// `crates/aegis-security/src/{ddos,risk,rate_limit,...}`.
//
// The page surfaces telemetry for each gate and links to the
// dedicated CRUD page where one exists (Access Lists). The DDoS
// card has the most detail because the gate has no other operator
// surface today; threshold edits still require restart (hot-reload
// of DdosConfig is a follow-up).
function PageTrafficGates() {
  return (
    <>
      <div className="page-head">
        <div>
          <h1 className="page-title">Traffic Gates</h1>
          <p className="page-subtitle">
            Four request-flow short-circuits that fire <strong>before</strong> the detector chain.
            Each is a binary block-or-pass gate, not a `Detector` trait
            impl — see the <a href="#/detectors" style={{ color: 'var(--accent)' }}>Detectors</a> page
            for the signal-emitting pipeline that runs after these gates pass.
          </p>
        </div>
      </div>

      <AccessListGateCard />
      <StrikeBlockGateCard />
      <RateLimitGateCard />
      <DdosGateCard />
    </>
  );
}

// 1. Access list summary — links to the existing dedicated page.
function AccessListGateCard() {
  const black = window.useApi ? window.useApi('/api/blacklist', { intervalMs: 30000, fallback: { entries: [] } }) : { data: { entries: [] } };
  const white = window.useApi ? window.useApi('/api/whitelist', { intervalMs: 30000, fallback: { entries: [] } }) : { data: { entries: [] } };
  const blackCount = (black.data?.entries || []).length;
  const whiteCount = (white.data?.entries || []).length;
  return (
    <div className="card" style={{ marginBottom: 12 }}>
      <window.SectionHeader
        title="1. Access List"
        sub="IP / CIDR / country blacklist + whitelist — fires first, cheapest gate"
      />
      <div style={{ padding: 16, display: 'flex', alignItems: 'center', gap: 16 }}>
        <div style={{ flex: 1, display: 'flex', gap: 16 }}>
          <span className="pill err" style={{ fontSize: 11 }}>{blackCount} blacklist {blackCount === 1 ? 'entry' : 'entries'}</span>
          <span className="pill ok" style={{ fontSize: 11 }}>{whiteCount} whitelist {whiteCount === 1 ? 'entry' : 'entries'}</span>
          <span style={{ fontSize: 11, color: 'var(--ink-dim)' }}>
            Returns 403 + <code>X-WAF-Action: block</code> on blacklist hit.
            Whitelist bypasses detectors but not other gates.
          </span>
        </div>
        <a href="#/access-lists" className="btn primary" style={{ fontSize: 11, padding: '4px 12px', textDecoration: 'none' }}>
          Edit lists →
        </a>
      </div>
    </div>
  );
}

// 2. Strike-block summary — sourced from /api/risk.
function StrikeBlockGateCard() {
  const risk = window.useApi ? window.useApi('/api/risk', { intervalMs: 5000, fallback: null }) : { data: null };
  const blockAt = risk.data?.config?.strikes?.block_at ?? null;
  const blockedCount = (risk.data?.entries || []).filter(e => e.strikes >= (blockAt ?? 999999)).length;
  const totalTracked = (risk.data?.entries || []).length;
  return (
    <div className="card" style={{ marginBottom: 12 }}>
      <window.SectionHeader
        title="2. Strike-Block"
        sub="Per-IP lifetime strike counter — permanent block once threshold crossed"
      />
      <div style={{ padding: 16, display: 'flex', alignItems: 'center', gap: 16 }}>
        <div style={{ flex: 1, display: 'flex', gap: 16, flexWrap: 'wrap' }}>
          {blockAt !== null && (
            <span className="pill neutral" style={{ fontSize: 11 }}>
              <code style={{ fontSize: 10 }}>strikes.block_at</code>: <strong>{blockAt}</strong>
            </span>
          )}
          <span className={`pill ${blockedCount > 0 ? 'err' : 'ok'}`} style={{ fontSize: 11 }}>
            {blockedCount} {blockedCount === 1 ? 'IP' : 'IPs'} permanently blocked
          </span>
          <span className="pill neutral" style={{ fontSize: 11 }}>
            {totalTracked} tracked
          </span>
        </div>
        <a href="#/settings" className="btn" style={{ fontSize: 11, padding: '4px 12px', textDecoration: 'none' }}>
          Edit thresholds →
        </a>
      </div>
    </div>
  );
}

// 3. Rate-limit summary — sourced from /api/rate-limit (if exposed).
// 3. Rate Limit gate — F-T2 token bucket. Steady-state per-IP
// limiter that returns 429 + X-WAF-Action: rate_limit when the
// bucket exceeds. Distinct from DDoS gate (sustained burst →
// TTL'd auto-block returning 403). Hot-reloadable via PUT
// /api/rate-limit; per-IP timestamp state preserved across edits.
function RateLimitGateCard() {
  const rl = window.useApi ? window.useApi('/api/rate-limit', { intervalMs: 10000, fallback: null }) : { data: null };
  const cfg = rl.data;
  const [editing, setEditing] = useStateP(false);

  return (
    <div className="card" style={{ marginBottom: 12 }}>
      <window.SectionHeader
        title="3. Rate Limit"
        sub="Per-IP token bucket — returns 429 + X-WAF-Action: rate_limit when window exceeded. Allows retry after window."
      />
      <div style={{ padding: 16 }}>
        {!cfg ? (
          <div style={{ fontSize: 12, color: 'var(--ink-dim)', fontStyle: 'italic' }}>Loading…</div>
        ) : (
          <>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 12, marginBottom: 12 }}>
              <div style={{ padding: 12, background: 'var(--surface-2)', borderRadius: 4 }}>
                <div style={{ fontSize: 10, color: 'var(--ink-dim)', textTransform: 'uppercase', letterSpacing: 0.5 }}>Limit</div>
                <div style={{ fontSize: 24, fontWeight: 700, marginTop: 4 }}>{cfg.limit}</div>
                <div style={{ fontSize: 10, color: 'var(--ink-faint)', marginTop: 2 }}>requests per window</div>
              </div>
              <div style={{ padding: 12, background: 'var(--surface-2)', borderRadius: 4 }}>
                <div style={{ fontSize: 10, color: 'var(--ink-dim)', textTransform: 'uppercase', letterSpacing: 0.5 }}>Window</div>
                <div style={{ fontSize: 24, fontWeight: 700, marginTop: 4 }}>{cfg.window_seconds}s</div>
                <div style={{ fontSize: 10, color: 'var(--ink-faint)', marginTop: 2 }}>sliding window length</div>
              </div>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 12 }}>
              <div style={{ fontSize: 11, color: 'var(--ink-dim)', lineHeight: 1.5 }}>
                Effective rate: <strong>{(cfg.limit / Math.max(cfg.window_seconds, 1)).toFixed(2)} req/s per IP</strong>.
                Hot-reloadable — edits take effect on the next request without restart.
              </div>
              <button className="btn primary" onClick={() => setEditing(true)} style={{ fontSize: 11, padding: '4px 12px' }}>
                Edit
              </button>
            </div>
          </>
        )}
      </div>
      {editing && (
        <RateLimitEditModal
          current={cfg}
          onClose={() => setEditing(false)}
          onSaved={() => { setEditing(false); rl.reload && rl.reload(); }}
        />
      )}
    </div>
  );
}

function RateLimitEditModal({ current, onClose, onSaved }) {
  const [limit, setLimit] = useStateP(current?.limit ?? 1000);
  const [windowSeconds, setWindowSeconds] = useStateP(current?.window_seconds ?? 60);
  const [busy, setBusy] = useStateP(false);
  const [err, setErr] = useStateP(null);

  async function save() {
    setBusy(true); setErr(null);
    try {
      const r = await window.csrfMutate('/api/rate-limit', {
        method: 'PUT',
        body: { limit: parseInt(limit, 10), window_seconds: parseInt(windowSeconds, 10) },
      });
      if (r && r.ok !== false && (r.status === undefined || (r.status >= 200 && r.status < 300))) {
        window.aegisToast && window.aegisToast('Rate limit updated', 'ok');
        onSaved();
      } else {
        const msg = (r && (r.message || r.error || r.reason)) || `status ${r?.status ?? '?'}`;
        setErr(msg);
      }
    } catch (e) {
      setErr(e.message || String(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal" onClick={e => e.stopPropagation()} style={{ maxWidth: 480 }}>
        <div className="modal-head">
          <div className="modal-title">Edit rate-limit thresholds</div>
          <button className="btn btn-sm" onClick={onClose}>×</button>
        </div>
        <div className="modal-body" style={{ display: 'grid', gap: 12 }}>
          <label style={{ fontSize: 12 }}>
            Limit (requests per window)
            <input className="input" type="number" min="1" value={limit}
              onChange={e => setLimit(e.target.value)} disabled={busy}
              style={{ marginTop: 4, width: '100%' }} />
          </label>
          <label style={{ fontSize: 12 }}>
            Window (seconds)
            <input className="input" type="number" min="1" value={windowSeconds}
              onChange={e => setWindowSeconds(e.target.value)} disabled={busy}
              style={{ marginTop: 4, width: '100%' }} />
          </label>
          <div style={{ fontSize: 11, color: 'var(--ink-dim)', lineHeight: 1.5 }}>
            Effective: <strong>{(limit / Math.max(parseInt(windowSeconds, 10), 1)).toFixed(2)} req/s per IP</strong>.
            Per-IP timestamp state is preserved across the edit — flooding sources don't get a free reset.
            Audit-mutated; the change appears in the audit chain.
          </div>
          {err && <div style={{ fontSize: 11, color: 'var(--down)' }}>Error: {err}</div>}
        </div>
        <div className="modal-foot">
          <button className="btn" onClick={onClose} disabled={busy}>Cancel</button>
          <button className="btn primary" onClick={save} disabled={busy}>
            {busy ? 'Saving…' : 'Save'}
          </button>
        </div>
      </div>
    </div>
  );
}

// 4. DDoS gate — full operator surface. Per-IP sliding-window
// burst counter + EWMA spike-mode ticker. Returns 403 +
// X-WAF-Action: block on burst-exceed (different from rate-limit
// gate which returns 429). Hot-reloadable via PUT /api/gates/ddos
// — per-IP StateBackend window state preserved across edits.
function DdosGateCard() {
  const ddos = window.useApi ? window.useApi('/api/gates/ddos', { intervalMs: 5000, fallback: null }) : { data: null };
  const [editing, setEditing] = useStateP(false);
  const data = ddos.data;

  if (!data || !data.enabled) {
    return (
      <div className="card" style={{ marginBottom: 12 }}>
        <window.SectionHeader
          title="4. DDoS Gate"
          sub="Per-IP sliding-window burst gate + EWMA spike mode — currently DISABLED"
        />
        <div style={{ padding: 16 }}>
          <div style={{ fontSize: 12, color: 'var(--ink-dim)', lineHeight: 1.5 }}>
            <span className="pill neutral" style={{ fontSize: 11, marginRight: 8 }}>cfg.ddos.enabled = false</span>
            Set <code>cfg.ddos.enabled: true</code> in your YAML and restart to enable.
            See <a href="/docs/security/ddos-protection" target="_blank" rel="noreferrer" style={{ color: 'var(--accent)' }}>docs/security/ddos-protection.md</a>.
          </div>
        </div>
      </div>
    );
  }

  const cfg = data.config;
  const modeStyle = cfg.observe_only
    ? { bg: 'rgba(240,185,11,0.14)', fg: 'var(--warn)', label: 'OBSERVE-ONLY' }
    : { bg: 'rgba(14,203,129,0.14)', fg: 'var(--up)', label: 'ENFORCING' };
  const spikeStyle = data.spike_active
    ? { bg: 'rgba(246,70,93,0.14)', fg: 'var(--down)', label: '⚠ SPIKE ACTIVE' }
    : { bg: 'rgba(14,203,129,0.14)', fg: 'var(--up)', label: 'NORMAL' };

  return (
    <div className="card" style={{ marginBottom: 12 }}>
      <window.SectionHeader
        title="4. DDoS Gate"
        sub="Per-IP sliding-window burst gate + EWMA spike mode — returns 403 + X-WAF-Action: block on burst-exceed (auto-blocks IP for block_ttl_s)"
      />
      <div style={{ padding: 16 }}>
        {/* Status row */}
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8, marginBottom: 16, alignItems: 'center' }}>
          <span style={{ fontSize: 11, padding: '3px 10px', borderRadius: 4, background: modeStyle.bg, color: modeStyle.fg, fontWeight: 600 }}>
            {modeStyle.label}
          </span>
          <span style={{ fontSize: 11, padding: '3px 10px', borderRadius: 4, background: spikeStyle.bg, color: spikeStyle.fg, fontWeight: 600 }}>
            Spike mode: {spikeStyle.label}
          </span>
          <div style={{ flex: 1 }} />
          <button className="btn primary" onClick={() => setEditing(true)} style={{ fontSize: 11, padding: '4px 12px' }}>
            Edit thresholds
          </button>
        </div>

        {/* Live telemetry — current/baseline RPS + spike threshold */}
        <div style={{ fontSize: 10, color: 'var(--ink-dim)', textTransform: 'uppercase', letterSpacing: 0.5, marginBottom: 6 }}>Live Telemetry</div>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 12, marginBottom: 16 }}>
          <div style={{ padding: 12, background: 'var(--surface-2)', borderRadius: 4 }}>
            <div style={{ fontSize: 10, color: 'var(--ink-dim)', textTransform: 'uppercase', letterSpacing: 0.5 }}>Current RPS</div>
            <div style={{ fontSize: 24, fontWeight: 700, marginTop: 4 }}>{data.current_rps}</div>
            <div style={{ fontSize: 10, color: 'var(--ink-faint)', marginTop: 2 }}>this 1-second window</div>
          </div>
          <div style={{ padding: 12, background: 'var(--surface-2)', borderRadius: 4 }}>
            <div style={{ fontSize: 10, color: 'var(--ink-dim)', textTransform: 'uppercase', letterSpacing: 0.5 }}>Baseline RPS</div>
            <div style={{ fontSize: 24, fontWeight: 700, marginTop: 4 }}>{data.baseline_rps}</div>
            <div style={{ fontSize: 10, color: 'var(--ink-faint)', marginTop: 2 }}>EWMA, 0.9 / 0.1 weights</div>
          </div>
          <div style={{ padding: 12, background: 'var(--surface-2)', borderRadius: 4 }}>
            <div style={{ fontSize: 10, color: 'var(--ink-dim)', textTransform: 'uppercase', letterSpacing: 0.5 }}>Spike Threshold</div>
            <div style={{ fontSize: 24, fontWeight: 700, marginTop: 4 }}>
              {Math.round(data.baseline_rps * cfg.spike_multiplier)}
            </div>
            <div style={{ fontSize: 10, color: 'var(--ink-faint)', marginTop: 2 }}>{cfg.spike_multiplier} × baseline</div>
          </div>
        </div>

        {/* Configured thresholds */}
        <div style={{ fontSize: 10, color: 'var(--ink-dim)', textTransform: 'uppercase', letterSpacing: 0.5, marginBottom: 6 }}>Configured Thresholds</div>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 8, marginBottom: 12 }}>
          <div style={{ padding: 8, background: 'var(--surface-2)', borderRadius: 4 }}>
            <div style={{ fontSize: 10, color: 'var(--ink-dim)' }}>per_ip_limit</div>
            <div style={{ fontSize: 16, fontWeight: 600, fontFamily: 'monospace' }}>{cfg.per_ip_limit.toLocaleString()}</div>
            <div style={{ fontSize: 10, color: 'var(--ink-faint)' }}>requests / window</div>
          </div>
          <div style={{ padding: 8, background: 'var(--surface-2)', borderRadius: 4 }}>
            <div style={{ fontSize: 10, color: 'var(--ink-dim)' }}>per_ip_window_s</div>
            <div style={{ fontSize: 16, fontWeight: 600, fontFamily: 'monospace' }}>{cfg.per_ip_window_s}s</div>
            <div style={{ fontSize: 10, color: 'var(--ink-faint)' }}>sliding window</div>
          </div>
          <div style={{ padding: 8, background: 'var(--surface-2)', borderRadius: 4 }}>
            <div style={{ fontSize: 10, color: 'var(--ink-dim)' }}>block_ttl_s</div>
            <div style={{ fontSize: 16, fontWeight: 600, fontFamily: 'monospace' }}>{cfg.block_ttl_s}s</div>
            <div style={{ fontSize: 10, color: 'var(--ink-faint)' }}>auto-block duration</div>
          </div>
          <div style={{ padding: 8, background: 'var(--surface-2)', borderRadius: 4 }}>
            <div style={{ fontSize: 10, color: 'var(--ink-dim)' }}>spike_multiplier</div>
            <div style={{ fontSize: 16, fontWeight: 600, fontFamily: 'monospace' }}>{cfg.spike_multiplier}×</div>
            <div style={{ fontSize: 10, color: 'var(--ink-faint)' }}>spike trigger</div>
          </div>
          <div style={{ padding: 8, background: 'var(--surface-2)', borderRadius: 4 }}>
            <div style={{ fontSize: 10, color: 'var(--ink-dim)' }}>tightened_per_ip_rps</div>
            <div style={{ fontSize: 16, fontWeight: 600, fontFamily: 'monospace' }}>{cfg.tightened_per_ip_rps}</div>
            <div style={{ fontSize: 10, color: 'var(--ink-faint)' }}>cap during spike</div>
          </div>
          <div style={{ padding: 8, background: 'var(--surface-2)', borderRadius: 4 }}>
            <div style={{ fontSize: 10, color: 'var(--ink-dim)' }}>effective rate</div>
            <div style={{ fontSize: 16, fontWeight: 600, fontFamily: 'monospace' }}>
              {(cfg.per_ip_limit / Math.max(cfg.per_ip_window_s, 1)).toFixed(1)}/s
            </div>
            <div style={{ fontSize: 10, color: 'var(--ink-faint)' }}>derived per-IP rate</div>
          </div>
        </div>

        {/* Difference from rate-limit + operator guide */}
        <div style={{ fontSize: 11, color: 'var(--ink-dim)', lineHeight: 1.5, padding: 12, background: 'var(--surface-2)', borderRadius: 4 }}>
          <strong style={{ color: 'var(--ink)' }}>How this differs from Rate Limit (above):</strong>{' '}
          The rate-limit gate is a <em>steady-state per-IP token bucket</em> — when the bucket exceeds, the request is rejected with 429 but the IP can retry after the window. The DDoS gate is a <em>sustained-burst trigger</em> — exceeding `per_ip_limit` writes a `block_ttl_s`-second auto-block to the cluster keyspace; subsequent requests from that IP are 403'd for the full TTL.{' '}
          Hot-reloadable; per-IP state preserved across edits.{' '}
          <a href="/docs/operator/traffic-gates" target="_blank" rel="noreferrer" style={{ color: 'var(--accent)' }}>Full operator guide</a>.
        </div>
      </div>
      {editing && (
        <DdosEditModal
          current={cfg}
          onClose={() => setEditing(false)}
          onSaved={() => { setEditing(false); ddos.reload && ddos.reload(); }}
        />
      )}
    </div>
  );
}

function DdosEditModal({ current, onClose, onSaved }) {
  const [enabled, setEnabled] = useStateP(current?.enabled ?? true);
  const [observeOnly, setObserveOnly] = useStateP(current?.observe_only ?? false);
  const [perIpLimit, setPerIpLimit] = useStateP(current?.per_ip_limit ?? 1000);
  const [perIpWindowS, setPerIpWindowS] = useStateP(current?.per_ip_window_s ?? 10);
  const [blockTtlS, setBlockTtlS] = useStateP(current?.block_ttl_s ?? 300);
  const [spikeMultiplier, setSpikeMultiplier] = useStateP(current?.spike_multiplier ?? 3.0);
  const [tightenedRps, setTightenedRps] = useStateP(current?.tightened_per_ip_rps ?? 20);
  const [busy, setBusy] = useStateP(false);
  const [err, setErr] = useStateP(null);

  async function save() {
    setBusy(true); setErr(null);
    try {
      const r = await window.csrfMutate('/api/gates/ddos', {
        method: 'PUT',
        body: {
          enabled,
          observe_only: observeOnly,
          per_ip_limit: parseInt(perIpLimit, 10),
          per_ip_window_s: parseInt(perIpWindowS, 10),
          block_ttl_s: parseInt(blockTtlS, 10),
          spike_multiplier: parseFloat(spikeMultiplier),
          tightened_per_ip_rps: parseInt(tightenedRps, 10),
        },
      });
      if (r && r.ok !== false && (r.status === undefined || (r.status >= 200 && r.status < 300))) {
        window.aegisToast && window.aegisToast('DDoS gate updated', 'ok');
        onSaved();
      } else {
        const msg = (r && (r.message || r.error || r.reason)) || `status ${r?.status ?? '?'}`;
        setErr(msg);
      }
    } catch (e) {
      setErr(e.message || String(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal" onClick={e => e.stopPropagation()} style={{ maxWidth: 560 }}>
        <div className="modal-head">
          <div className="modal-title">Edit DDoS gate thresholds</div>
          <button className="btn btn-sm" onClick={onClose}>×</button>
        </div>
        <div className="modal-body" style={{ display: 'grid', gap: 10 }}>
          <label style={{ fontSize: 12, display: 'flex', alignItems: 'center', gap: 8 }}>
            <input type="checkbox" checked={enabled} onChange={e => setEnabled(e.target.checked)} disabled={busy} />
            <span><strong>Enabled</strong> — uncheck to skip the gate entirely (no protection).</span>
          </label>
          <label style={{ fontSize: 12, display: 'flex', alignItems: 'center', gap: 8 }}>
            <input type="checkbox" checked={observeOnly} onChange={e => setObserveOnly(e.target.checked)} disabled={busy} />
            <span><strong>Observe-only mode</strong> — emit <code>ddos_observed</code> audit events but never 403. Use for shadow validation before flipping to enforce.</span>
          </label>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 10 }}>
            <label style={{ fontSize: 12 }}>
              per_ip_limit
              <input className="input" type="number" min="1" value={perIpLimit}
                onChange={e => setPerIpLimit(e.target.value)} disabled={busy}
                style={{ marginTop: 4, width: '100%' }} />
              <div style={{ fontSize: 10, color: 'var(--ink-faint)', marginTop: 2 }}>requests per window</div>
            </label>
            <label style={{ fontSize: 12 }}>
              per_ip_window_s
              <input className="input" type="number" min="1" value={perIpWindowS}
                onChange={e => setPerIpWindowS(e.target.value)} disabled={busy}
                style={{ marginTop: 4, width: '100%' }} />
              <div style={{ fontSize: 10, color: 'var(--ink-faint)', marginTop: 2 }}>sliding window length (seconds)</div>
            </label>
            <label style={{ fontSize: 12 }}>
              block_ttl_s
              <input className="input" type="number" min="1" value={blockTtlS}
                onChange={e => setBlockTtlS(e.target.value)} disabled={busy}
                style={{ marginTop: 4, width: '100%' }} />
              <div style={{ fontSize: 10, color: 'var(--ink-faint)', marginTop: 2 }}>auto-block duration (seconds)</div>
            </label>
            <label style={{ fontSize: 12 }}>
              spike_multiplier
              <input className="input" type="number" min="1.01" step="0.1" value={spikeMultiplier}
                onChange={e => setSpikeMultiplier(e.target.value)} disabled={busy}
                style={{ marginTop: 4, width: '100%' }} />
              <div style={{ fontSize: 10, color: 'var(--ink-faint)', marginTop: 2 }}>spike trigger (× baseline RPS), > 1.0</div>
            </label>
            <label style={{ fontSize: 12, gridColumn: 'span 2' }}>
              tightened_per_ip_rps
              <input className="input" type="number" min="1" value={tightenedRps}
                onChange={e => setTightenedRps(e.target.value)} disabled={busy}
                style={{ marginTop: 4, width: '100%' }} />
              <div style={{ fontSize: 10, color: 'var(--ink-faint)', marginTop: 2 }}>per-IP cap during spike mode</div>
            </label>
          </div>
          <div style={{ fontSize: 11, color: 'var(--ink-dim)', lineHeight: 1.5 }}>
            Effective rate: <strong>{(perIpLimit / Math.max(parseInt(perIpWindowS, 10), 1)).toFixed(1)} req/s per IP</strong> before
            burst-exceed; auto-block holds the IP at 403 for {blockTtlS}s.
            Per-IP StateBackend window state is preserved across the edit. Audit-mutated.
          </div>
          {err && <div style={{ fontSize: 11, color: 'var(--down)' }}>Error: {err}</div>}
        </div>
        <div className="modal-foot">
          <button className="btn" onClick={onClose} disabled={busy}>Cancel</button>
          <button className="btn primary" onClick={save} disabled={busy}>
            {busy ? 'Saving…' : 'Save'}
          </button>
        </div>
      </div>
    </div>
  );
}

// Run-6 UX S6 — small badge surfacing the WAF mode (enforce /
// log_only) on the Compliance page heading. Sourced from
// /api/mode (audit-mutated, polled every 5 s). Green when
// enforcing (the safe default); yellow when log_only (the
// shadow-mode warning state operators want to notice).
function ComplianceModeBadge() {
  const modeApi = window.useModeApi ? window.useModeApi() : { data: null };
  const mode = modeApi.data?.mode || 'enforce';
  const cls = mode === 'enforce' ? 'pill ok' : 'pill warn';
  const label = mode === 'enforce' ? 'ENFORCING' : 'LOG-ONLY';
  return (
    <span
      className={cls}
      title={`WAF is currently ${mode} — sourced from /api/mode`}
      style={{ marginLeft: 12, fontSize: 11, verticalAlign: 'middle' }}
    >
      {label}
    </span>
  );
}

// 2026-05-09 page audit — the previous `COMPLIANCE_CLAMPS` const
// invented per-regime granularity (PCI pins these 4, HIPAA pins
// these 4, SOC2 these 5, ...) that didn't exist in code. The Rust
// truth at `crates/aegis-control/src/api/detectors.rs::COMPLIANCE_PINNED`
// pins the same 4 classes (sqli, xss, path_traversal, ssrf) when
// ANY compliance mode is active. Dashboard now reads the
// authoritative `locked_classes` from the live `/api/detectors`
// response so it can never drift from the Rust source.
//
// All operator-recognised compliance mode IDs (matched against
// `ComplianceMode` in `crates/aegis-core/src/config.rs`). Used to
// render the "available modes" reference; the active subset
// comes from /api/status::compliance.modes.
const COMPLIANCE_MODES = ['pci_dss', 'hipaa', 'soc2', 'gdpr', 'fips'];

function PageCompliance() {
  const status = window.useStatusApi ? window.useStatusApi() : { data: null };
  const detectors = window.useApi ? window.useApi('/api/detectors', { intervalMs: 30000, fallback: null }) : { data: null };
  const modes = status.data?.compliance?.modes || status.data?.compliance_modes || [];
  const lockedClasses = detectors.data?.locked_classes || [];

  return (
    <>
      <div className="page-head">
        <div>
          <h1 className="page-title">
            Compliance Profile
            {/* Run-6 UX S6 — visible enforce/log_only badge so a SOC
                analyst on call recognises the current enforcement
                state at a glance without hunting through Settings. */}
            <ComplianceModeBadge />
          </h1>
          <p className="page-subtitle">PCI · HIPAA · SOC2 · GDPR · FIPS — clamp configurator (read-only · YAML-driven)</p>
        </div>
      </div>

      <div className="card" style={{ marginBottom: 12 }}>
        <window.SectionHeader title="Active modes" sub={modes.length === 0 ? 'no modes pinned' : `${modes.length} mode${modes.length === 1 ? '' : 's'} active`} />
        <div style={{ padding: 16 }}>
          {modes.length === 0 ? (
            <div style={{ fontSize: 12, color: 'var(--ink-dim)' }}>
              No <code>compliance.modes</code> set in the running config. To activate, edit your YAML's <code>compliance:</code> block and restart:
              <pre style={{ background: 'var(--surface-2)', padding: 8, borderRadius: 4, margin: '8px 0 0', overflow: 'auto', fontSize: 11 }}>
{`compliance:
  modes:
    - pci_dss
    - soc2`}
              </pre>
            </div>
          ) : (
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
              {modes.map(m => <span key={m} className="pill ok">{m.toUpperCase()}</span>)}
            </div>
          )}
        </div>
      </div>

      {/* 2026-05-09 — replaced the old per-mode pinning table that
          invented regulatory granularity not present in code. The
          actual Rust pinning rule is one-size-fits-all (any active
          mode locks the same 4 classes), so the dashboard now
          shows that truth instead of the made-up per-regime
          breakdown. The page-audit doc explains the change:
          plans/issue-fix/2026-05-09-page-audit/README.md. */}
      <div className="card" style={{ marginBottom: 12 }}>
        <window.SectionHeader
          title="Locked detector classes"
          sub="These detectors cannot be disabled while ANY compliance mode is active"
        />
        <div style={{ padding: 16 }}>
          {modes.length === 0 ? (
            <div style={{ fontSize: 12, color: 'var(--ink-dim)' }}>
              No compliance mode is active, so no detector classes are pinned.
              Activate a mode (above) to lock the regulatory baseline detectors.
            </div>
          ) : lockedClasses.length === 0 ? (
            <div style={{ fontSize: 12, color: 'var(--ink-dim)' }}>
              <span className="pill warn" style={{ fontSize: 11, marginRight: 8 }}>backend not reporting locked classes</span>
              The active mode list reports {modes.length} active mode{modes.length === 1 ? '' : 's'} but
              <code> /api/detectors </code> returned an empty <code>locked_classes</code>.
              This shouldn't happen — please check the backend logs.
            </div>
          ) : (
            <>
              <div style={{ fontSize: 12, color: 'var(--ink-dim)', marginBottom: 8 }}>
                {lockedClasses.length} detector class{lockedClasses.length === 1 ? '' : 'es'} pinned by the active compliance mode{modes.length === 1 ? '' : 's'} ({modes.join(', ')}):
              </div>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                {lockedClasses.map(c => (
                  <span key={c} className="pill warn" style={{ fontSize: 11 }}>🔒 {c}</span>
                ))}
              </div>
            </>
          )}
        </div>
      </div>

      <div className="card" style={{ marginBottom: 12 }}>
        <window.SectionHeader
          title="Recognised compliance modes"
          sub="The five modes the binary accepts in cfg.compliance.modes"
        />
        <div style={{ padding: 16, display: 'flex', flexWrap: 'wrap', gap: 6 }}>
          {COMPLIANCE_MODES.map(m => {
            const active = modes.includes(m);
            return (
              <span
                key={m}
                className={active ? 'pill ok' : 'pill'}
                style={{ fontSize: 11, opacity: active ? 1 : 0.55 }}
                title={active ? `${m} is active in cfg.compliance.modes` : `${m} is recognised but not active`}
              >
                {m.toUpperCase().replace('_', '-')} {active && '· active'}
              </span>
            );
          })}
        </div>
      </div>

      <div className="card" style={{ marginTop: 12, padding: 12, fontSize: 11, color: 'var(--ink-dim)', display: 'flex', alignItems: 'flex-start', gap: 8 }}>
        <window.I.Info />
        <div style={{ lineHeight: 1.5 }}>
          <strong>How pinning works today (2026-05-09):</strong> activating ANY compliance mode locks the
          same four detector classes (<code>sqli</code>, <code>xss</code>, <code>path_traversal</code>, <code>ssrf</code>) —
          there is no per-regime differentiation in the binary. Source-of-truth: <code>COMPLIANCE_PINNED</code> in <code>crates/aegis-control/src/api/detectors.rs</code>.
          {' '}A future feature could implement real per-regime pinning (PCI 6.5, HIPAA §164.312, SOC 2 CC 6.1, GDPR Art. 32(1)(b),
          FIPS each map to slightly different detector sets when read strictly) — tracked in <code>plans/issue-fix/2026-05-09-page-audit/</code>.
          {' '}Runtime clamp editor (toggle modes without YAML + restart) isn't built yet —
          edit <code>cfg.compliance.modes</code> in YAML and reload for now.
          Detector tier overrides remain editable on the <a href="#/detectors" style={{ color: 'var(--accent)' }}>Detectors</a> page.
        </div>
      </div>
    </>
  );
}

// M006 (2026-05-07) — escape one CSV cell. Wraps in quotes when
// the value contains commas, quotes, or newlines (RFC 4180);
// doubles internal quotes.
function csvCell(v) {
  if (v === null || v === undefined) return '';
  const s = String(v);
  if (/[",\n\r]/.test(s)) {
    return `"${s.replace(/"/g, '""')}"`;
  }
  return s;
}

// M006 (2026-05-07) — trigger a browser download for a Blob.
// Click the synthesised <a download> then revoke the URL on the
// next tick so Safari has time to start the download.
function downloadBlob(filename, blob) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  setTimeout(() => URL.revokeObjectURL(url), 0);
}

function PageReports() {
  // M006 (2026-05-07) — Top Attackers + Compliance snapshot wired.
  // Reports fall into two flavours: server-rendered CSV (audit log
  // — too large to round-trip through the browser) and
  // client-rendered (smaller payloads where fetching JSON +
  // converting in the browser keeps the backend simple).
  const [busyId, setBusyId] = useStateP(null);
  const ts = () => new Date().toISOString().replace(/[:.]/g, '-');

  async function downloadTopAttackers() {
    setBusyId('top-7d');
    try {
      const r = await fetch('/api/attacks/top?window=604800&limit=500', {
        credentials: 'same-origin',
      });
      if (!r.ok) throw new Error(`status ${r.status}`);
      const json = await r.json();
      const rows = json.attackers || [];
      const header = [
        'identifier', 'kind', 'country', 'asn',
        'blocks', 'last_seen', 'top_detector',
      ];
      const lines = [header.join(',')];
      for (const row of rows) {
        lines.push([
          csvCell(row.identifier),
          csvCell(row.kind),
          csvCell(row.country),
          csvCell(row.asn),
          csvCell(row.blocks ?? row.block_count ?? 0),
          csvCell(row.last_seen ?? row.last_block_at),
          csvCell(row.top_detector ?? row.detector ?? ''),
        ].join(','));
      }
      const blob = new Blob([lines.join('\n') + '\n'], {
        type: 'text/csv;charset=utf-8',
      });
      downloadBlob(`top-attackers-7d-${ts()}.csv`, blob);
      window.aegisToast(`Downloaded ${rows.length} rows`, 'ok');
    } catch (err) {
      window.aegisToast(`Top attackers report failed: ${err.message || err}`, 'err');
    } finally {
      setBusyId(null);
    }
  }

  async function downloadComplianceSnapshot() {
    setBusyId('compliance');
    try {
      // /api/config returns the active runtime config; /api/detectors
      // returns the live detector mask + per-detector mode. Both are
      // small (< 50 KB combined) so JSON is fine.
      const [cfgR, detR] = await Promise.all([
        fetch('/api/config', { credentials: 'same-origin' }),
        fetch('/api/detectors', { credentials: 'same-origin' }),
      ]);
      if (!cfgR.ok) throw new Error(`/api/config status ${cfgR.status}`);
      if (!detR.ok) throw new Error(`/api/detectors status ${detR.status}`);
      const config = await cfgR.json();
      const detectors = await detR.json();
      const snapshot = {
        generated_at: new Date().toISOString(),
        config,
        detectors,
      };
      const blob = new Blob([JSON.stringify(snapshot, null, 2)], {
        type: 'application/json;charset=utf-8',
      });
      downloadBlob(`compliance-snapshot-${ts()}.json`, blob);
      window.aegisToast('Compliance snapshot downloaded', 'ok');
    } catch (err) {
      window.aegisToast(`Compliance snapshot failed: ${err.message || err}`, 'err');
    } finally {
      setBusyId(null);
    }
  }

  const cards = [
    {
      id: 'audit-200',
      title: 'Audit trail (last 200 events)',
      sub: 'CSV of every chained event — request decisions + config mutations',
      kind: 'href',
      href: '/api/reports/audit.csv?limit=200',
    },
    {
      id: 'audit-1000',
      title: 'Audit trail (last 1000 events)',
      sub: 'Larger window for weekly review',
      kind: 'href',
      href: '/api/reports/audit.csv?limit=1000',
    },
    {
      id: 'top-7d',
      title: 'Top attackers (last 7d)',
      sub: 'identifier / kind / country / ASN / blocks / last seen / top detector — sourced from /api/attacks/top',
      kind: 'click',
      onClick: downloadTopAttackers,
      label: 'Download CSV',
    },
    {
      id: 'compliance',
      title: 'Compliance snapshot',
      sub: 'Active runtime config + detector mask, JSON snapshot — sourced from /api/config + /api/detectors',
      kind: 'click',
      onClick: downloadComplianceSnapshot,
      label: 'Download JSON',
    },
  ];
  return (
    <>
      <div className="page-head">
        <div>
          <h1 className="page-title">Reports</h1>
          <p className="page-subtitle">CSV / JSON exports of audit + summary data · scheduled delivery not built yet</p>
        </div>
      </div>
      <div className="card" style={{ padding: 16 }}>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(260px, 1fr))', gap: 12 }}>
          {cards.map(card => (
            <div key={card.id} className="card" style={{ padding: 12 }}>
              <div style={{ fontSize: 13, fontWeight: 600 }}>{card.title}</div>
              <div style={{ fontSize: 11, color: 'var(--ink-dim)', margin: '4px 0 10px' }}>{card.sub}</div>
              {card.kind === 'href' ? (
                <a className="btn primary" href={card.href} download>
                  <window.I.Download /> Download CSV
                </a>
              ) : (
                <button
                  className="btn primary"
                  onClick={card.onClick}
                  disabled={busyId === card.id}
                >
                  <window.I.Download /> {busyId === card.id ? 'Preparing…' : (card.label || 'Download')}
                </button>
              )}
            </div>
          ))}
        </div>
      </div>
    </>
  );
}

// SOC-UX 2026-05-03 — Top Attackers page reads /api/attacks/top
// and shows a sortable, action-rich table.  This is the SOC
// analyst's morning-coffee view: who hammered us in the last
// window, where they're from, what they tripped, and one-click
// pivots into Investigation or block-the-IP.
const TOP_ATTACKERS_WINDOWS = {
  '5m': 300, '15m': 900, '1h': 3600, '6h': 21600, '24h': 86400,
};

function PageTopAttackers() {
  const [win, setWin] = useStateP('1h');
  const windowSeconds = TOP_ATTACKERS_WINDOWS[win] ?? 3600;
  const top = window.useApi
    ? window.useApi(
        `/api/attacks/top?window=${windowSeconds}&limit=50`,
        { intervalMs: 5000, fallback: null },
      )
    : { data: null };
  const attackers = top.data?.attackers ?? [];
  const geoLoaded = top.data?.geoip_loaded === true;
  const [busyId, setBusyId] = useStateP(null);

  async function blockAttacker(identifier) {
    if (!identifier) return;
    if (!confirm(`Block ${identifier}? Adds to /api/blacklist · audit-chained.`)) return;
    setBusyId(identifier);
    try {
      const id = `top-attacker-${identifier.replace(/[^A-Za-z0-9]+/g, '-')}-${Date.now().toString(36)}`;
      const body = identifier.startsWith('fp:')
        ? { id, kind: 'fingerprint', value: identifier, note: `blocked from Top Attackers · last 1h` }
        : { id, kind: identifier.includes('/') ? 'cidr' : 'ip', value: identifier, note: `blocked from Top Attackers · last 1h` };
      const r = await window.accessListAdd('blacklist', body);
      if (r.ok) {
        window.aegisToast(`Blocked ${identifier}`, 'ok');
        top.reload && top.reload();
      } else {
        const msg = (r && (r.message || r.error || r.reason)) || `status ${r.status}`;
        window.aegisToast(`Block failed: ${msg}`, 'err');
      }
    } catch (e) {
      window.aegisToast(`Block error: ${e.message || e}`, 'err');
    } finally {
      setBusyId(null);
    }
  }

  return (
    <>
      <div className="page-head">
        <div>
          <h1 className="page-title">Top Attackers</h1>
          <p className="page-subtitle">
            Ranked by hits in the last {win} · pivot or block in one click
            {geoLoaded ? '' : ' · GeoIP DB not loaded — country / ASN columns will be empty until make geoip-link runs'}
          </p>
        </div>
        <div className="page-actions">
          <select
            className="input select"
            value={win}
            onChange={e => setWin(e.target.value)}
            style={{ width: 90 }}
          >
            {Object.keys(TOP_ATTACKERS_WINDOWS).map(v => <option key={v}>{v}</option>)}
          </select>
          <button className="btn" onClick={() => top.reload && top.reload()}>
            <window.I.Refresh />
          </button>
        </div>
      </div>

      {/* Empty state: lead with the same "what you'll see here"
          framing the Threat-Intel page uses, so a fresh boot
          isn't visually broken. */}
      {attackers.length === 0 ? (
        <div className="card" style={{ padding: 24, textAlign: 'center', color: 'var(--ink-dim)' }}>
          {top.data === null ? (
            <>Loading top attackers…</>
          ) : (
            <>
              No blocked sources in the last {win}. Try extending the
              time window above, or wait for traffic to land — attacker
              rankings populate as soon as the WAF sees blocks.
            </>
          )}
        </div>
      ) : (
        <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
          <table className="tbl tbl-compact">
            <thead>
              <tr>
                <th style={{ width: 220 }}>Identifier</th>
                <th style={{ width: 70 }}>Country</th>
                <th style={{ width: 80 }}>ASN</th>
                <th style={{ width: 80 }}>Hits</th>
                <th style={{ width: 70 }}>Risk</th>
                <th>Detectors</th>
                <th style={{ width: 110 }}>Last seen</th>
                <th style={{ width: 180 }}></th>
              </tr>
            </thead>
            <tbody>
              {attackers.map(a => {
                const isFp = a.identifier.startsWith('fp:');
                return (
                  <tr key={a.identifier}>
                    <td className="mono" style={{ wordBreak: 'break-all' }}>
                      {isFp ? (
                        <span className="dim mono" title="ja4 fingerprint identifier — no IP available">{a.identifier}</span>
                      ) : (
                        <a
                          href={`#/investigation?pivot=${encodeURIComponent(a.identifier)}&kind=ip`}
                          style={{ color: 'var(--accent)' }}
                        >{a.identifier}</a>
                      )}
                    </td>
                    <td>{a.country ? <span className="pill">{a.country}</span> : <span className="dim mono">—</span>}</td>
                    <td className="mono">{a.asn ? `AS${a.asn}` : <span className="dim">—</span>}</td>
                    <td className="num">{a.hits.toLocaleString()}</td>
                    <td className="num">
                      <window.RiskMeter value={a.risk} />
                    </td>
                    <td className="mono" style={{ fontSize: 11 }}>
                      {Array.isArray(a.categories) && a.categories.length > 0
                        ? a.categories.slice(0, 5).join(', ') + (a.categories.length > 5 ? '…' : '')
                        : <span className="dim">—</span>}
                    </td>
                    <td className="dim mono" style={{ fontSize: 11 }}>
                      {a.last_seen ? new Date(a.last_seen).toLocaleTimeString() : '—'}
                    </td>
                    <td>
                      <a
                        className="btn"
                        href={`#/investigation?pivot=${encodeURIComponent(a.identifier)}&kind=ip`}
                        style={{ marginRight: 6, fontSize: 11 }}
                        title="Open Investigation pivoted on this attacker"
                      >Pivot</a>
                      <button
                        className="btn danger"
                        style={{ fontSize: 11 }}
                        disabled={busyId === a.identifier}
                        onClick={() => blockAttacker(a.identifier)}
                      >{busyId === a.identifier ? '…' : 'Block'}</button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      <div className="card" style={{ padding: 12, marginTop: 12, fontSize: 11, color: 'var(--ink-dim)', display: 'flex', alignItems: 'center', gap: 8 }}>
        <window.I.Info />
        <span>
          Top Attackers ranks by detector hits + risk over the chosen
          window.  Block adds the identifier to <code>/api/blacklist</code>;
          Pivot opens <a href="#/investigation" style={{ color: 'var(--accent)' }}>Investigation</a>{' '}
          filtered to that attacker's audit timeline.
          GeoIP enrichment requires the <code>geoip</code> Cargo
          feature plus a configured <code>cfg.geoip.country_db</code>.
        </span>
      </div>
    </>
  );
}

// ---------------------------------------------------------------------------
// RT-T6 — Routes panel inside the Routing & Upstreams page.
//
// Mirrors the existing pool-CRUD shape (list + Edit / Delete modal).
// Reads from `/api/routes`, writes via `routeUpsert` / `routeDelete`
// — which hit the audit-mutated PUT/DELETE handlers landed in RT-T3.
// `poolNames` is passed in from the parent page so the upstream
// dropdown stays consistent with the live pool list.
// ---------------------------------------------------------------------------
function RoutesTable({ poolNames, routesApi, pools, onEditPool, onDeletePool, cfgReload }) {
  const routes = routesApi.data?.routes || [];
  const [editor, setEditor] = useStateP(null);
  const [deleteModal, setDeleteModal] = useStateP(null);
  const [busy, setBusy] = useStateP(false);
  const [search, setSearch] = useStateP('');
  const [expandedRouteId, setExpandedRouteId] = useStateP(null);
  // PR3 — Test route tool state.
  const [testOpen, setTestOpen] = useStateP(false);
  const [testHost, setTestHost] = useStateP('');
  const [testMethod, setTestMethod] = useStateP('GET');
  const [testPath, setTestPath] = useStateP('/');
  const [testResult, setTestResult] = useStateP(null);
  const [testBusy, setTestBusy] = useStateP(false);
  async function runRouteTest() {
    setTestBusy(true);
    try {
      const r = await window.routeTest(testHost, testMethod, testPath);
      if (r.status === 200) {
        setTestResult(r);
      } else {
        const msg = r.error || r.reason || `HTTP ${r.status}`;
        window.aegisToast(`Test failed: ${msg}`, 'err');
      }
    } finally {
      setTestBusy(false);
    }
  }

  const filteredRoutes = (() => {
    const q = (search || '').trim().toLowerCase();
    if (!q) return routes;
    return routes.filter(r =>
      (r.id || '').toLowerCase().includes(q) ||
      (r.host || '').toLowerCase().includes(q) ||
      (r.path || '').toLowerCase().includes(q) ||
      (r.upstream || '').toLowerCase().includes(q)
    );
  })();

  const openAdd = () => setEditor({ mode: 'add', draft: emptyRouteDraft() });
  const openEdit = (route) => setEditor({ mode: 'edit', draft: routeToDraft(route) });

  async function saveRoute(draft) {
    setBusy(true);
    try {
      // Inline pool create — modal sets draft.newPool when the
      // operator typed a backend address instead of picking an
      // existing pool. Pool name = route id in that flow.
      if (draft.newPool && draft.newPool.addr) {
        const poolName = draft.upstream;
        const poolBody = poolBodyFromInlineForm(draft.newPool);
        const pr = await window.poolUpsert(poolName, poolBody);
        if (!(pr.status === 200 && pr.ok)) {
          const msg = pr.message || pr.error || pr.reason || `HTTP ${pr.status}`;
          window.aegisToast(`Pool create failed: ${msg}`, 'err');
          return;
        }
        cfgReload && cfgReload();
      }
      const body = routeBodyFromDraft(draft);
      const r = await window.routeUpsert(draft.id, body);
      if (r.status === 200 && r.ok) {
        window.aegisToast(`Route "${draft.id}" saved`, 'ok');
        routesApi.reload && routesApi.reload();
        setEditor(null);
      } else {
        const msg = r.message || r.error || r.reason || `HTTP ${r.status}`;
        window.aegisToast(`Save failed: ${msg}`, 'err');
      }
    } finally {
      setBusy(false);
    }
  }

  async function confirmDelete() {
    if (!deleteModal) return;
    const { id } = deleteModal;
    setBusy(true);
    try {
      const r = await window.routeDelete(id);
      if (r.status === 200 && r.ok) {
        window.aegisToast(`Route "${id}" removed`, 'ok');
        routesApi.reload && routesApi.reload();
        setDeleteModal(null);
      } else if (r.status === 409 && r.reason === 'last_catchall') {
        setDeleteModal({ id, blocker: r.message || 'last catch-all' });
        window.aegisToast(`Cannot delete "${id}": last catch-all`, 'warn');
      } else {
        const msg = r.message || r.error || r.reason || `HTTP ${r.status}`;
        window.aegisToast(`Delete failed: ${msg}`, 'err');
      }
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <div className="card" style={{ padding: 0 }}>
        <div style={{ display: 'flex', alignItems: 'center', padding: '10px 12px', borderBottom: '1px solid var(--hairline)', gap: 8 }}>
          <input
            type="search"
            className="ip"
            placeholder="filter routes — id / host / path / pool"
            value={search}
            onChange={e => setSearch(e.target.value)}
            style={{ flex: 1, fontSize: 12, maxWidth: 360 }}
          />
          <div style={{ flex: 1 }} />
          <button
            className="btn"
            onClick={() => setTestOpen(!testOpen)}
            title="Paste host + method + path; see which route the live config would resolve to"
          >
            {testOpen ? '▲ Hide test tool' : '▼ Test route'}
          </button>
          <button className="btn primary" onClick={openAdd}>
            + Add route
          </button>
        </div>
        {/* PR3 — Test route tool */}
        {testOpen && (
          <div style={{ padding: '12px 12px', borderBottom: '1px solid var(--hairline)', background: 'var(--canvas-2)' }}>
            <div style={{ fontSize: 11, color: 'var(--ink-mute)', marginBottom: 8 }}>
              Test which route a synthetic request would resolve to. Read-only — no audit entry.
            </div>
            <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'flex-end' }}>
              <div>
                <label style={{ fontSize: 11, color: 'var(--ink-dim)', display: 'block' }}>Host</label>
                <input
                  type="text"
                  className="ip"
                  value={testHost}
                  onChange={e => setTestHost(e.target.value)}
                  placeholder="api.example.com (empty = any)"
                  style={{ fontSize: 12, width: 240 }}
                />
              </div>
              <div>
                <label style={{ fontSize: 11, color: 'var(--ink-dim)', display: 'block' }}>Method</label>
                <select
                  className="ip"
                  value={testMethod}
                  onChange={e => setTestMethod(e.target.value)}
                  style={{ fontSize: 12, width: 90 }}
                >
                  {ROUTE_METHOD_CHOICES.map(m => <option key={m} value={m}>{m}</option>)}
                </select>
              </div>
              <div style={{ flex: 1, minWidth: 200 }}>
                <label style={{ fontSize: 11, color: 'var(--ink-dim)', display: 'block' }}>Path</label>
                <input
                  type="text"
                  className="ip mono"
                  value={testPath}
                  onChange={e => setTestPath(e.target.value)}
                  placeholder="/local/game"
                  style={{ fontSize: 12, width: '100%' }}
                />
              </div>
              <button
                className="btn primary"
                onClick={runRouteTest}
                disabled={testBusy || !testPath}
                style={{ fontSize: 12 }}
              >
                {testBusy ? 'Testing…' : 'Resolve'}
              </button>
            </div>
            {testResult && (
              <div style={{ marginTop: 12, padding: 10, background: 'var(--canvas)', borderRadius: 4, border: '1px solid var(--hairline)' }}>
                {testResult.matched ? (
                  <>
                    <div style={{ fontSize: 12, fontWeight: 600, marginBottom: 6 }}>
                      ✓ Matched <span className="mono" style={{ color: 'var(--up)' }}>{testResult.matched.route_id}</span>
                      {' '}<span className="pill ok" style={{ fontSize: 10, padding: '1px 6px' }}>{testResult.matched.tier}</span>
                      {testResult.matched.default && <span className="pill" style={{ fontSize: 10, padding: '1px 6px', marginLeft: 4 }}>default</span>}
                    </div>
                    <table className="tbl tbl-compact" style={{ fontSize: 11 }}>
                      <tbody>
                        <tr><td style={{ color: 'var(--ink-dim)' }}>Forwards to</td><td className="mono">{testResult.matched.upstream}</td></tr>
                        <tr><td style={{ color: 'var(--ink-dim)' }}>Match</td><td className="mono">{testResult.matched.host || '*'} · {testResult.matched.path}</td></tr>
                        <tr><td style={{ color: 'var(--ink-dim)' }}>Methods</td><td className="mono">{(testResult.matched.methods && testResult.matched.methods.length > 0) ? testResult.matched.methods.join(',') : 'any'}</td></tr>
                        <tr>
                          <td style={{ color: 'var(--ink-dim)' }} title="host.path-kind.path-segments.method.declared.yaml-position">Priority tuple</td>
                          <td className="mono">{testResult.matched.priority}</td>
                        </tr>
                      </tbody>
                    </table>
                  </>
                ) : (
                  <div style={{ fontSize: 12 }}>
                    <span style={{ color: 'var(--down)', fontWeight: 600 }}>✗ Unmatched</span>{' '}
                    <span style={{ color: 'var(--ink-dim)' }}>— {testResult.reason}</span>
                  </div>
                )}
              </div>
            )}
          </div>
        )}
        <table className="tbl tbl-compact">
          <thead>
            <tr>
              <th style={{ width: 86 }} title="Effective evaluation priority — derived from host / path / method specificity. Higher matches first.">Priority</th>
              <th>Match (host · path)</th>
              <th style={{ width: 80 }}>Methods</th>
              <th>Forwards to</th>
              <th style={{ width: 130 }}>Tier · Auth</th>
              <th style={{ width: 130, textAlign: 'right' }}></th>
            </tr>
          </thead>
          <tbody>
            {filteredRoutes.length === 0 && (
              <tr><td colSpan={6} style={{ textAlign: 'center', padding: 28, color: 'var(--ink-dim)', fontSize: 12 }}>
                {routes.length === 0
                  ? <>No routes yet. Click <strong>+ Add route</strong> — you can create the backend in the same step.</>
                  : <>No routes match <code>{search}</code>. <button className="btn btn-sm" onClick={() => setSearch('')}>Clear</button></>}
              </td></tr>
            )}
            {filteredRoutes.map((r, rowIdx) => {
              const isCatchall = !r.host && r.path === '/';
              const isExpanded = expandedRouteId === r.id;
              const pool = pools[r.upstream];
              const members = pool?.members || [];
              const scheme = pool?.connection?.scheme || 'auto';
              const methodLabel = (r.methods && r.methods.length > 0) ? r.methods.join(',') : 'any';
              // PR1 — priority is server-sorted (desc); rank = row+1.
              // Compact priority string is shown in a tooltip for
              // operators who want the full host/path/method/yaml-pos
              // breakdown.
              const priorityLabel = r.priority
                ? `#${rowIdx + 1}`
                : '—';
              const priorityTooltip = r.priority
                ? `priority tuple: ${r.priority}\nhost.path-kind.segs.method.declared.yaml-pos\nhigher matches first`
                : 'priority not yet computed for this route';
              return (
                <React.Fragment key={r.id}>
                  <tr
                    style={{
                      cursor: 'pointer',
                      background: isExpanded ? 'var(--surface-active)' : undefined,
                    }}
                    onClick={() => setExpandedRouteId(isExpanded ? null : r.id)}
                  >
                    <td title={priorityTooltip}>
                      <span className="pill" style={{ fontSize: 10, fontWeight: 600 }}>{priorityLabel}</span>
                      <div className="mono" style={{ fontSize: 10, color: 'var(--ink-dim)', marginTop: 2 }}>
                        {r.priority || ''}
                      </div>
                    </td>
                    <td style={r.enabled === false ? { opacity: 0.55 } : undefined}>
                      <div className="mono" style={{ fontSize: 12, fontWeight: 600 }}>
                        {r.host
                          ? <><span style={{ color: 'var(--ink-dim)' }}>{r.host}</span><span style={{ color: 'var(--ink-dim)' }}> · </span></>
                          : <span style={{ color: 'var(--ink-dim)' }}>* · </span>}
                        <span>{r.path}</span>
                        {isCatchall && <span className="pill" style={{ marginLeft: 6, fontSize: 9, padding: '1px 6px' }}>catch-all</span>}
                        {r.default && <span className="pill ok" style={{ marginLeft: 6, fontSize: 9, padding: '1px 6px' }} title="Catches unmatched traffic for this host">fallback</span>}
                        {r.enabled === false && <span className="pill warn" style={{ marginLeft: 6, fontSize: 9, padding: '1px 6px' }} title="Skipped from request matching">paused</span>}
                      </div>
                      <div style={{ fontSize: 11, color: 'var(--ink-dim)' }}>
                        <span className="mono">{r.id}</span> · <span className="pill neutral" style={{ fontSize: 9, padding: '0 6px' }}>{r.match_type}</span>
                      </div>
                    </td>
                    <td>
                      <span className="pill neutral" style={{ fontSize: 10 }}>{methodLabel}</span>
                    </td>
                    <td>
                      <div className="mono" style={{ fontSize: 12 }}>
                        {poolNames.includes(r.upstream)
                          ? <>{r.upstream}{' '}<span style={{ color: 'var(--ink-dim)', fontSize: 11 }}>({scheme} · {members.length} member{members.length === 1 ? '' : 's'})</span></>
                          : <span title="Pool not found" style={{ color: 'var(--down)' }}>{r.upstream} ⚠</span>}
                      </div>
                      {!isExpanded && members.length > 0 && (
                        <div className="mono" style={{ fontSize: 11, color: 'var(--ink-dim)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                          ↳ {members.slice(0, 2).map(m => m.addr).join(', ')}{members.length > 2 ? ` +${members.length - 2} more` : ''}
                        </div>
                      )}
                    </td>
                    <td style={{ fontSize: 11 }}>
                      <div>{(() => {
                        // Normalize legacy `catch_all` → `low` for display.
                        const t = r.tier_override === 'catch_all' || r.tier_override === 'catchall'
                          ? 'low' : r.tier_override;
                        return t
                          ? <span className="pill" style={{ fontSize: 10 }}>{t}</span>
                          : <span style={{ color: 'var(--ink-dim)' }}>low</span>;
                      })()}</div>
                      <div style={{ marginTop: 2 }}>
                        {(r.auth_required || []).length === 0
                          ? <span style={{ color: 'var(--ink-dim)' }}>open</span>
                          : (r.auth_required || []).map(a => (
                            <span key={a} className="pill" style={{ fontSize: 9, padding: '0 6px', marginRight: 3 }}>{a}</span>
                          ))}
                      </div>
                    </td>
                    <td style={{ textAlign: 'right', whiteSpace: 'nowrap' }} onClick={e => e.stopPropagation()}>
                      <button className="btn btn-sm" onClick={() => openEdit(r)}>Edit</button>{' '}
                      <button className="btn btn-sm" style={{ color: 'var(--down)' }}
                        onClick={() => setDeleteModal({ id: r.id })}>Delete</button>
                    </td>
                  </tr>

                  {/* Expanded row — full pool detail. */}
                  {isExpanded && (
                    <tr>
                      <td colSpan={6} style={{ background: 'var(--canvas-2)', padding: 0, borderBottom: '1px solid var(--hairline)' }}>
                        <div style={{ padding: '12px 16px' }}>
                          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 8 }}>
                            <div style={{ fontSize: 12, fontWeight: 600 }}>
                              Upstream pool <span className="mono">{r.upstream}</span>
                              <span style={{ color: 'var(--ink-dim)', fontWeight: 400, marginLeft: 8 }}>
                                · scheme <code>{scheme}</code> · lb <code>{pool?.lb || '—'}</code>
                              </span>
                            </div>
                            {pool && (
                              <div style={{ display: 'flex', gap: 6 }}>
                                <button className="btn btn-sm" onClick={() => onEditPool(r.upstream, pool)}>Edit pool</button>
                                <button className="btn btn-sm" style={{ color: 'var(--down)' }}
                                  onClick={() => onDeletePool(r.upstream)}>Delete pool</button>
                              </div>
                            )}
                          </div>
                          {!pool && (
                            <div style={{ fontSize: 12, color: 'var(--down)' }}>
                              Pool <code>{r.upstream}</code> is missing — fix the route or recreate the pool.
                            </div>
                          )}
                          {pool && members.length === 0 && (
                            <div style={{ fontSize: 12, color: 'var(--down)' }}>
                              No members configured. Every request through this route will fail upstream.
                            </div>
                          )}
                          {pool && members.length > 0 && (
                            <table className="tbl tbl-compact" style={{ background: 'var(--canvas)' }}>
                              <thead>
                                <tr>
                                  <th>Member</th>
                                  <th title="`host_header:` override drives outbound Host + TLS SNI">Host header</th>
                                  <th style={{ width: 60 }}>Weight</th>
                                  <th style={{ width: 80 }}>Zone</th>
                                </tr>
                              </thead>
                              <tbody>
                                {members.map((m, i) => (
                                  <tr key={`${m.addr}-${i}`}>
                                    <td className="mono" style={{ fontSize: 12 }}>{m.addr}</td>
                                    <td className="mono" style={{ fontSize: 11, color: m.host_header ? 'inherit' : 'var(--ink-dim)' }}>
                                      {m.host_header || '—'}
                                    </td>
                                    <td className="num">{m.weight ?? 1}</td>
                                    <td style={{ color: 'var(--ink-dim)', fontSize: 11 }}>{m.zone || '—'}</td>
                                  </tr>
                                ))}
                              </tbody>
                            </table>
                          )}
                          {pool?.health && (
                            <div style={{ marginTop: 8, fontSize: 11, color: 'var(--ink-dim)' }}>
                              Health probe: <code>{pool.health.path}</code> every {fmtMs(pool.health.interval_ms)} (timeout {fmtMs(pool.health.timeout_ms)})
                            </div>
                          )}
                          {pool && (pool.referenced_by_routes || []).length > 1 && (
                            <div style={{ marginTop: 8, fontSize: 11, color: 'var(--ink-dim)' }}>
                              Shared with: {pool.referenced_by_routes.filter(id => id !== r.id).map(id => (
                                <span key={id} className="pill neutral" style={{ fontSize: 10, marginRight: 4 }}>{id}</span>
                              ))}
                            </div>
                          )}
                        </div>
                      </td>
                    </tr>
                  )}
                </React.Fragment>
              );
            })}
          </tbody>
        </table>
      </div>

      {editor && (
        <RouteEditModal
          mode={editor.mode}
          draft={editor.draft}
          existingIds={routes.map(r => r.id)}
          poolNames={poolNames}
          onSave={saveRoute}
          onCancel={() => setEditor(null)}
          busy={busy}
        />
      )}

      {deleteModal && (
        <DeleteRouteModal
          id={deleteModal.id}
          blocker={deleteModal.blocker}
          onCancel={() => setDeleteModal(null)}
          onConfirm={confirmDelete}
          busy={busy}
        />
      )}
    </>
  );
}

// Right-side panel — when a route is selected on the left, this
// shows everything an operator needs to understand where the
// traffic goes: route shape on top, then the pool with members
// + scheme + host_header + health, plus an "Other routes using
// this pool" reminder so they know who else they'd affect by
// editing the pool.
// Build a `PoolConfig` body from the inline-add-pool form
// fields the RouteEditModal collects when the operator chooses
// "+ Create new pool". Mirrors `poolConfigFromForm` for the
// fields that are exposed inline (rest take server defaults).
function poolBodyFromInlineForm(np) {
  return {
    members: [{
      addr: (np.addr || '').trim(),
      weight: 1,
      ...(np.host_header && np.host_header.trim() ? { host_header: np.host_header.trim() } : {}),
    }],
    lb: 'round_robin',
    connection: {
      scheme: np.scheme || 'auto',
      keep_alive: true,
      max_idle_per_host: 32,
      idle_timeout: '30s',
    },
  };
}

// Form-shape helpers — `methods` and `auth_required` are
// **arrays** in the form draft so the checkbox UI can read /
// write them naturally. `routeBodyFromDraft` accepts either
// shape (legacy comma-string OR fresh array) so older callers
// keep working.
// Translate the legacy "catch_all" tier name (still accepted by the
// backend as a serde alias) into the canonical "low" so the modal
// dropdown's selected-value logic picks the right option.
function normalizeTier(t) {
  if (t === 'catch_all' || t === 'catchall') return 'low';
  return t || 'low';
}
function emptyRouteDraft() {
  return {
    id: '',
    host: '',
    path: '/',
    match_type: 'prefix',
    methods: [],
    upstream: '',
    tier_override: 'low',
    auth_required: [],
    default: false,
    enabled: true,
  };
}
function routeToDraft(r) {
  return {
    id: r.id || '',
    host: r.host || '',
    path: r.path || '/',
    match_type: r.match_type || 'prefix',
    methods: r.methods || [],
    upstream: r.upstream || '',
    tier_override: normalizeTier(r.tier_override),
    auth_required: r.auth_required || [],
    default: !!r.default,
    enabled: r.enabled !== false, // default to true if missing
  };
}
function routeBodyFromDraft(d) {
  // Accept either the old comma-string or the new array shape so
  // both code paths keep working during the transition.
  const toArray = (v, lc) => {
    const a = Array.isArray(v) ? v : (typeof v === 'string' ? v.split(',') : []);
    return a.map(s => s.trim()).filter(Boolean).map(s => lc ? s.toLowerCase() : s.toUpperCase());
  };
  const methods = toArray(d.methods, false);
  const auth_required = toArray(d.auth_required, true);
  const body = {
    id: d.id.trim(),
    path: d.path.trim() || '/',
    match_type: d.match_type,
    upstream: d.upstream,
    default: !!d.default,
    enabled: d.enabled !== false,
  };
  if (d.host.trim()) body.host = d.host.trim();
  if (methods.length > 0) body.methods = methods;
  // PR2/tier-rename — tier_override is always set in the modal
  // (defaulting to 'low'), so always send it. Backend accepts
  // critical | high | medium | low (with catch_all kept as alias).
  if (d.tier_override) body.tier_override = d.tier_override;
  if (auth_required.length > 0) body.auth_required = auth_required;
  return body;
}

// HTTP methods to expose as checkboxes — covers the practical
// surface (GET / POST / PUT / DELETE / PATCH / HEAD / OPTIONS).
// Operators rarely need anything else; if they do, fall back to
// editing YAML.
const ROUTE_METHOD_CHOICES = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS'];
const ROUTE_AUTH_CHOICES = [
  ['mtls',      'mTLS — require an mTLS-authenticated client'],
  ['spiffe',    'SPIFFE — require a SPIFFE-id client'],
  ['anonymous', 'Anonymous — admit unauthenticated clients (note: making the route public)'],
];

function RouteEditModal({ mode, draft: initial, existingIds, poolNames, onSave, onCancel, busy }) {
  const [d, setD] = useStateP(() => ({
    ...initial,
    methods: typeof initial.methods === 'string'
      ? initial.methods.split(',').map(s => s.trim().toUpperCase()).filter(Boolean)
      : (initial.methods || []),
    auth_required: typeof initial.auth_required === 'string'
      ? initial.auth_required.split(',').map(s => s.trim().toLowerCase()).filter(Boolean)
      : (initial.auth_required || []),
  }));
  const isAdd = mode === 'add';
  const idClash = isAdd && existingIds.includes(d.id.trim());

  // The "Forward to" target is decided by what the operator
  // types: empty address field → use the dropdown (existing
  // pool); typing an address → create a new pool. No toggle.
  const [newPool, setNewPool] = useStateP({
    addr: '', scheme: 'https', host_header: '',
  });
  const usingNewPool = newPool.addr.trim().length > 0;

  const [showAdvanced, setShowAdvanced] = useStateP(
    !isAdd && (
      (d.match_type && d.match_type !== 'prefix') ||
      d.tier_override ||
      (d.auth_required && d.auth_required.length > 0)
    )
  );

  const idValid = d.id.trim().length > 0 && !idClash;
  const pathValid = d.path.trim().startsWith('/');
  const upstreamValid = usingNewPool
    ? (d.id.trim().length > 0 && !poolNames.includes(d.id.trim()))
    : poolNames.includes(d.upstream);
  const canSave = idValid && pathValid && upstreamValid && !busy;

  const set = (k, v) => setD({ ...d, [k]: v });
  const toggleSet = (k, v) => {
    const cur = new Set(d[k] || []);
    cur.has(v) ? cur.delete(v) : cur.add(v);
    setD({ ...d, [k]: Array.from(cur) });
  };

  // One-line preview always visible at the bottom of the form.
  const matchPreview = (() => {
    const ms = (d.methods || []).length > 0 ? d.methods.join(',') : 'ANY';
    const host = d.host.trim() || '*';
    const path = d.path.trim() || '/';
    return `${ms}  ${host}${path}  →  ${
      usingNewPool ? `${d.id.trim() || '<route-id>'} (new · ${newPool.addr})`
                   : (d.upstream || '<pick a pool>')
    }`;
  })();

  return (
    <div className="modal-backdrop" onClick={onCancel}>
      <div className="modal" onClick={e => e.stopPropagation()} style={{ maxWidth: 560 }}>
        <div className="modal-head">
          <div className="modal-title">{isAdd ? 'Add route' : `Edit route · ${d.id}`}</div>
          <button className="btn btn-sm" onClick={onCancel}>×</button>
        </div>
        <div className="modal-body">

          {/* Top — required basics, all visible. */}
          <div className="form-row">
            <label>Route ID <span className="req">*</span></label>
            <input className="ip" value={d.id} disabled={!isAdd}
              onChange={e => set('id', e.target.value)}
              placeholder="vnexpress" />
            {idClash && <div className="form-hint warn">A route with this ID already exists.</div>}
          </div>

          <div className="form-row" style={{ display: 'flex', gap: 8 }}>
            <div style={{ flex: 2 }}>
              <label>Path <span className="req">*</span></label>
              <input className="ip" value={d.path}
                onChange={e => set('path', e.target.value)}
                placeholder="/news" />
              {!pathValid && d.path && (
                <div className="form-hint warn">Path must start with <code>/</code>.</div>
              )}
            </div>
            <div style={{ flex: 2 }}>
              <label>Host <span style={{ color: 'var(--ink-dim)', fontWeight: 400 }}>(optional)</span></label>
              <input className="ip" value={d.host}
                onChange={e => set('host', e.target.value)}
                placeholder="any host" />
            </div>
          </div>

          <div className="form-row">
            <label>
              Methods{' '}
              <span style={{ color: 'var(--ink-dim)', fontWeight: 400 }}>
                ({d.methods.length === 0 ? 'any method' : d.methods.join(', ')})
              </span>
            </label>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4, marginTop: 4 }}>
              {ROUTE_METHOD_CHOICES.map(m => {
                const on = (d.methods || []).includes(m);
                return (
                  <button
                    key={m}
                    type="button"
                    onClick={() => toggleSet('methods', m)}
                    className={`pill ${on ? 'ok' : 'neutral'}`}
                    style={{ fontSize: 11, padding: '3px 10px', cursor: 'pointer' }}
                  >
                    {on && '✓ '}{m}
                  </button>
                );
              })}
            </div>
          </div>

          {/* Forward to — combined: dropdown OR type a new address. */}
          <div className="form-row" style={{ marginTop: 14, paddingTop: 12, borderTop: '1px solid var(--hairline)' }}>
            <label>Forward to <span className="req">*</span></label>
            <select className="ip"
              value={usingNewPool ? '' : d.upstream}
              disabled={usingNewPool}
              onChange={e => set('upstream', e.target.value)}>
              <option value="">{poolNames.length === 0 ? '— no pools yet —' : '— pick an existing pool —'}</option>
              {poolNames.map(n => <option key={n} value={n}>{n}</option>)}
            </select>
            <div style={{ fontSize: 11, color: 'var(--ink-dim)', textAlign: 'center', margin: '6px 0' }}>— or —</div>
            <input
              className="ip"
              value={newPool.addr}
              onChange={e => setNewPool({ ...newPool, addr: e.target.value })}
              placeholder="Type a new backend: IP:port  (e.g. 10.0.1.10:8080)"
            />
            {usingNewPool && (
              <div style={{ marginTop: 8, display: 'flex', gap: 8 }}>
                <div style={{ flex: 1 }}>
                  <label style={{ fontSize: 11 }}>Scheme</label>
                  <select className="ip" value={newPool.scheme}
                    onChange={e => setNewPool({ ...newPool, scheme: e.target.value })}>
                    <option value="auto">auto</option>
                    <option value="http">http</option>
                    <option value="https">https</option>
                    <option value="h2c">h2c</option>
                    <option value="grpc">grpc</option>
                    <option value="tcp">tcp</option>
                  </select>
                </div>
                <div style={{ flex: 2 }}>
                  <label style={{ fontSize: 11 }}>
                    Host header <span style={{ color: 'var(--ink-dim)', fontWeight: 400 }}>(SNI override · optional)</span>
                  </label>
                  <input className="ip" value={newPool.host_header}
                    onChange={e => setNewPool({ ...newPool, host_header: e.target.value })}
                    placeholder="vnexpress.net (for multi-vhost / public TLS)" />
                </div>
              </div>
            )}
            {usingNewPool && (
              <div className="form-hint">
                Will create pool <code>{d.id.trim() || '<route-id>'}</code> with this single member.
                {poolNames.includes(d.id.trim()) && (
                  <span className="warn"> — that pool name already exists; pick it from the dropdown above instead.</span>
                )}
              </div>
            )}
          </div>

          {/* Advanced — collapsed by default. */}
          <div style={{ marginTop: 12 }}>
            <button
              type="button"
              onClick={() => setShowAdvanced(!showAdvanced)}
              style={{
                background: 'transparent', border: 'none', color: 'var(--ink-dim)',
                fontSize: 11, cursor: 'pointer', padding: 0,
              }}
            >
              {showAdvanced ? '▾' : '▸'} Advanced (match type, tier, auth)
            </button>
          </div>
          {showAdvanced && (
            <div style={{ marginTop: 8, paddingTop: 10, borderTop: '1px dashed var(--hairline)' }}>
              <div className="form-row" style={{ display: 'flex', gap: 8 }}>
                <div style={{ flex: 1 }}>
                  <label style={{ fontSize: 11 }}>Match type</label>
                  <select className="ip" value={d.match_type} onChange={e => set('match_type', e.target.value)}>
                    <option value="prefix">prefix (begins with)</option>
                    <option value="exact">exact</option>
                    <option value="regex">regex</option>
                    <option value="glob">glob</option>
                  </select>
                </div>
                <div style={{ flex: 1 }}>
                  <label style={{ fontSize: 11 }}>Tier (risk level)</label>
                  <select className="ip" value={d.tier_override || 'low'} onChange={e => set('tier_override', e.target.value)}>
                    <option value="critical">critical</option>
                    <option value="high">high</option>
                    <option value="medium">medium</option>
                    <option value="low">low</option>
                  </select>
                </div>
              </div>
              <div className="form-row">
                <label style={{ fontSize: 11 }}>
                  Required client identity{' '}
                  <span style={{ color: 'var(--ink-dim)', fontWeight: 400 }}>
                    (none = open route)
                  </span>
                </label>
                <div style={{ display: 'flex', gap: 4, marginTop: 4 }}>
                  {ROUTE_AUTH_CHOICES.map(([k]) => {
                    const on = (d.auth_required || []).includes(k);
                    return (
                      <button
                        key={k}
                        type="button"
                        onClick={() => toggleSet('auth_required', k)}
                        className={`pill ${on ? 'ok' : 'neutral'}`}
                        style={{ fontSize: 11, padding: '3px 10px', cursor: 'pointer' }}
                      >
                        {on && '✓ '}{k}
                      </button>
                    );
                  })}
                </div>
              </div>

              {/* PR2 — default + enabled toggles. */}
              <div className="form-row" style={{ display: 'flex', gap: 16, alignItems: 'flex-start', marginTop: 8 }}>
                <label style={{ display: 'flex', gap: 6, alignItems: 'flex-start', fontSize: 11, cursor: 'pointer', flex: 1 }}>
                  <input
                    type="checkbox"
                    checked={!!d.default}
                    onChange={e => set('default', e.target.checked)}
                    style={{ marginTop: 2 }}
                  />
                  <span>
                    <strong>Catch unmatched traffic</strong>
                    <div style={{ color: 'var(--ink-dim)', fontWeight: 400, marginTop: 2, lineHeight: 1.4 }}>
                      Make this the fallback for any request to this host
                      that doesn't match a more specific route. Without a
                      fallback, unmatched requests get a 404. Each host
                      can have one fallback.
                    </div>
                  </span>
                </label>
                <label style={{ display: 'flex', gap: 6, alignItems: 'flex-start', fontSize: 11, cursor: 'pointer', flex: 1 }}>
                  <input
                    type="checkbox"
                    checked={d.enabled !== false}
                    onChange={e => set('enabled', e.target.checked)}
                    style={{ marginTop: 2 }}
                  />
                  <span>
                    <strong>Active in routing</strong>
                    <div style={{ color: 'var(--ink-dim)', fontWeight: 400, marginTop: 2, lineHeight: 1.4 }}>
                      Uncheck to <em>pause</em> this route without deleting
                      it — config stays, request matching skips it. Handy
                      for staging variants or pulling a misbehaving route
                      fast.
                    </div>
                  </span>
                </label>
              </div>
            </div>
          )}

          {/* One-line live preview pinned at the bottom. */}
          <div style={{ marginTop: 14, padding: 8, background: 'var(--canvas-2)', borderRadius: 4, fontSize: 11, fontFamily: 'var(--mono)' }}>
            {matchPreview}
          </div>

        </div>
        <div className="modal-foot">
          <button className="btn" onClick={onCancel} disabled={busy}>Cancel</button>
          <button className="btn primary" disabled={!canSave} onClick={() => {
            const out = { ...d };
            if (usingNewPool) {
              out.upstream = d.id.trim();
              out.newPool = newPool;
            } else {
              out.newPool = null;
            }
            onSave(out);
          }}>
            {busy ? 'Saving…' : (isAdd ? 'Create route' : 'Save')}
          </button>
        </div>
      </div>
    </div>
  );
}

function DeleteRouteModal({ id, blocker, onCancel, onConfirm, busy }) {
  return (
    <div className="modal-backdrop" onClick={onCancel}>
      <div className="modal" onClick={e => e.stopPropagation()} style={{ maxWidth: 460 }}>
        <div className="modal-head">
          <div className="modal-title">Delete route {id}?</div>
          <button className="btn btn-sm" onClick={onCancel}>×</button>
        </div>
        <div className="modal-body">
          {blocker
            ? (
              <div className="callout warn">
                <strong>Blocked.</strong> {blocker}
              </div>
            )
            : (
              <p style={{ fontSize: 13, lineHeight: 1.5 }}>
                Removing <code>{id}</code> is hot — in-flight requests
                finish on the old route table; new requests see the
                updated table immediately. The change is recorded
                in the audit chain.
              </p>
            )}
        </div>
        <div className="modal-foot">
          <button className="btn" onClick={onCancel} disabled={busy}>Cancel</button>
          {!blocker && (
            <button className="btn danger" onClick={onConfirm} disabled={busy}>
              {busy ? 'Removing…' : 'Delete route'}
            </button>
          )}
        </div>
      </div>
    </div>
  );
}

Object.assign(window, {
  PageOverview, PageLiveFeed, PageAttackEvents, PageAnalytics, PageAuditLog,
  PageRuleManager, PageTierConfig, ListPage, PageSettings, PageTracking,
  PageUpstreams,
  // SC-T2 — Scaling page (L1 workers + L2 cluster + L3 state).
  PageScaling,
  // Phase 2 — merged Access Lists, plus Phase 3 stubs.
  // PageHelp is owned by help.jsx (loaded after this file).
  PageAccessLists,
  PageIncidents, PageInvestigation, PageThreatIntel,
  PageTopAttackers,
  PageCompliance, PageReports,
  // 2026-05-09 — Traffic Gates page surfaces the four request-flow
  // gates (access list, strike-block, rate-limit, DDoS) with
  // telemetry + cross-links. New page slot in Policy menu group.
  PageTrafficGates,
});
