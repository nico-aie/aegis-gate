/* global React */
const { useState: useStateP, useEffect: useEffectP, useMemo: useMemoP, useRef: useRefP } = React;

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

function PageOverview() {
  const stats = window.useStatsApi();              // /api/stats — request_rate, blocks_total, block_rate_pct
  const tsApi = window.useTimeseriesApi(60, 1);    // /api/stats/timeseries — 60s window, 1s buckets
  const distApi = window.useAttacksDistributionApi(900); // /api/attacks/distribution — 15m
  const topApi = window.useAttacksTopApi(900, 5);  // /api/attacks/top — 5 attackers, 15m
  const tick = window.useTicking(2000);
  const [drawerEvent, setDrawerEvent] = useStateP(null);

  // Adapt /api/stats/timeseries → series shape the TrafficChart wants.
  const series = useMemoP(() => {
    const pts = tsApi.data?.points || [];
    if (pts.length === 0) return window.useTrafficSeries ? [] : [];
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
  const upstream = stats.data?.upstream;

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
    // The WorldMap renderer wants `{cc, city, lat, lon}`. We
    // only have `country` from the backend right now; lat/lon
    // would need a city DB. Pass partial geo so the map can
    // place a country-level blip; full lat/lon arrives when
    // the operator ships a GeoLite2-City.mmdb (follow-up).
    geo: a.country ? { cc: a.country, city: '', lat: 0, lon: 0 } : null,
  }));

  // Map blips — real country codes when available, else hide
  // the layer (the page used to fall back to mock fixtures
  // here, which lied about live state).
  const blips = topAttackers
    .filter(a => a.country)
    .slice(0, 12)
    .map((a, i) => ({
      cc: a.country, city: '', lat: 0, lon: 0,
      ip: a.id, label: a.country, show: i < 5,
    }));

  return (
    <>
      <div className="page-head">
        <div>
          <h1 className="page-title">Overview</h1>
          <p className="page-subtitle">Realtime WAF traffic monitoring · 5-cluster deployment · last update {tick}s</p>
        </div>
        <div className="page-actions">
          <button className="btn"><window.I.Refresh /> Refresh</button>
          <button className="btn"><window.I.Download /> Export</button>
          <button className="btn primary"><window.I.External /> Open Grafana</button>
        </div>
      </div>

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
          value={upstream
            ? (upstream.unhealthy === 0 ? 'Healthy' : upstream.unhealthy < upstream.healthy ? 'Degraded' : 'Down')
            : '—'}
          sub={upstream
            ? `${upstream.healthy} of ${upstream.healthy + upstream.unhealthy} members up`
            : 'awaiting first stats sample'}
          icon={<window.I.Server />}
          tone={upstream ? (upstream.unhealthy === 0 ? 'up' : 'warn') : undefined}
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
            <span className={`pill ${blips.length > 0 ? 'ok' : 'warn'}`}>
              {blips.length > 0 ? `${blips.length} geo-tagged` : 'geo DB not loaded'}
            </span>
          </div>
        </div>
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
            <div className="card-title">Risk heatmap — top routes × time</div>
            <div className="card-sub">Cell intensity = risk-score sum per 2-min bucket</div>
          </div>
          <div style={{ display: 'flex', gap: 6, alignItems: 'center', fontSize: 10, color: 'var(--ink-dim)' }}>
            <span>low</span>
            {['#1E2329','#3B2A1A','#6B4710','#A87715','#E0A415','#FCD535'].map(c => (
              <span key={c} style={{ width: 14, height: 10, background: c, display: 'inline-block', borderRadius: 1 }} />
            ))}
            <span>high</span>
          </div>
        </div>
        <window.RiskHeatmap rows={[
          { path: '/api/login', intensity: 0.95 },
          { path: '/api/admin/*', intensity: 0.85 },
          { path: '/wp-admin/*', intensity: 0.75 },
          { path: '/api/payments', intensity: 0.55 },
          { path: '/api/webhooks/*', intensity: 0.92 },
          { path: '/.env, /.git/*', intensity: 0.99 },
          { path: '/actuator/*', intensity: 0.42 },
          { path: '/api/users', intensity: 0.35 },
        ]} h={200} />
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
                  <button className="btn sm danger" style={{ marginRight: 6 }}>Block</button>
                  <button className="btn sm" onClick={() => setDrawerEvent(a)}>Inspect</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <window.Drawer open={!!drawerEvent} onClose={() => setDrawerEvent(null)} title={drawerEvent?.id}>
        {drawerEvent && <RequestDetail data={{ ip: drawerEvent.id, geo: drawerEvent.geo, hits: drawerEvent.hits, risk: drawerEvent.risk, cats: drawerEvent.cats }} />}
      </window.Drawer>
    </>
  );
}

function RequestDetail({ data }) {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
      <div>
        <div style={{ fontSize: 10, color: 'var(--ink-faint)', textTransform: 'uppercase', letterSpacing: 1.2, marginBottom: 6 }}>Summary</div>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8, fontSize: 12 }}>
          <div><div className="dim">Action</div><span className="pill block">block</span></div>
          <div><div className="dim">Reason</div><span className="mono">owasp-ssrf-001</span></div>
          <div><div className="dim">Risk</div><window.RiskMeter value={data.risk || 92} /></div>
          <div><div className="dim">Tier</div><span className="pill tier-crit">crit</span></div>
        </div>
      </div>
      <div>
        <div style={{ fontSize: 10, color: 'var(--ink-faint)', textTransform: 'uppercase', letterSpacing: 1.2, marginBottom: 6 }}>Network</div>
        <div style={{ fontSize: 12, lineHeight: 1.7, fontFamily: 'var(--font-mono)' }}>
          <div><span className="dim">client_ip</span> {data.ip}</div>
          <div><span className="dim">asn</span> AS14061 (DigitalOcean)</div>
          <div><span className="dim">geo</span> {data.geo?.cc} · {data.geo?.city} ({data.geo?.lat?.toFixed(2)}, {data.geo?.lon?.toFixed(2)})</div>
          <div><span className="dim">ja4</span> t13d_1516h2_8daaf6152771_e5627efa2ab1</div>
          <div><span className="dim">xff</span> 10.32.4.11 → 10.99.0.1</div>
        </div>
      </div>
      <div>
        <div style={{ fontSize: 10, color: 'var(--ink-faint)', textTransform: 'uppercase', letterSpacing: 1.2, marginBottom: 6 }}>Request</div>
        <pre style={{ background: 'var(--canvas)', border: '1px solid var(--hairline)', borderRadius: 6, padding: 10, fontSize: 11, fontFamily: 'var(--font-mono)', overflow: 'auto', margin: 0, color: 'var(--ink-mute)' }}>{`POST /api/webhooks/fetch HTTP/1.1
Host: api.aegis.example.com
User-Agent: curl/7.81.0
Content-Type: application/json
X-Forwarded-For: ${data.ip}

{"url": "http://169.254.169.254/latest/meta-data/iam/"}`}</pre>
      </div>
      <div>
        <div style={{ fontSize: 10, color: 'var(--ink-faint)', textTransform: 'uppercase', letterSpacing: 1.2, marginBottom: 6 }}>Detection</div>
        <div style={{ fontSize: 12 }}>
          <div className="mono"><span className="dim">rule</span> owasp-ssrf-001 — SSRF: Internal Addresses</div>
          <div className="mono"><span className="dim">match</span> body→url contains <span style={{ color: 'var(--down)' }}>169.254.169.254</span></div>
        </div>
      </div>
      <div>
        <div style={{ fontSize: 10, color: 'var(--ink-faint)', textTransform: 'uppercase', letterSpacing: 1.2, marginBottom: 6 }}>Audit</div>
        <div style={{ fontSize: 11, fontFamily: 'var(--font-mono)', color: 'var(--ink-mute)' }}>
          <div><span className="dim">request_id</span> req_8a1f2c4d9e0b</div>
          <div><span className="dim">chain_hash</span> a4f2e9c1b3d7…</div>
          <div><span className="dim">prev</span> a4f2e9c1b3d6 <span className="pill ok" style={{ marginLeft: 6 }}>verified</span></div>
          <div><span className="dim">sinks</span> splunk ✓ · datadog ✓ · s3-archive ✓</div>
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
        footer={<><button className="btn">Copy as cURL</button><button className="btn danger">Block IP</button><button className="btn primary">Whitelist</button></>}>
        {selected && <RequestDetail data={{ ip: selected.ip, geo: selected.geo, risk: selected.risk, cats: [selected.cat] }} />}
      </window.Drawer>
    </>
  );
}

// ============== ATTACK EVENTS ==============
function PageAttackEvents() {
  const [win, setWin] = useStateP('1h');
  const detectorBars = window.ATTACK_CATS.map(c => ({
    label: c.label, value: 50 + Math.floor(Math.random() * 1800), color: c.color,
  })).sort((a,b) => b.value - a.value);

  const topRules = window.RULES.slice(0, 10).sort((a,b) => b.hits1h - a.hits1h);

  const tiHits = [
    { src: 'spamhaus_drop', ind: '185.220.101.0/24', cat: 'tor-exit', hits: 8421, first: '8h', last: '2s' },
    { src: 'firehol_level1', ind: '95.214.55.10', cat: 'malware-c2', hits: 412, first: '3h', last: '1m' },
    { src: 'tor', ind: '46.166.139.111', cat: 'tor-exit', hits: 91, first: '1h', last: '4m' },
    { src: 'binarydefense', ind: 'AS14061', cat: 'abuse-asn', hits: 4128, first: '12h', last: '34s' },
    { src: 'emergingthreats', ind: '177.85.34.221', cat: 'compromised', hits: 38, first: '20m', last: '12m' },
  ];

  return (
    <>
      <div className="page-head">
        <div>
          <h1 className="page-title">Attack Events</h1>
          <p className="page-subtitle">Curated detector firings · OWASP + custom rules · last {win}</p>
        </div>
        <div className="page-actions">
          <select className="input select" value={win} onChange={e => setWin(e.target.value)} style={{ width: 90 }}>
            {['5m','15m','1h','6h','24h'].map(v => <option key={v}>{v}</option>)}
          </select>
          <button className="btn"><window.I.Download /> Export CSV</button>
        </div>
      </div>

      <div className="section-row">
        <div className="card">
          <window.SectionHeader title="Detector breakdown" sub={`${detectorBars.reduce((s,x)=>s+x.value,0).toLocaleString()} detections in window`} />
          <window.BarList items={detectorBars} />
        </div>
        <div className="card">
          <window.SectionHeader title="Bot classification mix" sub="Live classifier signal" />
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            <window.StackedBar segments={[
              { name: 'verified',  value: 4218, color: 'var(--up)' },
              { name: 'suspect',   value: 1842, color: 'var(--warn)' },
              { name: 'malicious', value: 3104, color: 'var(--down)' },
              { name: 'unknown',   value: 921,  color: 'var(--ink-faint)' },
            ]} h={28} />
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 6, fontSize: 11 }}>
              <div><span style={{ color: 'var(--up)' }}>● verified</span> <span className="num">4,218</span></div>
              <div><span style={{ color: 'var(--warn)' }}>● suspect</span> <span className="num">1,842</span></div>
              <div><span style={{ color: 'var(--down)' }}>● malicious</span> <span className="num">3,104</span></div>
              <div><span style={{ color: 'var(--ink-faint)' }}>● unknown</span> <span className="num">921</span></div>
            </div>
            <div style={{ marginTop: 6, padding: 8, background: 'var(--canvas-2)', borderRadius: 6, fontSize: 11, color: 'var(--ink-mute)' }}>
              <strong style={{ color: 'var(--ink-strong)' }}>30.4%</strong> of bot traffic in this window classified as malicious — above 14d baseline of 18%.
            </div>
          </div>
        </div>
      </div>

      <div className="card" style={{ marginBottom: 12 }}>
        <window.SectionHeader title="Top firing rules" actions={<button className="btn sm">Manage rules →</button>} />
        <table className="tbl tbl-compact">
          <thead><tr><th>Rule ID</th><th>Scope</th><th>Action</th><th>Risk</th><th>Count (1h)</th><th>Last fired</th><th></th></tr></thead>
          <tbody>
            {topRules.map((r, i) => (
              <tr key={`${r.id}-${r.kind}-${i}`}>
                <td><span className="mono" style={{ color: 'var(--brand-yellow)' }}>{r.id}</span> <span className="pill builtin" style={{ marginLeft: 6 }}>{r.kind}</span></td>
                <td><span className="dim">global</span></td>
                <td><window.ActionPill value={r.action} /></td>
                <td><window.RiskMeter value={r.risk} /></td>
                <td className="num">{r.hits1h.toLocaleString()}</td>
                <td className="dim">{r.last}</td>
                <td><button className="btn sm">Disable 1h</button></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div className="card">
        <window.SectionHeader title="Threat-intel hits" sub="Indicators matched in window" />
        <table className="tbl tbl-compact">
          <thead><tr><th>Source</th><th>Indicator</th><th>Category</th><th>Hits</th><th>First</th><th>Last</th></tr></thead>
          <tbody>
            {tiHits.map((t, i) => (
              <tr key={i}>
                <td className="mono"><span className="pill violet">{t.src}</span></td>
                <td className="mono">{t.ind}</td>
                <td><span className="pill neutral">{t.cat}</span></td>
                <td className="num">{t.hits.toLocaleString()}</td>
                <td className="dim">{t.first} ago</td>
                <td className="dim">{t.last} ago</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </>
  );
}

// ============== ANALYTICS ==============
function PageAnalytics() {
  const [range, setRange] = useStateP('24h');

  const reqOverTime = Array.from({ length: 60 }, (_, i) => 800 + Math.sin(i / 5) * 200 + Math.random() * 150);
  const blockRatio = Array.from({ length: 60 }, (_, i) => 0.05 + Math.abs(Math.sin(i / 8)) * 0.12 + Math.random() * 0.04);
  const latP50 = Array.from({ length: 60 }, () => 8 + Math.random() * 4);
  const latP95 = Array.from({ length: 60 }, () => 24 + Math.random() * 8);
  const latP99 = Array.from({ length: 60 }, () => 48 + Math.random() * 16);

  return (
    <>
      <div className="page-head">
        <div>
          <h1 className="page-title">Analytics</h1>
          <p className="page-subtitle">Historical trends · Prometheus-backed · {range} window</p>
        </div>
        <div className="page-actions">
          <div style={{ display: 'flex', gap: 4 }}>
            {['1h','6h','24h','7d','30d'].map(r => (
              <button key={r} className={`chip ${range === r ? 'active' : ''}`} onClick={() => setRange(r)}>{r}</button>
            ))}
          </div>
          <button className="btn"><window.I.Refresh /></button>
          <button className="btn"><window.I.External /> Grafana</button>
        </div>
      </div>

      <div className="grid-12" style={{ marginBottom: 12 }}>
        <div className="col-6 card">
          <window.SectionHeader title="Requests over time" sub={`avg ${Math.round(reqOverTime.reduce((s,x)=>s+x,0)/reqOverTime.length)} req/s`} />
          <window.Sparkline data={reqOverTime} w={460} h={120} color="#3B82F6" fill strokeWidth={1.5} />
        </div>
        <div className="col-6 card">
          <window.SectionHeader title="Latency p50/p95/p99" sub="WAF + upstream end-to-end" />
          <div style={{ position: 'relative', height: 120 }}>
            <window.Sparkline data={latP99} w={460} h={120} color="#F6465D" />
            <div style={{ position: 'absolute', inset: 0 }}><window.Sparkline data={latP95} w={460} h={120} color="#F0B90B" /></div>
            <div style={{ position: 'absolute', inset: 0 }}><window.Sparkline data={latP50} w={460} h={120} color="#0ECB81" /></div>
          </div>
          <div style={{ display: 'flex', gap: 14, fontSize: 11, marginTop: 6 }}>
            <span style={{ color: 'var(--up)' }}>● p50 9.2ms</span>
            <span style={{ color: 'var(--warn)' }}>● p95 28.4ms</span>
            <span style={{ color: 'var(--down)' }}>● p99 56.1ms</span>
          </div>
        </div>
        <div className="col-6 card">
          <window.SectionHeader title="Block ratio" sub="Blocked / total · histogram" />
          <window.Sparkline data={blockRatio.map(v => v * 100)} w={460} h={120} color="#F6465D" fill />
          <div style={{ fontSize: 11, color: 'var(--ink-mute)', marginTop: 4 }}>
            avg <span className="num" style={{ color: 'var(--down)' }}>9.4%</span> · peak <span className="num">21.8%</span> at 14:32
          </div>
        </div>
        <div className="col-6 card">
          <window.SectionHeader title="Error rate by route" sub="Top 5 routes by block volume" />
          <window.BarList items={[
            { label: '/api/login', value: 4218, color: 'var(--down)' },
            { label: '/wp-admin/install.php', value: 3812, color: 'var(--down)' },
            { label: '/.env', value: 2104, color: 'var(--down)' },
            { label: '/api/webhooks/*', value: 1521, color: 'var(--warn)' },
            { label: '/api/admin/*', value: 821, color: 'var(--warn)' },
          ]} />
        </div>
      </div>

      <div className="grid-12">
        <div className="col-8 card">
          <window.SectionHeader title="SLO budget remaining" sub="30d rolling burn" />
          <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
            {[
              { name: 'availability', target: '99.95%', val: '99.972%', remain: 78, sparkColor: 'var(--up)' },
              { name: 'latency p95 ≤ 30ms', target: '99%', val: '99.4%', remain: 62, sparkColor: 'var(--up)' },
              { name: 'WAF overhead p99 ≤ 100µs', target: '99.5%', val: '99.1%', remain: 18, sparkColor: 'var(--down)' },
              { name: 'audit delivery', target: '99.9%', val: '99.94%', remain: 84, sparkColor: 'var(--up)' },
              { name: 'cert freshness ≥ 7d', target: '100%', val: '100%', remain: 100, sparkColor: 'var(--up)' },
            ].map(s => (
              <div key={s.name} style={{ display: 'grid', gridTemplateColumns: '180px 80px 80px 1fr 80px', gap: 12, alignItems: 'center', fontSize: 12 }}>
                <span>{s.name}</span>
                <span className="dim">{s.target}</span>
                <span className="num" style={{ color: 'var(--ink)' }}>{s.val}</span>
                <div style={{ height: 6, background: 'var(--surface-3)', borderRadius: 3, overflow: 'hidden' }}>
                  <div style={{ width: `${s.remain}%`, height: '100%', background: s.remain < 30 ? 'var(--down)' : s.remain < 60 ? 'var(--warn)' : 'var(--up)' }} />
                </div>
                <span className="num right" style={{ color: s.remain < 30 ? 'var(--down)' : 'var(--ink-mute)' }}>{s.remain}% left</span>
              </div>
            ))}
          </div>
        </div>
        <div className="col-4 card">
          <window.SectionHeader title="Cert freshness" />
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            {window.CERTS.slice(0, 5).map(c => {
              const tone = c.days < 7 ? 'down' : c.days < 30 ? 'warn' : 'up';
              return (
                <div key={c.host} style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 12 }}>
                  <div style={{ flex: 1, overflow: 'hidden', textOverflow: 'ellipsis' }} className="mono">{c.host}</div>
                  <span className={`pill ${tone}`}>{c.days}d</span>
                </div>
              );
            })}
          </div>
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
  const [debouncedQ, setDebouncedQ] = useStateP({ ip: '', ruleId: '', requestId: '' });

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
    limit: 200,
  });
  const events = audit.data?.events || [];
  const gap = audit.data?.gap;

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
          <h1 className="page-title">Audit Log</h1>
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

      <div className="card flat" style={{ padding: 12, marginBottom: 12 }}>
        <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
          <input className="input" style={{ width: 160 }} placeholder="client IP"
                 value={ipFilter} onChange={e => setIpFilter(e.target.value)} />
          <input className="input" style={{ width: 200 }} placeholder="rule_id"
                 value={ruleIdFilter} onChange={e => setRuleIdFilter(e.target.value)} />
          <input className="input" style={{ flex: 1, maxWidth: 320 }} placeholder="request_id"
                 value={requestIdFilter} onChange={e => setRequestIdFilter(e.target.value)} />
          <span style={{ marginLeft: 'auto', fontSize: 11, color: 'var(--ink-dim)' }}>
            cursor {audit.data?.cursor ?? 0} → {audit.data?.next_cursor ?? 0}
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

function PageRuleManager() {
  const rulesApi = window.useRulesApi();
  // Prefer API rules when the array is non-empty; fall back to the
  // demo set so the page still renders before any rule is created.
  const apiRules = (rulesApi.data && Array.isArray(rulesApi.data.rules) && rulesApi.data.rules.length > 0)
    ? rulesApi.data.rules
    : window.RULES;

  // Display-merge: if the API returned a row whose id matches a mock
  // entry, overlay the mock display fields (name, kind, hits1h, etc.)
  // so the UI stays rich while ID/body/enabled stay authoritative.
  const mockById = useMemoP(() => {
    const m = new Map();
    window.RULES.forEach(r => { if (!m.has(r.id)) m.set(r.id, r); });
    return m;
  }, []);
  const merged = apiRules.map(r => {
    const mock = mockById.get(r.id) || {};
    return {
      id: r.id,
      name: mock.name || r.id,
      kind: mock.kind || 'custom',
      pri: mock.pri ?? 100,
      field: mock.field || 'any',
      op: mock.op || 'regex',
      pattern: mock.pattern || '',
      action: mock.action || 'block',
      risk: mock.risk ?? 50,
      enabled: r.enabled !== undefined ? r.enabled : (mock.enabled ?? true),
      cat: mock.cat || 'custom',
      hits1h: mock.hits1h ?? 0,
      body: r.body || mock.body || ruleRowToBody(mock.id ? mock : { id: r.id }),
    };
  });

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

  async function deleteSelected() {
    if (!selected) return;
    if (!window.confirm(`Delete rule ${selected.id}? This is audit-mutated and cannot be undone.`)) return;
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
          <h1 className="page-title">Rule Manager</h1>
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
                  <div>
                    <div style={{ marginBottom: 16 }}>
                      <div style={{ fontSize: 11, color: 'var(--ink-dim)', marginBottom: 6 }}>Match count · last 1h</div>
                      <window.Sparkline data={Array.from({length: 60}, () => 100 + Math.random()*200)} w={600} h={80} color="#FCD535" fill />
                    </div>
                    <window.BarList items={[
                      { label: '/api/login', value: 412 },
                      { label: '/api/users', value: 318 },
                      { label: '/api/orders', value: 217 },
                      { label: '/api/admin/*', value: 145 },
                      { label: '/api/products', value: 96 },
                    ]} />
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
    </>
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
function PageTierConfig() {
  const tiersApi = window.useTiersApi();
  const routesApi = window.useRoutesApi();
  const tiers = tiersApi.data?.tiers || [];
  const routes = routesApi.data?.routes || [];
  const [selectedName, setSelectedName] = useStateP(null);

  // Auto-select the first tier when data lands.
  useEffectP(() => {
    if (!selectedName && tiers.length > 0) setSelectedName(tiers[0].name);
  }, [tiers.length, selectedName]);

  const selected = tiers.find(t => t.name === selectedName) || tiers[0] || null;
  const routesForSelected = selected
    ? routes.filter(r => r.tier_override === selected.name)
    : [];

  return (
    <>
      <div className="page-head">
        <div>
          <h1 className="page-title">Tier Config</h1>
          <p className="page-subtitle">
            Pipeline assignment per tier ·
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

      <div className="split-list">
        <div className="left">
          <div style={{ overflow: 'auto', flex: 1 }}>
            {tiers.length === 0 && (
              <div style={{ padding: 16, fontSize: 12, color: 'var(--ink-dim)', textAlign: 'center' }}>
                No tiers configured.
              </div>
            )}
            {tiers.map(t => {
              const tierRouteCount = routes.filter(r => r.tier_override === t.name).length;
              const detectorCount = (t.pipeline || []).filter(p => !['rate', 'rules', 'risk', 'challenge'].includes(p)).length;
              return (
                <button key={t.name} onClick={() => setSelectedName(t.name)}
                  style={{ display: 'block', width: '100%', textAlign: 'left', padding: 14, border: 'none', borderBottom: '1px solid var(--hairline)',
                    background: selected && selected.name === t.name ? 'var(--surface-active)' : 'transparent',
                    borderLeft: selected && selected.name === t.name ? '3px solid var(--brand-yellow)' : '3px solid transparent',
                    cursor: 'pointer', color: 'inherit' }}>
                  <div style={{ fontSize: 13, fontWeight: 600, marginBottom: 2 }}>{t.name}</div>
                  <div style={{ fontSize: 11, color: 'var(--ink-dim)', marginBottom: 6 }}>
                    risk ≥ {t.risk_threshold} · block ≥ {t.block_threshold}/s
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
              <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 14 }}>
                <div>
                  <div style={{ fontSize: 16, fontWeight: 700 }}>{selected.name}</div>
                  <div style={{ fontSize: 11, color: 'var(--ink-dim)' }}>
                    {(selected.pipeline || []).length} pipeline stages · risk threshold <span className="num">{selected.risk_threshold}</span>
                  </div>
                </div>
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
                  <thead><tr><th>Route ID</th><th>Host</th><th>Path</th><th>Match</th><th>Methods</th><th>Upstream</th></tr></thead>
                  <tbody>
                    {routesForSelected.length === 0 && (
                      <tr><td colSpan={6} style={{ textAlign: 'center', padding: 16, color: 'var(--ink-dim)', fontSize: 12 }}>
                        No routes assigned to this tier.
                      </td></tr>
                    )}
                    {routesForSelected.map(r => (
                      <tr key={r.id}>
                        <td className="mono">{r.id}</td>
                        <td className="mono dim">{r.host || '*'}</td>
                        <td className="mono">{r.path}</td>
                        <td><span className="pill neutral">{r.match_type}</span></td>
                        <td className="mono dim">{r.methods.length === 0 ? 'ANY' : r.methods.join(', ')}</td>
                        <td className="mono">{r.upstream}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </>
          ) : (
            <div style={{ padding: 24, color: 'var(--ink-dim)', fontSize: 12 }}>Select a tier to inspect.</div>
          )}
        </div>
      </div>
    </>
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
          <button className="btn primary"><window.I.Plus /> Add entry</button>
        </div>
      </div>

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
            </tr>
          </thead>
          <tbody>
            {data.length === 0 && (
              <tr><td colSpan={6} style={{ textAlign: 'center', padding: 16, color: 'var(--ink-dim)', fontSize: 12 }}>
                No entries.
              </td></tr>
            )}
            {data.map(e => (
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
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </>
  );
}

// ============== SETTINGS ==============
function PageSettings() {
  const modeApi = window.useModeApi();
  const mode = modeApi.data?.mode || 'enforce';
  const isShadow = mode === 'log_only';
  const [busy, setBusy] = useStateP(false);

  // CI-T6 wires this single toggle to the live API. The other
  // controls below stay local-only (risk thresholds, honeypots,
  // response filtering) — wiring those needs new mutation
  // endpoints that aren't shipped yet.
  const [allow, setAllow] = useStateP(51);
  const [challenge, setChallenge] = useStateP(75);
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
        <div className="card-head"><div className="card-title">Risk thresholds</div></div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12, marginBottom: 6 }}>
              <span>Allow (0 – {allow})</span><span className="num">{allow}</span>
            </div>
            <input type="range" min="0" max="100" value={allow} onChange={e => setAllow(+e.target.value)} style={{ width: '100%', accentColor: 'var(--brand-yellow)' }} />
          </div>
          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12, marginBottom: 6 }}>
              <span>Challenge ({allow + 1} – {challenge})</span><span className="num">{challenge}</span>
            </div>
            <input type="range" min={allow+1} max="100" value={challenge} onChange={e => setChallenge(+e.target.value)} style={{ width: '100%', accentColor: 'var(--brand-yellow)' }} />
          </div>
          <div style={{ fontSize: 12, color: 'var(--ink-mute)' }}>Block threshold: <span className="num" style={{ color: 'var(--down)' }}>≥ {challenge + 1}</span></div>
        </div>
      </div>

      <div className="card" style={{ marginBottom: 12 }}>
        <div className="card-head"><div className="card-title">Challenge Engine</div></div>
        <div className="field-label">Challenge type</div>
        <select className="input select" defaultValue="JS Challenge"><option>JS Challenge</option><option>JS + CAPTCHA</option><option>Strict (PoW)</option></select>
      </div>

      <div className="card" style={{ marginBottom: 12 }}>
        <div className="card-head"><div className="card-title">Honeypot Paths</div></div>
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
        <div className="card-head"><div className="card-title">Response Filtering</div></div>
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

      <div className="card" style={{ marginTop: 12 }}>
        <div className="card-head">
          <div>
            <div className="card-title">Cache management</div>
            <div className="card-sub">Flush internal caches without restarting the WAF</div>
          </div>
          <button className="btn danger"><window.I.Refresh /> Reset all caches</button>
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 10 }}>
          {[
            { k: 'rules',   t: 'Rule cache',          d: 'Compiled regex / rule AST',         size: '128 MB', age: '14m', n: '1,247 entries' },
            { k: 'geoip',   t: 'GeoIP cache',         d: 'IP → country/ASN lookups',          size: '412 MB', age: '2h 8m', n: '8.4M entries' },
            { k: 'ti',      t: 'Threat-intel cache', d: 'Feed-derived indicators',           size: '58 MB',  age: '6m', n: '142,381 entries' },
            { k: 'fp',      t: 'Fingerprint cache',   d: 'JA4 / TLS fingerprints',            size: '24 MB',  age: '3m', n: '52,108 entries' },
            { k: 'session', t: 'Session cache',       d: 'Challenge-passed session tokens',   size: '16 MB',  age: '52s', n: '12,884 entries' },
            { k: 'dns',     t: 'DNS cache',           d: 'Upstream resolution',               size: '4 MB',   age: '11m', n: '3,212 entries' },
          ].map(c => (
            <div key={c.k} style={{ display: 'flex', alignItems: 'center', gap: 10, padding: 10, background: 'var(--canvas-2)', border: '1px solid var(--hairline)', borderRadius: 6 }}>
              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{ fontSize: 12, fontWeight: 600 }}>{c.t}</div>
                <div style={{ fontSize: 11, color: 'var(--ink-dim)' }}>{c.d}</div>
                <div style={{ fontSize: 10, color: 'var(--ink-faint)', marginTop: 2 }}>
                  <span className="num">{c.size}</span> · <span className="num">{c.n}</span> · refreshed <span className="num">{c.age}</span> ago
                </div>
              </div>
              <button className="btn sm">Flush</button>
            </div>
          ))}
        </div>
        <div className="banner warn" style={{ marginTop: 12, padding: 10 }}>
          <div style={{ marginTop: 1 }}><window.I.Siren /></div>
          <div style={{ flex: 1, fontSize: 12 }}>
            Flushing the GeoIP or rule cache briefly increases latency while caches warm up. The action is hash-chained into the audit log.
          </div>
        </div>
      </div>
    </>
  );
}

// ============== TRACKING ==============
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
          <h1 className="page-title">Tracking</h1>
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
          }}>
            <window.I.Refresh /> Refresh
          </button>
        </div>
      </div>

      <div className="grid-12" style={{ marginBottom: 12 }}>
        <div className="col-6 card">
          <window.SectionHeader title="SLO budget" sub="live engine · burn windows pending wiring" />
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

      <div className="card" style={{ marginBottom: 12 }}>
        {(() => {
          const totalMembers = upstreams.reduce((s, x) => s + (x.members || x.total_members || 0), 0);
          const totalHealthy = upstreams.reduce((s, x) => s + (x.healthy || x.healthy_members || 0), 0);
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
              const total = p.members ?? p.total_members ?? 0;
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

Object.assign(window, {
  PageOverview, PageLiveFeed, PageAttackEvents, PageAnalytics, PageAuditLog,
  PageRuleManager, PageTierConfig, ListPage, PageSettings, PageTracking,
});
