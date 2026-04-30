/* global React */
const { useState: useStateP, useEffect: useEffectP, useMemo: useMemoP, useRef: useRefP } = React;

// ============== OVERVIEW ==============
function PageOverview() {
  const series = window.useTrafficSeries(60);
  const tick = window.useTicking(2000);
  const [drawerEvent, setDrawerEvent] = useStateP(null);

  const totalNow = series[series.length - 1]?.total || 0;
  const blockNow = series[series.length - 1]?.blocked || 0;
  const blockRate = totalNow ? ((blockNow / totalNow) * 100).toFixed(1) : '0.0';
  const totalBlocks = series.reduce((s, x) => s + x.blocked, 0) + 638947;

  const sparkTotal = series.slice(-30).map(s => s.total);
  const sparkBlocked = series.slice(-30).map(s => s.blocked);

  // Distribution
  const dist = window.ATTACK_CATS.map(c => ({
    name: c.label, color: c.color, value: 50 + Math.floor(Math.random() * 600 + (c.id === 'ssrf' ? 400 : 0) + (c.id === 'sqli' ? 300 : 0)),
  }));

  // Map blips
  const blips = window.ATTACKER_GEO.slice(0, 12).map((g, i) => ({
    ...g,
    label: `${g.cc} · ${g.city}`,
    show: i < 5,
  }));

  // Top attackers
  const topAttackers = window.ATTACKER_GEO.slice(0, 5).map((g, i) => ({
    id: g.ip,
    geo: g,
    hits: 4521 - i * 720 + Math.floor(Math.random() * 100),
    cats: i === 0 ? ['honeypot', 'recon'] : i === 1 ? ['sqli', 'cmdi'] : i === 2 ? ['ssrf'] : i === 3 ? ['recon'] : ['xss', 'path_traversal'],
    risk: 100 - i * 8,
    fingerprint: i % 2 === 0 ? `fp:${Math.random().toString(16).slice(2, 18)}` : null,
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
          value={(totalNow / 10).toFixed(1)}
          sub={<>last 10 seconds <span style={{ color: 'var(--up)' }}><window.I.ArrowUp/> 12%</span></>}
          icon={<window.I.Activity />}
          sparkData={sparkTotal}
          sparkColor="#3B82F6"
        />
        <window.StatTile
          title="Block rate"
          value={`${blockRate}%`}
          sub={<><span className="num">{totalBlocks.toLocaleString()}</span> blocked total</>}
          icon={<window.I.Ban />}
          tone="down"
          sparkData={sparkBlocked}
          sparkColor="#F6465D"
        />
        <window.StatTile
          title="Active threats"
          value="47"
          sub={<>IPs over risk threshold · <span style={{ color: 'var(--down)' }}>3 critical</span></>}
          icon={<window.I.Siren />}
          tone="warn"
        />
        <window.StatTile
          title="Upstream"
          value="Healthy"
          sub="22 of 24 members up · 2 degraded"
          icon={<window.I.Server />}
          tone="up"
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
            <span className="pill block">12 active sources</span>
            <span className="pill warn">3 ASN-flagged</span>
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
            {topAttackers.map((a, i) => (
              <tr key={i} onClick={() => setDrawerEvent(a)}>
                <td className="num dim">{i + 1}</td>
                <td className="mono" style={{ fontSize: 12 }}>{a.fingerprint || a.id}</td>
                <td><span style={{ color: 'var(--ink-mute)' }}>{a.geo.cc} · {a.geo.city}</span></td>
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
  const events = window.useLiveFeed(80, paused, 8);
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
          <p className="page-subtitle">{events.length.toLocaleString()} of {events.length.toLocaleString()} events · streaming via SSE <span className="pill ok" style={{ marginLeft: 6 }}>connected</span></p>
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
            <span className="pill ok" style={{ marginRight: 6 }}>● live</span>
            buffer {events.length}/1000
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
  return (
    <>
      <div className="page-head">
        <div>
          <h1 className="page-title">Audit Log</h1>
          <p className="page-subtitle">
            Searchable hash chain · 1.4M events
            <span style={{ marginLeft: 8 }}><span className="pill ok">verified</span></span>
            <span style={{ marginLeft: 6 }}><span className="pill info">witness 12s ago</span></span>
          </p>
        </div>
        <div className="page-actions">
          <button className="btn"><window.I.Refresh /> Verify chain</button>
          <button className="btn"><window.I.Download /> NDJSON</button>
        </div>
      </div>

      <div className="card flat" style={{ padding: 12, marginBottom: 12 }}>
        <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
          <select className="input select" style={{ width: 120 }}><option>Last 24h</option><option>Last 7d</option><option>Custom range</option></select>
          <select className="input select" style={{ width: 120 }}><option>All classes</option><option>Admin</option><option>System</option><option>Detection</option></select>
          <select className="input select" style={{ width: 120 }}><option>All actors</option><option>admin</option><option>gitops</option><option>system</option></select>
          <input className="input" style={{ flex: 1, maxWidth: 280 }} placeholder="Search request_id, target, hash…" />
        </div>
      </div>

      <div className="card" style={{ padding: 0 }}>
        <table className="tbl tbl-compact">
          <thead><tr><th style={{ width: 90 }}>Time</th><th style={{ width: 90 }}>Class</th><th style={{ width: 110 }}>Actor</th><th style={{ width: 150 }}>Action</th><th>Target</th><th>Reason</th><th style={{ width: 130 }}>Hash</th></tr></thead>
          <tbody>
            {[...window.ADMIN_LOG, ...window.ADMIN_LOG.map(l => ({...l, ts: '15:'+l.ts.slice(3), hash: l.hash.slice(0,11)+'a'}))].slice(0, 14).map((l, i) => (
              <tr key={i}>
                <td className="num dim">{l.ts}</td>
                <td><span className={`pill ${l.class === 'admin' ? 'warn' : l.class === 'system' ? 'info' : 'allow'}`}>{l.class}</span></td>
                <td className="mono">{l.actor}</td>
                <td className="mono" style={{ color: 'var(--ink)' }}>{l.action}</td>
                <td className="mono dim">{l.target}</td>
                <td className="dim">{l.reason}</td>
                <td className="mono" style={{ fontSize: 10, color: 'var(--brand-yellow)' }}>{l.hash}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </>
  );
}

// ============== RULE MANAGER ==============
function PageRuleManager() {
  const [selected, setSelected] = useStateP(window.RULES[0]);
  const [tab, setTab] = useStateP('dsl');
  const [search, setSearch] = useStateP('');
  const filtered = window.RULES.filter(r => !search || r.id.includes(search) || r.name.toLowerCase().includes(search.toLowerCase()));
  return (
    <>
      <div className="page-head">
        <div>
          <h1 className="page-title">Rule Manager</h1>
          <p className="page-subtitle">{window.RULES.length} total · 45 builtin / 44 custom · validate before apply</p>
        </div>
        <div className="page-actions">
          <button className="btn"><window.I.Refresh /> Reload</button>
          <button className="btn">Update Built-in</button>
          <button className="btn primary"><window.I.Plus /> New rule</button>
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
            {filtered.map((r, i) => (
              <button key={i} onClick={() => setSelected(r)}
                style={{ display: 'block', width: '100%', textAlign: 'left', padding: '8px 12px', border: 'none', borderBottom: '1px solid var(--hairline)',
                  background: selected === r ? 'var(--surface-active)' : 'transparent',
                  borderLeft: selected === r ? '3px solid var(--brand-yellow)' : '3px solid transparent',
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
                  <span style={{ marginLeft: 'auto' }} className="num">+{r.risk}</span>
                </div>
              </button>
            ))}
          </div>
        </div>
        <div className="right">
          <div style={{ padding: 14, borderBottom: '1px solid var(--hairline)', display: 'flex', alignItems: 'center', gap: 10 }}>
            <div>
              <div style={{ fontSize: 14, fontWeight: 600 }}>{selected.name}</div>
              <div style={{ fontSize: 11, color: 'var(--ink-dim)' }} className="mono">{selected.id} · priority {selected.pri} · {selected.hits1h.toLocaleString()} hits/1h</div>
            </div>
            <div style={{ marginLeft: 'auto', display: 'flex', gap: 6 }}>
              <button className="btn"><window.I.Edit /> Edit</button>
              <button className="btn">Disable</button>
              <button className="btn danger"><window.I.Trash /></button>
            </div>
          </div>
          <div style={{ display: 'flex', borderBottom: '1px solid var(--hairline)' }}>
            {['general','dsl','diff','stats'].map(t => (
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
                <div style={{ gridColumn: '1 / -1' }}><div className="field-label">Description</div><div className="dim">Detects {selected.cat} attempts using regex pattern matching against {selected.field} of incoming requests.</div></div>
              </div>
            )}
            {tab === 'dsl' && (
              <div>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
                  <span className="pill ok">validate ok</span>
                  <span style={{ fontSize: 11, color: 'var(--ink-dim)' }}>0 errors · 1 warning · dry-run: 1,247 matches in last 1h</span>
                </div>
                <pre style={{ background: 'var(--canvas)', border: '1px solid var(--hairline)', borderRadius: 6, padding: 14, fontSize: 12, fontFamily: 'var(--font-mono)', margin: 0, overflow: 'auto', lineHeight: 1.6 }}>
<span style={{ color: 'var(--violet)' }}>rule</span> <span style={{ color: 'var(--brand-yellow)' }}>"{selected.id}"</span> {`{
  `}<span style={{ color: 'var(--ink-dim)' }}>// {selected.name}</span>{`
  `}<span style={{ color: 'var(--info)' }}>priority</span>{`   = `}<span className="num">{selected.pri}</span>{`
  `}<span style={{ color: 'var(--info)' }}>field</span>{`      = "${selected.field}"
  `}<span style={{ color: 'var(--info)' }}>operator</span>{`   = "${selected.op}"
  `}<span style={{ color: 'var(--info)' }}>pattern</span>{`    = `}<span style={{ color: 'var(--up)' }}>r"{selected.pattern}"</span>{`
  `}<span style={{ color: 'var(--info)' }}>action</span>{`     = "${selected.action}"
  `}<span style={{ color: 'var(--info)' }}>risk_delta</span>{` = `}<span className="num">{selected.risk}</span>{`
  `}<span style={{ color: 'var(--info)' }}>scope</span>{`      = `}[<span style={{ color: 'var(--up)' }}>"global"</span>]{`
  `}<span style={{ color: 'var(--info)' }}>tags</span>{`       = `}[<span style={{ color: 'var(--up)' }}>"owasp"</span>, <span style={{ color: 'var(--up)' }}>"{selected.cat}"</span>]
{`}`}
                </pre>
              </div>
            )}
            {tab === 'diff' && (
              <pre style={{ background: 'var(--canvas)', border: '1px solid var(--hairline)', borderRadius: 6, padding: 14, fontSize: 12, fontFamily: 'var(--font-mono)', margin: 0, lineHeight: 1.6 }}>
{`@@ -3,3 +3,3 @@
   priority   = 100
- `}<span style={{ background: 'rgba(246,70,93,0.18)', color: '#FF8896' }}>  risk_delta = 75</span>{`
+ `}<span style={{ background: 'rgba(14,203,129,0.18)', color: '#5BD9A2' }}>  risk_delta = {selected.risk}</span>{`
   action     = "{selected.action}"`}
              </pre>
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
            <button className="btn">Validate</button>
            <button className="btn">Cancel</button>
            <button className="btn primary">Save & deploy</button>
          </div>
        </div>
      </div>
    </>
  );
}

// ============== TIER CONFIG ==============
function PageTierConfig() {
  const [selected, setSelected] = useStateP(window.TIERS[1]);
  return (
    <>
      <div className="page-head">
        <div>
          <h1 className="page-title">Tier Config</h1>
          <p className="page-subtitle">Pipeline assignment per tier · 4 active tiers · 60 routes assigned</p>
        </div>
        <div className="page-actions"><button className="btn primary"><window.I.Plus /> New tier</button></div>
      </div>

      <div className="split-list">
        <div className="left">
          <div style={{ overflow: 'auto', flex: 1 }}>
            {window.TIERS.map(t => (
              <button key={t.name} onClick={() => setSelected(t)}
                style={{ display: 'block', width: '100%', textAlign: 'left', padding: 14, border: 'none', borderBottom: '1px solid var(--hairline)',
                  background: selected === t ? 'var(--surface-active)' : 'transparent',
                  borderLeft: selected === t ? '3px solid var(--brand-yellow)' : '3px solid transparent',
                  cursor: 'pointer', color: 'inherit' }}>
                <div style={{ fontSize: 13, fontWeight: 600, marginBottom: 2 }}>{t.name}</div>
                <div style={{ fontSize: 11, color: 'var(--ink-dim)', marginBottom: 6 }}>{t.desc}</div>
                <div style={{ display: 'flex', gap: 6, fontSize: 10 }}>
                  <span className="pill neutral">{t.routes} routes</span>
                  <span className="pill neutral">{t.detectors}/7 detectors</span>
                </div>
              </button>
            ))}
          </div>
        </div>
        <div className="right" style={{ padding: 16 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 14 }}>
            <div>
              <div style={{ fontSize: 16, fontWeight: 700 }}>{selected.name}</div>
              <div style={{ fontSize: 11, color: 'var(--ink-dim)' }}>{selected.desc} · <span className="num">{selected.hits1h.toLocaleString()}</span> req/1h</div>
            </div>
            <div style={{ marginLeft: 'auto', display: 'flex', gap: 6 }}>
              <button className="btn">Cancel</button>
              <button className="btn primary">Save tier</button>
            </div>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
            {[
              { name: 'TLS profile', icon: '🔒', val: selected.tls, opts: ['fips', 'modern', 'compat'] },
              { name: 'Rate-limit profile', icon: '⏱', val: selected.rateLimit, opts: ['lenient','standard','strict'] },
              { name: 'Challenge ladder', icon: '🛡', val: selected.challenge, opts: ['none','js-only','js+captcha','strict'] },
              { name: 'DLP action', icon: '🔐', val: 'mask', opts: ['audit_only','mask','block'] },
            ].map(s => (
              <div key={s.name} style={{ background: 'var(--canvas-2)', border: '1px solid var(--hairline)', borderRadius: 6, padding: 12 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
                  <div style={{ fontSize: 12, fontWeight: 600 }}>{s.name}</div>
                  <div className={`toggle on`} style={{ marginLeft: 'auto' }} />
                </div>
                <select className="input select" defaultValue={s.val}>
                  {s.opts.map(o => <option key={o}>{o}</option>)}
                </select>
              </div>
            ))}
          </div>

          <div style={{ marginTop: 16, background: 'var(--canvas-2)', border: '1px solid var(--hairline)', borderRadius: 6, padding: 12 }}>
            <div style={{ fontSize: 12, fontWeight: 600, marginBottom: 10 }}>Detector set ({selected.detectors}/7 enabled)</div>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 8 }}>
              {['sqli','xss','path_traversal','ssrf','header_injection','body_abuse','recon'].map((d, i) => (
                <label key={d} style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 12, padding: '6px 8px', background: 'var(--surface-2)', borderRadius: 4 }}>
                  <div className={`toggle ${i < selected.detectors ? 'on' : ''}`} style={{ width: 28, height: 16 }} />
                  <span>{d}</span>
                </label>
              ))}
            </div>
          </div>

          <div style={{ marginTop: 16 }}>
            <div style={{ fontSize: 12, fontWeight: 600, marginBottom: 8 }}>Routes assigned ({selected.routes})</div>
            <table className="tbl tbl-compact">
              <thead><tr><th>Route</th><th>Method</th><th>Hits 1h</th><th>Avg risk</th></tr></thead>
              <tbody>
                {window.ROUTES.slice(0, 6).map(r => (
                  <tr key={r}><td className="mono">{r}</td><td className="mono dim">ANY</td><td className="num">{Math.floor(Math.random()*8000).toLocaleString()}</td><td><window.RiskMeter value={Math.floor(Math.random()*60)} /></td></tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </>
  );
}

// ============== BLACKLIST / WHITELIST ==============
function ListPage({ kind }) {
  const isBL = kind === 'blacklist';
  const data = isBL ? window.BLACKLIST : window.WHITELIST;
  return (
    <>
      <div className="page-head">
        <div>
          <h1 className="page-title">{isBL ? 'Blacklist' : 'Whitelist'}</h1>
          <p className="page-subtitle">
            {data.length} entries ·
            <span className="num"> {data.reduce((s, x) => s + (isBL ? x.hits24 : x.bypasses24), 0).toLocaleString()}</span> {isBL ? 'hits' : 'bypasses'} in 24h
          </p>
        </div>
        <div className="page-actions">
          <button className="btn"><window.I.Download /> Bulk import</button>
          <button className="btn primary"><window.I.Plus /> Add entry</button>
        </div>
      </div>

      <div className="card flat" style={{ padding: 12, marginBottom: 12 }}>
        <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
          <select className="input select" style={{ width: 130 }}><option>All types</option><option>IP</option><option>CIDR</option><option>ASN</option><option>Country</option><option>Fingerprint</option></select>
          <select className="input select" style={{ width: 130 }}><option>All scopes</option><option>global</option><option>per-route</option><option>per-tier</option></select>
          <select className="input select" style={{ width: 110 }}><option>Active</option><option>Expired</option><option>All</option></select>
          <input className="input" style={{ flex: 1, maxWidth: 320 }} placeholder="Search by value, reason…" />
        </div>
      </div>

      <div className="card" style={{ padding: 0 }}>
        <table className="tbl tbl-compact">
          <thead>
            <tr>
              <th style={{ width: 90 }}>Type</th>
              <th>Value</th>
              <th style={{ width: 160 }}>Scope</th>
              <th style={{ width: 130 }}>{isBL ? 'Action' : 'Bypass'}</th>
              <th>Reason</th>
              <th style={{ width: 110 }}>Expires</th>
              <th style={{ width: 90 }}>{isBL ? 'Hits 24h' : 'Bypasses 24h'}</th>
              <th style={{ width: 100 }}>Last</th>
              <th style={{ width: 60 }}></th>
            </tr>
          </thead>
          <tbody>
            {data.map(e => (
              <tr key={e.id}>
                <td><span className={`pill ${e.type === 'country' ? 'solid-yellow' : 'neutral'}`}>{e.type}</span></td>
                <td className="mono" style={{ color: 'var(--ink-strong)' }}>
                  {e.type === 'country' ? (
                    <span style={{ display: 'inline-flex', alignItems: 'center', gap: 8 }}>
                      <span style={{ fontSize: 16, lineHeight: 1 }}>{e.flag}</span>
                      <span style={{ fontWeight: 600 }}>{e.value}</span>
                      <span className="dim" style={{ fontFamily: 'var(--font-sans)', fontWeight: 400 }}>{e.country}</span>
                    </span>
                  ) : e.value}
                </td>
                <td className="mono dim">{e.scope}</td>
                <td>
                  {isBL ? <window.ActionPill value={e.action} /> : (
                    <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
                      {e.bypass.includes('all')
                        ? <span className="pill solid-yellow">all · high-trust</span>
                        : e.bypass.map(b => <span key={b} className="pill neutral" style={{ fontSize: 9 }}>{b}</span>)}
                    </div>
                  )}
                </td>
                <td className="dim" style={{ maxWidth: 280, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{e.reason}</td>
                <td className="num" style={{ color: e.expires ? 'var(--warn)' : 'var(--ink-dim)' }}>{e.expires ? e.expires.slice(0, 10) : 'never'}</td>
                <td className="num">{(isBL ? e.hits24 : e.bypasses24).toLocaleString()}</td>
                <td className="dim">{isBL ? e.lastHit : e.lastBypass}</td>
                <td><button className="icon-btn"><window.I.Edit /></button></td>
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
  const [shadow, setShadow] = useStateP(true);
  const [allow, setAllow] = useStateP(51);
  const [challenge, setChallenge] = useStateP(75);
  const [honeypots, setHoneypots] = useStateP(['/.env', '/.git/config', '/wp-admin/install.php', '/phpmyadmin', '/aws/credentials', '/actuator/env']);
  const [stackTraces, setStackTraces] = useStateP(true);
  const [redactJSON, setRedactJSON] = useStateP(true);
  return (
    <>
      <div className="page-head">
        <div>
          <h1 className="page-title">Settings</h1>
          <p className="page-subtitle">Changes apply immediately — no restart required</p>
        </div>
        <div className="page-actions"><button className="btn primary"><window.I.Check /> Save all</button></div>
      </div>

      <div className="banner warn" style={{ marginBottom: 12 }}>
        <div style={{ marginTop: 1 }}><window.I.Siren /></div>
        <div style={{ flex: 1 }}>
          <div className="banner-strong">Shadow mode is ON — no traffic is being blocked.</div>
          <div>Use this to test new rules safely before enforcing. Detection events still appear in Live Feed with their original action.</div>
        </div>
        <span className="pill warn" style={{ alignSelf: 'flex-start' }}>ACTIVE</span>
      </div>

      <div className="card" style={{ marginBottom: 12 }}>
        <div className="card-head">
          <div className="card-title">Shadow Mode (Dry-Run)</div>
          <div className={`toggle ${shadow ? 'on' : ''}`} onClick={() => setShadow(s => !s)} />
        </div>
        <div style={{ fontSize: 12, color: 'var(--ink-mute)' }}>Log detections without blocking. Requests that would be blocked/challenged are forwarded; events still appear in Live Feed with original action.</div>
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
  return (
    <>
      <div className="page-head">
        <div>
          <h1 className="page-title">Tracking</h1>
          <p className="page-subtitle">Operational state · SLO · cluster · GitOps · cert health</p>
        </div>
        <div className="page-actions"><button className="btn"><window.I.Refresh /> Refresh</button></div>
      </div>

      <div className="grid-12" style={{ marginBottom: 12 }}>
        <div className="col-6 card">
          <window.SectionHeader title="SLO burn rate" sub="30d rolling window" />
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            {[
              { name: 'availability', val: '99.972%', target: '99.95%', burn: 0.4, tone: 'up' },
              { name: 'overhead p95', val: '12.4ms', target: '30ms',   burn: 0.2, tone: 'up' },
              { name: 'overhead p99', val: '94µs',   target: '100µs',  burn: 1.8, tone: 'warn' },
              { name: 'audit delivery', val: '99.94%', target: '99.9%', burn: 0.3, tone: 'up' },
            ].map(s => (
              <div key={s.name} style={{ display: 'grid', gridTemplateColumns: '120px 80px 80px 1fr 60px', gap: 10, alignItems: 'center', fontSize: 12 }}>
                <span>{s.name}</span>
                <span className="num" style={{ color: `var(--${s.tone === 'up' ? 'up' : s.tone === 'warn' ? 'warn' : 'down'})` }}>{s.val}</span>
                <span className="dim">{s.target}</span>
                <window.Sparkline data={Array.from({length:24}, () => 1 + Math.random()*s.burn)} w={180} h={20} color={s.tone === 'up' ? '#0ECB81' : s.tone === 'warn' ? '#F0B90B' : '#F6465D'} />
                <span className={`pill ${s.tone}`}>{s.burn}× burn</span>
              </div>
            ))}
          </div>
        </div>
        <div className="col-6 card">
          <window.SectionHeader title="Active alerts" sub={`${window.ALERTS.length} firing · 0 silenced`} actions={<button className="btn sm">Alertmanager →</button>} />
          <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
            {window.ALERTS.map((a, i) => (
              <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 8, padding: 8, background: 'var(--canvas-2)', borderRadius: 6, fontSize: 12 }}>
                <span className={`pill ${a.sev}`}>{a.sev}</span>
                <div style={{ flex: 1 }}>
                  <div className="mono" style={{ color: 'var(--ink)' }}>{a.name}</div>
                  <div className="dim" style={{ fontSize: 11 }}>{a.desc}</div>
                </div>
                <span className="dim">{a.since}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      <div className="card" style={{ marginBottom: 12 }}>
        <window.SectionHeader title="Upstream pools" sub={`${window.UPSTREAMS.length} pools · ${window.UPSTREAMS.reduce((s,x)=>s+x.healthy,0)}/${window.UPSTREAMS.reduce((s,x)=>s+x.members,0)} healthy`} />
        <table className="tbl tbl-compact">
          <thead><tr><th>Pool</th><th>Members</th><th>LB</th><th>Circuit</th><th>p99</th><th>req/s</th><th>Status</th></tr></thead>
          <tbody>
            {window.UPSTREAMS.map(p => {
              const ok = p.healthy === p.members;
              const half = p.cb === 'half-open';
              const open = p.cb === 'open';
              return (
                <tr key={p.name}>
                  <td className="mono">{p.name}</td>
                  <td>
                    <div style={{ display: 'flex', gap: 2 }}>
                      {Array.from({length: p.members}).map((_, i) => (
                        <span key={i} style={{ width: 8, height: 14, background: i < p.healthy ? 'var(--up)' : 'var(--down)', borderRadius: 1 }} />
                      ))}
                      <span className="num dim" style={{ marginLeft: 6, fontSize: 11 }}>{p.healthy}/{p.members}</span>
                    </div>
                  </td>
                  <td className="mono dim">{p.lb}</td>
                  <td><span className={`pill ${open ? 'err' : half ? 'warn' : 'ok'}`}>{p.cb}</span></td>
                  <td className="num">{p.p99 ? `${p.p99}ms` : '—'}</td>
                  <td className="num">{p.rps.toLocaleString()}</td>
                  <td>{ok && !open ? <span className="pill ok">healthy</span> : open ? <span className="pill err">down</span> : <span className="pill warn">degraded</span>}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      <div className="grid-12" style={{ marginBottom: 12 }}>
        <div className="col-6 card">
          <window.SectionHeader title="Cluster peers" sub="5 nodes · raft consensus" />
          <table className="tbl tbl-compact">
            <thead><tr><th>ID</th><th>Address</th><th>Version</th><th>Role</th><th>Heartbeat</th><th>Leases</th></tr></thead>
            <tbody>
              {window.CLUSTER.map(c => (
                <tr key={c.id}>
                  <td className="mono">{c.id}</td>
                  <td className="mono dim">{c.addr}</td>
                  <td><span className={`pill ${c.skew ? 'warn' : 'neutral'}`}>{c.ver}</span></td>
                  <td><span className={`pill ${c.role === 'leader' ? 'solid-yellow' : 'neutral'}`}>{c.role}</span></td>
                  <td className="num dim">{c.lastHB}</td>
                  <td>{c.leases.length === 0 ? <span className="dim">—</span> : c.leases.map(l => <span key={l} className="pill info" style={{ marginRight: 4 }}>{l}</span>)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <div className="col-6 card">
          <window.SectionHeader title="Cert freshness" />
          <table className="tbl tbl-compact">
            <thead><tr><th>Host</th><th>Issuer</th><th>Source</th><th>Expires</th><th>Action</th></tr></thead>
            <tbody>
              {window.CERTS.map(c => {
                const tone = c.days < 7 ? 'err' : c.days < 30 ? 'warn' : 'ok';
                return (
                  <tr key={c.host}>
                    <td className="mono">{c.host}</td>
                    <td className="dim">{c.issuer}</td>
                    <td><span className="pill neutral">{c.source}</span></td>
                    <td><span className={`pill ${tone}`}>{c.days}d</span></td>
                    <td>{c.source === 'acme' ? <button className="btn sm">Renew</button> : <span className="dim">—</span>}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>

      <div className="card">
        <window.SectionHeader title="GitOps sync" sub="auto-pull every 60s from main" actions={<button className="btn sm">Force resync</button>} />
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 14, fontSize: 12 }}>
          <div><div className="field-label">Repo</div><div className="mono">git@github.com:org/aegis-config</div></div>
          <div><div className="field-label">Branch</div><span className="pill neutral">main</span></div>
          <div><div className="field-label">Last sync</div><span className="num">14s ago</span></div>
          <div><div className="field-label">Drift</div><span className="pill ok">none</span></div>
          <div style={{ gridColumn: '1 / -1' }}>
            <div className="field-label">HEAD commit</div>
            <div className="mono" style={{ fontSize: 11 }}>
              <span style={{ color: 'var(--brand-yellow)' }}>a8b1f2c</span> <span className="dim">— update sqli-007 risk threshold (admin, 17:09)</span>
              <span className="pill ok" style={{ marginLeft: 8 }}>signature verified</span>
            </div>
          </div>
        </div>
      </div>
    </>
  );
}

Object.assign(window, {
  PageOverview, PageLiveFeed, PageAttackEvents, PageAnalytics, PageAuditLog,
  PageRuleManager, PageTierConfig, ListPage, PageSettings, PageTracking,
});
