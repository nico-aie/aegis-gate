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
          <p className="page-subtitle">Realtime WAF traffic monitoring · last update {tick}s</p>
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
          <h1 className="page-title">Attack Events</h1>
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
          {botSegments.length === 0 ? (
            <div style={{ padding: 16, fontSize: 12, color: 'var(--ink-dim)', textAlign: 'center' }}>
              No bot classifications recorded in the last {win}.
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
                  <strong style={{ color: 'var(--ink-strong)' }}>{malicious.pct.toFixed(1)}%</strong> of classified bot traffic in this window flagged malicious.
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
          <h1 className="page-title">Analytics</h1>
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
            sub="WAF + upstream end-to-end"
          />
          <div style={{ padding: 16, fontSize: 12, color: 'var(--ink-dim)', textAlign: 'center', minHeight: 120, display: 'flex', alignItems: 'center', justifyContent: 'center', flexDirection: 'column', gap: 6 }}>
            <span>Latency percentiles ship via Prometheus.</span>
            <span style={{ fontSize: 11 }}>Scrape <code>/metrics</code> for <code>waf_request_duration_ms_bucket</code> or wire Grafana for live sparklines.</span>
          </div>
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
          <window.SectionHeader
            title="Error rate by route"
            sub="Per-route block volumes"
          />
          <div style={{ padding: 16, fontSize: 12, color: 'var(--ink-dim)', textAlign: 'center', minHeight: 120, display: 'flex', alignItems: 'center', justifyContent: 'center', flexDirection: 'column', gap: 6 }}>
            <span>Per-route aggregation ships in a follow-up.</span>
            <span style={{ fontSize: 11 }}>For now: <a href="#/audit" style={{ color: 'var(--accent)' }}>Audit Log</a> shows every block with its <code>path</code>; <a href="#/attacks" style={{ color: 'var(--accent)' }}>Attack Events</a> shows top attackers.</span>
          </div>
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
    pri: 100,
    field: 'any',
    op: 'regex',
    pattern: '',
    action: 'block',
    risk: 50,
    enabled: r.enabled !== undefined ? r.enabled : true,
    cat: 'custom',
    hits1h: 0,
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
// CQF-T3 — detector mask editor. Audit-mutated edit of the
// base mask + per-tier overrides via `PUT /api/detectors`.
// Compliance-locked classes (sqli/xss/path_traversal/ssrf when
// any compliance mode is active) render as a disabled toggle.
const MASK_CLASSES = ['sqli', 'xss', 'path_traversal', 'ssrf', 'header_injection', 'body_abuse', 'recon', 'brute_force'];

function DetectorMaskCard() {
  const api = window.useDetectorsApi();
  const baseMask = api.data?.mask || null;
  const overrides = api.data?.overrides || {};
  const lockedClasses = api.data?.locked_classes || [];
  const complianceModes = api.data?.compliance_modes || [];

  const [busy, setBusy] = useStateP(false);
  const [editing, setEditing] = useStateP(null);
  const [draft, setDraft] = useStateP({});

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

  async function saveEdit() {
    if (busy) return;
    setBusy(true);
    try {
      const body = editing === 'base'
        ? { mask: draft }
        : { overrides: { [editing]: draft } };
      const r = await window.detectorsPut(body);
      if (r.ok) {
        window.aegisToast(`Saved detector mask · ${editing}`, 'ok');
        setEditing(null);
        api.reload && api.reload();
      } else {
        const msg = (r && (r.message || r.error || r.reason)) || `status ${r.status}`;
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
      if (r.ok) {
        window.aegisToast(`Cleared ${tierName} override`, 'ok');
        api.reload && api.reload();
      } else {
        const msg = (r && (r.message || r.error || r.reason)) || `status ${r.status}`;
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
            return (
              <button
                key={cls}
                onClick={() => {
                  if (!isEditing || locked) return;
                  setDraft(d => ({ ...d, [cls]: !d[cls] }));
                }}
                disabled={!isEditing || locked || busy}
                title={locked ? `${cls} is pinned by active compliance mode` : (enabled ? 'enabled — click to disable' : 'disabled — click to enable')}
                className={`pill ${enabled ? 'ok' : 'neutral'}`}
                style={{
                  fontSize: 10,
                  cursor: isEditing && !locked ? 'pointer' : 'default',
                  opacity: locked ? 0.6 : 1,
                  padding: '2px 8px',
                  border: isEditing && !locked ? '1px dashed var(--hairline)' : '1px solid transparent',
                }}
              >
                {locked && '🔒 '}{cls}{!enabled && ' · off'}
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
          <div className="card-title">Detector Mask</div>
          <div className="card-subtitle">
            Edit the base mask or per-tier overrides. Locked classes
            (🔒) are pinned by active compliance modes
            {complianceModes.length > 0 && (
              <> ({complianceModes.join(', ')})</>
            )}
            . Audit-mutated; takes effect within one hot-reload tick.
          </div>
        </div>
      </div>
      {renderRow('base', baseMask, 'base')}
      {Object.keys(overrides).length === 0 ? (
        <div style={{ borderTop: '1px solid var(--hairline)', padding: 10, fontSize: 11, color: 'var(--ink-dim)', fontStyle: 'italic' }}>
          No per-tier overrides configured. Use Edit on a tier-specific row below to add one — or PUT a JSON body with the desired tier name to /api/detectors.
        </div>
      ) : (
        Object.entries(overrides).map(([tier, mask]) => renderRow(tier, mask, tier))
      )}
    </div>
  );
}

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

  // CQF-T2 — Add entry form + per-row delete. Form is shown
  // inline in the page-head when "Add entry" is clicked; submit
  // lands via accessListAdd → audit-mutated POST.
  const [showForm, setShowForm] = useStateP(false);
  const [busy, setBusy] = useStateP(false);
  const [draftKind, setDraftKind] = useStateP('ip');
  const [draftValue, setDraftValue] = useStateP('');
  const [draftNote, setDraftNote] = useStateP('');
  const [draftBypass, setDraftBypass] = useStateP('');

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
      const r = await window.accessListAdd(kind, entry);
      if (r.ok) {
        window.aegisToast(`Added ${kind} entry ${draftKind}:${value}`, 'ok');
        setDraftValue(''); setDraftNote(''); setDraftBypass('');
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
          <button
            className="btn primary"
            onClick={() => setShowForm(v => !v)}
            disabled={busy}
          >
            <window.I.Plus /> {showForm ? 'Cancel' : 'Add entry'}
          </button>
        </div>
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
              </select>
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 4, flex: 1, minWidth: 220 }}>
              <label style={{ fontSize: 10, color: 'var(--ink-dim)', textTransform: 'uppercase', letterSpacing: 0.4 }}>Value</label>
              <input
                type="text"
                value={draftValue}
                onChange={e => setDraftValue(e.target.value)}
                onKeyDown={e => { if (e.key === 'Enter') submitAdd(); }}
                placeholder={draftKind === 'ip' ? '203.0.113.7' : draftKind === 'cidr' ? '203.0.113.0/24' : 'AS13335'}
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
            {data.length === 0 && (
              <tr><td colSpan={7} style={{ textAlign: 'center', padding: 16, color: 'var(--ink-dim)', fontSize: 12 }}>
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
    </>
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
        window.aegisToast(`Risk thresholds → challenge ≥ ${body.challenge_at} · block ≥ ${body.block_at}`, 'ok');
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
          <div className="card-title">Risk thresholds</div>
          <span className={`pill ${riskApi.error ? 'warn' : 'ok'}`}>
            {riskApi.error ? 'fetch failed' : 'live'}
          </span>
          {riskApi.data && (
            <span style={{ fontSize: 11, color: 'var(--ink-dim)', marginLeft: 'auto' }}>
              live: challenge ≥ {riskApi.data.challenge_at} · block ≥ {riskApi.data.block_at}
            </span>
          )}
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12, marginBottom: 6 }}>
              <span>Allow (0 – {allow})</span><span className="num">{allow}</span>
            </div>
            <input type="range" min="0" max="100" value={allow} disabled={riskBusy} onChange={e => setAllow(+e.target.value)} style={{ width: '100%', accentColor: 'var(--brand-yellow)' }} />
          </div>
          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12, marginBottom: 6 }}>
              <span>Challenge ({allow + 1} – {challenge})</span><span className="num">{challenge}</span>
            </div>
            <input type="range" min={allow+1} max="100" value={challenge} disabled={riskBusy} onChange={e => setChallenge(+e.target.value)} style={{ width: '100%', accentColor: 'var(--brand-yellow)' }} />
          </div>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 12 }}>
            <div style={{ fontSize: 12, color: 'var(--ink-mute)' }}>
              Block threshold: <span className="num" style={{ color: 'var(--down)' }}>≥ {challenge + 1}</span>
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

      <div className="card" style={{ marginTop: 12 }}>
        <div className="card-head">
          <div>
            <div className="card-title">
              Cache management
              <span className="pill warn" style={{ marginLeft: 8 }} title="Cache sizes / ages / entry counts are static demo values. Reset button is non-functional. Real cache stats need /api/caches/stats which isn't implemented yet.">
                demo data
              </span>
            </div>
            <div className="card-sub">Flush internal caches without restarting the WAF</div>
          </div>
          <button className="btn danger" disabled><window.I.Refresh /> Reset all caches</button>
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
      if (r && r.ok) {
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
            alertReceivers.reload && alertReceivers.reload();
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

      {/* CC-T2.2 — alert-channel management. Lives next to the
          Active alerts panel because the two are operationally
          paired: the alerts pane shows what fired; this pane
          configures *where* the next firing alert is sent. */}
      <AlertChannelsCard receiversApi={alertReceivers} />

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

function PageUpstreams() {
  const cfgApi = window.useUpstreamsConfigApi();
  const summaryApi = window.useUpstreamsApi();
  const pools = cfgApi.data?.pools || {};
  const names = Object.keys(pools).sort();
  const summary = summaryApi.data?.pools || [];

  const [selected, setSelected] = useStateP(null);
  const [editor, setEditor] = useStateP(null); // null | { mode: 'add'|'edit', name?, pool? }
  const [deleteModal, setDeleteModal] = useStateP(null); // null | { name, refs }
  const [busy, setBusy] = useStateP(false);

  // Auto-select first pool when data lands.
  useEffectP(() => {
    if (!selected && names.length > 0) setSelected(names[0]);
  }, [names.length, selected]);

  const totalMembers = names.reduce((s, n) => s + (pools[n].members?.length || 0), 0);
  const orphaned = names.filter(n => (pools[n].referenced_by_routes || []).length === 0).length;

  const openAdd = () => setEditor({ mode: 'add' });
  const openEdit = (name, pool) => setEditor({ mode: 'edit', name, pool });

  async function savePool({ name, body }) {
    setBusy(true);
    try {
      const r = await window.poolUpsert(name, body);
      if (r.status === 200 && r.ok) {
        window.aegisToast(`Pool "${name}" saved`, 'ok');
        cfgApi.reload && cfgApi.reload();
        setEditor(null);
        setSelected(name);
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

  async function confirmDelete() {
    if (!deleteModal) return;
    const { name } = deleteModal;
    setBusy(true);
    try {
      const r = await window.poolDelete(name);
      if (r.status === 200 && r.ok) {
        window.aegisToast(`Pool "${name}" removed`, 'ok');
        cfgApi.reload && cfgApi.reload();
        setDeleteModal(null);
        // Pick a different pool, since the current selection just disappeared.
        const remaining = names.filter(n => n !== name);
        setSelected(remaining[0] || null);
      } else if (r.status === 409 && Array.isArray(r.referenced_by_routes)) {
        // Backend returned the route-reference list — surface it
        // in the modal so the operator sees what's blocking.
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
          <h1 className="page-title">Upstreams</h1>
          <p className="page-subtitle">
            <span className="num">{names.length}</span> pool{names.length === 1 ? '' : 's'} ·
            <span className="num"> {totalMembers}</span> total members ·
            <span className="num"> {orphaned}</span> unreferenced
            <span style={{ marginLeft: 8 }}>
              <span className={`pill ${cfgApi.error ? 'warn' : 'ok'}`}>
                {cfgApi.error ? 'fetch failed' : 'live'}
              </span>
            </span>
            <span style={{ marginLeft: 8 }}>
              <span className="pill ok" title="CC-T1.1.b shipped — PUT/DELETE land via the audit-mutated pipeline; the proxy hot-swaps without restart.">audit-mutated CRUD</span>
            </span>
          </p>
        </div>
        <div className="page-actions">
          <button className="btn primary" onClick={openAdd}>+ Add pool</button>
          <button className="btn" onClick={() => {
            cfgApi.reload && cfgApi.reload();
            summaryApi.reload && summaryApi.reload();
          }}>
            <window.I.Refresh /> Refresh
          </button>
        </div>
      </div>

      <div className="grid-12">
        <div className="col-4">
          <div className="card" style={{ padding: 8 }}>
            {names.length === 0 && (
              <div style={{ padding: 16, textAlign: 'center', fontSize: 12, color: 'var(--ink-dim)' }}>
                No upstream pools configured. Click <strong>+ Add pool</strong> or edit <span className="mono">upstreams:</span> in waf.yaml.
              </div>
            )}
            {names.map(n => (
              <PoolListRow
                key={n}
                name={n}
                pool={pools[n]}
                summary={summary}
                isSelected={n === selected}
                onSelect={setSelected}
              />
            ))}
          </div>
        </div>
        <div className="col-8">
          <PoolDetail
            name={selected}
            pool={selected ? pools[selected] : null}
            onEdit={openEdit}
            onDelete={openDelete}
            busy={busy}
          />
        </div>
      </div>

      {editor && (
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
          onConfirm={confirmDelete}
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
    setD(prev => ({ ...prev, members: [...prev.members, { addr: '', weight: 1, zone: '' }] }));
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
                <span className="field-label" style={{ marginBottom: 0 }}>Upstream TLS (https)</span>
              </label>
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

  return (
    <div className="card" style={{ marginBottom: 12 }}>
      <div className="card-head">
        <div>
          <div className="card-title">Layer 2 · Cluster peers</div>
          <div className="card-sub">
            {peers.length} {peers.length === 1 ? 'peer' : 'peers'}
            {ourNode ? ` · this node ${ourNode}${isLeader ? ' · leader' : ''}` : ' · standalone'}
          </div>
        </div>
        <span className="pill neutral">L2</span>
      </div>
      {peers.length === 0 && (
        <div style={{ padding: 12, fontSize: 12, color: 'var(--ink-dim)', textAlign: 'center' }}>
          No cluster peers — running standalone.
        </div>
      )}
      {peers.length > 0 && (
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
            {peers.map(p => {
              const isMe = p.node_id === ourNode;
              return (
                <tr key={p.node_id} style={isMe ? { background: 'var(--surface-3)' } : undefined}>
                  <td>
                    <code>{p.node_id}</code>
                    {isMe && <span style={{ marginLeft: 6, fontSize: 10, color: 'var(--ink-dim)' }}>(this)</span>}
                  </td>
                  <td>
                    <span className={`pill ${p.healthy ? 'up' : 'down'}`}>
                      {p.healthy ? 'healthy' : 'down'}
                    </span>
                  </td>
                  <td style={{ textAlign: 'right' }} className="num">
                    {p.last_heartbeat_age_s != null ? `${p.last_heartbeat_age_s}s ago` : '—'}
                  </td>
                  <td>{p.leader ? <span className="pill solid-yellow">leader</span> : <span className="dim">replica</span>}</td>
                </tr>
              );
            })}
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
          }}>
            <window.I.Refresh /> Refresh
          </button>
        </div>
      </div>

      <ScalingL1Card runtime={runtime} />
      <ScalingL2Card cluster={cluster} onDrain={onDrain} draining={draining} />
      <ScalingL3Card state={state} />
    </>
  );
}

Object.assign(window, {
  PageOverview, PageLiveFeed, PageAttackEvents, PageAnalytics, PageAuditLog,
  PageRuleManager, PageTierConfig, ListPage, PageSettings, PageTracking,
  PageUpstreams,
  // SC-T2 — Scaling page (L1 workers + L2 cluster + L3 state).
  PageScaling,
});
