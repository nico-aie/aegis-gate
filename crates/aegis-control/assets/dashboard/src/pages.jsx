/* global React */
const { useState: useStateP, useEffect: useEffectP, useMemo: useMemoP, useRef: useRefP, Fragment } = React;

// LOW-ADM-05 (2026-05-12) — 24-hour clock helpers.  Without
// these, `Date.toLocaleString()` / `Date.toLocaleTimeString()`
// rendered en-US 12-hour AM/PM in places (Config history,
// HEARTBEAT column) while the rest of the dashboard read as
// 24-hour, which the QA pass flagged as inconsistent.  Pin
// `hour12: false` here so every wall-clock string the dashboard
// emits reads the same way.
//
// Two helpers because the call sites need different precision:
//   - `fmtClockTime(d)`         → "12:28:45"
//   - `fmtAbsoluteTimestamp(d)` → "May 12, 12:28:45"
// Both fall back to "—" for null / invalid Dates.
function fmtClockTime(d) {
  const date = d instanceof Date ? d : (d ? new Date(d) : null);
  if (!date || isNaN(date.getTime())) return '—';
  return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false });
}
function fmtAbsoluteTimestamp(d) {
  const date = d instanceof Date ? d : (d ? new Date(d) : null);
  if (!date || isNaN(date.getTime())) return '—';
  return date.toLocaleString([], {
    hour: '2-digit', minute: '2-digit', second: '2-digit',
    month: 'short', day: 'numeric',
    hour12: false,
  });
}

// 2026-05-19 — `AuditEvent` ts wire shape was renamed to `ts_ms`
// (integer milliseconds) at the Rust serde layer; the legacy
// string `ts` is no longer emitted (see crates/aegis-core/src/
// audit.rs:188 — `#[serde(rename = "ts_ms", serialize_with =
// serialize_ts_as_ms)]`). Pre-fix every dashboard surface read
// `e.ts` and got `undefined`, turning `new Date(undefined)`
// into Invalid Date → `NaN:NaN:NaN`. This helper centralises
// the field-name fallback so adding another sink shape later
// touches one site.
//
// Returns NaN when neither field is parseable; callers gate on
// `Number.isFinite` and render "—".
function eventTimestampMs(ev) {
  if (!ev || typeof ev !== 'object') return NaN;
  if (typeof ev.ts_ms === 'number' && Number.isFinite(ev.ts_ms)) {
    return ev.ts_ms;
  }
  if (typeof ev.ts === 'number' && Number.isFinite(ev.ts)) {
    return ev.ts;
  }
  if (typeof ev.ts === 'string' && ev.ts.length > 0) {
    const parsed = Date.parse(ev.ts);
    return Number.isFinite(parsed) ? parsed : NaN;
  }
  return NaN;
}

// Resolve a request's client IP from an audit event. The
// `/api/audit/since` wire shape renames the Rust `client_ip`
// field to `ip` (see aegis-core/src/audit.rs `#[serde(rename =
// "ip")]`, F-CRITICAL-002 contract alignment), so consumers that
// read `e.client_ip` got an empty cell. Prefer the wire field
// `ip`; keep `client_ip` as a fallback in case a caller passes a
// raw Rust-shaped object.
function eventIp(ev) {
  if (!ev || typeof ev !== 'object') return '';
  return ev.ip || ev.client_ip || '';
}

// ============== OVERVIEW ==============
// Deterministic distinct colour for any class name not in an explicit
// palette below — golden-angle hue spread (FNV-1a hash → hue) so an
// unrecognised or newly-added class gets its own hue instead of every
// such class collapsing onto one shared grey. Stable per name across
// renders.
function stableHueColor(name) {
  let h = 2166136261;
  for (let i = 0; i < name.length; i++) {
    h ^= name.charCodeAt(i);
    h = Math.imul(h, 16777619) >>> 0;
  }
  const hue = ((h % 360) * 137.508) % 360; // golden angle for spread
  return `hsl(${hue.toFixed(1)}, 62%, 58%)`;
}

// Color palette for detector/OWASP categories — overlaid on API-returned
// `name` strings (stable identifiers like `sqli`, `xss`, `ssrf`, …).
// Every distinct class has a distinct hex; aliases (recon/recon_path,
// cmdi/command_injection, ssti/template_injection) intentionally share.
const CAT_COLOR = {
  sqli: '#F6465D',
  xss: '#A555E0',
  ssrf: '#F472B6',
  path_traversal: '#A78BFA',
  recon: '#4DA8FF',
  recon_path: '#4DA8FF',
  cmdi: '#FF7A45',
  command_injection: '#FF7A45',
  nosql_injection: '#14B8A6',
  ssti: '#FB923C',
  template_injection: '#FB923C',
  open_redirect: '#38BDF8',
  header_injection: '#B45309',
  body_abuse: '#84CC16',
  brute_force: '#E11D48',
  velocity_sequence: '#6366F1',
  ai: '#D946EF',
  lfi: '#EAB308',
  honeypot: '#FACC15',
  rce: '#DC2626',
};
function colorFor(name) { return CAT_COLOR[name] || stableHueColor(name); }

// C-3 (multi-node consistency) — clarify that the per-node traffic
// metrics on this page (RPS, Top Attackers, latency, action mix) reflect
// THIS node's slice of the fleet's traffic, not cluster totals. The
// admin console reads a node-local Prometheus registry, while shared
// state (risk, block-list, config) is consistent via Redis — so a
// single node's "Top Attackers" / "RPS" is only ~1/N of the picture
// behind a load balancer. Rendered only when the cluster roster shows
// more than one node, so single-node deployments stay uncluttered.
// Fleet-wide aggregation lives in the observability stack (SigNoz),
// keyed by host.name — see plans/issues/multi-node-consistency.md (C-3).
function FleetNodeBanner() {
  const cluster = window.useClusterApi ? window.useClusterApi() : { data: null };
  const stats = window.useStatsApi ? window.useStatsApi() : { data: null };
  // Cluster Phase 4 (§2a) + SCOPE-P1a: `/api/fleet/status` self-declares
  // whether fleet view is `configured` (publish task up) and whether a
  // merged snapshot is currently `active`. `configured && !active` is the
  // degraded state (enabled but no merge yet) — distinct from fleet view
  // being off. Per-panel badges below say which panels are actually
  // merged, so this banner no longer over-claims (e.g. the traffic chart
  // and Upstream stay node-local even under Fleet view).
  //
  // NB: this hook MUST precede the single-node early return below —
  // calling it after a conditional return varies the hook count between
  // renders (React #310) as the cluster roster loads.
  const scope = window.useFleetScopeApi ? window.useFleetScopeApi() : { data: null };
  const peers = cluster.data?.peers || [];
  if (peers.length < 2) return null; // single node → no banner
  const ourNode = cluster.data?.our_node || 'this node';
  const configured = !!scope.data?.configured;
  const active = !!scope.data?.active;
  const fleetNodes = scope.data?.nodes ?? stats.data?.fleet_nodes;
  const degraded = configured && !active;
  const accent = active
    ? 'var(--ok, #2ea043)'
    : degraded
      ? 'var(--warn, #d29922)'
      : 'var(--accent)';
  return (
    <div
      className="callout"
      style={{
        marginBottom: 12,
        display: 'flex',
        alignItems: 'center',
        gap: 10,
        borderLeft: `3px solid ${accent}`,
      }}
      role="note"
    >
      <span style={{ fontSize: 16 }} aria-hidden="true">🖧</span>
      <div style={{ flex: 1, fontSize: 13 }}>
        {active ? (
          <>
            <strong>{peers.length}-node fleet — Fleet view</strong>
            <span style={{ marginLeft: 8, color: 'var(--ink-mute)' }}>
              Panels tagged <span className="scope-badge scope-fleet">Fleet</span> are merged across{' '}
              <code>{fleetNodes}</code> node{fleetNodes === 1 ? '' : 's'};{' '}
              <span className="scope-badge scope-node">This node</span> panels (e.g. Upstream, and
              the traffic chart beyond a 5m window) are <code>{ourNode}</code> only.
            </span>
          </>
        ) : degraded ? (
          <>
            <strong>{peers.length}-node fleet — Fleet view degraded</strong>
            <span style={{ marginLeft: 8, color: 'var(--ink-mute)' }}>
              <code>cluster.fleet_view</code> is enabled but no merged snapshot is live yet —
              showing <code>{ourNode}</code> only. Panels switch to{' '}
              <span className="scope-badge scope-fleet">Fleet</span> once a merge publishes.
            </span>
          </>
        ) : (
          <>
            <strong>{peers.length}-node fleet — showing THIS node</strong>
            <span style={{ marginLeft: 8, color: 'var(--ink-mute)' }}>
              Traffic metrics below are <code>{ourNode}</code>&apos;s slice, not
              fleet totals. Enable <code>cluster.fleet_view</code> for merged
              totals, or use your observability dashboards.
            </span>
          </>
        )}
      </div>
    </div>
  );
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
  // SCOPE-P1a — per-panel scope badges. `scopeBadge(capable)` reads
  // Fleet only when fleet view is active AND the panel is fleet-capable;
  // node-local panels (Upstream, timeseries) pass `false`.
  const scopeBadge = window.useScopeBadge ? window.useScopeBadge() : () => null;
  // LOW-SO-01 (2026-05-12) — the 1m/5m/15m/1h pills below now
  // drive the timeseries window + bucket size so the chart and
  // its subtitle stay in sync. Buckets pick the round number
  // that keeps the rendered series under ~120 points.
  const TRAFFIC_WINDOWS = [
    { label: '1m',  windowSecs: 60,    bucketSecs: 1   },
    { label: '5m',  windowSecs: 300,   bucketSecs: 5   },
    { label: '15m', windowSecs: 900,   bucketSecs: 10  },
    { label: '1h',  windowSecs: 3600,  bucketSecs: 30  },
  ];
  const [trafficWindow, setTrafficWindow] = useStateP(TRAFFIC_WINDOWS[0]);
  const tsApi = window.useTimeseriesApi(trafficWindow.windowSecs, trafficWindow.bucketSecs);
  const distApi = window.useAttacksDistributionApi(900); // /api/attacks/distribution — 15m
  const topApi = window.useAttacksTopApi(900, 5);  // /api/attacks/top — 5 attackers, 15m
  const tick = window.useTicking(2000);
  const [drawerEvent, setDrawerEvent] = useStateP(null);
  // 2026-05-19 — "Live attack origins" is the biggest card on the
  // Overview page. Operators staring at zero blips on a quiet
  // system prefer to fold it; collapsed state hides the WorldMap
  // body (the expensive render) but keeps the title + pills
  // visible so the count is still at a glance.
  const [originsExpanded, setOriginsExpanded] = useStateP(true);

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
    // 2026-05-18 (QC TLS-wiring batch — F-CRITICAL-015): ASN
    // ownership classification surfaced from the bot classifier's
    // `classify_asn` table. One of "hosting", "datacenter",
    // "residential", "mobile", "unknown", or null when no ASN
    // lookup happened (fingerprint identifier, or no MaxMind DB).
    asnClass: a.asn_class || null,
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
  // 2026-05-21 — driven by the overlay-aware /api/incidents enriched
  // list (status `firing` only), same source as the bell + Active
  // alerts panel, so an ack/snooze/resolve on the Incidents page
  // clears this banner too. The old /api/alerts source read a
  // separate legacy store (tracking.ack_store) that resolve never
  // touched, so resolved alerts lingered here. Falls back to
  // raw_alerts when the SLO engine isn't wired (tests).
  const overviewAlerts = window.useIncidentsApi
    ? window.useIncidentsApi()
    : { data: null };
  const firingAlerts = (
    Array.isArray(overviewAlerts.data?.incidents)
      ? overviewAlerts.data.incidents.filter(i => i.status === 'firing')
      : (overviewAlerts.data?.raw_alerts?.firing || [])
  ).map(i => ({ ...i, name: i.name || (i.sli ? `${i.sli}-${i.window_hours}h` : i.id) }));

  return (
    <>
      <FleetNodeBanner />
      <SecOpsPostureCard />
      <div className="page-head">
        <div>
          <h1 className="page-title">
            Overview
            <window.PageTitleRefresh
              onClick={() => {
                stats.reload && stats.reload();
                tsApi.reload && tsApi.reload();
                distApi.reload && distApi.reload();
                topApi.reload && topApi.reload();
                upstreamsLive.reload && upstreamsLive.reload();
              }}
              label="Refresh all Overview tiles"
            />
          </h1>
          <p className="page-subtitle">Realtime WAF traffic monitoring · last update {tick}s</p>
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

      {/* AI insights — Operator Copilot (shipped; Observability → Copilot) */}
      <div className="ai-card" style={{ marginBottom: 12 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <span className="ai-tag"><window.I.Sparkles /> AI INSIGHTS</span>
          <span className="pill ok">Available</span>
          <span style={{ fontSize: 12, color: 'var(--ink-mute)' }}>
            Situational briefs &amp; smart-catch triage over the WAF&apos;s own telemetry — advisory only.
          </span>
          <button
            type="button"
            className="btn sm"
            style={{ marginLeft: 'auto' }}
            onClick={() => window.openCopilot && window.openCopilot()}
          >
            Open Copilot →
          </button>
        </div>
      </div>

      {/* KPI tiles */}
      <div className="kpi-row">
        <window.StatTile
          title="Requests / s"
          value={requestRate !== undefined ? requestRate.toFixed(1) : '—'}
          sub={<>10-second sliding average</>}
          icon={<window.I.Activity />}
          sparkData={sparkTotal}
          sparkColor="#3B82F6"
          scope={scopeBadge(true)}
        />
        <window.StatTile
          title="Block rate · last 10s"
          value={blockRate !== undefined ? `${blockRate.toFixed(1)}%` : '—'}
          sub={<><span className="num">{blocksTotal.toLocaleString()}</span> blocked · process-lifetime count</>}
          icon={<window.I.Ban />}
          tone="down"
          sparkData={sparkBlocked}
          sparkColor="#F6465D"
          scope={scopeBadge(true)}
        />
        <window.StatTile
          title="Active threats"
          value={String(activeThreats)}
          sub={<>IPs over risk threshold · last 15m</>}
          icon={<window.I.Siren />}
          tone="warn"
          scope={scopeBadge(true)}
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
          scope={scopeBadge(false)}
        />
      </div>

      {/* World map (wow #1) */}
      <div className="card" style={{ padding: 0, overflow: 'hidden', marginBottom: 12 }}>
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            padding: '12px 16px',
            borderBottom: originsExpanded ? '1px solid var(--hairline)' : 'none',
          }}
        >
          <button
            type="button"
            onClick={() => setOriginsExpanded(!originsExpanded)}
            aria-expanded={originsExpanded}
            title={originsExpanded ? 'Collapse Live attack origins' : 'Expand Live attack origins'}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: 8,
              background: 'none',
              border: 'none',
              padding: 0,
              cursor: 'pointer',
              color: 'inherit',
              textAlign: 'left',
            }}
          >
            <span
              aria-hidden="true"
              style={{ fontSize: 10, color: 'var(--ink-dim)', width: 12 }}
            >
              {originsExpanded ? '▼' : '▶'}
            </span>
            <div>
              <div style={{ fontSize: 13, fontWeight: 600, display: 'flex', alignItems: 'center', gap: 8 }}>
                Live attack origins {scopeBadge(true)}
              </div>
              <div style={{ fontSize: 11, color: 'var(--ink-dim)' }}>
                Real-time geolocation of blocked requests · last 60s
                {!originsExpanded && ' · collapsed'}
              </div>
            </div>
          </button>
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
        {originsExpanded && (
          <>
            {blips.length === 0 && topAttackers.length > 0 && (
              <div style={{ padding: '8px 16px', fontSize: 11, color: 'var(--ink-dim)', borderBottom: '1px solid var(--hairline)' }}>
                {geoipLoaded
                  ? 'Map empty because none of the current attackers have a public IP MaxMind can resolve (e.g. localhost). The Top Attackers table below still shows every IP.'
                  : <>Map empty because GeoIP DB isn't loaded. The Top Attackers table below still shows every IP.{' '}<a href="#/help" style={{ color: 'var(--accent)' }}>How to install GeoIP →</a></>
                }
              </div>
            )}
            <window.WorldMap blips={blips} h={300} />
          </>
        )}
      </div>

      {/* Traffic chart + distribution */}
      <div className="section-row">
        <div className="card">
          <div className="card-head">
            <div>
              <div className="card-title" style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                {/* Fleet-merged only within the bounded window the snapshot
                    carries (≤5m); wider windows fall back to this node. */}
                Traffic vs Blocked {scopeBadge(trafficWindow.windowSecs <= 300)}
              </div>
              <div className="card-sub">
                Realtime · {trafficWindow.label} window · {trafficWindow.bucketSecs}s buckets
              </div>
            </div>
            <div style={{ display: 'flex', gap: 6 }}>
              {TRAFFIC_WINDOWS.map(w => (
                <button
                  key={w.label}
                  className={`chip ${trafficWindow.label === w.label ? 'active' : ''}`}
                  onClick={() => setTrafficWindow(w)}
                >
                  {w.label}
                </button>
              ))}
            </div>
          </div>
          <window.TrafficChart series={series} h={220} />
        </div>
        <div className="card">
          <div className="card-head">
            <div>
              <div className="card-title" style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                Attack distribution {scopeBadge(true)}
              </div>
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

      {/* Top attackers */}
      <div className="card">
        <div className="card-head">
          <div className="card-title" style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            Top attacker IPs · 15m {scopeBadge(true)}
          </div>
          <a className="btn sm" href="#/top-attackers">View all →</a>
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
                <td>
                  <span style={{ color: 'var(--ink-mute)' }}>{a.geo ? `${a.geo.cc} · ${a.geo.city}` : '—'}</span>
                  {/* 2026-05-18 (QC TLS-wiring batch — F-CRITICAL-015):
                      surface ASN ownership classification as a small
                      pill next to country. Tinted by tier so operators
                      can spot hosting/datacenter traffic at a glance
                      without reading the AS number. */}
                  {a.asnClass && a.asnClass !== 'unknown' && (
                    <span
                      className={`pill ${
                        a.asnClass === 'datacenter' ? 'down' :
                        a.asnClass === 'hosting'    ? 'warn' :
                        a.asnClass === 'mobile'     ? 'neutral' :
                        a.asnClass === 'residential' ? 'ok' :
                        'neutral'
                      }`}
                      style={{ fontSize: 9, marginLeft: 6 }}
                      title={a.asn ? `AS${a.asn} — ${a.asnClass}` : a.asnClass}
                    >
                      {a.asnClass}
                    </span>
                  )}
                </td>
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
  const tierInferred = !!data?.tierInferred;
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
  // 2026-05-20 — request echo captured on detection blocks: redacted
  // headers + a bounded body preview. Rendered in dedicated sections
  // below and excluded from the generic "Extra fields" dump.
  const reqHeaders = fields?.request_headers && typeof fields.request_headers === 'object'
    ? fields.request_headers
    : null;
  const headerEntries = reqHeaders
    ? Object.entries(reqHeaders).sort(([a], [b]) => a.localeCompare(b))
    : [];
  const bodyPreview = typeof fields?.request_body_preview === 'string' ? fields.request_body_preview : null;
  const bodyBytes = Number.isFinite(Number(fields?.request_body_bytes)) ? Number(fields.request_body_bytes) : null;
  const bodyTruncated = fields?.request_body_truncated === true;
  // 2026-05-21 — per-request detector score (sum of THIS request's
  // signals), distinct from `risk` (cumulative composite-key score).
  const reqScore = Number.isFinite(Number(fields?.request_score)) ? Number(fields.request_score) : null;
  // BUG-audit-detail Fix A — the cumulative-risk bucket key, emitted on
  // EVERY decision (allow / challenge / block). Lets an operator confirm
  // whether same-IP requests share one bucket. Privacy-safe: device_fp is
  // a hash, the raw session is never sent (only `session_present`).
  const riskKey = fields?.risk_key && typeof fields.risk_key === 'object' ? fields.risk_key : null;
  // BUG-streaming-surfaces — streaming-surface detail. A WebSocket frame
  // block carries `surface: "websocket"` + `matched_field` + `message_bytes`
  // (the Messages-tab analogue: which frame field tripped which detector). An
  // SSE response carries `streamed` + `response_inspection_skipped` + a
  // `reason`, so the row can explain that the event stream is pass-through by
  // design rather than looking like an un-scanned allow.
  const wsSurface = fields?.surface === 'websocket';
  const matchedField = typeof fields?.matched_field === 'string' && fields.matched_field ? fields.matched_field : null;
  const messageBytes = Number.isFinite(Number(fields?.message_bytes)) ? Number(fields.message_bytes) : null;
  // The offending frame's content (capped + UTF-8-lossy, only on a block) so
  // the operator can see WHAT tripped the detector, not just which field.
  const messagePreview = typeof fields?.message_preview === 'string' && fields.message_preview ? fields.message_preview : null;
  const isStreamed = fields?.streamed === true;
  const streamReason = typeof fields?.reason === 'string' ? fields.reason : null;
  // Render any backend-emitted scalar that isn't already covered
  // by the dedicated rows above. Stable key ordering so the
  // drawer doesn't reflow on every poll.
  const ECHO_KEYS = ['request_headers', 'request_body_preview', 'request_body_bytes', 'request_body_truncated', 'request_score', 'risk_key',
    'surface', 'matched_field', 'message_bytes', 'message_preview', 'streamed', 'response_inspection_skipped'];
  const extraEntries = fields
    ? Object.entries(fields)
        .filter(([k]) => !['method', 'path', 'status', 'region', 'route_id', 'latency_ms', ...ECHO_KEYS].includes(k))
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
            <div className="dim" title="Cumulative risk accumulated for this source's composite key (IP + device + session). Drives the cumulative IP-risk gate.">IP risk (cumulative)</div>
            {risk !== null ? <window.RiskMeter value={risk} /> : <span className="dim mono">—</span>}
          </div>
          <div>
            <div className="dim" title="Sum of THIS request's detector signals (capped at 100). Compared to the tier's per-request block threshold.">Request score (detectors)</div>
            {reqScore !== null
              ? <window.RiskMeter value={reqScore} />
              : <span className="dim mono">{rules.length > 0 || cats.length > 0 ? '—' : '0'}</span>}
          </div>
          <div>
            <div className="dim">Tier</div>
            {tier ? <window.TierPill value={tier} inferred={tierInferred} /> : <span className="dim mono">—</span>}
          </div>
        </div>
      </div>
      <div>
        <div style={{ fontSize: 10, color: 'var(--ink-faint)', textTransform: 'uppercase', letterSpacing: 1.2, marginBottom: 6 }}>Network</div>
        <div style={{ fontSize: 12, lineHeight: 1.7, fontFamily: 'var(--font-mono)' }}>
          <div><span className="dim">client_ip</span> {ip}</div>
          {riskKey && (
            <div title="The cumulative-risk bucket this request keyed into (IP + device_fp + session). Requests sharing key_hash accumulate risk together. Shown on allow/challenge/block.">
              <span className="dim">risk_key</span>{' '}
              <code style={{ fontSize: 10 }}>{riskKey.key_hash || '—'}</code>
              <span className="dim">{' · device_fp '}</span>
              {riskKey.device_fp ? <code style={{ fontSize: 10 }}>{riskKey.device_fp}</code> : <span className="dim">none</span>}
              <span className="dim">{' · session '}</span>
              <span>{riskKey.session_present ? 'present' : 'none'}</span>
            </div>
          )}
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
      {(wsSurface || isStreamed) && (
        <div>
          <div style={{ fontSize: 10, color: 'var(--ink-faint)', textTransform: 'uppercase', letterSpacing: 1.2, marginBottom: 6 }}>
            {wsSurface ? 'WebSocket frame' : 'SSE stream'}
          </div>
          <div style={{ fontSize: 12, lineHeight: 1.7, fontFamily: 'var(--font-mono)' }}>
            {wsSurface && (
              <>
                <div><span className="dim">surface</span> websocket</div>
                {matchedField && <div><span className="dim">matched_field</span> {matchedField}</div>}
                {messageBytes != null && <div><span className="dim">message_bytes</span> {messageBytes}</div>}
                {messagePreview && (
                  <div style={{ marginTop: 6 }}>
                    <div className="dim" style={{ marginBottom: 2 }}>message (inspected · capped)</div>
                    <pre style={{
                      margin: 0, padding: '6px 8px', borderRadius: 4,
                      background: 'var(--surface-2)', border: '1px solid var(--border)',
                      color: 'var(--ink)', fontSize: 11, whiteSpace: 'pre-wrap',
                      wordBreak: 'break-all', maxHeight: 160, overflow: 'auto',
                    }}>{messagePreview}</pre>
                  </div>
                )}
              </>
            )}
            {isStreamed && (
              <div style={{ color: 'var(--ink-dim)' }}>
                Response stream not inspected (by design){streamReason ? ` · ${streamReason}` : ''}.
                Request + response headers were inspected; the streamed body is pass-through.
              </div>
            )}
          </div>
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
      {headerEntries.length > 0 && (
        <div>
          <div style={{ fontSize: 10, color: 'var(--ink-faint)', textTransform: 'uppercase', letterSpacing: 1.2, marginBottom: 6 }}>
            Request headers
          </div>
          <div style={{ fontSize: 11, fontFamily: 'var(--font-mono)', background: 'var(--canvas-2)', border: '1px solid var(--hairline)', borderRadius: 4, padding: 8, maxHeight: 220, overflow: 'auto' }}>
            {headerEntries.map(([k, v]) => {
              const redacted = v === '[redacted]';
              return (
                <div key={k} style={{ display: 'flex', gap: 8, lineHeight: 1.6 }}>
                  <span style={{ color: 'var(--accent)', minWidth: 140, flexShrink: 0 }}>{k}</span>
                  <span style={{ wordBreak: 'break-all', color: redacted ? 'var(--ink-faint)' : 'var(--ink)', fontStyle: redacted ? 'italic' : 'normal' }}>
                    {String(v)}
                  </span>
                </div>
              );
            })}
          </div>
        </div>
      )}
      {bodyPreview != null && (
        <div>
          <div style={{ fontSize: 10, color: 'var(--ink-faint)', textTransform: 'uppercase', letterSpacing: 1.2, marginBottom: 6, display: 'flex', alignItems: 'center', gap: 8 }}>
            <span>Request payload</span>
            {bodyBytes != null && (
              <span className="dim" style={{ textTransform: 'none', letterSpacing: 0, fontSize: 10 }}>
                {bodyBytes} byte{bodyBytes === 1 ? '' : 's'}{bodyTruncated ? ' · preview truncated' : ''}
              </span>
            )}
          </div>
          {bodyPreview === '' ? (
            <div style={{ fontSize: 11, color: 'var(--ink-dim)', fontStyle: 'italic' }}>
              (empty body)
            </div>
          ) : (
            <pre style={{ fontSize: 11, fontFamily: 'var(--font-mono)', background: 'var(--canvas-2)', border: '1px solid var(--hairline)', borderRadius: 4, padding: 8, margin: 0, maxHeight: 260, overflow: 'auto', whiteSpace: 'pre-wrap', wordBreak: 'break-all', color: 'var(--ink)' }}>
              {bodyPreview}
            </pre>
          )}
          {bodyTruncated && (
            <div style={{ fontSize: 10, color: 'var(--ink-faint)', marginTop: 4 }}>
              Showing the first 2 KB. Sensitive header values are masked as <code>[redacted]</code>.
            </div>
          )}
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
// PR-UX-A3 (2026-05-12) — Suggested action heuristic. Same
// signal the operator would reach for: bias toward block when
// the event already blocked + carried meaningful risk, suggest
// investigation when a request was challenged or the risk
// trend is elevated, otherwise stay silent. Returns a small
// `{label, tone, title}` so the cell renders consistently with
// the rest of the dashboard's pill palette.
function suggestedAction(ev) {
  if (!ev) return null;
  const action = (ev.action || '').toLowerCase();
  const risk = typeof ev.risk === 'number' ? ev.risk : null;
  if (action === 'block' && risk != null && risk >= 70) {
    return { label: 'Block IP', tone: 'down', title: `Risk ${risk} · already blocked once — consider adding to blacklist` };
  }
  if (action === 'challenge') {
    return { label: 'Investigate', tone: 'warn', title: 'Challenge fired — review request shape before allowing' };
  }
  if (action === 'allow' && risk != null && risk >= 60) {
    return { label: 'Watch', tone: 'warn', title: `Risk ${risk} on an allowed request — IP trending` };
  }
  if (action === 'block') {
    return { label: 'Review', tone: 'neutral', title: 'Blocked at low risk — verify rule scope' };
  }
  return null;
}

function PageLiveFeed() {
  const [paused, setPaused] = useStateP(false);
  const { events, connected } = window.useRealLiveFeed(80, paused);
  const [filterAction, setFilterAction] = useStateP('all');
  const [filterTier, setFilterTier] = useStateP('all');
  const [search, setSearch] = useStateP('');
  const [selected, setSelected] = useStateP(null);
  // PR-UX-A3 keyboard nav cursor — index into `recent`.
  const [cursorIdx, setCursorIdx] = useStateP(-1);
  const searchInputRef = useRefP(null);

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

  // PR-UX-A3 (2026-05-12) — keyboard shortcuts. j/k advance the
  // selection cursor, Enter opens the drawer for the cursor row,
  // Esc closes the drawer, Space toggles pause, `/` focuses the
  // search input. Mirrors Gmail/Vim conventions familiar to most
  // SOC analysts. Disabled while the user is typing in an input
  // so j/k don't eat keystrokes inside the search box.
  useEffectP(() => {
    const isTextInput = (el) => {
      if (!el) return false;
      const tag = el.tagName;
      return tag === 'INPUT' || tag === 'TEXTAREA' || el.isContentEditable;
    };
    const onKey = (ev) => {
      if (isTextInput(document.activeElement) && ev.key !== 'Escape') return;
      if (ev.metaKey || ev.ctrlKey || ev.altKey) return;
      if (ev.key === 'j') {
        ev.preventDefault();
        setCursorIdx(i => Math.min(i + 1, recent.length - 1));
      } else if (ev.key === 'k') {
        ev.preventDefault();
        setCursorIdx(i => Math.max(i - 1, 0));
      } else if (ev.key === 'Enter') {
        if (cursorIdx >= 0 && cursorIdx < recent.length) {
          ev.preventDefault();
          setSelected(recent[cursorIdx]);
        }
      } else if (ev.key === 'Escape') {
        if (selected) {
          ev.preventDefault();
          setSelected(null);
        }
      } else if (ev.key === ' ') {
        ev.preventDefault();
        setPaused(p => !p);
      } else if (ev.key === '/') {
        ev.preventDefault();
        if (searchInputRef.current) searchInputRef.current.focus();
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [recent, cursorIdx, selected]);

  return (
    <>
      <SecOpsPostureCard />
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
          <button className={`btn ${paused ? 'primary' : ''}`} onClick={() => setPaused(p => !p)}>
            {paused ? <><window.I.Play /> Resume</> : <><window.I.Pause /> Pause</>}
          </button>
        </div>
      </div>
      <div className="card" style={{ padding: '8px 12px', marginBottom: 8, fontSize: 11, color: 'var(--ink-dim)', display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
        <window.I.Activity />
        <span>
          <strong>Live Feed</strong> shows every <em>request</em> the WAF inspected
          (allow / block / challenge). For configuration mutations and a
          chained, durable trail, see <a href="#/audit" style={{ color: 'var(--accent)' }}>Audit Trail →</a>.
        </span>
        <span style={{ marginLeft: 'auto', fontFamily: 'var(--mono)', fontSize: 10 }}>
          <kbd>j</kbd>/<kbd>k</kbd> nav · <kbd>Enter</kbd> open · <kbd>Esc</kbd> close · <kbd>Space</kbd> pause · <kbd>/</kbd> search
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
            <input
              ref={searchInputRef}
              className="input"
              style={{ paddingLeft: 28 }}
              placeholder="Filter by IP, path…   (press / to focus)"
              value={search}
              onChange={e => setSearch(e.target.value)}
            />
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
                <th style={{ width: 78 }} title="Cumulative risk accumulated for this source's composite key (IP + device + session)">IP risk</th>
                <th style={{ width: 56 }} title="Per-request detector score — sum of THIS request's signals (capped 100), compared to the tier's per-request block threshold">Req</th>
                <th style={{ width: 80 }}>Action</th>
                <th style={{ width: 160 }}>Rules</th>
                <th
                  style={{ width: 100 }}
                  title="Suggested next step based on action + risk score"
                >Suggested</th>
                <th style={{ width: 60 }}></th>
              </tr>
            </thead>
            <tbody>
              {recent.map((e, idx) => (
                <tr
                  key={e.id}
                  className={`${e.id === recent[0]?.id ? 'flash' : ''} ${idx === cursorIdx ? 'kb-cursor' : ''}`}
                  style={idx === cursorIdx ? { outline: '1px solid var(--accent)' } : undefined}
                  onClick={() => { setCursorIdx(idx); setSelected(e); }}
                >
                  <td className="num dim">{e.ts}</td>
                  <td className="mono">{e.ip}</td>
                  <td><span className="mono" style={{ color: e.method === 'POST' ? 'var(--info)' : e.method === 'DELETE' ? 'var(--down)' : 'var(--ink-mute)' }}>{e.method}</span></td>
                  <td>
                    {e.protocol && e.protocol !== 'http' ? (
                      // Plain mono text (no pill) so WS rows read like the
                      // `http` rows and stay on one line in the narrow Proto
                      // column — just a subtle colour cue (blue = ws,
                      // accent = other tunnels).
                      <span
                        className="mono"
                        title={`tunnel event: ${e.protocol}`}
                        style={{
                          fontSize: 10,
                          whiteSpace: 'nowrap',
                          color: e.protocol.startsWith('ws') ? '#60A5FA' : 'var(--accent)',
                        }}
                      >{e.protocol}</span>
                    ) : (
                      <span className="dim mono" style={{ fontSize: 10 }}>http</span>
                    )}
                  </td>
                  <td
                    className="mono"
                    style={{
                      color: 'var(--ink)',
                      maxWidth: 320,
                      overflow: 'hidden',
                      textOverflow: 'ellipsis',
                      whiteSpace: 'nowrap',
                    }}
                    title={e.path}
                  >{e.path}</td>
                  <td><span className="dim" style={{ fontSize: 11 }}>{e.region}</span></td>
                  <td><window.TierPill value={e.tier} inferred={e.tierInferred} /></td>
                  <td><window.RiskMeter value={e.risk} /></td>
                  <td className="num mono" style={{ fontSize: 11 }}>
                    {Number.isFinite(Number(e.fields?.request_score))
                      ? Number(e.fields.request_score)
                      : <span className="dim">{e.rules && e.rules.length ? '—' : '0'}</span>}
                  </td>
                  <td><window.ActionPill value={e.action} /></td>
                  <td className="mono" style={{ fontSize: 10, color: 'var(--ink-dim)' }}>{e.rules.join(', ') || '—'}</td>
                  <td>
                    {(() => {
                      const s = suggestedAction(e);
                      return s
                        ? <span className={`pill ${s.tone}`} style={{ fontSize: 10 }} title={s.title}>{s.label}</span>
                        : <span className="dim mono" style={{ fontSize: 10 }}>—</span>;
                    })()}
                  </td>
                  <td onClick={ev => ev.stopPropagation()}>
                    <button
                      className="icon-btn"
                      title="Inspect"
                      onClick={() => { setCursorIdx(idx); setSelected(e); }}
                    ><window.I.External /></button>
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
  command_injection: '#FF7A45', // orange-red — distinct from sqli's themed red
  path_traversal:    '#A78BFA',
  ssrf:        '#F472B6',
  crlf:        '#60A5FA',
  bot:         '#34D399',
  scanner:     '#9CA3AF',
  // 2026-05-24 — the core detector classes were missing here, so they
  // all fell to the grey fallback and rendered identically. Each now
  // has a distinct hue.
  recon:               '#4DA8FF', // blue
  recon_path:          '#4DA8FF',
  nosql_injection:     '#14B8A6', // teal
  template_injection:  '#FB923C', // orange
  ssti:                '#FB923C',
  open_redirect:       '#38BDF8', // sky
  jwt_inspection:      '#D946EF', // fuchsia
  cookie_injection:    '#F59E0B', // amber
  header_injection:    '#B45309', // brown
  body_abuse:          '#84CC16', // lime
  brute_force:         '#E11D48', // rose
  velocity_sequence:   '#6366F1', // indigo
  ai:                  '#D946EF', // magenta
  // 2026-05-18 (QC TLS wire-up + Phase F detectors): colours for
  // the new signal tags so the Detector Breakdown chart renders
  // them at stable hues. Picked to be distinct from the OWASP
  // class hues above (greens/teals for state-based signals;
  // reds/oranges shared with severity-class detectors).
  canary:                       '#EF4444', // red — single-hit-block tier
  // 2026-05-19 — `behavior_burst` retired (single-IP benchmarks
  // tripped it on every repeat). Teal #14B8A6 is now unassigned.
  behavior_no_ua:               '#06B6D4', // cyan — UA-absence signal
  behavior_missing_referer:     '#0EA5E9', // sky — CSRF-shape signal
  behavior_zero_depth:          '#3B82F6', // blue — first-touch signal
  velocity_login_to_deposit:    '#FB923C', // orange — ATO shape
  velocity_login_to_withdrawal: '#F97316', // darker orange — cashout shape
  velocity_otp_to_deposit:      '#FDBA74', // peach — post-2FA monetisation
  velocity_otp_to_withdrawal:   '#C2410C', // burnt orange — distinct from login_to_deposit
  device_ip_rotation:           '#8B5CF6', // violet — cross-IP rotation
};
function detectorColor(name) {
  return DETECTOR_COLORS[name] || stableHueColor(name);
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
          <h1 className="page-title">
            Attack Analytics
            <window.PageTitleRefresh
              onClick={() => {
                byDetector.reload && byDetector.reload();
                botMix.reload && botMix.reload();
                tiApi.reload && tiApi.reload();
              }}
              label="Refresh detector breakdown"
            />
          </h1>
          <p className="page-subtitle">
            Curated detector firings · OWASP + custom rules · last {win}
          </p>
        </div>
        <div className="page-actions">
          <select className="input select" value={win} onChange={e => setWin(e.target.value)} style={{ width: 90 }}>
            {Object.keys(ATTACK_WINDOWS).map(v => <option key={v}>{v}</option>)}
          </select>
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
            2026-05-21 — the mix is a tier breakdown of FLAGGED bots
            only (suspect / malicious / verified). The backend no
            longer emits a synthetic `unknown` bucket, and clean
            browser traffic isn't counted — so an empty mix just
            means nothing tripped a bot rule in the window. Surface
            that honestly with a setup pointer rather than a 100%
            "unknown" bar.
          */}
          {botSegments.length === 0 ? (
            <div style={{ padding: 16, fontSize: 12, color: 'var(--ink-dim)', textAlign: 'center' }}>
              No bot signals in the last {win}. The classifier flags{' '}
              <code>suspect</code>/<code>malicious</code> from scanner UAs,
              missing/short UA, or cloud/hosting ASNs (needs the GeoIP ASN
              DB loaded). Clean browser traffic isn't counted. See{' '}
              <a href="#/help" style={{ color: 'var(--accent)' }}>Help → Bot classifier setup</a>.
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
  // 2026-05-10 — SLO + Cert summaries removed from Performance.
  // The canonical home is the Health & SLOs page (root-cause hint
  // when below target + full cert table). Performance focuses on
  // throughput / latency / route-level metrics instead.

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
  // LOW-OBS-05 (2026-05-12) — pin to 24h HH:MM so the Block
  // ratio peak-time reads coherently with the rest of the
  // dashboard.  Forcing `hour12: false` avoids the en-US 12h/AM-PM
  // rendering that the QA pass flagged as visually mixed.
  const peakTs = peakIdx >= 0 && points[peakIdx]
    ? new Date(points[peakIdx].ts).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', hour12: false })
    : '—';

  const hasSeries = points.length > 0;

  return (
    <>
      <div className="page-head">
        <div>
          <h1 className="page-title">
            Performance
            <window.PageTitleRefresh
              onClick={() => ts.reload && ts.reload()}
              label="Refresh performance series"
            />
          </h1>
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
            const stageOrder = ['total', 'queue_wait', 'waf_overhead', 'detect', 'rate_limit', 'respond'];
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
                    : 'no resolved-route samples in window'}
                />
                {rows.length === 0 ? (
                  // LOW-OBS-01 (2026-05-12) — the previous copy
                  // ("no per-route samples yet · drive traffic with
                  // make mock-load") read as broken when the Error
                  // rate by route card right above it was populated.
                  // Both read from the audit ring but per-route
                  // latency only buckets resolved requests; blocked
                  // traffic never reaches a route resolver so it
                  // doesn't surface here.  Explicit copy so the
                  // operator reads the two cards coherently.
                  <div style={{ padding: 16, fontSize: 12, color: 'var(--ink-dim)', textAlign: 'center', minHeight: 80, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                    Per-route latency populates as resolved requests
                    arrive. Blocked traffic doesn't reach a route
                    resolver, so it lands in <em>Error rate by route</em>{' '}
                    (above) instead of here. Try{' '}
                    <code>make mock-load</code> to drive allow-class
                    requests.
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
                      {/* Render every active detector class. There is one row per
                          class (bounded by the detector set, ~18), and the header
                          counts rows.length — an old slice(0, 16) cap silently
                          dropped the 17th class (the `ai` detector) from the view. */}
                      {rows.map(r => {
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

    </>
  );
}

// ============== AUDIT LOG ==============

// MED-01 (2026-05-11) — extract the resource ID for the RULE
// column. Admin mutations (`rule_create`, `route_upsert`,
// `pool_upsert`, etc.) carry `rule_id: null` at the event's top
// level; the actual ID lives in `fields.resource` (e.g.
// `/api/rules/<id>`) or, for whole-section replaces, in the
// `fields.diff.after.<section>.<id>` map. The earlier renderer
// only checked the top-level field, so the RULE column read
// `—` even for the very events that mutated rules.
//
// Logic per QA report:
//   1. Try the top-level `rule_id` (covers data-plane events).
//   2. For action prefixes `rule_*` / `route_*` / `pool_*`, parse
//      `fields.resource` as `/api/<section>/<id>`.
//   3. Fall back to the first key of `fields.diff.after.<section>`.
//   4. LOW-OBS-04 (2026-05-12) — fall back to the joined
//      `fields.detectors[]` for detection rows whose top-level
//      `rule_id` is null but whose detector list is populated.
//      Brings PageAuditLog to parity with the Investigation
//      timeline (MED-SO-06 fix).
//   5. Otherwise return null so the cell renders as `—`.
function extractResourceId(event) {
  if (!event) return null;
  if (event.rule_id) return event.rule_id;
  const action = event.action || '';
  const fields = event.fields || {};
  const section = action.startsWith('rule_')
    ? 'rules'
    : action.startsWith('route_')
      ? 'routes'
      : action.startsWith('pool_')
        ? 'pools'
        : null;
  if (section) {
    // Step 2 — parse `/api/<plural>/<id>` style resource paths.
    const resource = typeof fields.resource === 'string' ? fields.resource : '';
    const apiBase = action.startsWith('pool_') ? '/api/upstreams/pool/' : `/api/${section}/`;
    if (resource.startsWith(apiBase)) {
      const tail = resource.slice(apiBase.length);
      // Tail might be empty (whole-section PUT); keep walking.
      if (tail && !tail.includes('/')) return tail;
    }
    // Step 3 — walk the diff for a single key under .after.<section>.
    const after = fields.diff && fields.diff.after;
    if (after && typeof after === 'object' && after[section]) {
      const keys = Object.keys(after[section]);
      if (keys.length === 1) return keys[0];
    }
  }
  // Step 4 — LOW-OBS-04. Detection rows often carry the
  // detector breakdown under `fields.detectors[]` while the
  // top-level rule_id is null (e.g. WAF blocked by `recon_path`).
  const detectors = Array.isArray(fields.detectors) ? fields.detectors : [];
  if (detectors.length) return detectors.join(',');
  return null;
}

function PageAuditLog() {
  // F-03 (2026-05-11) — honor `#/audit?rule_id=...&ip=...&request_id=...`
  // hash params on mount so deep-links from the Rules Stats tab,
  // request inspector, and other surfaces land pre-filtered.
  // Parses once at mount; subsequent in-page typing wins via the
  // controlled-input state below.
  const initialFromHash = (() => {
    const m = typeof location !== 'undefined' && location.hash.match(/\?(.+)$/);
    if (!m) return {};
    const p = new URLSearchParams(m[1]);
    return {
      ruleId: p.get('rule_id') || '',
      ip: p.get('ip') || '',
      requestId: p.get('request_id') || '',
    };
  })();
  const [ipFilter, setIpFilter] = useStateP(initialFromHash.ip || '');
  const [ruleIdFilter, setRuleIdFilter] = useStateP(initialFromHash.ruleId || '');
  const [requestIdFilter, setRequestIdFilter] = useStateP(initialFromHash.requestId || '');
  const [windowKey, setWindowKey] = useStateP('all');
  const [pageLimit, setPageLimit] = useStateP(200);
  const [debouncedQ, setDebouncedQ] = useStateP({
    ip: initialFromHash.ip || '',
    ruleId: initialFromHash.ruleId || '',
    requestId: initialFromHash.requestId || '',
  });
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
        const ts = eventTimestampMs(e);
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

  function fmt(ev) {
    // 2026-05-19 — accept either an event object or a bare value
    // so call sites stay short. The wire shape is `ts_ms: i64`
    // (rename from the deserialized `ts: DateTime<Utc>` in
    // aegis-core/audit.rs; the legacy `ts` string is no longer
    // emitted). Falling back to a plain Date constructor when a
    // raw value is passed keeps existing inline `fmt(row.ts)`
    // calls working if any survive.
    const ms = typeof ev === 'object' && ev !== null
      ? eventTimestampMs(ev)
      : (typeof ev === 'number' ? ev : Date.parse(ev));
    if (!Number.isFinite(ms)) return '—';
    const d = new Date(ms);
    const h = String(d.getHours()).padStart(2, '0');
    const m = String(d.getMinutes()).padStart(2, '0');
    const s = String(d.getSeconds()).padStart(2, '0');
    return `${h}:${m}:${s}`;
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
          <h1 className="page-title">
            Audit Trail
            <window.PageTitleRefresh
              onClick={() => audit.reload && audit.reload()}
              label="Refresh audit events"
            />
          </h1>
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
                  <td className="num dim">{fmt(e)}</td>
                  <td><span className={`pill ${classPill(e.class)}`}>{e.class}</span></td>
                  <td className="mono" style={{ color: 'var(--ink)' }}>{e.action}</td>
                  <td className="mono">{eventIp(e) || '—'}</td>
                  <td className="mono dim" style={{ fontSize: 11 }}>{extractResourceId(e) || '—'}</td>
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

// ============== POLICY POSTURE CARD ==============
//
// P1 (2026-05-11) — single-line "current posture" cheat-card that
// renders at the top of every Policy section page. Operators
// landing on Rules / Access Lists / Detectors / Traffic Gates /
// Routing & Upstreams previously had to read the whole page to
// learn what the WAF was currently enforcing. The data was
// already there across five APIs; this card cross-tabulates them
// in one ~28px-tall row so page-entry orientation drops from
// ~15s to ~2s.
//
// Chips are clickable — each one jumps to the relevant page.
// Read-only summary; no mutation controls live here.
function PolicyPostureCard() {
  const modeApi = window.useModeApi ? window.useModeApi() : { data: null };
  const tiersApi = window.useTiersApi ? window.useTiersApi() : { data: null };
  const aiApi = window.useAiEnabledApi ? window.useAiEnabledApi() : { data: null };
  const rulesApi = window.useApi
    ? window.useApi('/api/rules', { intervalMs: 30000, fallback: { rules: [] } })
    : { data: { rules: [] } };
  const blApi = window.useApi
    ? window.useApi('/api/blacklist', { intervalMs: 30000, fallback: { entries: [] } })
    : { data: { entries: [] } };
  const wlApi = window.useApi
    ? window.useApi('/api/whitelist', { intervalMs: 30000, fallback: { entries: [] } })
    : { data: { entries: [] } };
  const ddosApi = window.useApi
    ? window.useApi('/api/gates/ddos', { intervalMs: 30000, fallback: null })
    : { data: null };

  const mode = (modeApi.data?.mode || 'enforce').toUpperCase();
  const tierCount = Array.isArray(tiersApi.data?.tiers) ? tiersApi.data.tiers.length : '—';
  const aiOn = !!aiApi.data?.enabled && !!aiApi.data?.feature_present;
  const aiFeaturePresent = !!aiApi.data?.feature_present;
  const ruleCount = Array.isArray(rulesApi.data?.rules) ? rulesApi.data.rules.length : 0;
  const blCount = Array.isArray(blApi.data?.entries) ? blApi.data.entries.length : 0;
  const wlCount = Array.isArray(wlApi.data?.entries) ? wlApi.data.entries.length : 0;
  // 2026-05-22 — DDoS is "not enforcing" if EITHER the config
  // observe_only flag is set OR a set_profile log_only is in effect for
  // the ddos feature (effective_mode). Previously this chip read only
  // observe_only, so a global/feature log_only was mislabeled "enforce".
  const ddosConfigObserve = ddosApi.data?.observe_only === true;
  const ddosLogOnly = ddosApi.data?.effective_mode === 'log_only';
  const ddosObserve = ddosConfigObserve || ddosLogOnly;
  const ddosEnabled = ddosApi.data?.enabled === true;

  const chips = [
    {
      label: mode === 'LOG_ONLY' ? 'SHADOW' : mode,
      tone: mode === 'LOG_ONLY' ? 'warn' : 'ok',
      title: mode === 'LOG_ONLY'
        ? 'Mode: log_only — detections still recorded but no blocks. Flip from Settings.'
        : 'Mode: enforce — blocks land. Flip from Settings.',
      href: '#/settings',
    },
    {
      label: `${tierCount} tier${tierCount === 1 ? '' : 's'}`,
      tone: 'neutral',
      title: 'Per-request risk tiers · Detectors & Tiers page',
      href: '#/detectors',
    },
    {
      label: aiFeaturePresent ? (aiOn ? 'AI on' : 'AI off') : 'AI absent',
      tone: aiOn ? 'ok' : 'neutral',
      title: aiFeaturePresent
        ? (aiOn ? 'ML detector enabled · Detectors & Tiers' : 'ML detector disabled · Detectors & Tiers')
        : 'Binary built without --features ai',
      href: '#/detectors',
    },
    {
      label: `${ruleCount} rule${ruleCount === 1 ? '' : 's'}`,
      tone: 'neutral',
      title: 'Custom rule corpus · Rules page',
      href: '#/rules',
    },
    {
      label: `${blCount} blacklist${blCount === 1 ? '' : ''}`,
      tone: 'neutral',
      title: 'Blacklist entries · Access Lists page',
      href: '#/blacklist',
    },
    {
      label: `${wlCount} whitelist${wlCount === 1 ? '' : ''}`,
      tone: 'neutral',
      title: 'Whitelist entries · Access Lists page',
      href: '#/whitelist',
    },
    {
      label: ddosEnabled
        ? (ddosLogOnly ? 'DDoS log_only' : (ddosConfigObserve ? 'DDoS observe' : 'DDoS enforce'))
        : 'DDoS off',
      tone: ddosEnabled && !ddosObserve ? 'ok' : 'neutral',
      title: ddosEnabled
        ? (ddosLogOnly
            ? 'DDoS detecting but not blocking — set_profile log_only in effect · Traffic Gates'
            : (ddosConfigObserve
                ? 'DDoS gate in observe-only mode (config) · Traffic Gates'
                : 'DDoS gate enforcing · Traffic Gates'))
        : 'DDoS gate disabled · Traffic Gates',
      href: '#/traffic-gates',
    },
  ];

  return (
    <div
      className="card"
      style={{
        padding: '8px 12px',
        marginBottom: 12,
        display: 'flex',
        alignItems: 'center',
        gap: 8,
        flexWrap: 'wrap',
        fontSize: 11,
      }}
      role="status"
      aria-label="Current WAF policy posture"
    >
      <span style={{ color: 'var(--ink-dim)', fontWeight: 600, letterSpacing: 0.4 }}>
        POSTURE
      </span>
      {chips.map((c, i) => (
        <a
          key={i}
          href={c.href}
          className={`pill ${c.tone}`}
          title={c.title}
          style={{ textDecoration: 'none', fontSize: 11 }}
        >
          {c.label}
        </a>
      ))}
    </div>
  );
}

// PR-UX-A1 (2026-05-12) — Security Ops cheat card.  Mirrors the
// shape of `PolicyPostureCard` (compact horizontal pill strip,
// click-through chips) but focused on the "what's happening
// right now" view an analyst needs at a glance: blocks-in-window,
// firing alerts, top attacker, audit ring lag, and a one-click
// jump back to Investigation.
//
// Mounted on the five Sec Ops pages (Overview, Live Feed,
// Incidents, Investigation, Top Attackers) so the analyst sees
// the same heartbeat no matter where they navigate.
function SecOpsPostureCard() {
  const stats = window.useStatsApi ? window.useStatsApi() : { data: null };
  const incidents = window.useApi
    ? window.useApi('/api/incidents', { intervalMs: 5000, fallback: null })
    : { data: null };
  const topApi = window.useApi
    ? window.useApi('/api/attacks/top?window=3600&limit=1', { intervalMs: 10000, fallback: null })
    : { data: null };
  const witness = window.useApi
    ? window.useApi('/api/audit/witness', { intervalMs: 15000, fallback: null })
    : { data: null };

  const blocksTotal = stats.data?.blocks_total ?? 0;
  const blockRate = stats.data?.block_rate_pct;
  const requestRate = stats.data?.request_rate;
  const firingCount = Array.isArray(incidents.data?.incidents)
    ? incidents.data.incidents.filter(i => i.status === 'firing').length
    : (Array.isArray(incidents.data?.raw_alerts?.firing) ? incidents.data.raw_alerts.firing.length : 0);
  const ackedCount = Array.isArray(incidents.data?.incidents)
    ? incidents.data.incidents.filter(i => i.status === 'acknowledged').length
    : 0;
  const topAttacker = (topApi.data?.attackers || [])[0];
  const witnessLag = witness.data?.lag_seconds;
  const witnessFresh = typeof witnessLag === 'number' && witnessLag < 60;

  const chips = [
    {
      label: typeof requestRate === 'number'
        ? `${requestRate.toFixed(1)} req/s`
        : '— req/s',
      tone: 'neutral',
      title: 'Request rate · 10-second average · /api/stats',
      href: '#/overview',
    },
    {
      label: typeof blockRate === 'number'
        ? `${blockRate.toFixed(1)}% blocked`
        : `${blocksTotal.toLocaleString()} blocked`,
      tone: 'neutral',
      title: 'Block rate · last 10s window · /api/stats',
      href: '#/live',
    },
    {
      label: firingCount > 0 ? `${firingCount} firing` : 'no alerts',
      tone: firingCount > 0 ? 'warn' : 'ok',
      title: firingCount > 0
        ? `${firingCount} alert${firingCount === 1 ? '' : 's'} firing · ${ackedCount} acked`
        : 'No SLO alerts firing',
      href: '#/incidents',
    },
    topAttacker
      ? {
          label: topAttacker.country
            ? `top: ${topAttacker.identifier} · ${topAttacker.country}`
            : `top: ${topAttacker.identifier}`,
          tone: 'neutral',
          title: `Top attacker last 1h · ${topAttacker.hits} hits`,
          href: `#/investigation?pivot=${encodeURIComponent(topAttacker.identifier)}&kind=ip`,
        }
      : {
          label: 'no attackers',
          tone: 'ok',
          title: 'No ranked attackers in the last hour',
          href: '#/top-attackers',
        },
    {
      label: witness.data?.last_signature_ts
        ? (witnessFresh ? 'audit fresh' : `audit lag ${witnessLag}s`)
        : 'no witness yet',
      tone: witnessFresh ? 'ok' : 'neutral',
      title: witness.data?.last_signature_ts
        ? `Last chain witness · ${witnessLag}s ago`
        : 'No audit chain witness recorded yet',
      href: '#/audit',
    },
  ];

  return (
    <div
      className="card"
      style={{
        padding: '8px 12px',
        marginBottom: 12,
        display: 'flex',
        alignItems: 'center',
        gap: 8,
        flexWrap: 'wrap',
        fontSize: 11,
      }}
      role="status"
      aria-label="Current Security Ops posture"
    >
      <span style={{ color: 'var(--ink-dim)', fontWeight: 600, letterSpacing: 0.4 }}>
        SEC OPS
      </span>
      {chips.map(c => (
        <a
          key={c.label}
          className={`pill ${c.tone}`}
          href={c.href}
          title={c.title}
          style={{ textDecoration: 'none', fontSize: 11 }}
        >
          {c.label}
        </a>
      ))}
    </div>
  );
}

// ============== RULE MANAGER ==============
// DSL body templates used when the API doesn't supply one.
// 2026-05-17 F-CRITICAL-001 — rule DSL is YAML, not the brace-form
// the prior placeholder generated. The brace-form would store fine
// (validate_rule_body in aegis-control only checks size + empty +
// TODO markers) but the engine's `aegis_security::rules::parser`
// is `serde_yaml::from_str`, so the prior bodies never produced a
// live rule. With the CRUD bridge now wired (admin_mutate →
// rebuild_active_ruleset), the body MUST be valid YAML matching
// the AST in `crates/aegis-security/src/rules/ast.rs`.
function defaultRuleBody(id) {
  return `- id: ${id}\n  priority: 100\n  when:\n    path_matches:\n      contains: "/admin"\n  then:\n    block:\n      status: 403\n`;
}

// Synthesise a rule body from a mock-style row so we have something
// to PUT when an operator clicks Save & deploy on a builtin entry.
// 2026-05-17 — emit canonical YAML matching the engine parser.
function ruleRowToBody(r) {
  if (r.body) return r.body;
  const action = (r.action || 'block').toLowerCase();
  const lines = [
    `- id: ${r.id}`,
    `  priority: ${r.pri ?? 100}`,
    `  when:`,
    `    path_matches:`,
    `      contains: "${(r.pattern || '/').replace(/"/g, '\\"')}"`,
    `  then:`,
  ];
  if (action === 'block') {
    lines.push('    block:', `      status: 403`);
  } else if (action === 'allow') {
    lines.push('    allow');
  } else if (action === 'challenge') {
    lines.push('    challenge:', '      level: js');
  } else {
    lines.push('    log_only');
  }
  lines.push('');
  return lines.join('\n');
}

// 2026-06-21 — derive the rule's action from its DSL body. GET /api/rules
// returns only {id, body, enabled}, NOT an action field, so the merge can't
// default to 'block' — an `allow`/`log_only` rule then rendered as BLOCK. Parse
// the `then:` action (inline `then: allow` or nested `then:\n  block:`).
function ruleActionFromBody(body, fallback) {
  if (!body) return fallback || 'block';
  const known = ['allow', 'log_only', 'block', 'challenge', 'rate_limit', 'raise_risk'];
  const idx = body.search(/(^|\n)\s*then\s*:/);
  if (idx >= 0) {
    // Everything after the `then:` keyword (covers inline + nested forms).
    const after = body.slice(body.indexOf(':', idx) + 1);
    const m = after.match(/[a-z_]+/i);
    const tok = m ? m[0].toLowerCase() : null;
    if (tok && known.includes(tok)) {
      // raise_risk is non-terminal (forwards) — show it as log_only, not block.
      return tok === 'raise_risk' ? 'log_only' : tok;
    }
  }
  return fallback || 'block';
}

// 2026-06-21 (P1) — keep the DSL body's `id:` in lock-step with the form Rule
// ID. The engine matches on the body id, and the backend now rejects a form/body
// id mismatch, so we rewrite the first `id:` value to the entered id before
// submit (and when a template is inserted). No-op when no id is given.
function syncRuleBodyId(body, id) {
  const safe = (id || '').trim();
  if (!safe || !body) return body;
  let replaced = false;
  return body
    .split('\n')
    .map(line => {
      if (replaced) return line;
      const m = line.match(/^(\s*-?\s*id:\s*)(.*)$/);
      if (m) {
        replaced = true;
        return `${m[1]}${safe}`;
      }
      return line;
    })
    .join('\n');
}

// 2026-05-17 F-CRITICAL-001 (UI friendliness pass) — quick-start
// rule templates. Each template ships a canonical YAML body that
// parses against `aegis_security::rules::parser`; operators tweak
// the highlighted value and hit Save. The dashboard's New rule
// modal renders these as one-click chips. Empty-state pre-rules
// view also shows them prominently.
//
// Keep the list short (5-6 max) and skewed toward the most common
// hackathon demo: "block requests to /admin" + "block specific IP"
// + "allow my office IP". The advanced ones (regex on body,
// header CRLF detection, threat-feed lookup) belong in
// `docs/operator/rule-cookbook.md` rather than the modal — fewer
// choices in the UI = less friction for the operator's first save.
const RULE_TEMPLATES = [
  {
    label: 'Block by path',
    description: 'Returns 403 for any request whose path contains the given substring.',
    sampleId: 'block-admin-path',
    body:
`- id: block-admin-path
  priority: 100
  when:
    path_matches:
      contains: "/admin"
  then:
    block:
      status: 403
`,
  },
  {
    label: 'Block by IP',
    description: 'Blocks every request from one of the listed peer IPs (CIDR not supported here — use Access Lists for ranges).',
    sampleId: 'block-bad-ips',
    body:
`- id: block-bad-ips
  priority: 100
  when:
    ip_in:
      - "203.0.113.10"
      - "198.51.100.42"
  then:
    block:
      status: 403
`,
  },
  {
    label: 'Allow trusted IP',
    description: 'Short-circuits to allow for a trusted source — useful for office IPs, monitors, or partner APIs. Highest priority so it wins over any block rule.',
    sampleId: 'allow-office',
    body:
`- id: allow-office
  priority: 200
  when:
    ip_in:
      - "192.0.2.0"
  then: allow
`,
  },
  {
    label: 'Block suspicious header',
    description: 'Fires when a specific request header contains a substring (good for CRLF / injection signatures the detector chain missed).',
    sampleId: 'block-bad-user-agent',
    body:
`- id: block-bad-user-agent
  priority: 90
  when:
    header_matches:
      name: "User-Agent"
      op:
        contains: "sqlmap"
  then:
    block:
      status: 403
`,
  },
  {
    label: 'Observe only (log)',
    description: 'Records a match in the audit log but does NOT block. Useful for tuning a new pattern before flipping it to enforce.',
    sampleId: 'log-suspicious-path',
    body:
`- id: log-suspicious-path
  priority: 50
  when:
    path_matches:
      contains: ".php"
  then: log_only
`,
  },
  {
    label: 'Block query param value',
    description: 'Blocks when a named query parameter matches exactly — shows the nested op: form that query/header/cookie matchers use.',
    sampleId: 'block-query-param',
    body:
`- id: block-query-param
  priority: 100
  when:
    query_matches:
      name: "debug"
      op:
        exact: "true"
  then:
    block:
      status: 403
`,
  },
];

// DSL cheatsheet shown in the "Syntax help" disclosure. Kept terse —
// the full reference is docs/operator/rules-dsl.md. P3 (2026-07-02):
// covers the COMPLETE parser vocabulary; a structural guard test
// (aegis-security rules::ast::dsl_docs_and_dashboard_cheatsheet_cover_
// every_variant) fails the build when a new AST variant is missing here.
const RULE_DSL_CHEATSHEET = [
  'Each rule is a YAML list item. Full reference: docs/operator/rules-dsl.md',
  '  id: <string>          · unique identifier (1-64 alphanumerics + hyphens/underscores)',
  '  priority: <int>       · higher wins; default 0',
  '  scope: global         · or { route: "<route-id>" } to scope to one route',
  '  when: <condition>     · one of:',
  '    request     → method: [POST, …] | path_matches: <op> | host_matches: <op> | body_matches: <op>',
  '                  query_matches: { name, op: <op> } | header_matches: { name, op: <op> } | cookie_matches: { name, op: <op> }',
  '    identity    → ip_in: ["203.0.113.10", …] | country: ["CN", …] | asn: [64496, …]   (country/asn need GeoIP wiring)',
  '    advanced    → jwt_claim: { path, op: <op> } | bot_class: [scanner, …] | threat_feed: { id, min_confidence } | schema_violation | true',
  '    combinators → all: [<condition>, …] | any: [<condition>, …] | not: <condition>',
  '  <op> forms            · exact: "v" | prefix: "v" | suffix: "v" | contains: "v" | regex: "v"',
  '                          (query/header/cookie/jwt matchers nest it under op:, e.g. query_matches: { name: "test", op: { exact: "zxc" } })',
  '  then: <action>        · allow | log_only | block: { status: 403 } | challenge: { level: js }',
  '                          rate_limit: { key, limit, window_s } | raise_risk: <n>  (non-terminal)',
  '  enforcement           · the live engine enforces allow (detector bypass) + block today;',
  '                          challenge / rate_limit / log_only / raise_risk matches are audit-visible only',
];

// Read the current /api/config/version. Returns the numeric version
// or 0 on failure so the caller can still wait for `ver + 1`.
async function fetchCurrentVersion() {
  try {
    const r = await fetch('/api/config/version', { credentials: 'same-origin', cache: 'no-store' });
    if (!r.ok) return 0;
    const j = await r.json();
    // F2 (2026-06-11) — field renamed `version` → `audit_chain_len`.
    return Number(j.audit_chain_len) || 0;
  } catch (_) {
    return 0;
  }
}

// HACK-T3 — Tier-A bonus: rule simulator UI on the Rule
// Manager page. Operators type a method + path + body and click
// Simulate to preview the decision against the **live**
// detector chain — no real traffic, no audit emit.
// P2 (2026-07-02) — parse a `Name: value` lines textarea into a headers
// map. Blank lines + lines without a colon are skipped (forgiving, the
// simulator is a scratchpad, not a validator).
function parseHeaderLines(text) {
  const out = {};
  for (const line of (text || '').split('\n')) {
    const idx = line.indexOf(':');
    if (idx <= 0) continue;
    const name = line.slice(0, idx).trim();
    const value = line.slice(idx + 1).trim();
    if (name) out[name] = value;
  }
  return out;
}

function RuleSimulator() {
  const [method, setMethod] = useStateP('GET');
  const [path, setPath] = useStateP("/api/users?id=1' OR '1'='1");
  const [body, setBody] = useStateP('');
  // P2 — host / peer IP / headers inputs so host_matches, ip_in and
  // header/cookie/jwt rules are exercisable from the UI. The backend
  // already accepted host+headers; peer_ip is new.
  const [host, setHost] = useStateP('');
  const [peerIp, setPeerIp] = useStateP('');
  const [headersText, setHeadersText] = useStateP('');
  const [result, setResult] = useStateP(null);
  const [busy, setBusy] = useStateP(false);

  const onSimulate = async () => {
    if (busy) return;
    setBusy(true);
    setResult({ pending: true });
    try {
      const payload = { method, path };
      if (body && body.length > 0) payload.body = body;
      if (host.trim()) payload.host = host.trim();
      if (peerIp.trim()) payload.peer_ip = peerIp.trim();
      const headers = parseHeaderLines(headersText);
      if (Object.keys(headers).length > 0) payload.headers = headers;
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
  // P1/P2 — rule-engine outcome fields (older binaries won't send them).
  const matchedRule = ok ? (result.matched_rule || null) : null;
  const scopedSkipped = (ok && Array.isArray(result.route_scoped_rules_skipped))
    ? result.route_scoped_rules_skipped : [];
  const ruleTone = matchedRule
    ? (matchedRule.action === 'block' ? 'down' : matchedRule.action === 'allow' ? 'up' : 'warn')
    : 'neutral';

  return (
    <div className="card" style={{ marginBottom: 12, padding: 0 }}>
      <div className="card-head" style={{ padding: '10px 14px', borderBottom: '1px solid var(--hairline)' }}>
        <div>
          <div className="card-title">Rule simulator</div>
          <div className="card-sub">
            Replay a hypothetical request against the live custom rules + detector chain — no traffic, no audit emit.
          </div>
        </div>
        {/* 2026-06-21 — dropped the "Tier A" badge: it was internal
            hackathon-scoring jargon and linked to /detectors, which confused
            operators (it's unrelated to the request risk tier). */}
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
      {/* P2 — host / peer IP / headers so host_matches, ip_in and
          header/cookie/jwt-based rules are testable without curl. */}
      <div style={{ padding: '0 14px 8px', display: 'grid', gridTemplateColumns: '110px 1fr 1fr', gap: 8, alignItems: 'start' }}>
        <input
          className="input mono"
          value={peerIp}
          onChange={e => setPeerIp(e.target.value)}
          placeholder="peer IP"
          title="Simulated client IP — exercises ip_in / country / asn rules. Defaults to 127.0.0.1."
        />
        <input
          className="input mono"
          value={host}
          onChange={e => setHost(e.target.value)}
          placeholder="Host header (optional, e.g. api.example.com)"
          title="Exercises host_matches rules. Defaults to localhost."
        />
        <textarea
          className="input mono"
          value={headersText}
          onChange={e => setHeadersText(e.target.value)}
          placeholder={'optional headers, one per line:\nUser-Agent: sqlmap/1.7\nCookie: sid=abc123'}
          title="Exercises header_matches / cookie_matches / jwt_claim rules."
          rows={2}
          style={{ resize: 'vertical', minHeight: 34, fontSize: 12, lineHeight: 1.4 }}
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
            {/* P1 — rule-engine attribution. matched_rule is authoritative;
                fall back to the legacy rule_id (detector id) for old binaries. */}
            {matchedRule ? (
              <span style={{ fontSize: 11, color: 'var(--ink-mute)' }}>
                rule: <span className={`pill ${ruleTone}`} style={{ fontSize: 10 }}>{matchedRule.action}{matchedRule.status ? ` ${matchedRule.status}` : ''}</span>{' '}
                <code>{matchedRule.id}</code>
              </span>
            ) : result.rule_id && (
              <span style={{ fontSize: 11, color: 'var(--ink-mute)' }}>
                detector: <code>{result.rule_id}</code>
              </span>
            )}
            <span style={{ fontSize: 11, color: 'var(--ink-mute)' }}>
              risk: <span className="num">{result.risk_score}</span>
            </span>
            <span style={{ fontSize: 11, color: 'var(--ink-mute)' }}>
              tier: <code>{result.tier}</code>
            </span>
            {decision === 'allow' && fired.length > 0 && (
              <span style={{ fontSize: 11, color: 'var(--warn)' }}>
                · detected but allowed — score is below the <code>{result.tier}</code> tier's block threshold (repeat hits escalate via cumulative risk)
              </span>
            )}
          </>
        )}
      </div>
      {/* P1 — rule-engine context lines: allow-bypass, unenforced matches,
          route-scoped skips. Only rendered when there's something to say. */}
      {ok && (result.detectors_bypassed || (matchedRule && !matchedRule.enforced) || scopedSkipped.length > 0) && (
        <div style={{ padding: '0 14px 12px', display: 'flex', flexDirection: 'column', gap: 4 }}>
          {result.detectors_bypassed && (
            <span style={{ fontSize: 11, color: 'var(--up)' }}>
              ✓ detector chain skipped — <code>{matchedRule ? matchedRule.id : 'allow rule'}</code> short-circuits to allow (same trust contract as the whitelist)
            </span>
          )}
          {matchedRule && !matchedRule.enforced && (
            <span style={{ fontSize: 11, color: 'var(--warn)' }}>
              ⚠ rule <code>{matchedRule.id}</code> matched but <strong>{matchedRule.action}</strong> is not enforced by the live engine — v1 enforces <code>allow</code> and <code>block</code> only; the match is audit-visible.
            </span>
          )}
          {scopedSkipped.length > 0 && (
            <span style={{ fontSize: 11, color: 'var(--ink-dim)' }}>
              {scopedSkipped.length} route-scoped rule{scopedSkipped.length > 1 ? 's' : ''} not evaluated (the simulator runs global scope): {scopedSkipped.map((id, i) => <code key={id}>{i > 0 ? ', ' : ''}{id}</code>)}
            </span>
          )}
        </div>
      )}
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

  // Optimistic overlay (instant create/edit/toggle/delete, like the
  // Detectors mask card). Rule mutations apply via the async config-
  // plane pipeline, so the server list lags a beat; staged changes show
  // immediately and are dropped once a post-apply reload reflects them.
  const ruleOverlay = window.useOptimisticOverlay();
  const overlaidRules = window.applyOverlayList(apiRules, ruleOverlay.overlay, r => r.id);

  const merged = overlaidRules.map(r => ({
    id: r.id,
    name: r.id,
    kind: 'custom',
    pri: r.pri ?? r.priority ?? 100,
    field: 'any',
    op: 'regex',
    pattern: '',
    // GET /api/rules has no `action` field — derive it from the DSL body so
    // allow/log_only/challenge rules don't all render as BLOCK.
    action: ruleActionFromBody(r.body, r.action),
    enabled: r.enabled !== undefined ? r.enabled : true,
    cat: r.cat ?? 'custom',
    // 2026-06-21 — `risk` (+50 badge) and `hits1h` were removed from the UI:
    // the rule model has no risk field, and GET /api/rules carries no hit count
    // (real hits live on the unjoined /api/rules/top). See
    // plans/issues/PLAN-rules-screen-ux-and-ai-gen-2026-06-21.md (P3).
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

  // Reconcile: when a fresh /api/rules load arrives, drop any staged
  // optimistic entry the server now reflects. Self-correcting like the
  // Detectors card — a pre-apply reload won't match yet, so it never
  // reverts an optimistic row before the change has actually landed.
  useEffectP(() => {
    ruleOverlay.reconcile(apiRules, r => r.id, window.overlayMatches);
  }, [rulesApi.data]);

  // Re-sync when the config plane applies a change anywhere in the fleet
  // (config_reload SSE, re-broadcast by data.jsx) — no manual reload.
  useEffectP(() => {
    const onReload = () => { rulesApi.reload && rulesApi.reload(); };
    window.addEventListener('aegis:config-reload', onReload);
    return () => window.removeEventListener('aegis:config-reload', onReload);
  }, [rulesApi.reload]);

  // After a successful mutation, reload once THIS node has applied the
  // version the PUT produced (non-blocking) so the reconcile effect sees
  // post-apply data and drops the optimistic entry. The trailing
  // forget(key) bounds any lingering overlay if the server canonicalizes
  // a body so the field-match never fires.
  function settleAfterApply(version, key) {
    (async () => {
      if (typeof version === 'number') await window.waitForApplied(version, 10000);
      rulesApi.reload && rulesApi.reload();
      if (key != null) setTimeout(() => ruleOverlay.forget(key), 3000);
    })();
  }

  // Run a mutation with an instant optimistic update: `opt.stage()` flips
  // the UI before the PUT, `opt.rollback()` reverts it on failure. No
  // blocking wait — the optimistic layer already shows the result.
  async function runMutation(label, fn, opt) {
    if (busy) return;
    setBusy(true);
    if (opt && opt.stage) opt.stage();
    try {
      const result = await fn();
      if (result && result.ok) {
        window.aegisToast(label, 'ok');
        settleAfterApply(result.version, opt && opt.key);
      } else {
        if (opt && opt.rollback) opt.rollback();
        const msg = (result && (result.message || result.error || result.reason)) || 'unknown error';
        window.aegisToast(`${label} failed: ${msg}`, 'err');
      }
    } catch (err) {
      if (opt && opt.rollback) opt.rollback();
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
    const id = selected.id;
    const value = { body: editBody, enabled: selected.enabled };
    setEditing(false);
    await runMutation(`Rule ${id} updated`,
      () => window.rulesPut(id, value),
      { key: id, stage: () => ruleOverlay.stageUpsert(id, value), rollback: () => ruleOverlay.forget(id) });
  }

  async function toggleSelected() {
    if (!selected) return;
    const id = selected.id;
    const next = !selected.enabled;
    const label = next ? `Rule ${id} enabled` : `Rule ${id} disabled`;
    await runMutation(label, () => window.rulesToggle(id),
      { key: id, stage: () => ruleOverlay.stageUpsert(id, { enabled: next }), rollback: () => ruleOverlay.forget(id) });
  }

  function deleteSelected() {
    if (!selected) return;
    setShowDeleteModal(true);
  }

  async function confirmDeleteSelected() {
    if (!selected) return;
    const id = selected.id;
    setShowDeleteModal(false);
    await runMutation(`Rule ${id} deleted`, () => window.rulesDelete(id),
      { key: id, stage: () => ruleOverlay.stageRemoval(id), rollback: () => ruleOverlay.forget(id) });
  }

  async function createNew() {
    const id = newId.trim();
    if (!id) { window.aegisToast('Rule id is required', 'err'); return; }
    // P1 — force the body's `id:` to match the form id (engine matches body id;
    // the backend rejects a mismatch).
    const body = syncRuleBodyId(newBody, id);
    const value = { id, body, enabled: newEnabled };
    setShowNew(false);
    setNewId('');
    setNewBody(defaultRuleBody('my-rule-001'));
    setNewEnabled(true);
    // Optimistic create: the row appears instantly (appended by the
    // overlay) and is reconciled away once the server load includes it —
    // no waitForRuleVisible poll-loop needed.
    await runMutation(`Rule ${id} created`,
      () => window.rulesPost({ id, body, enabled: newEnabled }),
      { key: id, stage: () => ruleOverlay.stageUpsert(id, value), rollback: () => ruleOverlay.forget(id) });
    setSelectedId(id);
  }

  // P3 (2026-05-11) — tab the Rules page so Simulator is its own
  // full-viewport surface. Pre-fix the Simulator panel always
  // pinned ~200px at the top of the page even when the operator
  // was editing rule #47 they weren't simulating. Operators
  // managing 50+ rules can now see more list rows; Simulator
  // workflows get their own focused view. Default tab is Rules
  // so existing muscle memory + deep-links land where operators
  // expect.
  const [activeTab, setActiveTab] = useStateP('rules');

  return (
    <>
      <PolicyPostureCard />
      <div className="page-head">
        <div>
          <h1 className="page-title">
            Rules
            <span
              className="pill"
              title="Beta — the operator rule engine + simulator are still stabilizing. Validate rules in the Simulator and review carefully before relying on them in production."
              style={{ marginLeft: 8, fontSize: 10, verticalAlign: 'middle', background: 'rgba(252,213,53,0.16)', color: 'var(--brand-yellow)', border: '1px solid var(--brand-yellow)' }}
            >BETA</span>
            <window.PageTitleRefresh
              onClick={() => rulesApi.reload && rulesApi.reload()}
              label="Reload rules"
            />
          </h1>
          <p className="page-subtitle">{merged.length} total · validate before apply · audit-chained</p>
        </div>
        <div className="page-actions">
          <button className="btn primary" onClick={() => setShowNew(true)} disabled={busy}>
            <window.I.Plus /> New rule
          </button>
        </div>
      </div>

      {/* P3 tab bar — `chip active`/`chip` styling reuses the same
          chip pattern the Performance + Top Attackers windows
          use, so operators don't need to learn a new affordance. */}
      <div className="card" style={{ padding: '6px 10px', marginBottom: 10, display: 'flex', alignItems: 'center', gap: 6 }}>
        <button
          className={`chip ${activeTab === 'rules' ? 'active' : ''}`}
          onClick={() => setActiveTab('rules')}
          style={{ fontSize: 12 }}
        >
          Rules <span style={{ opacity: 0.6, marginLeft: 4 }}>· {merged.length}</span>
        </button>
        <button
          className={`chip ${activeTab === 'simulator' ? 'active' : ''}`}
          onClick={() => setActiveTab('simulator')}
          style={{ fontSize: 12 }}
        >
          Simulator
        </button>
        <span style={{ marginLeft: 'auto', fontSize: 11, color: 'var(--ink-dim)' }}>
          {activeTab === 'rules'
            ? 'List + detail view'
            : 'Replay a hypothetical request against the live detector chain — no traffic, no audit emit'}
        </span>
      </div>

      {activeTab === 'simulator' && <RuleSimulator />}

      {/* 2026-05-17 F-CRITICAL-001 UI: zero-rules onboarding card.
          Shown only when the live RuleStore is empty (no search,
          no filter — the operator just hasn't created any rules
          yet). Replaces the prior subtle "No rules match." that
          left operators staring at a blank list. */}
      {activeTab === 'rules' && merged.length === 0 && (
        <div className="card" style={{ padding: 20, marginBottom: 12 }}>
          <div style={{ display: 'flex', alignItems: 'flex-start', gap: 12 }}>
            <div style={{ flex: 1 }}>
              <div style={{ fontSize: 14, fontWeight: 600, marginBottom: 4 }}>
                No operator rules yet
              </div>
              <p style={{ fontSize: 12, color: 'var(--ink-dim)', margin: '0 0 12px 0', lineHeight: 1.5 }}>
                The WAF's built-in detector chain (SQLi, XSS, path traversal, SSRF, …) runs without
                any rules. Use rules to add policy on top — block specific paths or IPs, allow trusted
                sources, or log suspicious patterns. Pick a starter below or click <strong>New rule</strong>.
              </p>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
                {RULE_TEMPLATES.map(tpl => (
                  <button
                    key={tpl.label}
                    type="button"
                    className="btn"
                    style={{ fontSize: 12 }}
                    onClick={() => {
                      setNewBody(tpl.body);
                      setNewId(tpl.sampleId);
                      setNewEnabled(true);
                      setShowNew(true);
                    }}
                    title={tpl.description}
                  >
                    {tpl.label}
                  </button>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}

      {activeTab === 'rules' && (
      <div className="split-list">
        <div className="left">
          <div style={{ padding: 10, borderBottom: '1px solid var(--hairline)' }}>
            <div style={{ position: 'relative' }}>
              <span style={{ position: 'absolute', left: 8, top: 7, color: 'var(--ink-faint)' }}><window.I.Search /></span>
              <input className="input" style={{ paddingLeft: 28 }} placeholder="Search rule…" value={search} onChange={e => setSearch(e.target.value)} />
            </div>
          </div>
          <div style={{ overflow: 'auto', flex: 1 }}>
            {filtered.length === 0 && merged.length > 0 && (
              <div style={{ padding: 20, fontSize: 12, color: 'var(--ink-dim)', textAlign: 'center' }}>
                No rules match the search.
              </div>
            )}
            {filtered.length === 0 && merged.length === 0 && (
              <div style={{ padding: 20, fontSize: 12, color: 'var(--ink-dim)', textAlign: 'center' }}>
                Use a template above to get started.
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
                  <div style={{ fontSize: 11, color: 'var(--ink-dim)' }} className="mono">{selected.id} · priority {selected.pri}</div>
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
                {['general','dsl'].map(t => (
                  <button key={t} onClick={() => setTab(t)} style={{
                    flex: 'unset', padding: '10px 16px', background: 'transparent', border: 'none',
                    color: tab === t ? 'var(--brand-yellow)' : 'var(--ink-mute)',
                    borderBottom: tab === t ? '2px solid var(--brand-yellow)' : '2px solid transparent',
                    fontSize: 12, fontWeight: 600, textTransform: 'capitalize', cursor: 'pointer' }}>{t}</button>
                ))}
              </div>
              <div style={{ padding: 16 }}>
                {tab === 'general' && (
                  <div style={{ display: 'grid', gridTemplateColumns: 'max-content 1fr', columnGap: 24, rowGap: 12, fontSize: 12, alignItems: 'center', maxWidth: 440 }}>
                    <div className="field-label">ID</div>
                    <div className="mono">{selected.id}</div>
                    <div className="field-label">Kind</div>
                    <div><span className={`pill ${selected.kind}`}>{selected.kind}</span></div>
                    <div className="field-label">Action</div>
                    <div><window.ActionPill value={selected.action} /></div>
                    <div className="field-label">Priority</div>
                    <div className="num">{selected.pri}</div>
                    <div className="field-label">Enabled</div>
                    <div><span className={`pill ${selected.enabled ? 'ok' : 'warn'}`}>{selected.enabled ? 'enabled' : 'disabled'}</span></div>
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
      )}

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
  // F-02 (2026-05-11) — track whether the operator has attempted
  // to submit so we can show inline validation errors on empty
  // required fields instead of silently no-op'ing. Pre-fix the
  // Save button was just `disabled` when Rule ID was empty,
  // giving operators no signal that anything was wrong.
  const [attempted, setAttempted] = useStateP(false);
  // 2026-05-17 — collapsible DSL cheatsheet right inside the modal so
  // first-time operators don't have to leave the page to find
  // syntax. Defaults to collapsed; the textarea is the primary
  // affordance for users who already know the format.
  const [showHelp, setShowHelp] = useStateP(false);
  const idRef = useRefP(null);
  const idEmpty = !newId.trim();
  // 2026-05-17 — apply a quick-template: prefill the body AND, if
  // the operator hasn't typed an ID yet, seed it with the template's
  // sample id. Avoid clobbering anything the operator has already
  // typed — both fields are still editable after the prefill.
  const applyTemplate = (tpl) => {
    // P1 — keep the body id in lock-step with the form id (or the sample id
    // when the field is still empty) so create can't trip the id-match check.
    const targetId = idEmpty ? tpl.sampleId : newId.trim();
    setNewBody(syncRuleBodyId(tpl.body, targetId));
    if (idEmpty) setNewId(tpl.sampleId);
  };
  // P4 — AI rule generation. Drafts a body from a natural-language intent via
  // the Copilot; advisory (prefills the editor, never auto-applies).
  const [aiIntent, setAiIntent] = useStateP('');
  const [aiBusy, setAiBusy] = useStateP(false);
  // Inline result of the last generation so the operator is told to review —
  // AI output is a DRAFT and may be invalid or semantically wrong.
  const [aiNote, setAiNote] = useStateP(null); // { tone: 'ok'|'warn'|'err', msg }
  const generateWithAi = async () => {
    const intent = aiIntent.trim();
    if (!intent) { window.aegisToast('Describe the rule you want first', 'err'); return; }
    setAiBusy(true);
    setAiNote(null);
    try {
      const r = await window.rulesGenerate({ intent, id: newId.trim() });
      if (r && r.ok && r.body) {
        // Adopt the generated id when the operator hasn't typed one.
        let id = newId.trim();
        if (!id) {
          const m = r.body.match(/^\s*-?\s*id:\s*(.+)$/m);
          if (m) { id = m[1].trim(); setNewId(id); }
        }
        setNewBody(syncRuleBodyId(r.body, id) || r.body);
        const v = r.validation;
        if (v && v.ok === false) {
          const first = (v.errors && v.errors[0] && v.errors[0].message) || 'invalid syntax';
          setAiNote({ tone: 'err', msg: `Draft failed validation: ${first}. Fix it below before saving.` });
          window.aegisToast('AI draft has errors — review before saving', 'warn');
        } else {
          setAiNote({ tone: 'warn', msg: 'Draft inserted below. AI can be wrong — read every line (id, when, action, status) and confirm it does what you intend before saving.' });
          window.aegisToast('AI drafted a rule — review & save', 'ok');
        }
      } else {
        const msg = (r && (r.error || r.hint)) || 'generation failed';
        setAiNote({ tone: 'err', msg: `Generation failed: ${msg}` });
        window.aegisToast(`AI generate: ${msg}`, 'err');
      }
    } catch (e) {
      setAiNote({ tone: 'err', msg: `Generation error: ${e.message || e}` });
      window.aegisToast(`AI generate error: ${e.message || e}`, 'err');
    } finally {
      setAiBusy(false);
    }
  };
  const handleSave = () => {
    if (idEmpty) {
      setAttempted(true);
      if (idRef.current) idRef.current.focus();
      return;
    }
    onSave();
  };
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
            <span className="field-label">
              Rule ID <span style={{ color: 'var(--down)' }}>*</span>
            </span>
            <input
              ref={idRef}
              className="input"
              value={newId}
              onChange={e => setNewId(e.target.value)}
              placeholder="custom-xss-001"
              aria-required="true"
              aria-invalid={attempted && idEmpty}
              autoFocus
              style={attempted && idEmpty ? { borderColor: 'var(--down)' } : undefined}
            />
            {attempted && idEmpty && (
              <span style={{ fontSize: 11, color: 'var(--down)' }}>Rule ID is required.</span>
            )}
          </label>
          {/* 2026-05-17 F-CRITICAL-001 UI: quick-template chips so
              first-time operators can ship a working rule without
              learning the DSL up front. One click loads a canonical
              YAML body the engine parser accepts. */}
          <div>
            <div className="field-label" style={{ marginBottom: 6 }}>Quick templates</div>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
              {RULE_TEMPLATES.map(tpl => (
                <button
                  key={tpl.label}
                  type="button"
                  className="chip"
                  onClick={() => applyTemplate(tpl)}
                  title={tpl.description}
                  style={{ fontSize: 11 }}
                >
                  {tpl.label}
                </button>
              ))}
            </div>
            <div style={{ fontSize: 11, color: 'var(--ink-dim)', marginTop: 6 }}>
              Click a template to prefill the body — then edit values like paths, IPs, or status codes.
            </div>
          </div>
          {/* P4 — AI rule generation (advisory; prefills the editor). */}
          <div style={{ padding: '10px 12px', borderRadius: 6, background: 'var(--surface-2)', border: '1px solid var(--border)' }}>
            <div className="field-label" style={{ marginBottom: 6 }}>✨ Generate with AI</div>
            <div style={{ display: 'flex', gap: 6 }}>
              <input
                className="input"
                value={aiIntent}
                onChange={e => setAiIntent(e.target.value)}
                placeholder="Describe it, e.g. block /admin from outside 10.0.0.0/8"
                style={{ flex: 1 }}
                disabled={aiBusy || busy}
                onKeyDown={e => { if (e.key === 'Enter') { e.preventDefault(); generateWithAi(); } }}
              />
              <button
                type="button"
                className="btn primary"
                onClick={generateWithAi}
                disabled={aiBusy || busy}
                style={{ whiteSpace: 'nowrap' }}
              >
                {aiBusy ? 'Generating…' : 'Generate'}
              </button>
            </div>
            <div style={{ fontSize: 11, color: 'var(--ink-dim)', marginTop: 6 }}>
              ⚠️ AI drafts are a <strong>starting point, not a finished rule</strong> — they can be
              syntactically invalid or block/allow the wrong thing. Nothing is applied automatically:
              read every line and confirm the behavior before saving. Requires AI Copilot enabled.
            </div>
            {aiNote && (
              <div
                style={{
                  marginTop: 8, padding: '8px 10px', borderRadius: 4, fontSize: 11, lineHeight: 1.5,
                  border: '1px solid',
                  borderColor: aiNote.tone === 'err' ? 'var(--down)' : aiNote.tone === 'warn' ? 'var(--warn)' : 'var(--up)',
                  color: aiNote.tone === 'err' ? 'var(--down)' : aiNote.tone === 'warn' ? 'var(--warn)' : 'var(--up)',
                  background: 'var(--surface)',
                }}
              >
                {aiNote.msg}
              </div>
            )}
          </div>
          <label style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
            <div style={{ display: 'flex', alignItems: 'baseline', gap: 8 }}>
              <span className="field-label">Rule body (YAML)</span>
              <button
                type="button"
                onClick={() => setShowHelp(s => !s)}
                style={{
                  background: 'none', border: 'none', padding: 0,
                  color: 'var(--accent)', cursor: 'pointer', fontSize: 11,
                }}
              >
                {showHelp ? 'Hide syntax help' : 'Syntax help'}
              </button>
            </div>
            {showHelp && (
              <pre style={{
                background: 'var(--canvas)', border: '1px solid var(--hairline)',
                borderRadius: 6, padding: 10, fontSize: 11, lineHeight: 1.5,
                fontFamily: 'var(--font-mono)', color: 'var(--ink-dim)', margin: 0,
                // Keep the aligned columns but scroll inside the modal instead
                // of bleeding the long `then:`/`when:` lines past its edge.
                whiteSpace: 'pre', overflowX: 'auto', maxWidth: '100%',
              }}>
                {RULE_DSL_CHEATSHEET.join('\n')}
              </pre>
            )}
            <textarea
              className="input"
              style={{ minHeight: 220, fontFamily: 'var(--font-mono)', fontSize: 12, lineHeight: 1.5, padding: 12 }}
              value={newBody}
              onChange={e => setNewBody(e.target.value)}
              spellCheck={false}
            />
          </label>
          <label style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 12 }}>
            <input type="checkbox" checked={newEnabled} onChange={e => setNewEnabled(e.target.checked)} />
            <span>Enabled on save</span>
          </label>
        </div>
        <div style={{ padding: 12, borderTop: '1px solid var(--hairline)', display: 'flex', gap: 8, justifyContent: 'flex-end' }}>
          <button className="btn" onClick={onCancel} disabled={busy}>Cancel</button>
          {/* F-02 — Save is no longer disabled when the field is
              empty; clicking with an empty value surfaces the
              inline error + focuses the field, so operators see
              what they missed instead of an inert button. */}
          <button className="btn primary" onClick={handleSave} disabled={busy}>Save</button>
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
  // 2026-06-12 (JWT report) — JWT attack-shape detector.
  'jwt_inspection',
  // 2026-06-12 (WS report P2) — cookie-injection detector (default OFF).
  'cookie_injection',
  // 2026-05-19 — Phase F detectors promoted to first-class togglable
  // classes. Order matches DetectorClass::ALL on the backend.
  'behavior_signals', 'velocity', 'canary', 'ai',
];

// 2026-05-19 — one-line per-class help text rendered into the chip
// tooltip + the score-table reference card. Behavioural / ML
// detectors get the most explanation because their defaults and
// FP shape are non-obvious; OWASP detectors get a one-liner since
// the chip label and the per-signal `note` already cover the rest.
const CLASS_DESCRIPTIONS = {
  sqli: 'Classical + boolean + time-based + UNION SQL injection.',
  xss: 'Reflected / stored / DOM XSS via script tags, event handlers, javascript: URIs.',
  path_traversal: 'Directory traversal — `..`, encoded variants, sensitive paths.',
  ssrf: 'Server-side request forgery — internal IPs, cloud metadata, file:/gopher:/dict: schemes.',
  header_injection: 'CRLF / X-Forwarded-Host poisoning / method+URL override bypasses.',
  body_abuse: 'Oversize body, deep JSON nesting, prototype pollution, mass-assignment, XXE.',
  recon: 'Recon path probes (`/.env`, `/wp-admin`, actuators) + scanner user-agents (sqlmap, nikto, …).',
  brute_force: 'Login-failure rate cap; default 10/min per IP.',
  command_injection: 'Shell-meta payloads + Log4Shell / JNDI lookups.',
  template_injection: 'Server-side template injection (Jinja2, Twig, Mako, Freemarker, Velocity, SpEL, Handlebars).',
  nosql_injection: 'MongoDB-flavour operator injection (`?param[$ne]=foo`, `{$where:…}`).',
  open_redirect: 'Suspicious external URLs in `?next=` / `?redirect_uri=`. Allowlist via `cfg.detectors.open_redirect.allowed_domains`.',
  jwt_inspection: 'JWT attack shapes in `Authorization: Bearer` / `Cookie` — alg:none, inline key material (x5c/jwk), kid traversal/SQLi, external jku/x5u, forged time claims. Detection-only (no signature check). jku/x5u enforcement is OFF until you configure `cfg.detectors.jwt_inspection.jku_allowed_domains` (empty allowlist can\'t tell a first-party JWKS host from an attacker\'s); alg:none / x5c / kid fire regardless.',
  cookie_injection: 'SQLi / NoSQLi in SESSION cookie values (`sid`, `session`, `auth`, `token`, …). Tight patterns, scoped to session cookie names. DEFAULT OFF — cookie scanning is FP-prone (adtech cookies); opt in + observe before relying on it.',
  behavior_signals: 'Stateful per-IP signals — missing UA, missing Referer on mutations, zero-depth first-touch. DEFAULT OFF — designed to stack with OWASP detectors on bot-shaped traffic; turn on once you have real-IP traffic.',
  velocity: 'Cross-endpoint sequence engine — flags chains like login→deposit < 5 s, login→withdrawal < 5 s. DEFAULT ON; zero cost when the upstream has no matching routes.',
  canary: 'Operator-supplied recon tripwire (`/wp-admin`, `/.env`, …). DEFAULT OFF AND inert until you populate `cfg.risk.canary_paths` — enabling alone is a no-op.',
  ai: 'ONNX machine-learning classifier. Heavy per request; per-tier overrides are recommended (e.g. on for Critical, off for Low to skip inference on static-asset traffic). Hot-flippable globally via the AI Detector card too.',
};

// 2026-06-05 — human-readable row titles for the detector list. The
// raw `class` slug still renders beneath as a mono sub-label so the
// API name stays discoverable; this just gives each row a heading an
// operator reads at a glance instead of decoding `nosql_injection`.
const CLASS_LABELS = {
  sqli: 'SQL injection',
  xss: 'Cross-site scripting',
  path_traversal: 'Path traversal',
  ssrf: 'Server-side request forgery',
  header_injection: 'Header injection',
  body_abuse: 'Body abuse',
  recon: 'Recon & scanners',
  brute_force: 'Brute force',
  command_injection: 'Command injection',
  template_injection: 'Template injection',
  nosql_injection: 'NoSQL injection',
  open_redirect: 'Open redirect',
  jwt_inspection: 'JWT inspection',
  cookie_injection: 'Cookie injection',
  behavior_signals: 'Behavior signals',
  velocity: 'Velocity sequences',
  canary: 'Canary tripwire',
  ai: 'AI classifier',
};

// localStorage key for the Base detector mask card's collapsed state.
const DETECTOR_CARD_COLLAPSE_KEY = 'aegis_detector_mask_collapsed';

// Accessible on/off switch for a detector class. Wraps the shared
// `.toggle` CSS pill in a real <button role="switch"> so keyboard +
// screen-reader users get a proper control (the bare `.toggle` divs
// elsewhere are click-only). Locked classes render inert with a
// not-allowed cursor; the in-flight `busy` state shows a wait cursor.
function MaskSwitch({ on, locked, busy, onToggle, label }) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={on ? 'true' : 'false'}
      aria-label={label}
      disabled={locked || busy}
      onClick={(locked || busy) ? undefined : onToggle}
      className={`toggle ${on ? 'on' : ''}`}
      style={{
        cursor: locked ? 'not-allowed' : busy ? 'wait' : 'pointer',
        opacity: locked ? 0.45 : 1,
      }}
    />
  );
}

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
  // F7 (2026-06-11) — the config version this mask was rendered from.
  // Echoed in `If-Match` on every PUT so a concurrent toggle can't be
  // silently clobbered. `undefined` (single-node / no config plane) →
  // legacy unconditional PUT.
  const configVersion = api.data?.config_version;

  // 2026-06-05 — redesign: the Base mask is now a list of rows, each
  // with an inline on/off switch that commits immediately (one PUT per
  // flip) with an Undo affordance on the success toast. The old
  // Edit→click-chips→Save mode is gone. `rowBusy` tracks the class with
  // an in-flight PUT (for the wait cursor); `optimistic` holds the
  // flipped value until the reload reconciles it against server state;
  // `detailClass` drives the shared per-class details modal, opened
  // from either a row's "details" link or the reference table below.
  const [rowBusy, setRowBusy] = useStateP(null);
  const [optimistic, setOptimistic] = useStateP({});
  const [detailClass, setDetailClass] = useStateP(null);
  // 2026-06-05 — whole-card collapse, persisted to localStorage so the
  // operator's choice survives reloads (mirrors the theme-pref pattern).
  // Defaults to expanded; collapsing folds the list + AI row + score
  // reference behind the header, leaving the enabled-count summary.
  const [collapsed, setCollapsed] = useStateP(() => {
    try { return localStorage.getItem(DETECTOR_CARD_COLLAPSE_KEY) === '1'; }
    catch (_) { return false; }
  });
  useEffectP(() => {
    try { localStorage.setItem(DETECTOR_CARD_COLLAPSE_KEY, collapsed ? '1' : '0'); }
    catch (_) { /* storage disabled / quota — non-fatal */ }
  }, [collapsed]);

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

  // Group the score catalogue by class → drives the "N signals" count
  // on each row and the per-class details modal.
  const byClass = {};
  for (const row of scoreTable) {
    if (!byClass[row.class]) byClass[row.class] = [];
    byClass[row.class].push(row);
  }

  // 2026-06-12 (toggle clobber fix) — `pendingRef` is the SYNCHRONOUS
  // cumulative set of in-flight flips, mirroring `optimistic`. The PUT
  // sends the WHOLE mask, so it MUST be built from `baseMask` + ALL
  // pending flips — not `baseMask` + the single new flip. Otherwise a
  // second rapid toggle resends the stale `baseMask` (which still has the
  // first detector ON, because the reload hasn't landed yet) and silently
  // resurrects it: "I turned it off and it came back on." A ref (not the
  // `optimistic` state) is needed because back-to-back toggles run before
  // React re-renders, so the closed-over state would be stale.
  const pendingRef = useRefP({});

  // Reconcile optimistic flips against fresh server state on every
  // reload: drop any optimistic entry that now matches the mask (the
  // PUT landed) and keep only those still mid-flight, so a slow PUT
  // never snaps the switch back before the server confirms. `pendingRef`
  // is kept in lock-step so the next PUT's merge base is accurate.
  useEffectP(() => {
    const mask = api.data?.mask;
    if (!mask) return;
    setOptimistic(prev => {
      const next = {};
      for (const cls of Object.keys(prev)) {
        if (!!mask[cls] !== prev[cls]) next[cls] = prev[cls];
      }
      pendingRef.current = next;
      return Object.keys(next).length === Object.keys(prev).length ? prev : next;
    });
  }, [api.data]);

  // F7/F8 (2026-06-11) — re-sync to authoritative mask + version when
  // the config plane applies a new version anywhere in the fleet
  // (config_reload SSE, re-broadcast by data.jsx). A soft route change
  // no longer leaves the switches stale vs. the engine; no hard reload
  // needed. The reconcile effect above then drops any optimistic flip
  // the fresh mask has caught up to.
  useEffectP(() => {
    const onReload = () => { api.reload && api.reload(); };
    window.addEventListener('aegis:config-reload', onReload);
    return () => window.removeEventListener('aegis:config-reload', onReload);
  }, [api.reload]);

  // 2026-06-12 (toggle UX) — `versionRef` is the SYNCHRONOUS source of
  // truth for the `If-Match` config version, independent of the async GET
  // reload. Each successful PUT returns the new `version`; we stamp it
  // here immediately so a back-to-back toggle uses the fresh version
  // instead of the stale `configVersion` prop (which only updates after a
  // full reload lands). That stale prop was the cause of the spurious
  // "mask changed under you" 412 churn. Kept monotonic so a slow reload
  // carrying an older version never lowers it.
  const versionRef = useRefP(configVersion);
  useEffectP(() => {
    if (configVersion == null) return;
    if (versionRef.current == null || configVersion > versionRef.current) {
      versionRef.current = configVersion;
    }
  }, [configVersion]);

  // Debounced reload: collapse a burst of rapid toggles into ONE GET
  // refresh at the end instead of a full (heavy) reload per flip — the
  // optimistic switch state + versionRef already carry the truth, so the
  // reload only reconciles derived data (signal counts, overrides).
  const reloadTimerRef = useRefP(null);
  const scheduleReload = () => {
    if (reloadTimerRef.current) clearTimeout(reloadTimerRef.current);
    reloadTimerRef.current = setTimeout(() => {
      reloadTimerRef.current = null;
      api.reload && api.reload();
    }, 700);
  };
  useEffectP(() => () => {
    if (reloadTimerRef.current) clearTimeout(reloadTimerRef.current);
  }, []);

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

  // FIX 2026-05-04 — `/api/detectors` responds with the NEW MASK STATE
  // on success (not an `{ok: true}` envelope), so check a 2xx status.
  function isHttpOk(r) {
    return r && typeof r.status === 'number' && r.status >= 200 && r.status < 300;
  }

  function errMsg(r) {
    return (r && (r.message || r.error || r.reason)) || `status ${r?.status ?? '?'}`;
  }

  // Commit a full base-mask PUT (the API always takes the whole mask)
  // with `cls` flipped to `next`. Optimistic: the switch reflects the
  // new state immediately and only reverts if the PUT fails. On
  // success the toast carries an Undo that re-PUTs the prior mask.
  async function commitToggle(cls, next, { undoable = true } = {}) {
    if (rowBusy || lockedClasses.includes(cls)) return;
    const label = CLASS_LABELS[cls] || cls;
    // Record this flip in the cumulative pending set (synchronous ref +
    // render state) BEFORE building the PUT body.
    pendingRef.current = { ...pendingRef.current, [cls]: next };
    setOptimistic({ ...pendingRef.current });
    setRowBusy(cls);
    try {
      // F7 (2026-06-11) — commit against the freshest mask + version we
      // hold, echoing it in `If-Match`. On a 412 (the mask moved under
      // us — a concurrent toggle or a propagating change) re-fetch the
      // authoritative state and replay our pending flips onto it.
      // Bounded retries; falls back to the legacy unconditional PUT when
      // the server supplies no version (→ 409 handled by csrfMutate).
      //
      // CLOBBER FIX (2026-06-12): the PUT body is the whole mask built
      // from `baseMask` + ALL pending flips, NOT `baseMask` + this one
      // flip. baseMask lags (the reload is async/debounced), so merging
      // only the current flip would resend a stale value for any other
      // detector the operator just changed — silently reverting it.
      let base = baseMask;
      let version = versionRef.current;
      let r;
      for (let attempt = 0; attempt < 3; attempt++) {
        const fullMask = { ...base, ...pendingRef.current };
        r = await window.detectorsPut({ mask: fullMask }, { ifMatch: version });
        if (isHttpOk(r)) break;
        if (r && r.status === 412 && attempt < 2) {
          const fresh = await fetch('/api/detectors', { credentials: 'same-origin' })
            .then(res => (res.ok ? res.json() : null))
            .catch(() => null);
          if (fresh && fresh.mask) {
            base = fresh.mask;
            version = fresh.config_version;
            if (typeof version === 'number') versionRef.current = version;
            continue;
          }
        }
        break;
      }
      if (isHttpOk(r)) {
        // Stamp the new version SYNCHRONOUSLY so the next toggle doesn't
        // race a stale If-Match. The PUT body carries `version`.
        if (typeof r.version === 'number') versionRef.current = r.version;
        window.aegisToast(
          `${label} ${next ? 'enabled' : 'disabled'}`,
          'ok',
          null,
          undoable ? {
            ttl: 6000,
            action: { label: 'Undo', onClick: () => commitToggle(cls, !next, { undoable: false }) },
          } : null,
        );
        // Optimistic state already shows the flip; reconcile derived data
        // with a single debounced reload instead of a heavy GET per flip.
        scheduleReload();
      } else {
        // Roll back just this flip from both the ref and the render state.
        const { [cls]: _drop, ...rest } = pendingRef.current;
        pendingRef.current = rest;
        setOptimistic({ ...rest });
        const why = r && r.status === 412
          ? 'mask changed under you — reloaded latest; try again'
          : errMsg(r);
        window.aegisToast(`Toggle failed: ${why}`, 'err');
        // Re-sync so the switches reflect the true engine state.
        api.reload && api.reload();
      }
    } catch (e) {
      const { [cls]: _drop, ...rest } = pendingRef.current;
      pendingRef.current = rest;
      setOptimistic({ ...rest });
      window.aegisToast(`Toggle error: ${e.message || e}`, 'err');
    } finally {
      setRowBusy(null);
    }
  }

  // One detector row: switch · name + slug · dominant score badge ·
  // description · signal count + details link. Replaces the old
  // chip-grid-with-hidden-edit-mode.
  const renderDetectorRow = (cls) => {
    const enabled = cls in optimistic ? optimistic[cls] : !!baseMask[cls];
    const locked = lockedClasses.includes(cls);
    const busyRow = rowBusy === cls;
    const dominant = dominantByClass[cls];
    const tierStyle = dominant ? (SCORE_TIER_STYLE[dominant.tier] || SCORE_TIER_STYLE.probe) : null;
    const desc = CLASS_DESCRIPTIONS[cls];
    const sigCount = (byClass[cls] || []).length;
    const label = CLASS_LABELS[cls] || cls;
    return (
      <div
        key={cls}
        style={{
          borderTop: '1px solid var(--hairline)',
          padding: '10px 12px',
          display: 'flex',
          alignItems: 'center',
          gap: 12,
        }}
      >
        <MaskSwitch
          on={enabled}
          locked={locked}
          busy={busyRow}
          onToggle={() => commitToggle(cls, !enabled)}
          label={`${label} detector — ${enabled ? 'on' : 'off'}`}
        />
        <div style={{ minWidth: 168, display: 'flex', flexDirection: 'column', gap: 1, opacity: enabled ? 1 : 0.6 }}>
          <div style={{ display: 'flex', alignItems: 'baseline', gap: 6 }}>
            <span style={{ fontSize: 13, fontWeight: 600, color: 'var(--ink)' }}>{label}</span>
            {locked && <span title="pinned by active compliance mode" aria-label="locked">🔒</span>}
          </div>
          <span className="mono" style={{ fontSize: 10, color: 'var(--ink-dim)' }}>{cls}</span>
        </div>
        {dominant && (
          <span
            title={`Top signal: ${dominant.tag} → score ${dominant.score} (${tierStyle.label})`}
            style={{
              fontSize: 10, padding: '2px 8px', borderRadius: 4,
              background: tierStyle.bg, color: tierStyle.fg, fontWeight: 600,
              fontFamily: 'monospace', flexShrink: 0,
              opacity: enabled ? 1 : 0.6,
            }}
          >
            {dominant.tag} · {dominant.score}
          </span>
        )}
        <div
          style={{
            flex: 1, fontSize: 11, color: 'var(--ink-dim)', lineHeight: 1.4,
            opacity: enabled ? 1 : 0.6,
            overflow: 'hidden', textOverflow: 'ellipsis',
            display: '-webkit-box', WebkitLineClamp: 2, WebkitBoxOrient: 'vertical',
          }}
        >
          {desc}
          {cls === 'ai' && (
            <span style={{ color: 'var(--ink-faint)' }}> · runtime &amp; tuning below ↓</span>
          )}
        </div>
        <button
          type="button"
          className="btn"
          onClick={() => setDetailClass(cls)}
          title={`Full signal breakdown for ${label}`}
          style={{ fontSize: 11, padding: '4px 10px', flexShrink: 0, whiteSpace: 'nowrap' }}
        >
          {sigCount > 0 ? `${sigCount} signal${sigCount === 1 ? '' : 's'} · details ›` : 'details ›'}
        </button>
      </div>
    );
  };


  const enabledCount = MASK_CLASSES.filter(
    cls => (cls in optimistic ? optimistic[cls] : !!baseMask[cls])
  ).length;

  return (
    <div data-component="detector-mask-card" className="card" style={{ marginBottom: 12, padding: 0 }}>
      {/* Header doubles as the collapse toggle. A real <button> wraps the
          title block so it's keyboard-operable and announces expanded
          state; the enabled-count summary stays on the right so the card
          is still informative when folded. */}
      <button
        type="button"
        onClick={() => setCollapsed(c => !c)}
        aria-expanded={collapsed ? 'false' : 'true'}
        className="card-head"
        style={{
          padding: 12, width: '100%', textAlign: 'left',
          background: 'transparent', border: 'none', cursor: 'pointer',
          font: 'inherit', color: 'inherit',
          // `.card-head` carries a 12px bottom margin meant to sit
          // between the header and the first row; drop it when folded.
          marginBottom: collapsed ? 0 : undefined,
        }}
      >
        <div style={{ display: 'flex', alignItems: 'baseline', gap: 8 }}>
          <span
            aria-hidden="true"
            style={{
              fontSize: 10, color: 'var(--ink-dim)', lineHeight: 1,
              transform: collapsed ? 'rotate(-90deg)' : 'none',
              transition: 'transform 120ms', display: 'inline-block',
            }}
          >
            ▼
          </span>
          <div>
            <div className="card-title">
              Base detector mask
              <span style={{ marginLeft: 8, fontSize: 10, fontWeight: 400, color: 'var(--ink-dim)', textTransform: 'uppercase', letterSpacing: 0.5 }}>
                default for all tiers
              </span>
            </div>
            {!collapsed && (
              <div className="card-subtitle">
                Toggle any detector on or off. Each flip saves immediately
                (one audit event) and takes effect within a hot-reload tick;
                the confirmation toast offers an Undo. Per-tier overrides live
                in the Edit Tier modal; score calibration is read-only below.
              </div>
            )}
          </div>
        </div>
        <div style={{ fontSize: 11, color: 'var(--ink-dim)', whiteSpace: 'nowrap', alignSelf: collapsed ? 'center' : 'flex-start', display: 'flex', alignItems: 'center', gap: 8 }}>
          {/* F8 (2026-06-11 cluster QC) — a real Refresh that re-pulls
              the authoritative mask + version, so when the UI desyncs
              (or after a soft nav) the operator can reconcile without a
              hard browser reload. role=button (not a nested <button>,
              which would be invalid inside the collapse button) +
              stopPropagation so it doesn't also toggle the card. The
              config_reload SSE listener already auto-syncs; this is the
              manual escape hatch the QC asked for. */}
          <span
            role="button"
            tabIndex={0}
            aria-label="Refresh detector mask from server"
            title="Re-fetch the live mask + version from /api/detectors"
            onClick={(e) => { e.stopPropagation(); api.reload && api.reload(); }}
            onKeyDown={(e) => {
              if (e.key === 'Enter' || e.key === ' ') {
                e.preventDefault(); e.stopPropagation(); api.reload && api.reload();
              }
            }}
            style={{ cursor: 'pointer', color: 'var(--ink-dim)', userSelect: 'none' }}
          >
            ↻ Refresh
          </span>
          <span>
            <span className="num" style={{ color: 'var(--ink)', fontWeight: 600 }}>{enabledCount}</span>
            {' / '}{MASK_CLASSES.length} enabled
          </span>
        </div>
      </button>

      {!collapsed && (
        <>
          {/* Detector list — one inline-toggle row per class. Replaces the
              prior chip grid + hidden Edit mode. `ai` is the base-mask bit;
              its runtime on/off + confidence tuning is the AiDetectorRow
              immediately below. */}
          {MASK_CLASSES.map(renderDetectorRow)}

          {/* AI runtime detector — separate AtomicBool (PUT /api/ai/enabled)
              + confidence threshold + live metrics. Distinct from the `ai`
              mask bit above, which only gates the dispatcher per tier. */}
          <AiDetectorRow />

          {/* Risk score reference — read-only calibration table. Moved BELOW
              the controls: each row already carries its dominant score badge,
              so the full per-tag catalogue is reference material, not the
              primary surface. Shares the detail modal via `onDetails`. */}
          <DetectorScorePanel scoreTable={api.data?.score_table || []} onDetails={setDetailClass} />
        </>
      )}

      {detailClass && (
        <DetectorDetailModal
          cls={detailClass}
          rows={byClass[detailClass] || []}
          onClose={() => setDetailClass(null)}
        />
      )}
    </div>
  );
}

// 2026-05-22 — Availability gate explainer. `load_shed` is the one
// "block reason" that appears in Attack distribution / Top Attackers
// but has NO row in the Base detector mask, which confused operators.
// This read-only card states plainly: it is a tier-aware adaptive
// concurrency shedder, not a content detector. It sheds (503 +
// Retry-After) only when in-flight concurrency exceeds the adaptive
// limit, and it respects the SAME risk tiers shown below — Critical is
// never shed; Low/Medium/High shed in that order. The limit auto-tunes
// from WAF-inspection latency ONLY (upstream RTT is excluded, so a slow
// backend never makes a healthy WAF shed). Tunables live in the
// `load_shedder:` config block; see docs/data-plane/adaptive-load-shedding.md.
function LoadShedGateCard() {
  return (
    <div data-component="load-shed-gate-card" className="card" style={{ marginBottom: 12, padding: 0 }}>
      <div className="card-head" style={{ padding: 12 }}>
        <div>
          <div className="card-title">
            Availability gate · load_shed
            <span style={{ marginLeft: 8, fontSize: 10, fontWeight: 600, color: 'var(--ink-dim)', textTransform: 'uppercase', letterSpacing: 0.5, padding: '2px 6px', borderRadius: 4, background: 'var(--surface-active)' }}>
              not a detector
            </span>
          </div>
          <div className="card-subtitle">
            You won't find <code>load_shed</code> in the Base mask above — it
            isn't a content detector. It's an adaptive concurrency shedder
            (Gradient2) that returns <span className="num">503</span> +{' '}
            <code>Retry-After: 1</code> only when in-flight requests exceed the
            auto-tuned limit. It appears in Attack distribution because the
            aggregator buckets every block by <code>rule_id</code>.
          </div>
        </div>
      </div>

      <div style={{ borderTop: '1px solid var(--hairline)', padding: '10px 12px', display: 'flex', flexDirection: 'column', gap: 10 }}>
        {/* Shed order — keyed off the very tiers listed below this card. */}
        <div>
          <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--ink)', marginBottom: 6 }}>
            Shed order under overload
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap', fontSize: 11, color: 'var(--ink-dim)' }}>
            <span className="pill tier-low">Low</span>
            <span className="pill tier-med">Medium</span>
            <span className="pill tier-high">High</span>
            <span>shed first → in that order;</span>
            <span className="pill tier-crit">Critical</span>
            <span style={{ fontWeight: 600, color: 'var(--ink)' }}>never shed.</span>
          </div>
        </div>

        {/* The single most important property — why it doesn't false-trip. */}
        <div style={{ fontSize: 11, color: 'var(--ink-dim)', lineHeight: 1.5 }}>
          The limit auto-tunes from <strong style={{ color: 'var(--ink)' }}>WAF-inspection
          latency only</strong> — the upstream round-trip is excluded, so a slow
          or jittery backend never makes a healthy WAF shed traffic it could
          serve. Tune via the <code>load_shedder:</code> block
          (<code>enabled</code> / <code>initial_limit</code> / <code>min_limit</code>)
          in your config profile.
        </div>
      </div>
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
function DetectorScorePanel({ scoreTable, onDetails }) {
  const [expanded, setExpanded] = useStateP(false);
  // 2026-05-19 — clickable class detail. The help-cursor chips +
  // class labels in the full table open a modal showing the full
  // description + every sub-tag with score / tier / note. Replaces
  // the prior "hover-only tooltip with no follow-through" UX.
  // 2026-06-05 — when the parent passes `onDetails`, defer the modal
  // to it (the Detectors card owns one shared modal for both the rows
  // and this table); otherwise fall back to a local modal so the panel
  // still works standalone.
  const [detailClassLocal, setDetailClassLocal] = useStateP(null);
  const openDetail = onDetails || setDetailClassLocal;
  // 2026-05-10 — read live thresholds from /api/risk/thresholds
  // so the explanatory text shows the operator's *current* values,
  // not the hardcoded defaults. The Cumulative IP risk thresholds
  // editor (Traffic Gates → #3) is the only authoritative source.
  const riskApi = window.useRiskThresholdsApi
    ? window.useRiskThresholdsApi()
    : { data: null };
  const liveChallengeAt = Number.isFinite(Number(riskApi.data?.challenge_at))
    ? Number(riskApi.data.challenge_at)
    : null;
  const liveBlockAt = Number.isFinite(Number(riskApi.data?.block_at))
    ? Number(riskApi.data.block_at)
    : null;

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
        Scores are calibrated against your live cumulative IP risk
        thresholds:{' '}
        <code style={{ fontSize: 10 }}>challenge_at</code>{' '}
        {liveChallengeAt !== null ? (
          <strong style={{ color: 'var(--ink)' }}>= {liveChallengeAt}</strong>
        ) : (
          <span style={{ fontStyle: 'italic' }}>(loading…)</span>
        )}
        {' '}and{' '}
        <code style={{ fontSize: 10 }}>block_at</code>{' '}
        {liveBlockAt !== null ? (
          <strong style={{ color: 'var(--ink)' }}>= {liveBlockAt}</strong>
        ) : (
          <span style={{ fontStyle: 'italic' }}>(loading…)</span>
        )}.
        {' '}Edit those on{' '}
        <a href="#/traffic-gates" style={{ color: 'var(--accent)' }}>
          Traffic Gates → #3 Cumulative IP risk thresholds
        </a>
        . To tune posture without touching detector scores, use{' '}
        <code style={{ fontSize: 10 }}>set_profile log_only</code>,
        adjust those thresholds, add a{' '}
        <code style={{ fontSize: 10 }}>RaiseRisk(delta)</code> rule,
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
              {/* Class label is now a clickable affordance — opens
                  the detail modal. The trailing "ⓘ" makes the click
                  target discoverable; the prior hover-cursor only
                  hinted at help without follow-through. */}
              <button
                type="button"
                onClick={() => openDetail(cls)}
                title={`Open full details for ${cls}`}
                style={{
                  fontSize: 11, fontWeight: 600, color: 'var(--ink)',
                  background: 'transparent', border: 'none', padding: 0,
                  textAlign: 'left', cursor: 'pointer',
                  display: 'inline-flex', alignItems: 'baseline', gap: 4,
                }}
              >
                {cls}
                <span style={{ fontSize: 10, color: 'var(--ink-dim)', fontWeight: 400 }} aria-hidden="true">ⓘ</span>
              </button>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                {byClass[cls].map(row => {
                  const tierStyle = SCORE_TIER_STYLE[row.tier] || SCORE_TIER_STYLE.probe;
                  return (
                    <button
                      type="button"
                      key={`${row.class}-${row.tag}`}
                      onClick={() => openDetail(row.class)}
                      title={`${row.tag} → ${row.score} · ${tierStyle.label} tier\n\n${row.note}\n\nClick for full details.`}
                      style={{
                        fontSize: 10, padding: '2px 8px', borderRadius: 4,
                        background: tierStyle.bg, color: tierStyle.fg,
                        fontWeight: 500, fontFamily: 'monospace',
                        cursor: 'pointer', border: '1px solid transparent',
                      }}
                    >
                      {row.tag} · {row.score}
                    </button>
                  );
                })}
              </div>
            </React.Fragment>
          ))}
        </div>
      )}

      {!onDetails && detailClassLocal && (
        <DetectorDetailModal
          cls={detailClassLocal}
          rows={byClass[detailClassLocal] || []}
          onClose={() => setDetailClassLocal(null)}
        />
      )}
    </div>
  );
}

// 2026-05-19 — modal opened from `DetectorScorePanel` chips +
// class labels. Surfaces the per-class description, every signal
// the class can emit (tag · score · tier · note), and a config-
// pointer line so operators know which YAML knob / API call
// changes its behaviour.
function DetectorDetailModal({ cls, rows, onClose }) {
  const description = CLASS_DESCRIPTIONS[cls] || null;
  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal" onClick={e => e.stopPropagation()} style={{ maxWidth: 560 }}>
        <div className="modal-head">
          <div className="modal-title">
            <code style={{ fontFamily: 'monospace' }}>{cls}</code>{' '}
            <span style={{ fontSize: 11, color: 'var(--ink-dim)', fontWeight: 400 }}>
              · detector details
            </span>
          </div>
          <button className="btn btn-sm" onClick={onClose} aria-label="Close">×</button>
        </div>
        <div className="modal-body">
          {description ? (
            <p style={{ fontSize: 12, lineHeight: 1.55, marginTop: 0, color: 'var(--ink)' }}>
              {description}
            </p>
          ) : (
            <p style={{ fontSize: 12, lineHeight: 1.55, marginTop: 0, color: 'var(--ink-dim)', fontStyle: 'italic' }}>
              No per-class description available yet — see the signals below
              for the per-tag detail this detector emits.
            </p>
          )}

          <div style={{ fontSize: 10, color: 'var(--ink-dim)', textTransform: 'uppercase', letterSpacing: 0.5, margin: '12px 0 6px' }}>
            Signals this detector can emit
          </div>
          {rows.length === 0 ? (
            <p style={{ fontSize: 12, color: 'var(--ink-dim)', fontStyle: 'italic' }}>
              No catalogue entries for this class — the detector runs but
              its sub-tag scores aren't published in <code>score_table</code>.
            </p>
          ) : (
            <div style={{ display: 'grid', gridTemplateColumns: 'minmax(160px, auto) 1fr', columnGap: 12, rowGap: 8, alignItems: 'baseline' }}>
              {rows.map(row => {
                const tierStyle = SCORE_TIER_STYLE[row.tier] || SCORE_TIER_STYLE.probe;
                return (
                  <React.Fragment key={`${row.class}-${row.tag}`}>
                    <div style={{ display: 'flex', alignItems: 'baseline', gap: 6, fontFamily: 'monospace', fontSize: 11 }}>
                      <span style={{ color: 'var(--ink)', fontWeight: 600 }}>{row.tag}</span>
                      <span style={{
                        fontSize: 10, padding: '1px 6px', borderRadius: 4,
                        background: tierStyle.bg, color: tierStyle.fg,
                        fontWeight: 600,
                      }}>
                        +{row.score}
                      </span>
                      <span style={{ fontSize: 10, color: 'var(--ink-faint)' }}>{tierStyle.label}</span>
                    </div>
                    <div style={{ fontSize: 11, color: 'var(--ink-dim)', lineHeight: 1.45 }}>
                      {row.note}
                    </div>
                  </React.Fragment>
                );
              })}
            </div>
          )}

          <div style={{ fontSize: 10, color: 'var(--ink-dim)', textTransform: 'uppercase', letterSpacing: 0.5, margin: '14px 0 6px' }}>
            Where it's configured
          </div>
          <ul style={{ fontSize: 11, color: 'var(--ink)', lineHeight: 1.55, paddingLeft: 18, margin: 0 }}>
            <li>
              <strong>Global toggle:</strong>{' '}
              {cls === 'ai' ? (
                <>
                  <code>cfg.ai.enabled</code> (sibling block) — also hot-flippable via{' '}
                  <code>PUT /api/ai/enabled</code> and the <em>AI Detector</em> row on this page.
                </>
              ) : (
                <>
                  <code>cfg.detectors.{cls}.enabled</code> — hot-flippable via{' '}
                  <code>PUT /api/detectors</code> and the chip in the mask grid above.
                </>
              )}
            </li>
            <li>
              <strong>Per-tier override:</strong>{' '}
              <code>cfg.detectors.per_tier.&lt;tier&gt;.{cls}</code> ·{' '}
              or click <em>Override Base mask</em> on the tier row to flip the chip.
            </li>
            <li>
              <strong>Mask bit:</strong>{' '}
              <code>DetectorClass::{cls.split('_').map(s => s.charAt(0).toUpperCase() + s.slice(1)).join('')}</code>
              {' '}— gates the dispatcher loop; disabled classes pay zero CPU.
            </li>
          </ul>
        </div>
        <div className="modal-foot">
          <button className="btn" onClick={onClose}>Close</button>
        </div>
      </div>
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
  // 2026-05-29 — live + default confidence_threshold. GET surfaces
  // both so the operator sees what config says and what they (or a
  // previous operator) have adjusted it to.
  const aiConfidenceApi = window.useAiConfidenceApi
    ? window.useAiConfidenceApi()
    : { data: null, reload: () => {} };
  // Model hot-reload — GET tells us whether a reloadable model exists + its
  // path; POST re-reads it and atomically swaps it into the live detector.
  const aiReloadApi = window.useAiReloadApi
    ? window.useAiReloadApi()
    : { data: null, reload: () => {} };
  const [busy, setBusy] = useStateP(false);
  const [reloading, setReloading] = useStateP(false);
  const [expanded, setExpanded] = useStateP(false);
  const [metrics, setMetrics] = useStateP(null);
  // Draft value for the threshold input. Stays null until the GET
  // resolves, then seeds from the live value so the input shows the
  // current gate (not the cfg default) — operators see what's live.
  const [draftThreshold, setDraftThreshold] = useStateP(null);
  const [savingThreshold, setSavingThreshold] = useStateP(false);
  useEffectP(() => {
    if (draftThreshold === null && typeof aiConfidenceApi.data?.confidence_threshold === 'number') {
      setDraftThreshold(aiConfidenceApi.data.confidence_threshold);
    }
  }, [aiConfidenceApi.data?.confidence_threshold]);

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

  // F-06 (2026-05-11) — confirm before disabling. Enabling is
  // safe to flip immediately; disabling has broader traffic
  // impact (attack detection stops on the next request) so the
  // operator gets a confirm() prompt. Mirrors the Rules Delete +
  // Access Lists Remove styled-modal pattern — small enough that
  // a one-line confirm here is fine.
  async function flip() {
    if (busy || !featurePresent) return;
    if (runtimeOn) {
      const ok = window.confirm(
        'Disable the AI detector?\n\n' +
        'Attack detection from the ML model stops on the next request. ' +
        'The regex/heuristic detectors keep running. ' +
        'You can re-enable from this same button.'
      );
      if (!ok) return;
    }
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

  // 2026-05-29 — save the adjusted confidence_threshold. Routes
  // through the cluster config plane so the value persists across
  // restarts and propagates to every node. Validation matches the
  // server: finite + [0.0, 1.0].
  async function saveThreshold() {
    if (savingThreshold) return;
    const v = Number(draftThreshold);
    if (!Number.isFinite(v) || v < 0 || v > 1) {
      window.aegisToast('Threshold must be a number in [0.0, 1.0]', 'err');
      return;
    }
    setSavingThreshold(true);
    try {
      const r = await window.aiConfidencePut(v);
      if (r.status === 200 && r.ok) {
        window.aegisToast(`Confidence threshold set to ${v}`, 'ok');
        aiConfidenceApi.reload && aiConfidenceApi.reload();
      } else if (r.status === 409 && r.error === 'version_conflict') {
        window.aegisToast(`Config version conflict (current=${r.current}); reloading…`, 'warn');
        aiConfidenceApi.reload && aiConfidenceApi.reload();
      } else {
        const msg = r.message || r.error || r.reason || `HTTP ${r.status}`;
        window.aegisToast(`Save failed: ${msg}`, 'err');
      }
    } finally {
      setSavingThreshold(false);
    }
  }

  // Hot-reload the model from its on-disk path. Per-node, local action — the
  // running model keeps serving until the new one loads; a bad file is
  // rejected and the old model stays. Confirm first so an accidental click
  // doesn't reload a half-copied file.
  const canReload = !!aiReloadApi.data?.feature_present;
  const reloadPath = aiReloadApi.data?.model_path;
  async function reloadModel() {
    if (reloading || !canReload) return;
    const ok = window.confirm(
      'Reload the AI model from disk?\n\n' +
      (reloadPath ? `Path: ${reloadPath}\n\n` : '') +
      'This re-reads the file on THIS node and atomically swaps it into the ' +
      'live detector. In-flight requests finish on the current model; a ' +
      'corrupt/half-written file is rejected and the running model is kept. ' +
      'On a multi-node fleet, repeat on each node.'
    );
    if (!ok) return;
    setReloading(true);
    try {
      const r = await window.aiReloadPost();
      if (r.status === 200 && r.ok) {
        const ms = typeof r.load_ms === 'number' ? ` in ${r.load_ms}ms` : '';
        const sess = typeof r.sessions === 'number' ? ` · ${r.sessions} session(s)` : '';
        window.aegisToast(`AI model reloaded${ms}${sess}`, 'ok');
        aiReloadApi.reload && aiReloadApi.reload();
      } else {
        const msg = r.message || r.error || r.reason || `HTTP ${r.status}`;
        window.aegisToast(`Reload failed: ${msg} (running model kept)`, 'err');
      }
    } finally {
      setReloading(false);
    }
  }

  const liveThreshold = aiConfidenceApi.data?.confidence_threshold;
  const defaultThreshold = aiConfidenceApi.data?.default;
  const thresholdDirty =
    draftThreshold !== null &&
    typeof liveThreshold === 'number' &&
    Number(draftThreshold) !== Number(liveThreshold);

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
            <span>
              rebuild with <code>--features ai</code> and set <code>cfg.ai.model_path</code> to a valid ONNX file (run <code>make ai-link MODEL=&lt;path&gt;</code>)
            </span>
          )}
          {/* R2-009 sub-A (2026-06-01) — expandable even feature-off so
              the operator can see the disabled threshold input + the
              configured default, rather than the row being a dead end. */}
          <button
            type="button"
            onClick={() => setExpanded(!expanded)}
            style={{ background: 'transparent', border: 'none', color: 'var(--ink-dim)', cursor: 'pointer', fontSize: 11, padding: 0 }}
          >
            {expanded ? '▾ hide details' : '▸ details'}
          </button>
        </div>
        <div style={{ display: 'flex', gap: 6 }}>
          {/* R2-009 sub-B (2026-06-01) — feature-off a11y. Native
              `disabled` suppresses both the title tooltip and a
              not-allowed cursor and drops the control from the focus
              order, so a screen reader can't announce *why* the button
              is dead. For the feature-off case we use aria-disabled
              instead (flip() already early-returns on !featurePresent,
              so the click is a safe no-op) — the button stays
              hoverable/focusable, announces its disabled state, shows
              the rebuild hint on hover, and renders cursor:not-allowed.
              The transient `busy` state is only reachable feature-on,
              so it keeps the real native `disabled`. */}
          {/* Hot-reload the model from disk. Only meaningful when a model is
              loaded (canReload), so it's hidden in the feature-off case rather
              than rendered inert — the Enable/Disable button already carries
              the rebuild hint there. Audit-logged + CSRF-gated server-side. */}
          {canReload && (
            <button
              className="btn"
              onClick={reloadModel}
              disabled={reloading}
              title={reloadPath ? `Reload model from ${reloadPath}` : 'Reload the AI model from its configured path'}
              style={{ fontSize: 11, padding: '4px 10px', cursor: reloading ? 'not-allowed' : 'pointer' }}
            >
              {reloading ? 'Reloading…' : '↻ Reload model'}
            </button>
          )}
          <button
            className="btn"
            onClick={flip}
            disabled={featurePresent && busy}
            aria-disabled={!featurePresent || busy ? 'true' : undefined}
            title={!featurePresent ? 'AI feature not built — see hint below' : undefined}
            style={{ fontSize: 11, padding: '4px 10px', cursor: (!featurePresent || busy) ? 'not-allowed' : 'pointer' }}
          >
            {busy ? '…' : (runtimeOn ? 'Disable' : 'Enable')}
          </button>
        </div>
      </div>
      {expanded && (
        <div style={{ borderTop: '1px solid var(--hairline)', padding: '12px 16px', background: 'var(--canvas-2)' }}>
          {/* 2026-05-29 — confidence_threshold tuning. Input shows the
              live value (the gate the data plane is actually reading);
              the label states the cfg-loaded default so the operator
              knows where to reset. PUT routes through the cluster
              config plane → persists + propagates.
              R2-009 sub-A (2026-06-01) — feature-off renders the input
              disabled showing the configured default rather than hiding
              it, so the control is visible-but-inert (NT-UI-06). The
              Save/reset/live caption + metrics only make sense when the
              detector is actually in the chain, so they stay gated. */}
          <div style={{ marginBottom: 14, display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap', fontSize: 12 }}>
            <div style={{ minWidth: 160 }}>
              <div className="field-label">Confidence threshold</div>
              <div style={{ fontSize: 10, color: 'var(--ink-dim)' }}>
                P(Attack) gate · default <span className="num">{typeof defaultThreshold === 'number' ? defaultThreshold.toFixed(2) : '—'}</span>
              </div>
            </div>
            <input
              type="number"
              min="0"
              max="1"
              step="0.01"
              aria-label="Confidence threshold"
              value={featurePresent
                ? (draftThreshold === null ? '' : draftThreshold)
                : (typeof defaultThreshold === 'number' ? defaultThreshold : '')}
              onChange={(e) => setDraftThreshold(e.target.value === '' ? '' : Number(e.target.value))}
              disabled={!featurePresent || savingThreshold || draftThreshold === null}
              aria-disabled={!featurePresent ? 'true' : undefined}
              title={!featurePresent ? 'AI feature not built — value shown is the configured default' : undefined}
              style={{ width: 90, fontSize: 12, padding: '4px 6px', cursor: !featurePresent ? 'not-allowed' : undefined }}
            />
            {featurePresent ? (
              <>
                <button
                  type="button"
                  className="btn"
                  onClick={saveThreshold}
                  disabled={savingThreshold || !thresholdDirty}
                  style={{ fontSize: 11, padding: '4px 10px' }}
                  title={thresholdDirty ? 'Save and activate cluster-wide' : 'No change vs. live value'}
                >
                  {savingThreshold ? '…' : 'Save'}
                </button>
                {thresholdDirty && (
                  <button
                    type="button"
                    onClick={() => setDraftThreshold(liveThreshold)}
                    disabled={savingThreshold}
                    style={{ background: 'transparent', border: 'none', color: 'var(--ink-dim)', cursor: 'pointer', fontSize: 11 }}
                  >
                    reset
                  </button>
                )}
                <div style={{ flex: 1, fontSize: 10, color: 'var(--ink-mute)' }}>
                  live <span className="num">{typeof liveThreshold === 'number' ? liveThreshold.toFixed(2) : '—'}</span>
                  {' · '}lower = more sensitive (catches more, may FP)
                  {' · '}higher = stricter (fewer FPs, may miss)
                </div>
              </>
            ) : (
              <div style={{ flex: 1, fontSize: 10, color: 'var(--ink-mute)' }}>
                read-only — AI detector not built into this binary; rebuild with <code>--features ai</code> to adjust the gate
              </div>
            )}
          </div>
          {featurePresent && (metrics && metrics.present ? (
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
          ))}
          {featurePresent && metrics && fbTotal > 0 && (
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
  // 2026-05-10 — read at the top so we don't violate the Rules of
  // Hooks. The Live Policy summary in the right pane consumes
  // `detectorsApi.data?.overrides[selected.name]` and `?.mask` to
  // show whether the tier inherits Base or has an explicit override.
  const detectorsApi = window.useDetectorsApi
    ? window.useDetectorsApi()
    : { data: null };
  const tiers = tiersApi.data?.tiers || [];
  const routes = routesApi.data?.routes || [];
  // P7 (2026-05-11) — honor `#/detectors?tier=critical` on mount
  // so deep-links from other surfaces (e.g. Live Feed → tier
  // detail) land pre-selected. Parses once at first render; the
  // tier-card click below still controls selection on the page.
  const initialTier = (() => {
    if (typeof window === 'undefined') return null;
    const h = window.location.hash || '';
    const q = h.indexOf('?');
    if (q < 0) return null;
    const p = new URLSearchParams(h.slice(q + 1));
    return p.get('tier');
  })();
  const [selectedName, setSelectedName] = useStateP(initialTier);
  const [tierEditor, setTierEditor] = useStateP(null);  // null | tier object
  const [busy, setBusy] = useStateP(false);

  async function saveTier(name, body) {
    setBusy(true);
    try {
      // 2026-05-10 — pull the detector-override delta out of the
      // body (TierEditModal stuffs it under __detectorOverride
      // when the operator changed mask state). Sequence the
      // detectors PUT first because (a) it's the one most likely
      // to fail validation (compliance clamp etc.) and (b) the
      // tier PUT touches different state, so partial failure
      // leaves the system in a coherent intermediate.
      const detectorOverride = body.__detectorOverride;
      delete body.__detectorOverride;

      if (detectorOverride) {
        const detPayload = detectorOverride.mask
          ? { overrides: { [name]: detectorOverride.mask } }
          : { overrides: { [name]: null } };
        // F7 (2026-06-11) — version-guard the per-tier override PUT too
        // (same clobber risk as a base-mask flip). Echo the version we
        // last read; a 412 means a concurrent change landed — tell the
        // operator to reopen the editor against fresh state rather than
        // overwrite it.
        const dr = await window.detectorsPut(detPayload, {
          ifMatch: detectorsApi.data?.config_version,
        });
        const detOk = dr && typeof dr.status === 'number' && dr.status >= 200 && dr.status < 300;
        if (!detOk) {
          const msg = dr && dr.status === 412
            ? 'detector mask changed since you opened this editor — reopen and reapply'
            : ((dr && (dr.message || dr.error || dr.reason)) || `status ${dr?.status ?? '?'}`);
          window.aegisToast(`Detector override save failed: ${msg}`, 'err');
          detectorsApi.reload && detectorsApi.reload();
          return;
        }
      }

      const r = await window.tierPut(name, body);
      if (r.status === 200 && r.ok) {
        const detSuffix = detectorOverride
          ? (detectorOverride.mask ? ' · detector override saved' : ' · detector override cleared')
          : '';
        window.aegisToast(`Tier "${name}" updated${detSuffix}`, 'ok');
        tiersApi.reload && tiersApi.reload();
        detectorsApi.reload && detectorsApi.reload();
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
      <PolicyPostureCard />
      <div className="page-head">
        <div>
          <h1 className="page-title">
            Detectors &amp; Tiers
            <window.PageTitleRefresh
              onClick={() => { tiersApi.reload && tiersApi.reload(); routesApi.reload && routesApi.reload(); }}
              label="Refresh tier + route data"
            />
          </h1>
          <p className="page-subtitle">
            Per-class detector mask (with per-tier overrides) + per-tier risk thresholds ·
            <span className="num"> {tiers.length}</span> active tiers ·
            <span className="num"> {routes.length}</span> routes
            <span style={{ marginLeft: 8 }}>
              <span className={`pill ${tiersApi.error || routesApi.error ? 'warn' : 'ok'}`}>
                {tiersApi.error || routesApi.error ? 'fetch failed' : 'live'}
              </span>
            </span>
          </p>
        </div>
      </div>

      {/* `DetectorMaskCard` renders the unified Detectors card —
          base mask + per-tier overrides + an `AiDetectorRow`
          folded in at the bottom (separate runtime knob, same
          card so operators see the full detector inventory in
          one place). */}
      <DetectorMaskCard />

      {/* 2026-05-22 — load_shed explainer. Operators kept hunting for a
          `load_shed` row in the Base mask above (it surfaces in Attack
          distribution because the aggregator buckets every block by
          rule_id). It is NOT a detector: it is a tier-aware availability
          gate. Documenting it here, next to the tiers it keys off of. */}
      <LoadShedGateCard />

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
              return (
                <button key={t.name} onClick={() => setSelectedName(t.name)}
                  style={{ display: 'block', width: '100%', textAlign: 'left', padding: 14, border: 'none', borderBottom: '1px solid var(--hairline)',
                    background: selected && selected.name === t.name ? 'var(--surface-active)' : 'transparent',
                    borderLeft: selected && selected.name === t.name ? '3px solid var(--brand-yellow)' : '3px solid transparent',
                    cursor: 'pointer', color: 'inherit' }}>
                  <div style={{ fontSize: 13, fontWeight: 600, marginBottom: 2 }}>{t.name}</div>
                  <div
                    style={{ fontSize: 11, color: 'var(--ink-dim)', marginBottom: 6 }}
                    title={`Per-request: this tier blocks a request when its detector scores sum to ${t.risk_threshold} or more`}
                  >
                    block when score ≥ <span className="num">{t.risk_threshold}</span>
                  </div>
                  <div style={{ display: 'flex', gap: 6, fontSize: 10 }}>
                    <span className="pill neutral">{tierRouteCount} routes</span>
                    {t.challenges_enabled === true && (
                      <span className="pill ok" title="Cumulative-IP-risk challenges are enabled on this tier (PoW puzzle on score crossing)">challenges on</span>
                    )}
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
                    Per-request block ≥ <span className="num">{selected.risk_threshold}</span>
                    {' · '}
                    cumulative challenge {selected.cumulative_challenge_at != null
                      ? <>≥ <span className="num">{selected.cumulative_challenge_at}</span></>
                      : <span style={{ fontStyle: 'italic' }}>inherit</span>}
                    {' · '}
                    cumulative block {selected.cumulative_block_at != null
                      ? <>≥ <span className="num">{selected.cumulative_block_at}</span></>
                      : <span style={{ fontStyle: 'italic' }}>inherit</span>}
                    {' · '}
                    challenges {selected.challenges_enabled === true
                      ? <span style={{ color: 'var(--up)' }}>on</span>
                      : 'off'}
                  </div>
                </div>
                <button className="btn" onClick={() => setTierEditor(selected)} disabled={busy}>
                  Edit tier
                </button>
              </div>

              {/* 2026-05-10 — replaced the dead "Pipeline (N stages)"
                  pill list. Per `docs/security/security-engine.md`,
                  pipeline is descriptive metadata only — the runtime
                  detector gate is the per-tier mask grid at the top
                  of this page. This summary points operators at the
                  three surfaces where this tier's live policy is
                  actually configured. */}
              <div style={{ background: 'var(--canvas-2)', border: '1px solid var(--hairline)', borderRadius: 6, padding: 12, marginBottom: 16 }}>
                <div style={{ fontSize: 12, fontWeight: 600, marginBottom: 10 }}>
                  Live policy for <span className="mono">{selected.name}</span>
                </div>
                <div style={{ display: 'grid', gridTemplateColumns: 'minmax(160px, max-content) 1fr', gap: '6px 12px', fontSize: 11, lineHeight: 1.5 }}>
                  <div style={{ color: 'var(--ink-dim)' }}>Detectors that run</div>
                  <div>
                    {(() => {
                      // Pure projection over `detectorsApi.data` — the
                      // hook itself is called at the top of
                      // PageTierConfig (Rules of Hooks).
                      const tierOverride = detectorsApi.data?.overrides?.[selected.name];
                      const baseMask = detectorsApi.data?.mask;
                      const explicit = !!tierOverride;
                      const effective = tierOverride || baseMask || {};
                      const enabledCount = Object.entries(effective).filter(([, v]) => v).length;
                      const totalCount = Object.keys(effective).length;
                      return (
                        <>
                          {explicit ? (
                            <strong>{enabledCount}/{totalCount} enabled</strong>
                          ) : (
                            <>
                              <em>inherits Base</em> ({totalCount > 0 ? `${enabledCount}/${totalCount} enabled` : 'loading…'})
                            </>
                          )}
                          {' · '}
                          <a
                            href="#detector-mask-grid"
                            onClick={(e) => {
                              e.preventDefault();
                              const card = document.querySelector('[data-component="detector-mask-card"]');
                              if (card) card.scrollIntoView({ behavior: 'smooth', block: 'start' });
                            }}
                            style={{ color: 'var(--accent)' }}
                          >
                            {explicit ? 'Edit override ↑' : 'Override on mask grid ↑'}
                          </a>
                        </>
                      );
                    })()}
                  </div>

                  <div style={{ color: 'var(--ink-dim)' }}>Per-request gate</div>
                  <div>
                    Block when this single request's detector scores sum to ≥
                    {' '}<strong className="num">{selected.risk_threshold}</strong>.
                    Edit on this card → <em>Edit tier</em>.
                  </div>

                  <div style={{ color: 'var(--ink-dim)' }}>Cumulative IP gate</div>
                  <div>
                    {selected.challenges_enabled === true ? (
                      <><span style={{ color: 'var(--up)', fontWeight: 600 }}>challenges on</span> · PoW on threshold crossing</>
                    ) : (
                      <>challenges off · challenge band passes through (blocks only at block threshold)</>
                    )}
                    {' · '}
                    thresholds: <a href="#/traffic-gates" style={{ color: 'var(--accent)' }}>Traffic Gates → #3</a>
                  </div>

                  <div style={{ color: 'var(--ink-dim)' }}>Rules</div>
                  <div>
                    Authored on <a href="#/rules" style={{ color: 'var(--accent)' }}>Rules</a>;
                    rules can be tier-scoped via their DSL (priority order: global → tier → route → session).
                  </div>

                  <div style={{ color: 'var(--ink-dim)' }}>Volumetric gates</div>
                  <div>
                    Rate-limit + DDoS run <strong>before</strong> tier classification — global, configured on
                    {' '}<a href="#/traffic-gates" style={{ color: 'var(--accent)' }}>Traffic Gates</a>.
                  </div>
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
                    {routesForSelected.map(r => {
                      return (
                        <tr key={r.id}>
                          <td className="mono">{r.id}</td>
                          <td className="mono dim">{r.host || '*'}</td>
                          <td className="mono">{r.path}</td>
                          <td><span className="pill neutral">{r.match_type}</span></td>
                          <td className="mono dim">{r.methods.length === 0 ? 'ANY' : r.methods.join(', ')}</td>
                          <td className="mono">{r.upstream}</td>
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
// 2026-05-10 — TIER_PIPELINE_STAGES checkbox grid retired (Option B).
// Every stage in the previous list was either descriptive metadata
// or already configurable elsewhere (detector mask, Traffic Gates,
// Rules page). The Tier editor now focuses on the four real
// per-tier knobs: per-request block score, cumulative challenge
// threshold, cumulative block threshold, and the challenges
// on/off toggle. The wire shape still carries `pipeline` so
// existing YAML loads; we POST whatever the tier already had.

function TierEditModal({ tier, onCancel, onSave, busy }) {
  // Preserve the existing pipeline list verbatim — wire shape stays
  // stable, dashboard just doesn't expose the checkboxes any more.
  const preservedPipeline = tier.pipeline || [];
  const [risk, setRisk] = useStateP(tier.risk_threshold ?? 50);
  // 2026-05-10 R3 — per-tier cumulative threshold inputs retired
  // from the dashboard (operator-confirmed: in practice the
  // global cumulative thresholds + the per-request block score
  // cover the common needs; per-tier cumulative tuning is a
  // niche use case). Wire shape kept intact so:
  //   (a) values previously set via API persist across saves —
  //       we round-trip `tier.cumulative_*` verbatim;
  //   (b) restoring the inputs is a UI-only change.
  const preservedCumChallenge = tier.cumulative_challenge_at ?? null;
  const preservedCumBlock = tier.cumulative_block_at ?? null;
  // 2026-05-10 R2 — challenges default to OFF. Treat missing /
  // undefined as false (was: missing-as-true), matching the new
  // backend default.
  const [challengesEnabled, setChallengesEnabled] = useStateP(tier.challenges_enabled === true);
  const [showFlow, setShowFlow] = useStateP(false);

  // 2026-05-10 — per-tier detector mask edit moved here from the
  // unified card (which now only edits Base). Operators get one
  // focused surface per tier: thresholds + challenges + detector
  // overrides. On save we sequence the existing detectors PUT and
  // tiers PUT — both audit-mutated, both idempotent.
  const detectorsApi = window.useDetectorsApi
    ? window.useDetectorsApi()
    : { data: null };
  const baseMask = detectorsApi.data?.mask || {};
  const existingOverride = detectorsApi.data?.overrides?.[tier.name] || null;
  // `overrideMask` is null when the operator hasn't decided to
  // override yet (inherits Base) or has cleared the override; an
  // object when actively customizing.
  const [overrideMask, setOverrideMask] = useStateP(
    existingOverride ? { ...existingOverride } : null
  );
  // Track the original state so we know whether to emit a
  // detectors PUT on save (no PUT if nothing changed).
  const initialOverride = useRefP(existingOverride);
  // Re-seed when the modal opens for a different tier — the
  // existingOverride read happens after the hook resolves.
  useEffectP(() => {
    if (detectorsApi.data) {
      setOverrideMask(existingOverride ? { ...existingOverride } : null);
      initialOverride.current = existingOverride;
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [tier.name, !!detectorsApi.data]);

  const isOverriding = !!overrideMask;
  const startOverride = () => {
    // Seed with the current Base mask so the operator sees what's
    // running today + can toggle classes off/on.
    setOverrideMask({ ...baseMask });
  };
  const dropOverride = () => {
    setOverrideMask(null);
  };
  const toggleOverrideClass = (cls) => {
    setOverrideMask((m) => (m ? { ...m, [cls]: !m[cls] } : m));
  };
  // Whether the in-modal state differs from what the server has.
  const overrideChanged =
    JSON.stringify(overrideMask) !== JSON.stringify(initialOverride.current);

  const riskValid = risk >= 0 && risk <= 100;
  const canSave = riskValid && !busy;

  return (
    <div className="modal-backdrop" onClick={onCancel}>
      <div className="modal" onClick={e => e.stopPropagation()} style={{ maxWidth: 620 }}>
        <div className="modal-head">
          <div className="modal-title">Edit tier · {tier.name}</div>
          <button className="btn btn-sm" onClick={onCancel}>×</button>
        </div>
        <div className="modal-body">
          {/* Collapsible decision-flow primer for operators new to
              the page. Default collapsed — power users skip it. */}
          <div style={{ marginBottom: 14, border: '1px solid var(--hairline)', borderRadius: 4 }}>
            <button
              type="button"
              onClick={() => setShowFlow(s => !s)}
              style={{
                width: '100%', textAlign: 'left', background: 'transparent',
                border: 'none', padding: '8px 12px', cursor: 'pointer',
                fontSize: 11, fontWeight: 600, color: 'var(--ink)',
                display: 'flex', alignItems: 'center', gap: 8,
              }}
            >
              <span style={{ fontSize: 10, color: 'var(--ink-dim)' }}>{showFlow ? '▼' : '▶'}</span>
              How is a request blocked or challenged on this tier?
              <span style={{ marginLeft: 'auto', fontSize: 10, color: 'var(--ink-dim)', fontWeight: 400 }}>
                {showFlow ? 'click to collapse' : 'click to expand'}
              </span>
            </button>
            {showFlow && (
              <div style={{ padding: '4px 12px 12px', fontSize: 11, color: 'var(--ink-dim)', lineHeight: 1.5 }}>
                Three independent gates run in order; the first one that fires wins.
                <ol style={{ margin: '6px 0 0', paddingLeft: 18 }}>
                  <li><strong>Traffic Gates</strong> (global, before tier matching) — access list, strike-block, rate-limit, DDoS. Configured on Traffic Gates page.</li>
                  <li><strong>Per-request block score</strong> (this tier) — when THIS one request's detector scores sum to ≥ the value below, block immediately.</li>
                  <li><strong>Cumulative IP history</strong> — IP's running score crosses the global thresholds (Traffic Gates → #3). On this tier, the challenge band either runs a PoW puzzle or is skipped (allowed through) based on the toggle below; either way only the block threshold blocks.</li>
                </ol>
                Otherwise → allow + forward to upstream. <code>X-WAF-Risk-Score</code> always reports the cumulative IP score (contract §5.1).
              </div>
            )}
          </div>

          {/* ── Per-request gate ───────────────────────────────── */}
          <div className="form-row">
            <div style={{ fontSize: 10, fontWeight: 600, color: 'var(--ink-dim)', textTransform: 'uppercase', letterSpacing: 0.5, marginBottom: 6 }}>
              Per-request gate
            </div>
            <label>Block score (0-100) <span className="req">*</span></label>
            <input className="ip" type="number" min="0" max="100"
              value={risk}
              onChange={e => {
                const v = parseInt(e.target.value, 10);
                if (!Number.isFinite(v)) { setRisk(0); return; }
                setRisk(Math.max(0, Math.min(100, v)));
              }} />
            <div className="form-hint">
              Block when this request's detector scores sum ≥ this value. Lower = stricter.
            </div>
            {!riskValid && (
              <div className="form-hint warn">Must be between 0 and 100.</div>
            )}
          </div>

          {/* ── Cumulative IP gate ──
              R3 — Threshold inputs retired. Only the on/off toggle
              remains per-tier. Threshold defaults are global; edit on
              Traffic Gates → #3. */}
          <div className="form-row" style={{ marginTop: 16, paddingTop: 12, borderTop: '1px solid var(--hairline)' }}>
            <div style={{ fontSize: 10, fontWeight: 600, color: 'var(--ink-dim)', textTransform: 'uppercase', letterSpacing: 0.5, marginBottom: 6 }}>
              Cumulative IP gate
            </div>
            <label style={{ display: 'flex', alignItems: 'center', gap: 8, cursor: 'pointer' }}>
              <input type="checkbox" checked={challengesEnabled} onChange={e => setChallengesEnabled(e.target.checked)} />
              <span><strong>Allow challenges</strong> <span style={{ color: 'var(--ink-dim)', fontWeight: 400 }}>(off → challenge band skipped, blocks only at block threshold)</span></span>
            </label>
            <div className="form-hint" style={{ marginTop: 6 }}>
              Cumulative thresholds are global — edit on <a href="#/traffic-gates" style={{ color: 'var(--accent)' }}>Traffic Gates → #3</a>.
            </div>
          </div>

          {/* ── Detector overrides (per-tier mask) ─────────── */}
          <div className="form-row" style={{ marginTop: 16, paddingTop: 12, borderTop: '1px solid var(--hairline)' }}>
            <div style={{ fontSize: 10, fontWeight: 600, color: 'var(--ink-dim)', textTransform: 'uppercase', letterSpacing: 0.5, marginBottom: 6 }}>
              Detectors
            </div>

            <label style={{ display: 'flex', alignItems: 'center', gap: 8, cursor: 'pointer', marginBottom: 8 }}>
              <input
                type="checkbox"
                checked={isOverriding}
                onChange={() => isOverriding ? dropOverride() : startOverride()}
              />
              <span><strong>Override Base mask</strong> <span style={{ color: 'var(--ink-dim)', fontWeight: 400 }}>(off → inherit Base)</span></span>
            </label>

            {isOverriding && overrideMask && (
              <>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, marginBottom: 6 }}>
                  {MASK_CLASSES.map(cls => {
                    const enabled = !!overrideMask[cls];
                    const baseEnabled = !!baseMask[cls];
                    const differsFromBase = enabled !== baseEnabled;
                    const description = CLASS_DESCRIPTIONS[cls];
                    const baseTitle = `${cls} — ${enabled ? 'on' : 'off'}${differsFromBase ? ` (Base: ${baseEnabled ? 'on' : 'off'})` : ''}`;
                    return (
                      <button
                        key={cls}
                        type="button"
                        onClick={() => toggleOverrideClass(cls)}
                        title={description ? `${baseTitle}\n\n${description}` : baseTitle}
                        style={{
                          fontSize: 10, padding: '3px 9px', borderRadius: 4,
                          background: enabled ? 'rgba(14,203,129,0.14)' : 'transparent',
                          color: enabled ? 'var(--up)' : 'var(--ink-dim)',
                          fontWeight: differsFromBase ? 700 : 500,
                          border: differsFromBase ? '1px solid var(--brand-yellow)' : '1px solid var(--hairline)',
                          textDecoration: enabled ? 'none' : 'line-through',
                          cursor: 'pointer',
                        }}
                      >
                        {cls}{!enabled && ' · off'}
                      </button>
                    );
                  })}
                </div>
                {(() => {
                  const diff = MASK_CLASSES.filter(c => !!overrideMask[c] !== !!baseMask[c]).length;
                  return (
                    <div className="form-hint">
                      {diff === 0
                        ? 'Matches Base. Toggle a chip to diverge.'
                        : <><strong>{diff}</strong> {diff === 1 ? 'class differs' : 'classes differ'} from Base (yellow border).</>}
                    </div>
                  );
                })()}
              </>
            )}
          </div>

          <div style={{ marginTop: 14, padding: 8, background: 'var(--canvas-2)', borderRadius: 4, fontSize: 11, fontFamily: 'var(--mono)' }}>
            block≥{risk}
            {' · '}challenges {challengesEnabled ? 'on' : 'off'}
            {' · '}detectors {isOverriding
              ? `${Object.entries(overrideMask).filter(([, v]) => v).length}/${Object.keys(overrideMask).length}`
              : 'base'}
          </div>
        </div>
        <div className="modal-foot">
          <button className="btn" onClick={onCancel} disabled={busy}>Cancel</button>
          <button className="btn primary" disabled={!canSave} onClick={() => onSave({
            pipeline: preservedPipeline,
            risk_threshold: risk,
            block_threshold: tier.block_threshold ?? 100,
            // R3 — cumulative thresholds are not edited from the
            // dashboard. Round-trip whatever the API has.
            cumulative_challenge_at: preservedCumChallenge,
            cumulative_block_at: preservedCumBlock,
            challenges_enabled: challengesEnabled,
            // 2026-05-10 — detector override delta. The parent's
            // saveTier() sequences a `PUT /api/detectors` (audit-
            // mutated) when this is non-null. `null` means "no
            // change to detectors" (skip the second PUT).
            __detectorOverride: overrideChanged
              ? { mask: overrideMask, hadBefore: !!initialOverride.current }
              : null,
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

  // P4 (2026-05-11) — per-entry hit counts in the last 1h / 24h.
  // Polled every 15s; the data plane increments the counter
  // inside `AccessListStore::matches()` on each access-list
  // match. Operators see which entries are still earning their
  // keep and a "consider removing" link for entries that haven't
  // matched anything in the last 24h.
  const hitsPath = isBL ? '/api/blacklist/hits?window=3600' : '/api/whitelist/hits?window=3600';
  const hits24Path = isBL ? '/api/blacklist/hits?window=86400' : '/api/whitelist/hits?window=86400';
  const hits1hApi = window.useApi
    ? window.useApi(hitsPath, { intervalMs: 15000, fallback: { hits: {} } })
    : { data: { hits: {} } };
  const hits24hApi = window.useApi
    ? window.useApi(hits24Path, { intervalMs: 60000, fallback: { hits: {} } })
    : { data: { hits: {} } };
  const hits1h = hits1hApi.data?.hits || {};
  const hits24h = hits24hApi.data?.hits || {};

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
  // F-02 (2026-05-11) — submit-attempt tracking so the Add form
  // shows inline validation on empty Value instead of a silently
  // disabled button. The value ref also lets us focus the field
  // after a failed submit.
  const [attempted, setAttempted] = useStateP(false);
  const valueRef = useRefP(null);

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
    if (busy) return;
    // F-02 — surface a visible "Value is required" error +
    // focus the field instead of silently no-op'ing.
    if (!value) {
      setAttempted(true);
      if (valueRef.current) valueRef.current.focus();
      return;
    }
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

  // F-07 (2026-05-11) — replaced native window.confirm() with
  // a styled modal so the Remove flow looks consistent with the
  // Rules Delete and Detector Disable patterns. Native confirm()
  // bypasses the dark theme and is auto-dismissible by some
  // browser settings.
  const [pendingDelete, setPendingDelete] = useStateP(null); // null | entry object

  async function deleteRow(entry) {
    if (busy) return;
    setPendingDelete(entry);
  }

  async function confirmDeleteRow() {
    const entry = pendingDelete;
    if (!entry || busy) return;
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
      setPendingDelete(null);
    }
  }

  return (
    <>
      <PolicyPostureCard />
      <div className="page-head">
        <div>
          <h1 className="page-title">
            {isBL ? 'Blacklist' : 'Whitelist'}
            <window.PageTitleRefresh
              onClick={() => api.reload && api.reload()}
              label={isBL ? 'Refresh blacklist' : 'Refresh whitelist'}
            />
          </h1>
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
            {/* F-08 — drop the `+` icon in the Cancel state.
                `+` semantically means "add"; pairing it with
                Cancel is contradictory. Drop the icon entirely
                when collapsing the form. */}
            {showForm ? 'Cancel' : <><window.I.Plus /> Add entry</>}
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
              <label style={{ fontSize: 10, color: 'var(--ink-dim)', textTransform: 'uppercase', letterSpacing: 0.4 }}>
                Value <span style={{ color: 'var(--down)' }}>*</span>
              </label>
              <input
                ref={valueRef}
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
                aria-required="true"
                aria-invalid={attempted && !draftValue.trim()}
                style={{
                  padding: '6px 8px', background: 'var(--canvas-2)',
                  border: `1px solid ${attempted && !draftValue.trim() ? 'var(--down)' : 'var(--hairline)'}`,
                  borderRadius: 4, color: 'var(--ink)', fontFamily: 'monospace',
                }}
              />
              {attempted && !draftValue.trim() && (
                <span style={{ fontSize: 11, color: 'var(--down)' }}>Value is required.</span>
              )}
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
              disabled={busy}
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
              <th style={{ width: 90 }} title="Per-entry hit count in the last hour · last day (hover for the 24h figure)">Hits · 1h</th>
              <th style={{ width: 130 }}>Expires</th>
              <th style={{ width: 130 }}>Created</th>
              <th style={{ width: 80 }}></th>
            </tr>
          </thead>
          <tbody>
            {filtered.length === 0 && (
              <tr><td colSpan={8} style={{ textAlign: 'center', padding: 16, color: 'var(--ink-dim)', fontSize: 12 }}>
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
                <td className="num">
                  {(() => {
                    const h1 = hits1h[e.id] || 0;
                    const h24 = hits24h[e.id] || 0;
                    const tone = h1 > 0 ? 'ok' : (h24 > 0 ? 'neutral' : 'warn');
                    const tip = `last 1h: ${h1} · last 24h: ${h24}`;
                    return (
                      <span className={`pill ${tone}`} title={tip} style={{ fontSize: 10 }}>
                        {h1}
                        {h24 === 0 && h1 === 0 && (
                          <span style={{ marginLeft: 4, fontSize: 9, fontStyle: 'italic' }}>
                            · stale
                          </span>
                        )}
                      </span>
                    );
                  })()}
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
      {pendingDelete && (
        <RemoveAccessListEntryModal
          kind={kind}
          entry={pendingDelete}
          busy={busy}
          onCancel={() => setPendingDelete(null)}
          onConfirm={confirmDeleteRow}
        />
      )}
    </>
  );
}

// F-07 (2026-05-11) — styled confirmation modal for the Access
// Lists Remove flow, replacing native window.confirm(). Mirrors
// DeleteRuleModal / DeleteRouteModal so all three "destructive
// remove" surfaces share one visual language.
function RemoveAccessListEntryModal({ kind, entry, busy, onCancel, onConfirm }) {
  return (
    <div className="modal-backdrop" onClick={onCancel}>
      <div className="modal" onClick={e => e.stopPropagation()} style={{ maxWidth: 460 }}>
        <div className="modal-head">
          <div className="modal-title">
            Remove {kind} entry <code>{entry.kind}:{entry.value}</code>?
          </div>
          <button className="btn btn-sm" onClick={onCancel}>×</button>
        </div>
        <div className="modal-body">
          <p style={{ fontSize: 13, lineHeight: 1.5 }}>
            Removing <code>{entry.kind}:{entry.value}</code> is audit-mutated and
            cannot be undone. New requests stop matching this entry on the
            next request; in-flight requests finish on the old list.
          </p>
          {entry.note && (
            <p style={{ fontSize: 12, color: 'var(--ink-dim)', marginTop: 8 }}>
              Note on this entry: <em>{entry.note}</em>
            </p>
          )}
        </div>
        <div className="modal-foot">
          <button className="btn" onClick={onCancel} disabled={busy}>Cancel</button>
          <button className="btn danger" onClick={onConfirm} disabled={busy}>
            {busy ? 'Removing…' : 'Remove'}
          </button>
        </div>
      </div>
    </div>
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
              // LOW-ADM-05 (2026-05-12) — pin 24h so Config
              // history TIME reads consistent with Audit Trail.
              const ts = fmtAbsoluteTimestamp(v.ts);
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
    ? window.useApi('/api/zero-trust/downstream/mode', { intervalMs: 10000, fallback: null })
    : { data: null };
  const [busy, setBusy] = useStateP(false);
  // 2026-06-12 — optimistic local override so the buttons flip INSTANTLY on
  // click. Previously the active state came only from `api.data` (a 10s
  // poll), so a toggle didn't visually update until the next poll/reload —
  // "very slow to update". The PUT already echoes the authoritative new
  // mode (used below); this effect drops the optimistic value once the
  // poll brings fresh server state, so a change from another operator still
  // reconciles.
  const [local, setLocal] = useStateP(null);
  useEffectP(() => { setLocal(null); }, [api.data]);

  if (!api.data) {
    return (
      <div className="card" style={{ padding: 16, fontSize: 12, color: 'var(--ink-dim)' }}>
        Loading mTLS mode…
      </div>
    );
  }
  const view = local || api.data;
  const { configured, override: ovr, effective, requires_restart } = view;

  async function setMode(target) {
    if (target === 'required') {
      const ok = window.confirm(
        `Switch effective mTLS mode to REQUIRED?\n\nClients that don't present a valid client certificate will fail the TLS handshake. This affects every active session. Type OK in the next prompt to confirm.`
      );
      if (!ok) return;
    }
    // Flip the button immediately (an override sets effective = target).
    setLocal({ ...(local || api.data), override: target, effective: target });
    setBusy(true);
    try {
      const csrf = document.cookie.split('; ').find(c => c.startsWith('aegis_csrf='))?.slice(11) || '';
      const r = await fetch('/api/zero-trust/downstream/mode', {
        method: 'PUT',
        headers: { 'content-type': 'application/json', 'x-csrf-token': csrf },
        body: JSON.stringify({ mode: target }),
        credentials: 'same-origin',
      });
      if (!r.ok) throw new Error(`status ${r.status}`);
      // The PUT echoes the authoritative new mode — use it directly instead
      // of a separate GET round-trip.
      const j = await r.json().catch(() => null);
      if (j && j.mode) setLocal(j.mode);
    } catch (e) {
      setLocal(null); // revert the optimistic flip
      (window.aegisToast || window.toast)?.(`mTLS mode set failed: ${e.message}`, 'err');
    } finally {
      setBusy(false);
    }
  }
  async function clearOverride() {
    // Optimistically revert to the configured mode.
    setLocal({ ...(local || api.data), override: null, effective: configured });
    setBusy(true);
    try {
      const csrf = document.cookie.split('; ').find(c => c.startsWith('aegis_csrf='))?.slice(11) || '';
      const r = await fetch('/api/zero-trust/downstream/mode', {
        method: 'PUT',
        headers: { 'content-type': 'application/json', 'x-csrf-token': csrf },
        body: JSON.stringify({ clear: true }),
        credentials: 'same-origin',
      });
      if (!r.ok) throw new Error(`status ${r.status}`);
      const j = await r.json().catch(() => null);
      if (j && j.mode) setLocal(j.mode);
    } catch (e) {
      setLocal(null);
      (window.aegisToast || window.toast)?.(`mTLS mode clear failed: ${e.message}`, 'err');
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
// `zero_trust_ca_bundle_validated`. The hot-swap of the live trust
// store ships with the listener-rebuild track (Phase 2).
function MtlsCaBundleCard() {
  const cap = window.useApi
    ? window.useApi('/api/zero-trust/downstream/ca-bundle/capability', { intervalMs: 60000, fallback: { allow_ca_upload: false } })
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
      const r = await fetch('/api/zero-trust/downstream/ca-bundle', {
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
// 2026-05-20 — Canary honeypot path editor. Replaces the old
// local-only chip stub: this card reads `/api/risk/canary-paths`
// and edits the live set through the audit-mutated PUT, so paths
// hot-apply with no restart. Each add/remove sends the full
// (replace-only) list, matching the Settings page's "changes apply
// immediately" contract. The `enabled` flag reflects whether the
// `canary` detector mask bit is on — editing paths while it's off
// is allowed (so operators can stage a list) but inert until they
// enable the detector on the Detectors page.
function CanaryPathsCard() {
  const api = window.useCanaryPathsApi();
  const list = Array.isArray(api?.data?.paths) ? api.data.paths : [];
  const enabled = api?.data?.enabled === true;
  const [draft, setDraft] = useStateP('');
  const [busy, setBusy] = useStateP(false);

  async function applyList(next, okMsg) {
    setBusy(true);
    try {
      const r = await window.canaryPathsPut(next);
      if (r && r.ok) {
        window.aegisToast(okMsg, 'ok');
        setDraft('');
        api.reload && api.reload();
        return true;
      }
      const msg = (r && (r.message || r.error || r.reason)) || `HTTP ${r && r.status}`;
      window.aegisToast(`Canary paths: ${msg}`, 'err');
      return false;
    } catch (e) {
      window.aegisToast(`Canary paths error: ${e.message || e}`, 'err');
      return false;
    } finally {
      setBusy(false);
    }
  }

  async function addOne() {
    const next = (draft || '').trim();
    if (!next || busy) return;
    if (!next.startsWith('/')) {
      window.aegisToast("Canary path must start with '/' (e.g. /wp-admin)", 'warn');
      return;
    }
    if (list.includes(next)) {
      window.aegisToast(`'${next}' is already a canary path`, 'warn');
      return;
    }
    await applyList([...list, next], `Added canary path '${next}'`);
  }

  async function removeOne(p) {
    if (busy) return;
    if (!confirm(`Remove canary path '${p}'?`)) return;
    await applyList(list.filter(x => x !== p), `Removed canary path '${p}'`);
  }

  const empty = list.length === 0;

  return (
    <div className="card" style={{ marginBottom: 12 }}>
      <div className="card-head">
        <div>
          <div className="card-title">Canary Honeypot Paths</div>
          <div className="card-subtitle">
            Paths no legitimate client should ever request
            (<code>/wp-admin</code>, <code>/.env</code>,
            {' '}<code>/phpmyadmin/*</code>). A single hit scores 100
            (max confidence) and blocks at every tier. Edits hot-apply
            via audit-mutated <code>PUT /api/risk/canary-paths</code> —
            no restart. Use a trailing <code>/*</code> to match any
            subpath.
          </div>
        </div>
        <span className={`pill ${empty ? 'warn' : 'ok'}`}>
          {empty ? 'none configured' : `${list.length} path${list.length === 1 ? '' : 's'}`}
        </span>
      </div>

      {!enabled && (
        <div className="banner warn" style={{ marginBottom: 8 }}>
          <div style={{ flex: 1, fontSize: 12 }}>
            The <code>canary</code> detector is currently <strong>off</strong>,
            so these paths are inert. Enable it on the{' '}
            <a href="#/detectors" style={{ color: 'var(--accent)', fontWeight: 600 }}>
              Detectors page
            </a>{' '}
            to start tripping on honeypot hits.
          </div>
        </div>
      )}

      <div style={{ display: 'flex', gap: 8, alignItems: 'center', marginBottom: 8 }}>
        <input
          type="text"
          placeholder="/wp-admin   or   /.env   or   /phpmyadmin/*"
          value={draft}
          onChange={e => setDraft(e.target.value)}
          onKeyDown={e => { if (e.key === 'Enter') addOne(); }}
          disabled={busy}
          style={{ flex: 1, padding: '6px 8px', background: 'var(--canvas-2)', border: '1px solid var(--hairline)', borderRadius: 4, color: 'var(--ink)', fontFamily: 'monospace' }}
        />
        <button className="btn primary" onClick={addOne} disabled={busy || !draft.trim()}>
          Add path
        </button>
      </div>

      {empty ? (
        <div style={{ padding: 8, fontSize: 12, color: 'var(--ink-dim)', fontStyle: 'italic' }}>
          No honeypot paths configured — the canary detector never fires.
        </div>
      ) : (
        <table className="table" style={{ width: '100%' }}>
          <thead>
            <tr>
              <th style={{ textAlign: 'left' }}>Path</th>
              <th style={{ textAlign: 'left', width: 90 }}>Match</th>
              <th style={{ textAlign: 'right', width: 120 }}>Actions</th>
            </tr>
          </thead>
          <tbody>
            {list.map(p => (
              <tr key={p}>
                <td style={{ fontFamily: 'monospace' }}>{p}</td>
                <td style={{ fontSize: 11, color: 'var(--ink-mute)' }}>
                  {p.endsWith('*') ? 'prefix' : 'exact'}
                </td>
                <td style={{ textAlign: 'right' }}>
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
    </div>
  );
}

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

// ---------------------------------------------------------------------------
// Zero Trust page (P3) — unified mutual-TLS surface, both directions.
// Upstream (WAF→backend, client auth) cards are new; downstream
// (client→WAF) reuses the relocated MtlsModeCard / MtlsCaBundleCard /
// MtlsSansCard (moved off the Settings page).
// ---------------------------------------------------------------------------

// Shared helper: read the aegis_csrf cookie for the Zero Trust
// mutation cards (raw-PEM bodies can't use the JSON `csrfMutate`).
function ztCsrf() {
  return document.cookie.split('; ').find(c => c.startsWith('aegis_csrf='))?.slice(11) || '';
}

// Expiry pill — green ≥30d, amber <30d, red if already expired.
function ZtExpiryPill({ days }) {
  if (days == null) return null;
  const tone = days < 0 ? 'down' : days < 30 ? 'warn' : 'ok';
  const txt = days < 0 ? 'expired' : `${days}d`;
  return <span className={`pill ${tone}`}>{txt}</span>;
}

// Anchor ids the upstream cards register so the stepper / inline banners
// can jump straight to the card a control depends on.
const ZT_ANCHOR = { identity: 'zt-identity', pools: 'zt-pools' };

// Scroll a target card into view, honouring prefers-reduced-motion (no
// hash change — bare #anchors would confuse the hash router).
function ztScrollTo(id) {
  const el = document.getElementById(id);
  if (!el) return;
  const reduce = typeof matchMedia === 'function'
    && matchMedia('(prefers-reduced-motion: reduce)').matches;
  el.scrollIntoView({ behavior: reduce ? 'auto' : 'smooth', block: 'start' });
}

// A link-styled button that scrolls to a card without touching the hash.
function ZtJumpLink({ to, children }) {
  return (
    <button
      type="button"
      onClick={() => ztScrollTo(to)}
      style={{
        background: 'none', border: 'none', padding: 0, cursor: 'pointer',
        color: 'var(--info)', font: 'inherit', textDecoration: 'underline',
      }}
    >
      {children}
    </button>
  );
}

// Single source of truth for "when does the upstream identity take effect?",
// reused by the identity card, its rotation pill, and the per-pool drawer so
// the page never gives three different answers (issue improvement #5).
const ZT_IDENTITY_APPLIES =
  'Stored in the config plane. A first-time identity takes effect when each '
  + 'node restarts (the cert materializes at boot); rotating an already-live '
  + 'identity hot-applies fleet-wide with no restart.';
const ZT_ROTATION_PILL_TITLE = 'Rotated live — hot-applied fleet-wide, no restart';

// Upstream WAF client identity — the shared fleet cert the WAF presents to
// backends. Read-only metadata + a public-cert download, plus an upload modal
// (PUBLIC cert + private key PEM) gated behind allow_ca_upload.
function ZtIdentityCard() {
  const api = window.useApi('/api/zero-trust/upstream/identity', {
    intervalMs: 15000, fallback: { configured: false },
  });
  const cap = window.useApi('/api/zero-trust/downstream/ca-bundle/capability', {
    intervalMs: 60000, fallback: { allow_ca_upload: false },
  });
  const canUpload = !!cap.data?.allow_ca_upload;
  const rot = window.useApi('/api/zero-trust/upstream/rotation', {
    intervalMs: 5000, fallback: { generation: 0, live: false },
  });
  const d = api.data || { configured: false };
  const [certPem, setCertPem] = useStateP('');
  const [certFileName, setCertFileName] = useStateP('');
  const [keyPem, setKeyPem] = useStateP('');
  const [keyFileName, setKeyFileName] = useStateP('');
  const [busy, setBusy] = useStateP(false);
  const [showForm, setShowForm] = useStateP(false);

  // Real-time PEM validation helpers.
  // Returns { ok, err } — err is null when valid or empty.
  function validateCertPem(pem) {
    const t = pem.trim();
    if (!t) return { ok: false, err: null };
    if (t.includes('PRIVATE KEY'))
      return { ok: false, err: 'This looks like a private key — upload the PUBLIC certificate here' };
    if (!t.includes('BEGIN CERTIFICATE'))
      return { ok: false, err: 'Not a valid certificate PEM (missing BEGIN CERTIFICATE)' };
    if (!t.includes('END CERTIFICATE'))
      return { ok: false, err: 'Incomplete PEM — missing END CERTIFICATE' };
    return { ok: true, err: null };
  }

  function validateKeyPem(pem) {
    const t = pem.trim();
    if (!t) return { ok: false, err: null };
    if (t.includes('BEGIN CERTIFICATE'))
      return { ok: false, err: 'This looks like a certificate — upload the PRIVATE KEY here' };
    const hasBegin = t.includes('BEGIN PRIVATE KEY')
      || t.includes('BEGIN RSA PRIVATE KEY')
      || t.includes('BEGIN EC PRIVATE KEY');
    if (!hasBegin)
      return { ok: false, err: 'Not a valid private key PEM (expected BEGIN PRIVATE KEY / RSA / EC)' };
    const hasEnd = t.includes('END PRIVATE KEY')
      || t.includes('END RSA PRIVATE KEY')
      || t.includes('END EC PRIVATE KEY');
    if (!hasEnd)
      return { ok: false, err: 'Incomplete PEM — missing END marker, file may be truncated' };
    return { ok: true, err: null };
  }

  const certValid = validateCertPem(certPem);
  const keyValid  = validateKeyPem(keyPem);
  const canSave   = !busy && certValid.ok && keyValid.ok;

  function onCertFile(e) {
    const f = e.target.files?.[0];
    if (!f) return;
    setCertFileName(f.name);
    const reader = new FileReader();
    reader.onload = () => setCertPem(String(reader.result || ''));
    reader.readAsText(f);
  }

  function onKeyFile(e) {
    const f = e.target.files?.[0];
    if (!f) return;
    setKeyFileName(f.name);
    const reader = new FileReader();
    reader.onload = () => setKeyPem(String(reader.result || ''));
    reader.readAsText(f);
  }

  async function save() {
    if (!certValid.ok) {
      window.aegisToast(certValid.err || 'Upload or paste the public certificate first', 'warn');
      return;
    }
    if (!keyValid.ok) {
      window.aegisToast(keyValid.err || 'Upload or paste the private key first', 'warn');
      return;
    }
    setBusy(true);
    try {
      const r = await fetch('/api/zero-trust/upstream/identity', {
        method: 'PUT',
        headers: { 'content-type': 'application/json', 'x-csrf-token': ztCsrf() },
        body: JSON.stringify({ cert_pem: certPem, key_pem: keyPem }),
        credentials: 'same-origin',
      });
      const body = await r.json().catch(() => ({}));
      if (r.ok && body.ok) {
        window.aegisToast(d.configured ? 'Identity rotated' : 'Identity stored', 'ok');
        setCertPem(''); setKeyPem(''); setCertFileName(''); setKeyFileName('');
        setShowForm(false);
        api.reload && api.reload();
      } else {
        window.aegisToast(`Identity: ${body.message || body.error || ('HTTP ' + r.status)}`, 'err');
      }
    } catch (e) {
      window.aegisToast(`Identity error: ${e.message || e}`, 'err');
    } finally { setBusy(false); }
  }

  function downloadCert() {
    if (!d.cert_pem) return;
    const blob = new Blob([d.cert_pem], { type: 'application/x-pem-file' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = 'waf-client.pem';
    document.body.appendChild(a); a.click(); a.remove();
    URL.revokeObjectURL(url);
  }

  const muted = { color: 'var(--ink-mute)' };
  const fieldStyle = {
    fontSize: 13, padding: '8px 10px', color: 'var(--ink)',
    background: 'var(--surface-2)', border: '1px solid var(--hairline-strong)',
    borderRadius: 6, width: '100%', boxSizing: 'border-box',
  };

  return (
    <div id={ZT_ANCHOR.identity} className="card" style={{ marginBottom: 14 }}>
      <div className="card-head">
        <div>
          <div className="card-title">WAF Client Identity</div>
          <div className="card-sub">The certificate the WAF presents to your backends</div>
        </div>
        <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
          {d.cert_pem && (
            <button
              className="btn primary"
              onClick={downloadCert}
              title="Download the WAF's public client cert to install in your backend's trust store"
            >
              ⬇ Download cert
            </button>
          )}
          <span className={`pill ${d.configured ? 'ok' : 'neutral'}`}>
            {d.configured ? 'configured' : 'not set'}
          </span>
        </div>
      </div>

      {!d.configured ? (
        <p style={{ fontSize: 13, ...muted, margin: '2px 2px 12px' }}>
          Not set yet — add the WAF client identity to let it connect to backends
          that require mTLS.
        </p>
      ) : (
        <div style={{ padding: '2px 2px 12px', fontSize: 13 }}>
          {d.error && (
            <div className="banner warn" style={{ marginBottom: 8 }}>Cert unreadable: {d.error}</div>
          )}
          {(d.certificates || []).map((c, i) => (
            <div key={i} style={{ display: 'flex', gap: 10, alignItems: 'center', flexWrap: 'wrap', color: 'var(--ink)' }}>
              <span>{c.subject}</span>
              <span style={muted}>expires in</span>
              <ZtExpiryPill days={c.days_until_expiry} />
              {rot.data?.generation > 0 && (
                <span className="pill ok" title={ZT_ROTATION_PILL_TITLE}>live · rotated ×{rot.data.generation}</span>
              )}
            </div>
          ))}
          <p style={{ ...muted, margin: '8px 0 0' }}>
            Hand this cert to your backend operators for their trust store — the
            private key never leaves the WAF.
          </p>
          {/* LOW-5 (2026-06-13) — reconcile the confusing split where this
              card reads CONFIGURED (from the boot YAML / live runtime) but a
              per-pool mTLS toggle is rejected with "upstream_identity … none
              is set". A file-sourced identity lives only in the boot config;
              pool-toggle validation runs against the active config plane,
              which doesn't carry the file-only zero_trust section until it's
              published. Say so, with the fix, instead of letting the two
              surfaces silently disagree. */}
          {d.source === 'file' && (
            <div className="banner warn" style={{ marginTop: 10, fontSize: 12 }}>
              <div style={{ marginTop: 1 }}><window.I.Shield /></div>
              <div style={{ flex: 1 }}>
                <div className="banner-strong">File-sourced identity — not yet in the active config plane.</div>
                <div>
                  This identity comes from the boot YAML. Enabling a pool's
                  upstream mTLS validates against the published config and will
                  be rejected (<code>upstream_identity … none is set</code>) until
                  the <code>zero_trust</code> section is published to the plane —
                  re-publish the config (or upload the identity in-console when
                  <code> allow_ca_upload</code> is on) so both surfaces agree.
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      <div style={{ borderTop: '1px solid var(--hairline)', paddingTop: 10 }}>
        {!canUpload ? (
          <p style={{ fontSize: 12, ...muted, margin: 0 }}>
            In-console upload is off. Set <code>zero_trust.upstream_identity</code> in
            YAML, or enable <code>allow_ca_upload</code>.
          </p>
        ) : (
          <button className="btn" onClick={() => setShowForm(true)}>
            {d.configured ? 'Rotate identity' : 'Set identity'}
          </button>
        )}
      </div>

      {showForm && (() => {
        const close = () => {
          if (!busy) {
            setShowForm(false); setCertPem(''); setCertFileName('');
            setKeyPem(''); setKeyFileName('');
          }
        };
        const inp = {
          width: '100%', boxSizing: 'border-box', fontSize: 13,
          color: 'var(--ink)', background: 'var(--surface-2)', borderRadius: 6,
        };
        const label = { fontSize: 12, fontWeight: 600, color: 'var(--ink-mute)', marginBottom: 6, display: 'block' };
        const fileBtn = { fontSize: 12, display: 'inline-block', flexShrink: 0 };
        return (
          <div className="modal-backdrop" onClick={close}>
            <div className="modal" style={{ maxWidth: 560 }} onClick={e => e.stopPropagation()}>

              <div className="modal-head">
                <div className="modal-title">
                  {d.configured ? 'Rotate WAF Client Identity' : 'Set WAF Client Identity'}
                </div>
                <button className="btn ghost" onClick={close} disabled={busy}>✕</button>
              </div>

              <div className="modal-body" style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>

                {/* ── Public Certificate ── */}
                <div>
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 6 }}>
                    <span style={{ fontSize: 12, fontWeight: 600, color: 'var(--ink)' }}>Public Certificate <span style={{ color: 'var(--ink-mute)', fontWeight: 400 }}>(.pem / .crt)</span></span>
                    {certValid.ok
                      ? <span style={{ fontSize: 11, color: 'var(--ok)' }}>✓ valid {certFileName || 'PEM'}</span>
                      : certValid.err
                        ? <span style={{ fontSize: 11, color: 'var(--down)' }}>✗ {certValid.err}</span>
                        : <span style={{ fontSize: 11, color: 'var(--warn)' }}>required</span>}
                  </div>
                  <div style={{ display: 'flex', gap: 8, alignItems: 'center', marginBottom: 8 }}>
                    <label style={{ cursor: 'pointer' }}>
                      <span className="btn" style={fileBtn}>📂 Choose cert file</span>
                      <input type="file" accept=".pem,.crt,.cer,application/x-pem-file" onChange={onCertFile} style={{ display: 'none' }} />
                    </label>
                    <span style={{ fontSize: 12, color: 'var(--ink-mute)' }}>or paste below</span>
                  </div>
                  <textarea
                    value={certPem}
                    onChange={e => { setCertPem(e.target.value); setCertFileName(''); }}
                    placeholder={'-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----'}
                    rows={5}
                    style={{
                      ...inp, fontFamily: 'monospace', fontSize: 11, padding: 10, resize: 'vertical',
                      border: certValid.ok ? '1px solid var(--ok)' : certValid.err ? '1px solid var(--down)' : '1px solid var(--hairline-strong)',
                    }}
                  />
                </div>

                {/* ── Private Key ── */}
                <div>
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 6 }}>
                    <span style={{ fontSize: 12, fontWeight: 600, color: 'var(--ink)' }}>Private Key</span>
                    {keyValid.ok
                      ? <span style={{ fontSize: 11, color: 'var(--ok)' }}>✓ valid {keyFileName || 'PEM'}</span>
                      : keyValid.err
                        ? <span style={{ fontSize: 11, color: 'var(--down)' }}>✗ {keyValid.err}</span>
                        : <span style={{ fontSize: 11, color: 'var(--warn)' }}>required</span>}
                  </div>
                  <div style={{ display: 'flex', gap: 8, alignItems: 'center', marginBottom: 8 }}>
                    <label style={{ cursor: 'pointer' }}>
                      <span className="btn" style={fileBtn}>📂 Choose key file</span>
                      <input type="file" accept=".key,.pem,application/x-pem-file" onChange={onKeyFile} style={{ display: 'none' }} />
                    </label>
                    <span style={{ fontSize: 12, color: 'var(--ink-mute)' }}>or paste below</span>
                  </div>
                  <textarea
                    value={keyPem}
                    onChange={e => { setKeyPem(e.target.value); setKeyFileName(''); }}
                    placeholder={'-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----'}
                    rows={5}
                    style={{
                      ...inp, fontFamily: 'monospace', fontSize: 11, padding: 10, resize: 'vertical',
                      border: keyValid.ok ? '1px solid var(--ok)' : keyValid.err ? '1px solid var(--down)' : '1px solid var(--hairline-strong)',
                    }}
                  />
                </div>

              </div>

              <div className="modal-foot">
                <button className="btn" onClick={close} disabled={busy}>Cancel</button>
                <button
                  className="btn primary"
                  disabled={!canSave}
                  onClick={save}
                  title={
                    certValid.err ? certValid.err
                    : keyValid.err ? keyValid.err
                    : !certValid.ok ? 'Upload or paste the public certificate'
                    : !keyValid.ok ? 'Upload or paste the private key'
                    : ''
                  }
                >
                  {busy ? 'Saving…' : (d.configured ? 'Save & rotate' : 'Save identity')}
                </button>
              </div>

            </div>
          </div>
        );
      })()}
    </div>
  );
}

// Per-pool upstream mTLS — the core surface. Lists every pool with an mTLS
// on/off toggle and a "Upload / Replace cert" button that opens a modal. The
// uploaded PEM is pinned to the config plane (Redis) under a per-pool bundle
// name and wired to the pool's `upstream_mtls.trust`. Disabling clears
// `upstream_mtls`; the pinned cert is kept for easy re-enable.
function ZtUpstreamPoolsCard() {
  const api = window.useApi('/api/zero-trust/upstream/config', {
    intervalMs: 10000, fallback: { pools: [] },
  });
  const trustApi = window.useApi('/api/zero-trust/upstream/trust', {
    intervalMs: 30000, fallback: { bundles: [] },
  });
  const idApi = window.useApi('/api/zero-trust/upstream/identity', {
    intervalMs: 15000, fallback: { configured: false },
  });
  const cap = window.useApi('/api/zero-trust/downstream/ca-bundle/capability', {
    intervalMs: 60000, fallback: { allow_ca_upload: false },
  });
  const canUpload = !!cap.data?.allow_ca_upload;
  const identityReady = !!idApi.data?.configured;
  const pools = api.data?.pools || [];
  const bundleByName = {};
  for (const b of (trustApi.data?.bundles || [])) bundleByName[b.name] = b;
  const [openPool, setOpenPool] = useStateP(null);
  const [pem, setPem] = useStateP('');
  const [busy, setBusy] = useStateP(''); // pool name currently mutating

  const muted = { color: 'var(--ink-mute)' };
  const cell = { padding: '8px 10px', borderBottom: '1px solid var(--hairline)', textAlign: 'left' };
  const th = { ...cell, color: 'var(--ink-mute)', fontWeight: 600 };

  function poolBundleName(pool) {
    return ('pool-' + String(pool).replace(/[^A-Za-z0-9._-]/g, '-')).slice(0, 64);
  }

  async function applyPoolMtls(poolName, opts) {
    const r = await fetch('/api/upstreams/config', { credentials: 'same-origin', cache: 'no-store' });
    const j = await r.json().catch(() => ({}));
    const view = j.pools?.[poolName];
    if (!view) throw new Error('pool not found');
    const d = poolFormFromView(view);
    d.upstream_mtls = opts.enabled
      ? { ...(view.upstream_mtls || {}), enabled: true, verify: true, trust: opts.trust ? opts.trust : null }
      : null;
    const res = await window.poolUpsert(poolName, poolConfigFromForm(d));
    if (!res || !res.ok) {
      throw new Error((res && (res.message || res.error)) || ('HTTP ' + (res && res.status)));
    }
  }

  async function toggle(p) {
    const next = !p.enabled;
    if (next && !identityReady) {
      window.aegisToast('Set the WAF client identity first', 'warn');
      return;
    }
    setBusy(p.pool);
    try {
      const pinned = bundleByName[poolBundleName(p.pool)] ? poolBundleName(p.pool) : (p.trust || null);
      await applyPoolMtls(p.pool, { enabled: next, trust: next ? pinned : null });
      window.aegisToast(`Pool '${p.pool}' mTLS ${next ? 'enabled' : 'disabled'}`, 'ok');
      api.reload && api.reload();
    } catch (e) {
      window.aegisToast(`Pool '${p.pool}': ${e.message || e}`, 'err');
    } finally { setBusy(''); }
  }

  function onFile(e) {
    const f = e.target.files?.[0];
    if (!f) return;
    const reader = new FileReader();
    reader.onload = () => setPem(String(reader.result || ''));
    reader.readAsText(f);
  }

  async function uploadCert(poolName) {
    if (!pem.trim()) { window.aegisToast('Paste the backend cert first', 'warn'); return; }
    const bundle = poolBundleName(poolName);
    setBusy(poolName);
    try {
      const r = await fetch(`/api/zero-trust/upstream/trust/${encodeURIComponent(bundle)}`, {
        method: 'POST',
        headers: { 'content-type': 'application/x-pem-file', 'x-csrf-token': ztCsrf() },
        body: pem, credentials: 'same-origin',
      });
      const body = await r.json().catch(() => ({}));
      if (!(r.ok && body.ok)) {
        window.aegisToast(`Cert upload: ${body.message || body.error || ('HTTP ' + r.status)}`, 'err');
        return;
      }
      window.aegisToast(`Backend cert saved for '${poolName}'`, 'ok');
      setPem(''); setOpenPool(null);
      api.reload && api.reload();
      trustApi.reload && trustApi.reload();
    } catch (e) {
      window.aegisToast(`Pool '${poolName}': ${e.message || e}`, 'err');
    } finally { setBusy(''); }
  }

  return (
    <div id={ZT_ANCHOR.pools} className="card" style={{ marginBottom: 14 }}>
      <div className="card-head">
        <div>
          <div className="card-title">Upstream mTLS by Pool</div>
          <div className="card-sub">Pin each backend's cert and turn mTLS on or off</div>
        </div>
      </div>

      {!identityReady && (
        <div className="banner info" style={{ marginBottom: 10 }}>
          Set the <ZtJumpLink to={ZT_ANCHOR.identity}>WAF client identity</ZtJumpLink>{' '}
          first — enabling mTLS is blocked until then.
        </div>
      )}

      {pools.length === 0 ? (
        <p style={{ fontSize: 13, ...muted, padding: 4 }}>
          No pools yet — add one on the{' '}
          <a href="#/upstreams" style={{ color: 'var(--info)' }}>Routing &amp; Upstreams</a> page.
        </p>
      ) : (
        <table style={{ width: '100%', fontSize: 13, borderCollapse: 'collapse' }}>
          <thead>
            <tr>
              <th style={th}>Pool</th>
              <th style={th}>Backend cert</th>
              <th style={th}>mTLS</th>
              <th style={th}></th>
            </tr>
          </thead>
          <tbody>
            {pools.map((p) => {
              const bundle = poolBundleName(p.pool);
              const pinned = bundleByName[bundle];
              const locked = busy === p.pool;
              const canEnable = identityReady || p.enabled;
              const certCell = pinned
                ? (pinned.error
                    ? <span className="pill warn">{pinned.error}</span>
                    : (pinned.certificates || []).map((c, i) => (
                        <span key={i} style={{ display: 'inline-flex', gap: 8, alignItems: 'center', color: 'var(--ink)' }}>
                          {c.subject} <ZtExpiryPill days={c.days_until_expiry} />
                        </span>)))
                : <span style={muted}>none</span>;
              return (
                <tr key={p.pool}>
                  <td style={{ ...cell, color: 'var(--ink)' }}>{p.pool}</td>
                  <td style={cell}>{certCell}</td>
                  <td style={cell}>
                    <div
                      className={`toggle ${p.enabled ? 'on' : ''}`}
                      title={!canEnable
                        ? 'Set the WAF client identity first'
                        : (p.enabled ? 'mTLS on — click to disable' : 'mTLS off — click to enable')}
                      onClick={(locked || !canEnable) ? undefined : () => toggle(p)}
                      style={{ cursor: locked ? 'wait' : (!canEnable ? 'not-allowed' : 'pointer'), opacity: !canEnable ? 0.5 : 1 }}
                    />
                  </td>
                  <td style={cell}>
                    <button className="btn" onClick={() => { setOpenPool(p.pool); setPem(''); }}>
                      {pinned ? 'Replace cert' : 'Upload cert'}
                    </button>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      )}

      {openPool && (() => {
        const isBusy = busy === openPool;
        const close = () => { if (!isBusy) { setOpenPool(null); setPem(''); } };
        return (
          <div className="modal-backdrop" onClick={close}>
            <div className="modal" style={{ maxWidth: 580 }} onClick={e => e.stopPropagation()}>
              <div className="modal-head">
                <div className="modal-title">Backend cert · {openPool}</div>
                <button className="btn ghost" onClick={close} disabled={isBusy}>✕</button>
              </div>
              <div className="modal-body">
                {!canUpload ? (
                  <div className="banner info" style={{ margin: 0 }}>
                    In-console upload is off. Pin the backend CA in YAML via{' '}
                    <code>{openPool}.upstream_mtls.trust</code>, or enable{' '}
                    <code>allow_ca_upload</code>.
                  </div>
                ) : (
                  <>
                    <p style={{ fontSize: 13, color: 'var(--ink-mute)', marginTop: 0, marginBottom: 10, lineHeight: 1.5 }}>
                      Paste the public certificate that{' '}
                      <strong style={{ color: 'var(--ink)' }}>{openPool}</strong>'s backend
                      presents. The cert is saved to the config plane — use the toggle
                      in the table to enable mTLS once ready.
                    </p>
                    <textarea
                      value={pem}
                      onChange={e => setPem(e.target.value)}
                      placeholder="-----BEGIN CERTIFICATE-----&#10;backend cert / CA (public)&#10;-----END CERTIFICATE-----"
                      rows={9}
                      style={{ width: '100%', boxSizing: 'border-box', fontFamily: 'monospace', fontSize: 12, padding: 10, color: 'var(--ink)', background: 'var(--surface-2)', border: '1px solid var(--hairline-strong)', borderRadius: 6 }}
                    />
                    <div style={{ marginTop: 10 }}>
                      <input type="file" accept=".pem,.crt,.cer,application/x-pem-file" onChange={onFile} />
                    </div>
                  </>
                )}
              </div>
              <div className="modal-foot">
                <button className="btn" onClick={close} disabled={isBusy}>Cancel</button>
                {canUpload && (
                  <button
                    className="btn primary"
                    disabled={isBusy || !pem.trim()}
                    onClick={() => uploadCert(openPool)}
                  >
                    {isBusy ? 'Saving…' : 'Save'}
                  </button>
                )}
              </div>
            </div>
          </div>
        );
      })()}
    </div>
  );
}

// Upstream mTLS handshake-failure histogram (WAF → backend), grouped
// by pool + reason. Recorded by the data plane on a failed dial.
function ZtUpstreamFailuresCard() {
  const api = window.useApi('/api/zero-trust/upstream/failures', {
    intervalMs: 8000, fallback: { total: 0, failures: [] },
  });
  const rows = api.data?.failures || [];
  const total = api.data?.total || 0;
  const cell = { padding: '8px 10px', borderBottom: '1px solid var(--hairline)', textAlign: 'left' };
  const th = { ...cell, color: 'var(--ink-mute)', fontWeight: 600 };
  const reasonTone = {
    untrusted_backend_cert: 'warn', san_mismatch: 'warn',
    cert_expired: 'down', client_identity_error: 'down', handshake_failed: 'neutral',
  };
  return (
    <div className="card" style={{ marginBottom: 14 }}>
      <div className="card-head">
        <div>
          <div className="card-title">Handshake Failures</div>
          <div className="card-sub">Failed WAF → backend mTLS connections, by reason</div>
        </div>
        <span className={`pill ${total > 0 ? 'warn' : 'ok'}`}>{total} total</span>
      </div>
      {rows.length === 0 ? (
        <div style={{ fontSize: 13, color: 'var(--ink-mute)', padding: 4 }}>
          No handshake failures recorded.
        </div>
      ) : (
        <table style={{ width: '100%', fontSize: 13, borderCollapse: 'collapse' }}>
          <thead>
            <tr>
              <th style={th}>Pool</th>
              <th style={th}>Reason</th>
              <th style={th}>Count</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((f, i) => (
              <tr key={i}>
                <td style={{ ...cell, color: 'var(--ink)' }}>{f.pool}</td>
                <td style={cell}>
                  <span className={`pill ${reasonTone[f.reason] || 'neutral'}`}>{f.reason}</span>
                </td>
                <td style={{ ...cell, color: 'var(--ink)' }}>{f.count}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

// Lightweight page-level section divider so the Zero Trust page reads
// as two clearly separated mutual-TLS directions rather than one flat
// stack of cards. Kept local (not the card-internal SectionHeader) so
// it can carry a direction-flow caption.
function ZtDirectionHeading({ title, flow, children }) {
  return (
    <div style={{ margin: '18px 0 8px', display: 'flex', alignItems: 'baseline', gap: 10, flexWrap: 'wrap' }}>
      <h2 style={{ margin: 0, fontSize: 14, fontWeight: 700, letterSpacing: 0.2 }}>{title}</h2>
      <span className="pill" style={{ fontFamily: 'var(--mono, monospace)', fontSize: 11 }}>{flow}</span>
      {children && <span style={{ fontSize: 12, color: 'var(--ink-dim)' }}>{children}</span>}
    </div>
  );
}

// 2026-06-14 — downstream mTLS (client certs presented TO the WAF) is
// hidden for now: this deployment fronts human end users, who can't
// present a client cert at TLS handshake, so the Mode / CA-bundle /
// allowed-SANs cards (MtlsModeCard / MtlsCaBundleCard / MtlsSansCard)
// are noise. Flip to `true` to restore the downstream section if the WAF
// ever fronts service/machine clients. The backend
// /api/zero-trust/downstream/* endpoints stay live regardless — this is
// purely a dashboard visibility gate.
const SHOW_DOWNSTREAM_MTLS = false;

function PageZeroTrust() {
  return (
    <>
      <div className="page-head">
        <div>
          <h1 className="page-title">Zero Trust</h1>
          <p className="page-subtitle">
            {SHOW_DOWNSTREAM_MTLS
              ? 'Mutual TLS in both directions — clients authenticating to the WAF, and the WAF authenticating to your backends'
              : 'Mutual TLS from the WAF to your backends'}
          </p>
        </div>
      </div>

      {SHOW_DOWNSTREAM_MTLS && (
        <>
          <ZtDirectionHeading title="Downstream" flow="client → WAF">
            Client certificates presented to the WAF at TLS handshake.
          </ZtDirectionHeading>
          <MtlsModeCard />
          <MtlsCaBundleCard />
          <MtlsSansCard />

          <ZtDirectionHeading title="Upstream" flow="WAF → backend">
            The WAF's own client identity + per-pool mTLS to your backends.
          </ZtDirectionHeading>
        </>
      )}

      <ZtIdentityCard />
      <ZtUpstreamPoolsCard />
      <ZtUpstreamFailuresCard />
    </>
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

  // 2026-05-19 — Honeypot Paths card removed (was local-only with
  // no backend mutation surface). The real honeypot/canary
  // implementation now lives behind the `canary` detector on the
  // Detectors page; operator-supplied paths come from
  // `cfg.risk.canary_paths` (YAML-only today). The local
  // `useStateP(['/.env', …])` was decorative only.

  async function toggleShadow() {
    if (busy) return;
    setBusy(true);
    const next = isShadow ? 'enforce' : 'log_only';
    try {
      const before = await fetch('/api/config/version', { credentials: 'same-origin', cache: 'no-store' })
        .then(r => r.json()).then(j => Number(j.audit_chain_len) || 0).catch(() => 0); // F2: renamed field
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

      {/* 2026-06-09 — mTLS cards (mode / CA bundle / SANs) moved to the
          dedicated Zero Trust page. These are the DOWNSTREAM (client-cert)
          controls, so the breadcrumb is gated on the same visibility flag
          (2026-06-14) — no point pointing operators at a section we hide
          for end-user deployments. */}
      {SHOW_DOWNSTREAM_MTLS && (
        <div style={{ marginBottom: 12, padding: '8px 12px', background: 'var(--surface-2)', borderRadius: 6, border: '1px solid var(--hairline)', fontSize: 11, color: 'var(--ink-dim)', display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
          <window.I.Shield />
          <span>Looking for mTLS (client-cert mode, CA bundle, allowed SANs)?</span>
          <span style={{ color: 'var(--ink-mute)' }}>·</span>
          <a href="#/zero-trust" style={{ color: 'var(--accent)', fontWeight: 600 }}>Zero Trust</a>
        </div>
      )}

      {/* 2026-05-19 — two dashboard features removed from this page
          during cleanup:
          1. "Cumulative IP risk thresholds" (moved to Traffic Gates
             on 2026-05-10 — breadcrumb below points operators there).
          2. "Challenge Engine" card (local-only dropdown; the
             backend always renders JS challenge — no API to swap
             challenge type today).
          2026-05-20 — the "Honeypot Paths" card is BACK (CanaryPathsCard
          below), now backed by the audit-mutated
          PUT /api/risk/canary-paths and hot-applied to the live
          canary detector.

          Inline redirect line below keeps operator memory happy
          without a full-card stub. */}
      <div style={{ marginBottom: 12, padding: '8px 12px', background: 'var(--surface-2)', borderRadius: 6, border: '1px solid var(--hairline)', fontSize: 11, color: 'var(--ink-dim)', display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
        <window.I.Shield />
        <span>Looking for cumulative IP risk thresholds or challenge type?</span>
        <span style={{ color: 'var(--ink-mute)' }}>·</span>
        <a href="#/traffic-gates" style={{ color: 'var(--accent)', fontWeight: 600 }}>Traffic Gates</a>
        <span style={{ color: 'var(--ink-mute)' }}>(risk thresholds)</span>
      </div>

      <CanaryPathsCard />

      <ResponseFilterCard />

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

// 2026-05-11 PR #7 — three-rung response-filter live toggle.
// Reads `/api/response-filter` for current state, flips rungs
// through the audit-mutated PUT. Each rung is independently
// togglable; defaults are all-on. The "wired: false" branch shows
// when the binary boots without a `Pipeline` writer (test bundles)
// — the toggles render in a read-only state with a warn pill.
function ResponseFilterCard() {
  const api = window.useResponseFilterApi
    ? window.useResponseFilterApi()
    : { data: null };
  const data = api.data || {};
  const wired = data.wired !== false; // default to wired so live state lights up before first poll
  const [busy, setBusy] = useStateP(null); // which rung is currently in-flight, for the wait cursor

  async function flip(rung) {
    if (busy || !wired) return;
    const patch = {
      scrub_stack_traces: !!data.scrub_stack_traces,
      mask_internal_ips:  !!data.mask_internal_ips,
      redact_dlp:         !!data.redact_dlp,
    };
    patch[rung] = !patch[rung];
    setBusy(rung);
    try {
      const r = await window.responseFilterPut(patch);
      if (r.status === 200 && r.ok) {
        window.aegisToast(`Response filter · ${rung} ${patch[rung] ? 'on' : 'off'}`, 'ok');
        api.reload && api.reload();
      } else if (r.status === 409 && r.reason === 'feature_off') {
        window.aegisToast('Response filter pipeline not wired in this build', 'warn');
      } else {
        const msg = r.message || r.error || r.reason || `HTTP ${r.status}`;
        window.aegisToast(`Response filter toggle failed: ${msg}`, 'err');
      }
    } finally {
      setBusy(null);
    }
  }

  const rungs = [
    {
      key: 'scrub_stack_traces',
      label: 'Scrub stack traces',
      desc: 'Node.js / JVM / Python / Rust / PHP / .NET / Ruby / Go → [REDACTED]',
    },
    {
      key: 'mask_internal_ips',
      label: 'Mask internal IPs',
      desc: 'RFC 1918 + loopback + link-local → [INTERNAL]',
    },
    {
      key: 'redact_dlp',
      label: 'Redact DLP payloads',
      desc: 'Credit cards (Luhn), SSN, IBAN, email, AWS/GitHub/Stripe/Slack tokens',
    },
  ];

  return (
    <div className="card" style={{ marginBottom: 12 }}>
      <div className="card-head" style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
        <div>
          <div className="card-title">Response Filtering</div>
          <div className="card-sub">
            Hot-reloadable via audit-mutated PUT /api/response-filter ·
            applied to every upstream response body via Pipeline::on_body_frame
          </div>
        </div>
        {!wired && (
          <span
            className="pill warn"
            title="Pipeline writer not wired in this build — toggles are read-only"
          >
            not wired
          </span>
        )}
      </div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
        {rungs.map(r => (
          <div
            key={r.key}
            style={{ display: 'flex', alignItems: 'flex-start', gap: 12 }}
          >
            <div
              className={`toggle ${data[r.key] ? 'on' : ''}`}
              onClick={wired && busy !== r.key ? () => flip(r.key) : undefined}
              style={{
                cursor: !wired ? 'not-allowed' : busy === r.key ? 'wait' : 'pointer',
                opacity: !wired ? 0.5 : 1,
                marginTop: 2,
              }}
            />
            <div style={{ flex: 1 }}>
              <div style={{ fontSize: 13, fontWeight: 600 }}>{r.label}</div>
              <div style={{ fontSize: 11, color: 'var(--ink-mute)' }}>
                {r.desc}
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

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
        // LOW-OBS-03 (2026-05-12) — surface the upstream reason
        // instead of the generic "unknown error". The server
        // response is `{ ok:false, failed: [{name, reason}, ...] }`
        // when dispatch fails, so the meaningful text lives at
        // `failed[0].reason` (e.g. "VipTalk returned 401
        // Unauthorized"). Fall back to the legacy
        // message/error/reason fields in case some other handler
        // shape lands here.
        const fail = Array.isArray(r?.failed) && r.failed.length > 0 ? r.failed[0] : null;
        const failReason = fail?.reason;
        const msg = failReason
          || (r && (r.message || r.error || r.reason))
          || 'unknown error';
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
  // 2026-05-21 — Active alerts is driven by the overlay-aware
  // /api/incidents enriched list (same source the Incidents page +
  // notification bell use) so an ack/snooze/resolve there is
  // reflected here. /api/alerts reads a separate legacy store
  // (tracking.ack_store) that the Incidents resolve never touches.
  const incidentsApi = window.useIncidentsApi();
  const gitops = window.useGitopsApi();
  // CC-T2.2 — alert channels (read + audit-mutated PUT/DELETE/POST-test)
  const alertReceivers = window.useAlertReceiversApi();

  // Pool list adapter — server returns `{pools: [{...}]}`; mock
  // fallback is `[{...}]`; accept either shape.
  const upstreamsRaw = upstreamsApi.data?.pools ?? upstreamsApi.data ?? [];
  const upstreams = Array.isArray(upstreamsRaw) ? upstreamsRaw : [];

  const peers = cluster.data?.peers || [];
  const ourNode = cluster.data?.our_node;

  return (
    <>
      <div className="page-head">
        <div>
          <h1 className="page-title">Health &amp; SLOs</h1>
          <p className="page-subtitle">
            Operational state · SLO · cluster · GitOps · cert health
            <span style={{ marginLeft: 8 }}>
              <span className="pill neutral">
                {ourNode ? `node ${ourNode}` : 'standalone'}
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
          <window.SectionHeader
            title="SLO budget"
            sub="Service-level objectives — current value vs. target, plus error-budget remaining over the rolling window. Budget drains when current drops below target."
          />
          {/* S7 (2026-05-08) — root-cause hint when an SLO is below
              target. Pre-fix: the SOC analyst saw a red SLO and had
              to cross-reference attack logs manually to find the
              culprit. Now we surface the top blocking detector and
              link to the audit trail filtered to it. */}
          <SloRootCauseHint slis={slo.data?.slis || []} />
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            {(slo.data?.slis || []).length === 0 ? (
              <div style={{ padding: 12, fontSize: 12, color: 'var(--ink-dim)', textAlign: 'center' }}>
                No SLO data yet — drive some traffic to populate the SLI window
                {' ('}<code>cfg.slo</code> defines the SLIs).
              </div>
            ) : (
              <>
                {/* Column headers — without these, the three percentages
                    in each row read as a mystery wall to operators new
                    to the page. 2026-05-10. */}
                <div style={{
                  display: 'grid',
                  gridTemplateColumns: '180px 80px 80px 1fr 80px',
                  gap: 10,
                  alignItems: 'center',
                  fontSize: 10,
                  color: 'var(--ink-dim)',
                  textTransform: 'uppercase',
                  letterSpacing: 0.5,
                  paddingBottom: 4,
                  borderBottom: '1px solid var(--hairline)',
                  marginBottom: 4,
                }}>
                  <span>SLI</span>
                  <span>Current</span>
                  <span>Target</span>
                  <span>Error budget</span>
                  <span style={{ textAlign: 'right' }}>Remaining</span>
                </div>
                {(slo.data?.slis || []).map(s => {
                  const tone = s.budget_remaining > 0.5 ? 'up' : s.budget_remaining > 0.1 ? 'warn' : 'down';
                  const meeting = s.current >= s.target;
                  return (
                    <div
                      key={s.name}
                      title={`${s.name} — currently ${s.current.toFixed(2)}% (target ${s.target.toFixed(2)}%). ${meeting ? 'Meeting target.' : 'Below target — error budget is draining.'}`}
                      style={{ display: 'grid', gridTemplateColumns: '180px 80px 80px 1fr 80px', gap: 10, alignItems: 'center', fontSize: 12 }}
                    >
                      <span className="mono" style={{ overflow: 'hidden', textOverflow: 'ellipsis' }}>{s.name}</span>
                      <span className="num" style={{ color: `var(--${tone === 'up' ? 'up' : tone === 'warn' ? 'warn' : 'down'})` }}>
                        {s.current.toFixed(2)}%
                      </span>
                      <span className="dim">{s.target.toFixed(2)}%</span>
                      <div style={{ height: 6, background: 'var(--surface-3)', borderRadius: 3, overflow: 'hidden' }}>
                        <div style={{ width: `${(s.budget_remaining * 100).toFixed(0)}%`, height: '100%', background: tone === 'up' ? 'var(--up)' : tone === 'warn' ? 'var(--warn)' : 'var(--down)' }} />
                      </div>
                      <span className={`pill ${tone}`} style={{ textAlign: 'right' }}>{(s.budget_remaining * 100).toFixed(0)}% left</span>
                    </div>
                  );
                })}
              </>
            )}
          </div>
        </div>
        <div className="col-6 card">
          {(() => {
            // Overlay-aware: a `firing` alert is one whose IncidentTracker
            // status is still `firing` (ack/snooze/resolve all drop it).
            // Falls back to the legacy /api/alerts shape only when the
            // SLO engine isn't wired (test builds → no enriched list).
            const enriched = Array.isArray(incidentsApi.data?.incidents)
              ? incidentsApi.data.incidents.map(i => ({
                  name: `${i.sli}-${i.window_hours}h`,
                  severity: i.severity,
                  since: i.fired_at,
                  runbook_url: i.runbook_url,
                  status: i.status,
                }))
              : (alerts.data?.firing || []).map(a => ({ ...a, status: 'firing' }));
            const firing = enriched.filter(a => a.status === 'firing');
            const acked = enriched.filter(a => a.status === 'acknowledged');
            return (
              <>
                <window.SectionHeader
                  title="Active alerts"
                  sub={`${firing.length} firing · ${acked.length} acked`}
                />
                <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                  {firing.length === 0 && (
                    <div style={{ padding: 12, fontSize: 12, color: 'var(--ink-dim)', textAlign: 'center' }}>
                      No alerts firing.
                    </div>
                  )}
                  {firing.map(a => (
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
              </>
            );
          })()}
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
            sub={`${peers.length} ${peers.length === 1 ? 'node' : 'nodes'} · leaderless`}
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
                  <td><span className={`pill ${c.id === cluster.data?.our_node ? 'info' : 'neutral'}`}>
                    {c.id === cluster.data?.our_node ? 'this node' : 'peer'}
                  </span></td>
                  {/* LOW-ADM-05 (2026-05-12) — 24h heartbeat. */}
                  <td className="num dim">{fmtClockTime(c.last_heartbeat)}</td>
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
// SC-1 (2026-06-06) — per-upstream smart-cache stats card. Reads
// `GET /api/cache/stats` (one row per opted-in upstream). The backend badge
// makes the cache TIER explicit — L1 in-process today; flips to "L1+L2 ·
// in-mem + Redis" automatically once the stats `backend` field reports redis.
function cacheBackendBadge(backend) {
  if (backend === 'redis') return { label: 'L2 · Redis', tone: 'warn' };
  if (backend && backend.includes('redis')) return { label: 'L1+L2 · in-mem + Redis', tone: 'warn' };
  return { label: 'L1 · in-memory', tone: 'neutral' };
}

function fmtCacheBytes(n) {
  if (n == null) return '—';
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1024 * 1024 * 1024) return `${(n / (1024 * 1024)).toFixed(1)} MB`;
  return `${(n / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}

function CacheMetric({ label, value, tone }) {
  return (
    <div>
      <div style={{ fontSize: 9, textTransform: 'uppercase', letterSpacing: 0.5, color: 'var(--ink-dim)' }}>{label}</div>
      <div className="num" style={{ fontSize: 16, color: tone || 'var(--ink)' }}>{value}</div>
    </div>
  );
}

function CacheStatsCard() {
  const api = window.useCacheStatsApi ? window.useCacheStatsApi() : { data: null };
  const pools = api.data?.pools || [];

  return (
    <div className="card" data-component="cache-stats-card" style={{ marginTop: 12, padding: 0 }}>
      <div className="card-head" style={{ padding: 12 }}>
        <div>
          <div className="card-title">
            Smart cache
            <span style={{ marginLeft: 8, fontSize: 10, fontWeight: 400, color: 'var(--ink-dim)', textTransform: 'uppercase', letterSpacing: 0.5 }}>
              per upstream
            </span>
          </div>
          <div className="card-subtitle">
            L1 in-process response cache (per node) — serves repeat GET/HEAD
            from memory, never caches CRITICAL tier. Stats are this node's
            in-memory cache; a Redis L2 tier is planned (badge flips when wired).
          </div>
        </div>
      </div>

      {pools.length === 0 ? (
        <div style={{ padding: '14px 12px', fontSize: 12, color: 'var(--ink-dim)' }}>
          No upstream has smart caching enabled. Add a <code>cache:</code> block
          under <code>upstreams.&lt;pool&gt;</code> with one or more path-prefix
          rules to turn it on.
        </div>
      ) : (
        pools.map(p => {
          const be = cacheBackendBadge(p.backend);
          const util = Math.min(100, Math.max(0, p.budget_utilization_pct || 0));
          const ratioPct = ((p.hit_ratio || 0) * 100).toFixed(1);
          return (
            <div key={p.pool} style={{ borderTop: '1px solid var(--hairline)', padding: 12 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 10, flexWrap: 'wrap' }}>
                <span style={{ fontWeight: 600, fontSize: 13 }}>{p.pool}</span>
                <span className={`pill ${be.tone}`} style={{ fontSize: 10 }} title="Cache tier these numbers describe">{be.label}</span>
                <span className={`pill ${p.enabled ? 'ok' : 'neutral'}`} style={{ fontSize: 10 }}>
                  {p.enabled ? 'enabled' : 'configured · off'}
                </span>
                <span style={{ marginLeft: 'auto', fontSize: 12, color: 'var(--ink-dim)' }}>
                  hit ratio{' '}
                  <span className="num" style={{ color: Number(ratioPct) >= 50 ? 'var(--up)' : 'var(--ink)', fontWeight: 600 }}>{ratioPct}%</span>
                </span>
              </div>

              <div style={{ marginBottom: 10 }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 10, color: 'var(--ink-dim)', marginBottom: 3 }}>
                  <span>Memory budget</span>
                  <span className="num">{fmtCacheBytes(p.bytes)} / {fmtCacheBytes(p.budget_bytes)} · {util.toFixed(0)}%</span>
                </div>
                <div style={{ height: 6, borderRadius: 3, background: 'var(--surface-3)', overflow: 'hidden' }}>
                  <div style={{ width: `${util}%`, height: '100%', background: util > 90 ? 'var(--down)' : 'var(--brand-yellow)', transition: 'width 240ms' }} />
                </div>
              </div>

              <div style={{ display: 'flex', gap: 18, flexWrap: 'wrap' }}>
                <CacheMetric label="Entries" value={(p.entries ?? 0).toLocaleString()} />
                <CacheMetric label="Hits" value={(p.hit ?? 0).toLocaleString()} tone="var(--up)" />
                <CacheMetric label="Misses" value={(p.miss ?? 0).toLocaleString()} />
                <CacheMetric label="Stores" value={(p.stores ?? 0).toLocaleString()} />
                <CacheMetric label="Evictions" value={(p.evictions ?? 0).toLocaleString()} tone={p.evictions > 0 ? 'var(--warn)' : undefined} />
              </div>
            </div>
          );
        })
      )}
    </div>
  );
}

function PageUpstreams() {
  const cfgApi = window.useUpstreamsConfigApi();
  const summaryApi = window.useUpstreamsApi();
  const routesApi = window.useRoutesApi();
  // Optimistic overlays (instant pool/route edits, like the Detectors
  // card): staged changes show immediately and reconcile away once a
  // post-apply reload reflects them.
  const poolOverlay = window.useOptimisticOverlay();
  const routeOverlay = window.useOptimisticOverlay();
  const pools = window.applyOverlayMap(cfgApi.data?.pools || {}, poolOverlay.overlay);
  const names = Object.keys(pools).sort();
  const summary = summaryApi.data?.pools || [];
  // Zone-aware LB P3 — the node's own availability zone (when configured),
  // surfaced as a readout so operators can see "this node is in az-a" and
  // reason about same-zone preference / spillover.
  const selfZone = summaryApi.data?.self_zone || null;
  const routes = window.applyOverlayList(routesApi.data?.routes || [], routeOverlay.overlay, r => r.id);

  // Drop staged entries once a fresh load reflects them (self-correcting:
  // a pre-apply reload won't match yet, so it never reverts early).
  useEffectP(() => {
    const serverPools = Object.entries(cfgApi.data?.pools || {}).map(([name, cfg]) => ({ name, ...cfg }));
    poolOverlay.reconcile(serverPools, p => p.name, window.overlayMatches);
  }, [cfgApi.data]);
  useEffectP(() => {
    routeOverlay.reconcile(routesApi.data?.routes || [], r => r.id, window.overlayMatches);
  }, [routesApi.data]);

  // routing-upstream #1 — index the live health summary by pool name so
  // the routes table + pool rows can show per-pool / per-member health.
  const healthByPool = (() => {
    const m = {};
    for (const p of summary) m[p.name] = p;
    return m;
  })();

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

  // Reload ALL THREE views after a mutation, but only AFTER the config-
  // plane applies the new version — pool/route mutations land via the
  // async apply pipeline (watcher's next poll), so reloading immediately
  // reads the pre-apply config and the UI looks unchanged until a manual
  // refresh. waitForVersion(before + 1) closes that gap.
  //
  // 2026-06-13 — reload routes + pools + health TOGETHER. Previously pool
  // mutations refreshed cfg+health but not routes, and route mutations
  // refreshed routes+cfg but not health, so whichever view a given action
  // skipped stayed stale until a manual refresh (e.g. removing a pool from
  // a route left the pool visibly attached until reload). One shared
  // reloader keeps every dependent view in sync after any mutation.
  async function reloadAfterApply(before, appliedTarget) {
    // Prefer the applied-version signal: wait until THIS node has applied
    // the config-doc version the mutation returned, so the reload reads
    // the post-apply registry instead of racing the async watcher (the
    // bug where an edit didn't show until a manual refresh). `before`'s
    // audit-chain wait is the fallback when the node exposes no
    // applied_version (no state backend / single-node).
    if (appliedTarget != null) {
      const res = await window.waitForApplied(appliedTarget, 10000);
      if (res && res.noSignal && before != null) {
        await window.waitForVersion(before + 1, 10000);
      }
    } else if (before != null) {
      await window.waitForVersion(before + 1, 10000);
    }
    cfgApi.reload && cfgApi.reload();
    summaryApi.reload && summaryApi.reload();
    routesApi.reload && routesApi.reload();
  }

  async function savePool({ name, body }) {
    setBusy(true);
    // Optimistic: the pool card reflects the edit instantly; rolled back
    // if the PUT fails, and reconciled away once the reload lands.
    poolOverlay.stageUpsert(name, body);
    try {
      const before = await window.currentConfigVersion();
      const r = await window.poolUpsert(name, body);
      if (r.status === 200 && r.ok) {
        window.aegisToast(`Pool "${name}" saved`, 'ok');
        setEditor(null);
        await reloadAfterApply(before, r.version);
        setTimeout(() => poolOverlay.forget(name), 3000);
      } else {
        poolOverlay.forget(name);
        const msg = r.message || r.error || r.reason || `HTTP ${r.status}`;
        window.aegisToast(`Save failed: ${msg}`, 'err');
      }
    } catch (e) {
      poolOverlay.forget(name);
      window.aegisToast(`Save failed: ${e.message || e}`, 'err');
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
      const before = await window.currentConfigVersion();
      const r = await window.poolDelete(name);
      if (r.status === 200 && r.ok) {
        // Hide the pool instantly; reconciled once the reload drops it.
        poolOverlay.stageRemoval(name);
        window.aegisToast(`Pool "${name}" removed`, 'ok');
        setDeleteModal(null);
        await reloadAfterApply(before, r.version);
        setTimeout(() => poolOverlay.forget(name), 3000);
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
      <PolicyPostureCard />
      <div className="page-head">
        <div>
          <h1 className="page-title">
            Routing &amp; Upstreams
            {selfZone && (
              <span
                className="pill ok"
                style={{ marginLeft: 10, fontSize: 11, verticalAlign: 'middle' }}
                title="This node's availability zone (node.zone / AEGIS_ZONE). Zone-aware pools prefer same-zone upstream members."
              >
                this node: {selfZone}
              </span>
            )}
            <window.PageTitleRefresh
              onClick={() => {
                cfgApi.reload && cfgApi.reload();
                summaryApi.reload && summaryApi.reload();
                routesApi.reload && routesApi.reload();
              }}
              label="Refresh route + pool data"
            />
          </h1>
          <p className="page-subtitle">
            {/* LOW-05 (2026-05-11) — the previous copy
                `N routes → M pools (X members, Y unreferenced)`
                implied "those N routes use M pools". When some of
                those pools are orphans, the implication is wrong.
                New copy splits routed vs unrouted explicitly. */}
            <span className="num">{routes.length}</span> route{routes.length === 1 ? '' : 's'} ·
            <span className="num"> {names.length - orphaned}</span> pool{(names.length - orphaned) === 1 ? '' : 's'} routed
            {orphaned > 0 && (
              <>
                {' · '}
                <span className="num">{orphaned}</span> pool{orphaned === 1 ? '' : 's'} unrouted
              </>
            )}
            {' '}({totalMembers} member{totalMembers === 1 ? '' : 's'}){' · '}
            <span
              className={`pill ${cfgApi.error ? 'warn' : 'ok'}`}
              title="Routes + pools land via the audit-mutated pipeline; the proxy hot-swaps without restart."
            >
              {cfgApi.error ? 'fetch failed' : 'live · audit-mutated'}
            </span>
          </p>
        </div>
        {/* MED-RU-03 (2026-05-12) — surface "+ Add pool" at the
            page level so operators can author a standalone pool
            from a clean state.  Previously the button only
            appeared inside the "Pools without routes" panel,
            which is hidden until an orphan already exists. */}
        <div className="page-actions">
          <button
            type="button"
            className="btn"
            onClick={openPoolAdd}
            title="Author a pool without a route (members, scheme, TLS, health, circuit breaker). Routes that want to use it later just pick it from the 'Forward to' dropdown."
          >+ Add pool</button>
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
        health={healthByPool}
        onEditPool={openPoolEdit}
        onDeletePool={(n) => setDeleteModal({ name: n, refs: pools[n]?.referenced_by_routes || [] })}
        onMutated={reloadAfterApply}
        cfgReload={cfgApi.reload}
        routeOverlay={routeOverlay}
      />

      {/* SC-1 — per-upstream smart-cache stats (L1 in-process today). */}
      <window.CacheStatsCard />

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
              {/* MED-RU-03 (2026-05-12) — explain how orphans arise.
                  Pre-fix the operator had no clue whether an orphan
                  was authored deliberately or leaked from a failed
                  route create. */}
              <div style={{ padding: '4px 8px 8px', fontSize: 11, color: 'var(--ink-dim)' }}>
                Pools listed here have no route forwarding to them yet.
                That's expected when you used <strong>+ Add pool</strong>{' '}
                to author one ahead of its route, or when you deleted
                a route without removing the underlying pool. Wire a
                route to one of them via <strong>+ Add route</strong>,
                or remove the pool below.
              </div>
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
  // HIGH-RU-01 (2026-05-12) — include `scheme` on save and
  // derive `tls` from it.  The previous shape omitted `scheme`,
  // so a `tls` flip silently reset the saved scheme to `auto`
  // server-side (via `#[serde(default)]`). Sending both keeps
  // the legacy `tls` flag consistent with the canonical scheme.
  const scheme = d.connection?.scheme || 'auto';
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
      scheme,
      tls: tlsFromScheme(scheme, d.connection?.tls),
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
  // SC-1 — response cache. Only emit the block when enabled; an unchecked
  // toggle drops `cache:` entirely (caching off). We start from the raw cache
  // object the GET returned (`_raw`) so advanced fields the form doesn't edit
  // (l2, methods, deny_query_keys, max_entries, …) survive a UI save — the PUT
  // replaces the whole pool node, so anything not echoed back is lost.
  if (d.cache_enabled) {
    const raw = d.cache?._raw || {};
    cfg.cache = {
      ...raw,
      enabled: true,
      default_ttl: (d.cache?.default_ttl || '60s').trim() || '60s',
      max_total_bytes: Math.max(1, Math.round((Number(d.cache?.max_total_bytes_mb) || 64))) * 1024 * 1024,
      rules: (d.cache?.rules || [])
        .filter(r => (r.prefix || '').trim() !== '')
        .map(r => ({
          prefix: r.prefix.trim(),
          ...(r.ttl && r.ttl.trim() ? { ttl: r.ttl.trim() } : {}),
          ...(r.content_types && r.content_types.trim()
            ? { content_types: r.content_types.split(',').map(s => s.trim()).filter(Boolean) }
            : {}),
        })),
    };
  }
  // P4 — preserve the per-pool upstream-mTLS block. The PUT replaces
  // the whole pool node, so echo it back unchanged (the Zero Trust
  // drawer is the only editor that mutates it; everywhere else just
  // round-trips). Absent / disabled ⇒ omit the block entirely.
  if (d.upstream_mtls && d.upstream_mtls.enabled) {
    cfg.upstream_mtls = d.upstream_mtls;
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
      cache_enabled: false,
      cache: cacheFormFromView(null),
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
      // 2026-05-13 — load the saved scheme into the form state so
      // the Edit Pool dropdown reflects the live config.  Without
      // this the dropdown defaulted to `auto` (its fallback when
      // `d.connection.scheme` is undefined) and a Save without an
      // explicit pick silently downgraded the saved scheme.
      scheme:            view.connection?.scheme || 'auto',
    },
    cache_enabled: !!(view.cache && view.cache.enabled),
    cache: cacheFormFromView(view.cache),
    // P4 — carry the per-pool upstream-mTLS block verbatim so a Save
    // (which replaces the whole pool node) preserves it. The Zero Trust
    // drawer edits this; the Routing pool editor just round-trips it.
    upstream_mtls: view.upstream_mtls || null,
  };
}

// SC-1 — seed the cache section of the pool form from the GET view's `cache`
// object (or null for a pool with no cache). The form edits a friendly subset
// (default TTL, memory budget in MB, path rules); `_raw` keeps the original
// block verbatim so advanced fields (l2, methods, …) survive a round-trip.
function cacheFormFromView(c) {
  return {
    default_ttl: (c && c.default_ttl) || '60s',
    max_total_bytes_mb: c && c.max_total_bytes
      ? Math.max(1, Math.round(c.max_total_bytes / (1024 * 1024)))
      : 64,
    rules: ((c && c.rules) || []).map(r => ({
      prefix: r.prefix || '',
      ttl: r.ttl || '',
      content_types: (r.content_types || []).join(', '),
    })),
    _raw: c || {},
  };
}

// MED-RU-03 (2026-05-12) — orphan-leak audit.
//
// `PoolEditModal` is opened from two surfaces:
//   1. "+ Add pool" at the top of Routing & Upstreams (standalone).
//   2. "+ Create new pool" inside `RouteEditModal` (child modal).
//
// Both paths must guarantee that closing the modal without an
// explicit save produces NO `POOL_UPSERT` event:
//
//   - Cancel button       → `onCancel()` → parent flips its state
//                           flag, no API call. ✓ safe
//   - Click on backdrop   → routes through onCancel via the
//                           `.modal-backdrop onClick`. ✓ safe
//   - Escape / unmount    → parent component unmounts the modal
//                           the same way; no API call. ✓ safe
//
// On `Save`, `onSave({name, body})` runs `poolUpsert` and the
// modal stays open until success — so a server-side failure
// leaves the modal in its current state and a second click can
// retry without committing the previous attempt.  ✓ safe
//
// The only `POOL_UPSERT` audit-chain entry this modal can
// produce is an intentional, operator-confirmed save.  If an
// orphan pool appears in "Pools without routes" today, it was
// either (a) authored via "+ Add pool" deliberately, (b) left
// over from a route that was later deleted, or (c) seeded by
// the YAML at boot — never from a stray cancel here.
// routing-upstream #2 — render a connectivity-probe result as compact
// per-stage chips (DNS / TCP / TLS / HTTP) with timings + details.
function ProbeResultLine({ result }) {
  if (!result) return null;
  if (result.error) {
    return <span style={{ fontSize: 11, color: 'var(--down)' }}>Probe failed: {result.error}</span>;
  }
  const stages = [['DNS', result.dns], ['TCP', result.tcp], ['TLS', result.tls], ['HTTP', result.http]];
  return (
    <div style={{ display: 'flex', flexWrap: 'wrap', alignItems: 'center', gap: 8, fontSize: 11 }}>
      <span style={{ fontWeight: 600, color: result.ok ? 'var(--up)' : 'var(--down)' }}>
        {result.ok ? '✓ reachable' : '✗ failed'}
      </span>
      {stages.map(([label, s]) => {
        if (!s) return null;
        const color = s.skipped ? 'var(--ink-dim)' : (s.ok ? 'var(--up)' : 'var(--down)');
        const icon = s.skipped ? '–' : (s.ok ? '✓' : '✗');
        return (
          <span key={label} title={s.detail || ''} style={{ color }}>
            {icon} {label}{!s.skipped && typeof s.ms === 'number' ? ` ${s.ms}ms` : ''}
          </span>
        );
      })}
      <span className="mono" style={{ color: 'var(--ink-dim)', flexBasis: '100%', marginTop: 2 }}>
        {stages.filter(([, s]) => s && !s.skipped && s.detail).map(([l, s]) => `${l}: ${s.detail}`).join('  ·  ')}
      </span>
    </div>
  );
}

function PoolEditModal({ mode, existingNames, initialName, initialPool, onCancel, onSave, busy }) {
  const [name, setName] = useStateP(initialName || '');
  const [d, setD] = useStateP(() => poolFormFromView(initialPool));
  // routing-upstream #2 — per-member connectivity-probe state (keyed by
  // member index): { result } and a busy flag.
  const [probes, setProbes] = useStateP({});
  const [probing, setProbing] = useStateP({});

  async function runProbe(i) {
    const m = d.members[i];
    if (!m || !(m.addr || '').trim()) return;
    setProbing(p => ({ ...p, [i]: true }));
    try {
      const scheme = d.connection?.scheme || 'http';
      const healthPath = d.health_enabled ? (d.health?.path || '/healthz') : undefined;
      const res = await window.probeMember(m.addr.trim(), scheme, (m.host_header || '').trim() || undefined, healthPath);
      setProbes(p => ({ ...p, [i]: res }));
    } finally {
      setProbing(p => ({ ...p, [i]: false }));
    }
  }

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
  // SC-1 — enabled caching needs at least one path-prefix rule, else it would
  // match nothing and silently cache zero responses.
  const cacheOk = !d.cache_enabled ||
    (d.cache?.rules || []).some(r => (r.prefix || '').trim() !== '');
  const canSave = trimmedName !== '' && !nameTaken && memberOk && healthOk && cbOk && cacheOk;

  // HIGH-RU-01 follow-up (2026-05-12) — auto-infer scheme from
  // the member port so an operator who types `znews.vn:443` and
  // hits Save without touching the scheme dropdown gets a
  // working TLS pool instead of `scheme: auto + tls: false`
  // (which produces `http://host:443/` and an upstream 400
  // "plain HTTP to HTTPS port"). The inference only fires when
  // the operator hasn't already picked a non-auto scheme — so
  // explicit selections are never overridden.
  function inferSchemeFromPort(port) {
    if (port === 443) return 'https';
    if (port === 80)  return 'http';
    return null;
  }
  function portFromAddr(addr) {
    const m = /:(\d+)\s*$/.exec((addr || '').trim());
    if (!m) return null;
    const n = Number(m[1]);
    return Number.isFinite(n) ? n : null;
  }
  function setMember(i, key, val) {
    setD(prev => {
      const nextMembers = prev.members.map((m, idx) =>
        idx === i ? { ...m, [key]: val } : m,
      );
      // Only re-derive scheme when the operator edits an address
      // AND the current scheme is still the unspecified `auto`.
      // Picking https / http / h2c / grpc / tcp explicitly locks
      // the choice.
      if (key !== 'addr') {
        return { ...prev, members: nextMembers };
      }
      const currentScheme = prev.connection?.scheme || 'auto';
      if (currentScheme !== 'auto') {
        return { ...prev, members: nextMembers };
      }
      const inferred = inferSchemeFromPort(portFromAddr(val));
      if (!inferred) {
        return { ...prev, members: nextMembers };
      }
      return {
        ...prev,
        members: nextMembers,
        connection: {
          ...prev.connection,
          scheme: inferred,
          tls: tlsFromScheme(inferred, prev.connection?.tls),
        },
      };
    });
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

  // SC-1 — cache rule editors. Rules are the path-prefix allow-list: a request
  // whose path matches no rule is never cached.
  function setCacheRule(i, key, val) {
    setD(prev => ({
      ...prev,
      cache: {
        ...prev.cache,
        rules: prev.cache.rules.map((r, idx) => (idx === i ? { ...r, [key]: val } : r)),
      },
    }));
  }
  function addCacheRule() {
    setD(prev => ({
      ...prev,
      cache: { ...prev.cache, rules: [...prev.cache.rules, { prefix: '', ttl: '', content_types: '' }] },
    }));
  }
  function removeCacheRule(i) {
    setD(prev => ({
      ...prev,
      cache: { ...prev.cache, rules: prev.cache.rules.filter((_, idx) => idx !== i) },
    }));
  }
  function setCacheField(key, val) {
    setD(prev => ({ ...prev, cache: { ...prev.cache, [key]: val } }));
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
                  <React.Fragment key={i}>
                  <tr>
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
                    <td style={{ whiteSpace: 'nowrap' }}>
                      <button
                        className="btn btn-sm"
                        onClick={() => runProbe(i)}
                        disabled={probing[i] || !(m.addr || '').trim()}
                        title="DNS → TCP → TLS → health-path probe of this member (read-only; uses the pool's scheme)"
                      >{probing[i] ? '…' : 'Test'}</button>{' '}
                      <button
                        className="btn btn-sm"
                        onClick={() => removeMember(i)}
                        disabled={busy || d.members.length === 1}
                        title={d.members.length === 1 ? 'A pool needs at least one member' : 'Remove this member'}
                      >×</button>
                    </td>
                  </tr>
                  {probes[i] && (
                    <tr>
                      <td colSpan={5} style={{ padding: '4px 8px 8px', background: 'var(--canvas-2)' }}>
                        <ProbeResultLine result={probes[i]} />
                      </td>
                    </tr>
                  )}
                  </React.Fragment>
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
            <legend style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '0 6px' }}>
              <input
                type="checkbox"
                checked={d.cache_enabled}
                onChange={e => setD(prev => ({ ...prev, cache_enabled: e.target.checked }))}
              />
              <span className="field-label" style={{ marginBottom: 0 }}>Response cache</span>
            </legend>
            {d.cache_enabled && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
                <div style={{ fontSize: 11, color: 'var(--ink-dim)' }}>
                  Serves repeat <strong>GET/HEAD</strong> from memory. Only paths matching a
                  rule below are cached — everything else is bypassed. CRITICAL-tier routes
                  (login / OTP / payment) and responses with <code>Set-Cookie</code> /{' '}
                  <code>Authorization</code> are never cached.
                </div>

                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
                  <label style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                    <span className="field-label">Default TTL</span>
                    <input
                      className="input mono"
                      value={d.cache.default_ttl}
                      onChange={e => setCacheField('default_ttl', e.target.value)}
                      placeholder="60s"
                      title="Freshness for entries whose rule has no explicit TTL. e.g. 30s, 5m, 1h"
                    />
                  </label>
                  <label style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                    <span className="field-label">Memory budget (MB)</span>
                    <input
                      className="input num"
                      type="number"
                      min="1"
                      value={d.cache.max_total_bytes_mb}
                      onChange={e => setCacheField('max_total_bytes_mb', e.target.value)}
                      title="Per-node byte budget for this pool's cache; eviction keeps it under this."
                    />
                  </label>
                </div>

                <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                    <span className="field-label" style={{ marginBottom: 0 }}>Path rules</span>
                    <button className="btn" onClick={addCacheRule} disabled={busy}>+ Add rule</button>
                  </div>
                  {d.cache.rules.length === 0 ? (
                    <div style={{ fontSize: 11, color: 'var(--down)' }}>
                      Add at least one path-prefix rule, or caching matches nothing.
                    </div>
                  ) : (
                    <table className="tbl tbl-compact">
                      <thead>
                        <tr>
                          <th>Path prefix</th>
                          <th style={{ width: 90 }} title="Optional — falls back to the default TTL above.">TTL</th>
                          <th
                            title="Optional content-type allow-list (comma-separated; supports image/*). Stores only when the upstream Content-Type matches — guards against cache deception."
                          >Content-types</th>
                          <th style={{ width: 36 }}></th>
                        </tr>
                      </thead>
                      <tbody>
                        {d.cache.rules.map((r, i) => (
                          <tr key={i}>
                            <td>
                              <input
                                className="input mono"
                                value={r.prefix}
                                onChange={e => setCacheRule(i, 'prefix', e.target.value)}
                                placeholder="/static/"
                              />
                            </td>
                            <td>
                              <input
                                className="input mono"
                                value={r.ttl}
                                onChange={e => setCacheRule(i, 'ttl', e.target.value)}
                                placeholder="1h"
                              />
                            </td>
                            <td>
                              <input
                                className="input mono"
                                value={r.content_types}
                                onChange={e => setCacheRule(i, 'content_types', e.target.value)}
                                placeholder="text/css, image/*"
                              />
                            </td>
                            <td>
                              <button className="btn" onClick={() => removeCacheRule(i)} disabled={busy} title="Remove rule">×</button>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  )}
                </div>
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
              {/* HIGH-RU-01 (2026-05-12) — `tls` is only operator-
                  editable when scheme is `auto`. For every explicit
                  scheme the derived value applies, so a contradicting
                  toggle would mislead. Disabled checkbox shows the
                  derived state for clarity. */}
              <label style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                <input
                  type="checkbox"
                  checked={tlsFromScheme(d.connection.scheme || 'auto', d.connection.tls)}
                  disabled={(d.connection.scheme || 'auto') !== 'auto'}
                  onChange={e => setD(prev => ({
                    ...prev,
                    connection: { ...prev.connection, tls: e.target.checked },
                  }))}
                />
                <span className="field-label" style={{ marginBottom: 0 }}>
                  Upstream TLS
                  {(d.connection.scheme || 'auto') !== 'auto' && (
                    <span style={{ color: 'var(--ink-dim)', fontWeight: 400 }}>
                      {' '}(derived from scheme)
                    </span>
                  )}
                </span>
              </label>
              <label style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                <span className="field-label" style={{ marginBottom: 0 }}>Scheme</span>
                <select
                  value={d.connection.scheme || 'auto'}
                  onChange={e => {
                    // HIGH-RU-01 — keep `tls` in lock-step with the
                    // new scheme so the form's checkbox reflects what
                    // we'll actually save.
                    const next = e.target.value;
                    setD(prev => ({
                      ...prev,
                      connection: {
                        ...prev.connection,
                        scheme: next,
                        tls: tlsFromScheme(next, prev.connection?.tls),
                      },
                    }));
                  }}
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
            {/* HIGH-RU-01 follow-up (2026-05-12) — explicit warning
                when the form is about to save a pool that will talk
                plain HTTP to a TLS port. Catches the case where the
                operator opens an existing `scheme: auto + tls: false`
                pool with a :443 member (which produces an upstream
                400 "plain HTTP to HTTPS port"). The auto-infer on
                member edit handles fresh forms; this banner closes
                the gap for already-saved pools. */}
            {(() => {
              const scheme = d.connection.scheme || 'auto';
              const usesTls = tlsFromScheme(scheme, d.connection.tls);
              if (usesTls) return null;
              const tlsPortMember = (d.members || []).find(m => {
                const p = portFromAddr(m.addr);
                return p === 443 || p === 8443;
              });
              if (!tlsPortMember) return null;
              return (
                <div
                  className="callout warn"
                  style={{ marginTop: 8, padding: '8px 10px', fontSize: 11 }}
                  role="alert"
                >
                  <strong>TLS / port mismatch.</strong>{' '}
                  Member <code>{tlsPortMember.addr}</code> is on a TLS
                  port but this pool will forward plain HTTP
                  ({scheme === 'auto' ? <>scheme <code>auto</code> + TLS off</> : <>scheme <code>{scheme}</code></>}).
                  Most <code>:443</code> upstreams answer with{' '}
                  <em>400 plain HTTP to HTTPS port</em>. Flip the
                  scheme to <code>https</code> to fix.
                </div>
              );
            })()}
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
//   L2 — Cross-node cluster. Two facets, both carrying an `L2` pill:
//          • Cluster peers   (membership, heartbeat, drain)
//          • Config plane    (shared config version, fleet convergence)
//        Previously both facets were titled "Layer 2 · …", which read as
//        two competing layer-2s; the config-plane card is now titled
//        "Config plane" so the layer numbering stays unambiguous.
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
    <div className="card" style={{ marginBottom: 12, borderLeft: '3px solid var(--info)' }}>
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

function ScalingL2Card({ cluster, onDrain, onUndrain, isDraining, busy }) {
  const peers = cluster?.data?.peers || [];
  const ourNode = cluster?.data?.our_node;
  const [confirmStep, setConfirmStep] = useStateP(0); // 0 idle, 1 confirm
  const [drainResult, setDrainResult] = useStateP(null);

  const onConfirmFirst = () => setConfirmStep(1);
  const onCancel = () => setConfirmStep(0);
  const onConfirmFinal = async () => {
    setConfirmStep(0);
    setDrainResult({ pending: true });
    const res = await onDrain();
    setDrainResult(res && res.status < 300 ? null : res); // clear on success (state pill takes over)
  };
  // Resume is the safe, restorative action — single click, no double-confirm.
  const onResume = async () => {
    setConfirmStep(0);
    setDrainResult({ pending: true });
    const res = await onUndrain();
    setDrainResult(res && res.status < 300 ? null : res);
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
    const isMe = p.id === ourNode;
    return { ...p, ageSec, healthy, isMe };
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
    <div className="card" style={{ marginBottom: 12, borderLeft: '3px solid var(--violet)' }}>
      <div className="card-head">
        <div>
          <div className="card-title">Layer 2 · Cluster peers</div>
          <div className="card-sub">
            {peerCountLabel}
            {ourNode ? ` · this node ${ourNode}` : ''}
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
                <td>
                  {p.isMe ? <span className="pill info">this node</span> : <span className="dim">peer</span>}
                  {p.isMe && isDraining && (
                    <span className="pill warn" style={{ marginLeft: 6 }} title="Readiness is 503 — the load balancer is not sending new traffic here.">draining</span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {/* Drain / Resume toggle for this node's LB readiness. */}
      <div style={{ marginTop: 10, paddingTop: 10, borderTop: '1px solid var(--hairline)' }}>
        {/* Status line — the live source of truth. */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
          <span style={{ fontSize: 11, color: 'var(--ink-dim)' }}>Readiness</span>
          {isDraining ? (
            <span className="pill warn">Draining · /healthz/ready → 503</span>
          ) : (
            <span className="pill up">Serving · in LB rotation</span>
          )}
        </div>

        {isDraining ? (
          /* Draining → offer Resume (restorative, single-click). */
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
            <button className="btn solid-yellow" disabled={busy} onClick={onResume}>
              Resume serving
            </button>
            <span style={{ fontSize: 11, color: 'var(--ink-dim)' }}>
              {ourNode || 'This node'} is out of the LB pool (in-flight requests still complete).
              Resume clears readiness so the LB routes traffic back within one health-check interval.
            </span>
          </div>
        ) : confirmStep === 0 ? (
          /* Serving → offer Drain (two-step confirm; it removes the node from the pool). */
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
            <button className="btn" disabled={busy} onClick={onConfirmFirst}>
              Drain this node
            </button>
            <span style={{ fontSize: 11, color: 'var(--ink-dim)' }}>
              Flips readiness to 503 — the LB pulls this node within one health-check interval.
              In-flight requests finish; reversible from here (no restart needed).
            </span>
          </div>
        ) : (
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
            <span style={{ fontSize: 12, color: 'var(--warn)' }}>
              Drain {ourNode || 'this node'}? The LB will stop sending it new traffic.
            </span>
            <button className="btn" onClick={onCancel}>Cancel</button>
            <button className="btn solid-yellow" disabled={busy} onClick={onConfirmFinal}>
              Yes, drain
            </button>
          </div>
        )}

        {/* Transient feedback (success is reflected by the status pill above; this row only lingers on error/pending). */}
        {drainResult?.pending && (
          <div style={{ marginTop: 6, fontSize: 11, color: 'var(--ink-dim)' }}>Applying…</div>
        )}
        {drainResult && !drainResult.pending && (
          <div style={{ marginTop: 6 }}>
            <span className="pill down">Action failed (HTTP {drainResult.status || '—'})</span>
          </div>
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
    <div className="card" style={{ borderLeft: '3px solid var(--teal)' }}>
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

// 2026-05-27 — cluster config-plane status. Shows the active shared
// config version + each node's applied version, flagging drift (a node
// stuck behind the active version). Backed by GET /api/config; renders an
// honest empty state on single-node (in-memory) or before any activation.
function ConfigVersionCard({ config }) {
  const data = config?.data;
  const active = (data && typeof data.version === 'number') ? data.version : 0;
  const applied = (data && Array.isArray(data.applied)) ? data.applied : [];
  const hasBackend = data ? data.backend !== false : true;
  return (
    <div className="card" style={{ marginBottom: 12, borderLeft: '3px solid var(--violet)' }}>
      <div className="card-head">
        <div>
          <div className="card-title">Config plane</div>
          <div className="card-sub">shared config version · fleet-wide convergence</div>
        </div>
        <span className="pill neutral">L2</span>
      </div>
      {!hasBackend ? (
        <div style={{ padding: 12, fontSize: 12, color: 'var(--ink-dim)', textAlign: 'center' }}>
          Single-node (in-memory) — config is process-local; no shared
          version. Run with a Redis state backend for fleet-wide config.
        </div>
      ) : (active === 0 && applied.length === 0) ? (
        <div style={{ padding: 12, fontSize: 12, color: 'var(--ink-dim)', textAlign: 'center' }}>
          No config version activated yet. A <code>PUT /api/config</code> publishes
          version 1; every node then converges on it.
        </div>
      ) : (
        <>
          <div style={{ display: 'flex', alignItems: 'baseline', gap: 8, marginBottom: 10 }}>
            <span style={{ fontSize: 12, color: 'var(--ink-faint)', textTransform: 'uppercase', letterSpacing: 0.5 }}>
              Active version
            </span>
            <span className="num" style={{ fontSize: 18, fontWeight: 600 }}>v{active}</span>
            <span style={{ fontSize: 11, color: 'var(--ink-dim)' }}>
              · {applied.length} node(s) reporting
            </span>
          </div>
          <table className="data-table" style={{ width: '100%', fontSize: 12 }}>
            <thead>
              <tr>
                <th style={{ textAlign: 'left' }}>Node</th>
                <th style={{ textAlign: 'left' }}>Applied</th>
                <th style={{ textAlign: 'left' }}>Status</th>
              </tr>
            </thead>
            <tbody>
              {applied.length === 0 ? (
                <tr><td colSpan="3" style={{ color: 'var(--ink-dim)' }}>No nodes have reported yet.</td></tr>
              ) : applied.map((n) => {
                const drift = n.version !== active;
                return (
                  <tr key={n.node}>
                    <td><code>{n.node}</code></td>
                    <td className="num">v{n.version}</td>
                    <td>
                      <span className={`pill ${drift ? 'warn' : 'up'}`}>
                        {drift ? `behind · active v${active}` : 'in sync'}
                      </span>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </>
      )}
    </div>
  );
}

function PageScaling() {
  const runtime = window.useRuntimeApi();
  const cluster = window.useClusterApi();
  const config = window.useConfigApi();
  const state = window.useStateApi();
  const drainState = window.useNodeDrainApi ? window.useNodeDrainApi() : { data: null, reload: null };
  const loadmode = window.useLoadModeApi ? window.useLoadModeApi() : { data: null };
  const [busy, setBusy] = useStateP(false);

  // Live drain state is the source of truth (survives reload; reflects a
  // SIGTERM / automation drain). The POST just flips it, then we refetch.
  const isDraining = !!drainState.data?.draining;

  const runDrainAction = async (post) => {
    setBusy(true);
    try {
      const r = await post();
      return r;
    } finally {
      setBusy(false);
      // Refetch the authoritative state after the flip.
      if (drainState.reload) drainState.reload();
    }
  };
  const onDrain = () => runDrainAction(window.adminDrainPost);
  const onUndrain = () => runDrainAction(window.adminUndrainPost);

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
            drainState.reload && drainState.reload();
            loadmode.reload && loadmode.reload();
          }}>
            <window.I.Refresh /> Refresh
          </button>
        </div>
      </div>

      <LoadModeCard loadmode={loadmode} />
      <ScalingL1Card runtime={runtime} />
      <ScalingL2Card
        cluster={cluster}
        onDrain={onDrain}
        onUndrain={onUndrain}
        isDraining={isDraining}
        busy={busy}
      />
      <ConfigVersionCard config={config} />
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

  // A real segmented control: each mode is a clearly-bordered pill with a
  // surface fill; the active mode is filled brand-yellow with dark on-yellow
  // text. (Was written against undefined `--border`/`--accent` tokens and used
  // `var(--canvas)` for the selected label — i.e. dark text on a failed-
  // transparent background, so the active mode was invisible.)
  const pillStyle = (mode) => {
    const selected = effective === mode;
    return {
      padding: '6px 16px',
      border: `1px solid ${selected ? 'var(--brand-yellow)' : 'var(--hairline-strong)'}`,
      borderRadius: 999,
      cursor: busy ? 'not-allowed' : 'pointer',
      fontSize: 12,
      fontWeight: 600,
      textTransform: 'capitalize',
      background: selected ? 'var(--brand-yellow)' : 'var(--surface-2)',
      color: selected ? 'var(--on-yellow)' : 'var(--ink)',
      opacity: busy ? 0.6 : 1,
      transition: 'all 120ms',
    };
  };

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
  // IF-P1b — the firing list is now a fleet roll-up (deduped by uid, with
  // per-row firing_on breadth), so the queue is fleet-capable. Note: the
  // ack/snooze/resolve OVERLAY still resolves per-node until IF-P1c.
  const scopeBadge = window.useScopeBadge ? window.useScopeBadge() : () => null;

  // Compose: prefer the enriched /api/incidents view; fall back
  // to /api/alerts when the engine isn't wired yet (test builds).
  const overlay = incidents.data?.incidents || [];
  const overlayById = new Map(overlay.map(i => [i.id, i]));
  const rawAlerts = alerts.data?.alerts || alerts.data?.firing || incidents.data?.raw_alerts?.alerts || [];

  // MED-SO-03 (2026-05-12) — parse the alert.name as
  // `<sli>-<window>` so the SLI column shows the meaningful
  // half and the window chips next to it.
  // Examples: `DataPlaneAvailability-1h`, `LatencyP99-72h`.
  function sliFromAlertName(name) {
    if (!name) return { sli: 'unknown', window: '' };
    const m = /^(.+)-([0-9]+[smhd])$/.exec(name);
    return m ? { sli: m[1], window: m[2] } : { sli: name, window: '' };
  }

  // Derive a unified "incident list".
  // IF-P1b — when the enriched /api/incidents view is populated it IS the
  // authoritative firing list: fleet-rolled-up (deduped by uid) with a
  // `firing_on` node breadth. Build rows from it directly. Fall back to
  // the raw /api/alerts shape only when the enriched view is empty (engine
  // not wired / older backend). MED-SO-03: the raw shape surfaces `name` /
  // `since` / `severity` (NOT `sli` / `fired_at` / `budget_consumed_pct`).
  const merged = overlay.length > 0
    ? overlay.map(i => {
        const name = i.id;
        const { sli, window: sliWindow } = sliFromAlertName(name);
        return {
          id: i.id,
          name,
          sli: i.sli || sli,
          sli_window: sliWindow,
          severity: (i.severity || 'warn').toLowerCase(),
          fired_at: i.fired_at,
          burn_rate: i.burn_rate,
          budget_consumed_pct: i.budget_consumed_pct,
          window_hours: i.window_hours,
          runbook_url: i.runbook_url,
          status: i.status || 'firing',
          acked_at: i.acked_at,
          acked_by: i.acked_by,
          snoozed_until: i.snoozed_until,
          note: i.note,
          firing_on: Array.isArray(i.firing_on) ? i.firing_on : [],
        };
      })
    : (Array.isArray(rawAlerts) ? rawAlerts : []).map(a => {
        const name = a.name || a.sli || a.kind || 'unknown';
        const fired_at = a.since || a.fired_at;
        const { sli, window: sliWindow } = sliFromAlertName(name);
        // IF-P1a — id is node-independent (`<SLI>-<window>h` == name).
        const id = a.id || name;
        const o = overlayById.get(id) || overlayById.get(name);
        return {
          id,
          name,
          sli,
          sli_window: sliWindow,
          severity: (a.severity || 'warn').toLowerCase(),
          fired_at,
          burn_rate: a.burn_rate,
          budget_consumed_pct: a.budget_consumed_pct,
          window_hours: a.window_hours,
          runbook_url: a.runbook_url,
          status: o?.status || o?.state || 'firing',
          acked_at: o?.acked_at,
          acked_by: o?.acked_by,
          snoozed_until: o?.snoozed_until,
          note: o?.note,
          firing_on: [],
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
        // LOW-FINAL-01 (2026-05-13) — collapse the previous
        // "lifecycle UI pending" warn fallback.  It was a
        // stop-gap from when MED-SO-04 / MED-OBS-01 left the
        // overlay-store write broken; commits `e6b307c` +
        // `cadd01b` closed the round-trip end-to-end and the
        // regression test
        // `ack_then_enrich_returns_acknowledged_status` guards
        // against re-opening that class of bug.  The 2xx path is
        // now unambiguous.
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
      <SecOpsPostureCard />
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
          actions={scopeBadge(true)}
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
                  <td>
                    <code style={{ fontSize: 11 }}>{m.sli}</code>
                    {m.sli_window && (
                      <span className="pill neutral" style={{ fontSize: 9, marginLeft: 4, padding: '0 6px' }}>{m.sli_window}</span>
                    )}
                    {/* IF-P1b — fleet breadth: how many nodes are firing this incident. */}
                    {Array.isArray(m.firing_on) && m.firing_on.length > 1 && (
                      <span
                        className="scope-badge scope-fleet"
                        style={{ marginLeft: 4 }}
                        title={`Firing on ${m.firing_on.length} nodes: ${m.firing_on.join(', ')}`}
                      >
                        {m.firing_on.length} nodes
                      </span>
                    )}
                  </td>
                  <td title={m.fired_at}>{fmtRel(m.fired_at)}</td>
                  <td className="num" title={m.budget_consumed_pct != null ? `${m.budget_consumed_pct.toFixed(2)}% of error budget consumed` : 'Budget metric not available on this build'}>
                    {m.budget_consumed_pct != null ? m.budget_consumed_pct.toFixed(1) + '%' : '—'}
                  </td>
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
  // SCOPE-P1a — detector breakdown, bot mix, the audit table (scope=fleet)
  // and the derived pivot panels are all fleet-merged when fleet view is
  // active; badge the section headers Fleet.
  const scopeBadge = window.useScopeBadge ? window.useScopeBadge() : () => null;
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
  const rawEvents = audit.data?.events || [];

  // MED-SO-02 (2026-05-12) — PR-UX-A2 now filters server-side
  // (admin_get.rs parses ip / rule_id / request_id query params
  // and `AuditFilter` short-circuits in the ring walk). This
  // client-side pass remains as a defence-in-depth no-op so the
  // dashboard still works correctly against older WAF binaries
  // that don't yet honour the query params.
  const events = useMemoP(() => {
    if (!activePivot) return rawEvents;
    const needle = activePivot.toLowerCase();
    return rawEvents.filter(row => {
      const e = row.event || row;
      if (effectiveKind === 'ip') {
        return eventIp(e).toLowerCase() === needle;
      }
      if (effectiveKind === 'request_id') {
        return (e.request_id || '').toLowerCase() === needle;
      }
      if (effectiveKind === 'rule_id') {
        const ruleId = (e.rule_id || '').toLowerCase();
        if (ruleId === needle) return true;
        const f = (e.fields && typeof e.fields === 'object') ? e.fields : {};
        const detectors = Array.isArray(f.detectors) ? f.detectors : [];
        return detectors.some(d => String(d).toLowerCase() === needle);
      }
      return true;
    });
  }, [rawEvents, activePivot, effectiveKind]);

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

  // Stats roll-up over the (now pivot-filtered) audit window.
  // MED-SO-06 (2026-05-12) — detectors live under
  // `event.fields.detectors[]`; the top-level `event.detector` /
  // `event.detectors` keys are placeholders the audit ring
  // doesn't emit.  Walk `fields.detectors` for the breakdown so
  // the inline panel matches the by-detector aggregator.
  const summary = useMemoP(() => {
    if (!events.length) return null;
    const byAction = {};
    const byDetector = {};
    const byPath = {};
    const ips = new Set();
    let earliest = Infinity, latest = -Infinity;
    for (const row of events) {
      const e = row.event || row;
      const f = (e.fields && typeof e.fields === 'object') ? e.fields : {};
      const a = e.action || 'unknown';
      byAction[a] = (byAction[a] || 0) + 1;
      const detectors = Array.isArray(f.detectors) ? f.detectors : [];
      if (detectors.length) {
        for (const d of detectors) {
          const key = String(d);
          byDetector[key] = (byDetector[key] || 0) + 1;
        }
      } else if (e.rule_id) {
        byDetector[e.rule_id] = (byDetector[e.rule_id] || 0) + 1;
      }
      const p = f.path || e.path || '/';
      byPath[p] = (byPath[p] || 0) + 1;
      const eip = eventIp(e);
      if (eip) ips.add(eip);
      const ts = eventTimestampMs(e);
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
      <SecOpsPostureCard />
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
        //
        // MED-SO-05 (2026-05-12) — when /api/attacks/by-detector
        // returns empty (fresh process, aggregator hasn't started
        // bucketing yet, or any other hook-level failure) fall
        // back to deriving the breakdown from the audit ring so
        // the card matches what Live-Feed and Audit-Trail see.
        // The audit ring carries `event.fields.detectors[]` per
        // detection — exactly what the aggregator buckets server
        // side. Same window (last 1h) by clipping to the live
        // ring window.
        const apiDetectors = insightsByDetector.data?.detectors ?? [];
        let detectorBars;
        let totalDetections;
        let breakdownSource;
        if (apiDetectors.length > 0) {
          detectorBars = apiDetectors
            .map(d => ({ label: d.name, value: d.count, color: detectorColor(d.name) }))
            .sort((a, b) => b.value - a.value);
          totalDetections = detectorBars.reduce((s, x) => s + x.value, 0);
          breakdownSource = 'by-detector aggregator';
        } else {
          const counts = {};
          for (const row of rawEvents) {
            const e = row.event || row;
            const f = (e.fields && typeof e.fields === 'object') ? e.fields : {};
            const list = Array.isArray(f.detectors) && f.detectors.length
              ? f.detectors
              : (e.rule_id ? [e.rule_id] : []);
            for (const name of list) {
              const key = String(name);
              counts[key] = (counts[key] || 0) + 1;
            }
          }
          detectorBars = Object.entries(counts)
            .map(([name, value]) => ({ label: name, value, color: detectorColor(name) }))
            .sort((a, b) => b.value - a.value);
          totalDetections = detectorBars.reduce((s, x) => s + x.value, 0);
          breakdownSource = 'audit ring (fallback)';
        }
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
            // 2026-05-20 — the wire timestamp field is `ts_ms`, NOT
            // `ts`; reading `ea.ts` gave undefined → Date.parse → NaN
            // → both sides 0 → the "newest first" sort was a no-op,
            // so Recent requests showed the OLDEST 200 (stale allows)
            // and recent blocks never surfaced. Use the shared
            // `eventTimestampMs` helper (prefers ts_ms).
            const ta = eventTimestampMs(a.event || a);
            const tb = eventTimestampMs(b.event || b);
            return (Number.isFinite(tb) ? tb : 0) - (Number.isFinite(ta) ? ta : 0);
          });

        return (
          <>
            <div className="grid-12" style={{ marginBottom: 12 }}>
              <div className="col-6 card">
                <window.SectionHeader
                  title="Detector breakdown"
                  sub={`${totalDetections.toLocaleString()} detections · last 1h · ${breakdownSource}`}
                  actions={scopeBadge(true)}
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
                  actions={scopeBadge(true)}
                />
                {/* 2026-05-21 — the mix is a tier breakdown of FLAGGED
                    bots only. Classification is UA + ASN based (NOT
                    JA4 — there is no "JA4 baseline" mechanism). The
                    backend no longer emits a synthetic `unknown`
                    bucket and clean browser traffic isn't counted, so
                    an empty mix means nothing tripped a bot rule. */}
                {botSegments.length === 0 ? (
                  <div style={{ padding: 16, fontSize: 12, color: 'var(--ink-dim)', textAlign: 'center' }}>
                    No bot signals in the last hour. Classification is{' '}
                    <strong>UA + ASN</strong> based: scanner UAs →{' '}
                    <code>malicious</code>; no/short UA →{' '}
                    <code>suspect</code>; cloud/hosting ASN →{' '}
                    <code>suspect</code> (needs the <strong>GeoIP ASN
                    database</strong> loaded — check{' '}
                    <code>/api/geoip/status</code>). The mix counts only
                    flagged bots; clean browser traffic isn't shown. See{' '}
                    <a href="#/help" style={{ color: 'var(--accent)' }}>Help → Bot classifier setup</a>.
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
                actions={scopeBadge(true)}
              />
              <div style={{ padding: '8px 16px', fontSize: 11, color: 'var(--ink-dim)', borderBottom: '1px solid var(--hairline)', lineHeight: 1.6 }}>
                <strong>How to read a row:</strong>{' '}
                <span className="mono">IP risk</span> = the source's running score (per {'{ip, device, session}'} bucket; decays over time).{' '}
                <span className="mono">Req</span> = this request's own detector score.{' '}
                <span className="mono">Rule</span> = the gate that actioned it; for{' '}
                <span className="mono">risk-challenge</span> / <span className="mono">risk-score</span> the contributing detector is appended (e.g.{' '}
                <span className="mono" style={{ color: 'var(--accent)' }}>· recon_path</span>), or{' '}
                <em>· cumulative</em> when this request scored 0 and was actioned on the IP's accumulated risk from earlier requests.
              </div>
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
                        title="Cumulative risk score for this request's RiskKey bucket ({ip, device_fp?, session?}) — decays over time. Two browsers on the same NAT'd IP each carry their own bucket score. This is NOT the score of this single request."
                      >IP risk</th>
                      <th
                        style={{ width: 60 }}
                        title="Per-request detector score — sum of THIS request's detector signals (capped 100), compared to the tier's per-request block threshold. Blank when no detector fired."
                      >Req</th>
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
                            {(() => {
                              const ms = eventTimestampMs(e);
                              return Number.isFinite(ms) ? new Date(ms).toLocaleTimeString() : '—';
                            })()}
                          </td>
                          <td><window.ActionPill value={e.action || '—'} /></td>
                          <td className="mono">{eventIp(e) || '—'}</td>
                          <td className="mono">{f.method || e.method || '—'}</td>
                          <td className="mono"><code style={{ fontSize: 11 }}>{(f.path || e.path || '/').slice(0, 80)}</code></td>
                          <td className="num">{f.status || e.status || '—'}</td>
                          <td className="num">{e.risk_score ?? '—'}</td>
                          <td className="num">{Number.isFinite(Number(f.request_score)) ? Number(f.request_score) : '—'}</td>
                          <td className="mono">
                            <code style={{ fontSize: 10, color: 'var(--ink-dim)' }}>{e.rule_id || e.reason || '—'}</code>
                            {(e.rule_id === 'risk-challenge' || e.rule_id === 'risk-score') && (
                              f.detectors
                                ? <span
                                    style={{ fontSize: 10, color: 'var(--accent)' }}
                                    title="Detector that raised this request's score; the cumulative gate then actioned it"
                                  >{' · '}{f.detectors}</span>
                                : <span
                                    style={{ fontSize: 10, color: 'var(--ink-dim)', fontStyle: 'italic' }}
                                    title="No detector fired on THIS request — actioned on the IP's accumulated risk built by earlier requests"
                                  >{' · cumulative'}</span>
                            )}
                          </td>
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
              footer={selected && eventIp(selected) ? (
                <>
                  <button
                    className="btn"
                    onClick={() => {
                      const sip = eventIp(selected);
                      setPivot(sip);
                      setActivePivot(sip);
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
                ip: eventIp(selected),
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
              <window.SectionHeader title="Attacker context" sub="from /api/attacks/top" actions={scopeBadge(true)} />
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
            <window.SectionHeader
              title={`Audit timeline (newest first, ${events.length} of last 200)`}
              sub={activePivot ? `filtered to ${effectiveKind || 'pivot'}: ${activePivot}` : undefined}
              actions={scopeBadge(true)}
            />
            <table className="tbl tbl-compact">
              <thead><tr><th>ts</th><th>action</th><th>ip</th><th>method</th><th>path</th><th>rule_id</th></tr></thead>
              <tbody>
                {events.slice(0, 100).map((row, i) => {
                  // MED-SO-06 (2026-05-12) — request fields live under
                  // `event.fields.{method,path}`; the rule identifier
                  // comes from `extractResourceId(e)` for admin rows
                  // and `event.rule_id` / detectors list for detection
                  // rows.  Live-Feed already reads from `fields.*`;
                  // this brings Investigation to parity.
                  const e = row.event || row;
                  const f = (e.fields && typeof e.fields === 'object') ? e.fields : {};
                  const method = f.method || e.method || '—';
                  const path = f.path || e.path || '/';
                  const detectors = Array.isArray(f.detectors) ? f.detectors : [];
                  const ruleCell = e.rule_id
                    || (detectors.length ? detectors.join(',') : null)
                    || extractResourceId(e)
                    || '—';
                  return (
                    <tr key={i}>
                      <td style={{ fontFamily: 'monospace', fontSize: 11 }}>
                        {(() => {
                          const ms = eventTimestampMs(e);
                          return Number.isFinite(ms) ? new Date(ms).toLocaleTimeString() : '—';
                        })()}
                      </td>
                      <td><span className={`pill ${e.action === 'block' ? 'down' : e.action === 'allow' ? 'up' : 'warn'}`}>{e.action || '—'}</span></td>
                      <td className="num">{eventIp(e) || '—'}</td>
                      <td>{method}</td>
                      <td><code style={{ fontSize: 11 }}>{path.slice(0, 60)}</code></td>
                      <td><code style={{ fontSize: 11 }}>{ruleCell}</code></td>
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
      <PolicyPostureCard />
      <div className="page-head">
        <div>
          <h1 className="page-title">Traffic Gates</h1>
          <p className="page-subtitle">
            Five per-flow controls that fire <strong>before</strong> the detector chain — four binary
            block-or-pass gates plus the cumulative IP-risk threshold tuner — and an observational
            bot classifier. Each card carries its own "how does it work" explanation. See
            {' '}
            <a href="#/detectors" style={{ color: 'var(--accent)' }}>Detectors &amp; Tiers</a>
            {' '}for the signal-emitting pipeline that runs after these gates pass.
          </p>
        </div>
      </div>

      <TrafficGatesFlowDiagram />

      <AccessListGateCard />
      <StrikeBlockGateCard />
      <CumulativeIpRiskCard />
      <RateLimitGateCard />
      <DdosGateCard />
      <BotClassifierGateCard />
      {/* 2026-05-19 — per-bucket scores moved to the Top Attackers
          page as a "Composite RiskKey view" toggle so operators
          have one mental model for "who's worth investigating". */}
      <div style={{ marginBottom: 12, padding: '8px 12px', background: 'var(--surface-2)', borderRadius: 6, border: '1px solid var(--hairline)', fontSize: 11, color: 'var(--ink-dim)', display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
        <window.I.Shield />
        <span>Looking for per-bucket risk scores (one row per IP / device_fp / session)?</span>
        <a href="#/top-attackers?view=riskkey" style={{ color: 'var(--accent)', fontWeight: 600 }}>Top Attackers → Composite RiskKey view</a>
      </div>
    </>
  );
}

// 2026-05-21 — bot-classifier gate. On/off toggle for the UA+ASN
// bot classifier (observational — feeds Investigation → "Bot
// classification mix" + audit `bot_category`). Audit-mutated
// PUT /api/gates/bots; hot-applied (no restart). Modelled as a gate
// (like DDoS / Strike-Block), not a detector.
function BotClassifierGateCard() {
  const api = window.useApi
    ? window.useApi('/api/gates/bots', { intervalMs: 10000, fallback: { enabled: false } })
    : { data: { enabled: false } };
  const enabled = api.data?.enabled === true;
  const [busy, setBusy] = useStateP(false);

  async function toggle() {
    if (busy) return;
    setBusy(true);
    const next = !enabled;
    try {
      const r = await window.csrfMutate('/api/gates/bots', {
        method: 'PUT',
        body: JSON.stringify({ enabled: next }),
      });
      if (r && r.ok) {
        window.aegisToast(`Bot classifier ${next ? 'enabled' : 'disabled'}`, 'ok');
        api.reload && api.reload();
      } else {
        const msg = (r && (r.message || r.error || r.reason)) || 'unknown error';
        window.aegisToast(`Bot gate toggle failed: ${msg}`, 'err');
      }
    } catch (e) {
      window.aegisToast(`Bot gate error: ${e.message || e}`, 'err');
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="card" style={{ marginBottom: 12 }}>
      <div className="card-head" style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 12 }}>
        <window.SectionHeader
          title="6. Bot classifier"
          sub="Labels each request human / verified / suspect / malicious from UA + ASN signals (feeds Investigation → Bot classification mix). Observational — it does not block by class. Needs the GeoIP ASN DB to classify cloud/hosting traffic."
        />
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexShrink: 0 }}>
          <span className={`pill ${enabled ? 'ok' : 'warn'}`} style={{ fontSize: 10 }}>
            {enabled ? 'ON' : 'OFF'}
          </span>
          <div
            className={`toggle ${enabled ? 'on' : ''}`}
            onClick={busy ? undefined : toggle}
            title={enabled
              ? 'Bot classifier is ON — requests are labelled and the mix populates. Click to disable.'
              : 'Bot classifier is OFF — no classification runs; bot_category stays unset. Click to enable.'}
            style={{ cursor: busy ? 'wait' : 'pointer' }}
          />
        </div>
      </div>
      <GateExplain
        rows={[
          ['How it fires', <span key="hf">Per request the listener runs a UA + ASN rule-set: scanner UAs (<code>sqlmap</code>/<code>nikto</code>/…) → <code>malicious</code>; no/short UA or a cookieless cloud/hosting ASN → <code>suspect</code>. Verdict is recorded in audit <code>fields.bot_category</code> and aggregated on the Investigation page.</span>],
          ['Setup', <span key="s">Classification of cloud/hosting traffic needs the <strong>GeoIP ASN database</strong> (<code>geoip.asn_db</code>); confirm via <code>/api/geoip/status</code>. Scanner-UA and short-UA classification work without it.</span>],
          ['Observational', <span key="o">Today it only labels + feeds the mix — it does <strong>not</strong> run a per-class block/challenge. <code>verified</code> (good bots) and <code>human</code> require reverse-DNS / JS-challenge signals that aren\'t wired yet.</span>],
          ['Tunable', <span key="t">Toggle above. Audit-mutated <code>PUT /api/gates/bots</code>; hot-applied on the next request. See Help → "Bot classification (setup)".</span>],
        ]}
      />
    </div>
  );
}

// P6 (2026-05-11) — request-flow diagram at the top of Traffic
// Gates. Operators reading the page before this couldn't tell
// whether Strike-Block fires before or after Access List; the
// page intro said "fire before the detector chain" but didn't
// commit to the inter-gate order. Each chip is a click-scroll
// target to its corresponding card below.
function TrafficGatesFlowDiagram() {
  const stages = [
    { id: 'access-list',   label: '1. Access List',   target: 'access-list-card',  hint: 'IP / CIDR / country block + bypass' },
    { id: 'strike-block',  label: '2. Strike-Block',  target: 'strike-block-card', hint: 'Lifetime malicious-event counter' },
    { id: 'cumulative-ip', label: '3. Cumulative IP', target: 'cum-ip-risk-card',  hint: 'Per-RiskKey-bucket score (decays over time) — keyed by {ip, device_fp?, session?}' },
    { id: 'rate-limit',    label: '4. Rate Limit',    target: 'rate-limit-card',   hint: 'Global per-IP token bucket' },
    { id: 'ddos',          label: '5. DDoS',          target: 'ddos-card',         hint: 'Sliding-window burst + EWMA spike' },
  ];
  const scrollToCard = (id) => {
    const el = document.getElementById(id);
    if (el) el.scrollIntoView({ behavior: 'smooth', block: 'start' });
  };
  return (
    <div className="card" style={{ padding: '12px 14px', marginBottom: 12 }}>
      <div style={{ fontSize: 11, color: 'var(--ink-dim)', marginBottom: 8 }}>
        Request flow — gates fire in this order; first short-circuit wins. The detector chain runs after every gate passes.
      </div>
      <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap' }}>
        <span style={{ fontSize: 11, color: 'var(--ink-mute)', fontFamily: 'var(--mono)' }}>
          inbound
        </span>
        <span style={{ color: 'var(--ink-dim)' }}>→</span>
        {stages.map((s, idx) => (
          <React.Fragment key={s.id}>
            <button
              type="button"
              onClick={() => scrollToCard(s.target)}
              title={s.hint}
              className="pill neutral"
              style={{
                cursor: 'pointer',
                border: '1px solid var(--hairline-strong)',
                background: 'var(--surface-2)',
                fontSize: 11,
              }}
            >
              {s.label}
            </button>
            <span style={{ color: 'var(--ink-dim)' }}>→</span>
          </React.Fragment>
        ))}
        <span
          style={{
            fontSize: 11,
            color: 'var(--ink-mute)',
            fontFamily: 'var(--mono)',
            paddingLeft: 4,
          }}
        >
          detector chain
        </span>
      </div>
    </div>
  );
}

// 1. Access list summary — links to the existing dedicated page.
function AccessListGateCard() {
  const black = window.useApi ? window.useApi('/api/blacklist', { intervalMs: 30000, fallback: { entries: [] } }) : { data: { entries: [] } };
  const white = window.useApi ? window.useApi('/api/whitelist', { intervalMs: 30000, fallback: { entries: [] } }) : { data: { entries: [] } };
  const blackCount = (black.data?.entries || []).length;
  const whiteCount = (white.data?.entries || []).length;
  return (
    <div id="access-list-card" className="card" style={{ marginBottom: 12 }}>
      <window.SectionHeader
        title="1. Access List"
        sub="IP / CIDR / country blacklist + whitelist — fires first, cheapest gate"
      />
      <div style={{ padding: 16, display: 'flex', alignItems: 'center', gap: 16 }}>
        <div style={{ flex: 1, display: 'flex', gap: 16, flexWrap: 'wrap' }}>
          <span className="pill err" style={{ fontSize: 11 }}>{blackCount} blacklist {blackCount === 1 ? 'entry' : 'entries'}</span>
          <span className="pill ok" style={{ fontSize: 11 }}>{whiteCount} whitelist {whiteCount === 1 ? 'entry' : 'entries'}</span>
        </div>
        <a href="#/access-lists" className="btn primary" style={{ fontSize: 11, padding: '4px 12px', textDecoration: 'none' }}>
          Edit lists →
        </a>
      </div>
      <GateExplain
        rows={[
          ['How it fires', 'Operator-curated IP / CIDR / ASN / country blacklist or whitelist. Match → terminate request before the detector chain.'],
          ['Response', '403 + ', <code key="c">X-WAF-Action: block</code>, ' on blacklist hit. Whitelist bypasses detectors but not other gates.'],
          ['Recovery', <span key="r">Manual — operator removes the entry on Access Lists. No automatic expiry unless an entry is created with a TTL.</span>],
          ['Tunable', 'Add / remove entries on the Access Lists page (audit-mutated, hot-reload).'],
        ]}
      />
    </div>
  );
}

// Compact "how does it work" strip used at the bottom of every
// gate card on this page. Renders a 2-column key/value grid so
// operators can read the operating semantics without having to
// open the operator doc. Keeps wording tight (one-liner per row).
//
// 2026-05-10 — collapsible. Defaults to collapsed (just the header
// row + chevron) so the five cards on the page stay compact for
// routine ops; an operator clicks the header to dump the full
// rows when they need the explanation.
function GateExplain({ rows }) {
  const [expanded, setExpanded] = useStateP(false);
  return (
    <div style={{
      borderTop: '1px solid var(--hairline)',
      background: 'var(--surface-2)',
      fontSize: 11,
      color: 'var(--ink-dim)',
      lineHeight: 1.5,
    }}>
      <button
        type="button"
        onClick={() => setExpanded(e => !e)}
        aria-expanded={expanded}
        style={{
          width: '100%',
          textAlign: 'left',
          background: 'transparent',
          border: 'none',
          padding: '10px 16px',
          cursor: 'pointer',
          display: 'flex',
          alignItems: 'center',
          gap: 8,
          fontSize: 11,
          fontWeight: 600,
          color: 'var(--ink)',
        }}
      >
        <span style={{ fontSize: 10, color: 'var(--ink-dim)', width: 10, display: 'inline-block' }}>
          {expanded ? '▼' : '▶'}
        </span>
        How does it work?
        <span style={{ fontSize: 10, color: 'var(--ink-dim)', fontWeight: 400, marginLeft: 'auto' }}>
          {expanded ? 'click to collapse' : `${rows.length} rows · click to expand`}
        </span>
      </button>
      {expanded && (
        <div style={{ padding: '0 16px 12px', display: 'grid', gridTemplateColumns: 'minmax(96px, max-content) 1fr', gap: '4px 12px' }}>
          {rows.map(([k, ...v], i) => (
            <React.Fragment key={i}>
              <div style={{ color: 'var(--ink)', fontWeight: 500 }}>{k}</div>
              <div>{v}</div>
            </React.Fragment>
          ))}
        </div>
      )}
    </div>
  );
}

// 2. Strike-Block — per-IP lifetime strike counter. Reads
// /api/gates/strikes for live `enabled` + `block_at` and the
// telemetry counts (tracked_ips, at_or_over_threshold).
// Operators flip enable/disable + tune block_at via the Edit
// modal — audit-mutated PUT /api/gates/strikes; per-IP strike
// state is preserved across edits.
//
// 2026-05-10 — Strike-Block defaults to *disabled* in production
// (opt-in). The lifetime counter never decays, which can interact
// awkwardly with the contract's risk-score decay invariant; opt-in
// keeps the never-decay knob explicit.
function StrikeBlockGateCard() {
  const sb = window.useApi ? window.useApi('/api/gates/strikes', { intervalMs: 10000, fallback: null }) : { data: null };
  const cfg = sb.data;
  const [editing, setEditing] = useStateP(false);
  const enabled = !!cfg?.enabled;

  return (
    <div id="strike-block-card" className="card" style={{ marginBottom: 12 }}>
      <window.SectionHeader
        title="2. Strike-Block"
        sub="Per-RiskKey-bucket lifetime strike counter — permanent block once threshold crossed (opt-in). Buckets are keyed by {ip, device_fp?, session?}; two sessions on the same NAT'd IP each climb independently."
      />
      <div style={{ padding: 16 }}>
        {!cfg ? (
          <div style={{ fontSize: 12, color: 'var(--ink-dim)', fontStyle: 'italic' }}>Loading…</div>
        ) : (
          <>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 12, marginBottom: 12 }}>
              <div style={{ padding: 12, background: 'var(--surface-2)', borderRadius: 4 }}>
                <div style={{ fontSize: 10, color: 'var(--ink-dim)', textTransform: 'uppercase', letterSpacing: 0.5 }}>Status</div>
                <div style={{ fontSize: 18, fontWeight: 700, marginTop: 4, color: enabled ? 'var(--ok)' : 'var(--ink-dim)' }}>
                  {enabled ? 'ENABLED' : 'DISABLED'}
                </div>
                <div style={{ fontSize: 10, color: 'var(--ink-faint)', marginTop: 2 }}>
                  {enabled ? 'gate is firing' : 'gate is off (opt-in)'}
                </div>
              </div>
              <div style={{ padding: 12, background: 'var(--surface-2)', borderRadius: 4 }}>
                <div style={{ fontSize: 10, color: 'var(--ink-dim)', textTransform: 'uppercase', letterSpacing: 0.5 }}>Block at</div>
                <div style={{ fontSize: 24, fontWeight: 700, marginTop: 4, opacity: enabled ? 1 : 0.5 }}>{cfg.block_at}</div>
                <div style={{ fontSize: 10, color: 'var(--ink-faint)', marginTop: 2 }}>lifetime strikes</div>
              </div>
              <div style={{ padding: 12, background: 'var(--surface-2)', borderRadius: 4 }}>
                <div style={{ fontSize: 10, color: 'var(--ink-dim)', textTransform: 'uppercase', letterSpacing: 0.5 }}>At-or-over</div>
                <div style={{ fontSize: 24, fontWeight: 700, marginTop: 4, color: cfg.at_or_over_threshold > 0 ? 'var(--down)' : 'var(--ink)' }}>
                  {cfg.at_or_over_threshold}
                </div>
                <div
                  style={{ fontSize: 10, color: 'var(--ink-faint)', marginTop: 2 }}
                  title={`The /api/gates/strikes JSON still names this field "tracked_ips" for wire compatibility, but the value counts unique RiskKey buckets — one per (ip, device_fp?, session?) combination — not unique IPs. See the docs for the 2026-05-19 composite-key migration.`}
                >
                  of {cfg.tracked_ips} tracked {cfg.tracked_ips === 1 ? 'bucket' : 'buckets'}
                </div>
              </div>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 12 }}>
              <div style={{ fontSize: 11, color: 'var(--ink-dim)', lineHeight: 1.5 }}>
                {enabled
                  ? <>Gate is firing. {cfg.at_or_over_threshold > 0
                      ? <strong>{cfg.at_or_over_threshold} {cfg.at_or_over_threshold === 1 ? 'bucket is' : 'buckets are'} currently 403'd</strong>
                      : 'No bucket at or above threshold.'}{' '}Per-bucket strikes preserved across edits.</>
                  : <>Gate is off — strike counts still climb in <code>/api/risk</code> for forensics, but the data plane does not 403. Enable to opt in.</>
                }
              </div>
              <button className="btn primary" onClick={() => setEditing(true)} style={{ fontSize: 11, padding: '4px 12px' }}>
                Edit
              </button>
            </div>
          </>
        )}
      </div>
      <GateExplain
        rows={[
          ['How it fires', <span key="hf">Each detector hit increments the request's RiskKey bucket's lifetime strike counter by 1. When the bucket crosses <code>block_at</code>, the next request on that bucket 403s at the gate before any further detector cost. Bucket is keyed by <code>{`{ip, device_fp?, session?}`}</code> — two browsers on the same NAT'd IP each have their own counter.</span>],
          ['Counter', <span key="c"><strong>Lifetime, never decays.</strong> A bucket that hits <code>block_at</code> stays blocked across days unless an operator resets it.</span>],
          ['Response', '403 + ', <code key="rc">X-WAF-Action: block</code>, ' + ', <code key="rid">X-WAF-Rule-Id: risk-strikes</code>, '. ', <code key="rs">X-WAF-Risk-Score</code>, ' continues to report the (decayed) cumulative score, distinct from the strike count.'],
          ['Recovery', <span key="r">Two options: <code>POST /api/risk/&lt;ip&gt;/reset</code> wipes every bucket sharing that IP (legacy IP-only reset, simpler operator UX); <a href="#/top-attackers?view=riskkey" style={{ color: 'var(--accent)' }}>Top Attackers → Composite RiskKey view</a> lets you reset one bucket without disturbing siblings on the same IP. Or disable the gate entirely from this card.</span>],
          ['Tunable', <span key="t">Edit modal on this card — flip <code>enabled</code> and tune <code>block_at</code>. Audit-mutated <code>PUT /api/gates/strikes</code>; per-bucket strike state preserved across edits.</span>],
          ['When to use', 'Production hardening for repeat offenders. For benchmark / risk-decay lifecycle tests, leave disabled (default) so cumulative score is the only score-based gate.'],
        ]}
      />
      {editing && (
        <StrikesEditModal
          current={cfg}
          onClose={() => setEditing(false)}
          onSaved={() => { setEditing(false); sb.reload && sb.reload(); }}
        />
      )}
    </div>
  );
}

function StrikesEditModal({ current, onClose, onSaved }) {
  const [enabled, setEnabled] = useStateP(!!current?.enabled);
  const [blockAt, setBlockAt] = useStateP(current?.block_at ?? 50);
  const [busy, setBusy] = useStateP(false);
  const [err, setErr] = useStateP(null);

  async function save() {
    setBusy(true); setErr(null);
    try {
      const r = await window.csrfMutate('/api/gates/strikes', {
        method: 'PUT',
        body: { enabled, block_at: parseInt(blockAt, 10) },
      });
      if (r && r.ok !== false && (r.status === undefined || (r.status >= 200 && r.status < 300))) {
        window.aegisToast && window.aegisToast(`Strike-Block ${enabled ? 'enabled' : 'disabled'} · block_at=${blockAt}`, 'ok');
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
      <div className="modal" onClick={e => e.stopPropagation()} style={{ maxWidth: 520 }}>
        <div className="modal-head">
          <div className="modal-title">Edit Strike-Block gate</div>
          <button className="btn btn-sm" onClick={onClose}>×</button>
        </div>
        <div className="modal-body" style={{ display: 'grid', gap: 12 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <div className={`toggle ${enabled ? 'on' : ''}`} onClick={busy ? undefined : () => setEnabled(e => !e)} style={{ cursor: busy ? 'wait' : 'pointer' }} />
            <div>
              <div style={{ fontSize: 12, fontWeight: 600 }}>Enabled</div>
              <div style={{ fontSize: 11, color: 'var(--ink-dim)' }}>
                When off, strikes still accumulate for forensics but the data plane does not 403.
              </div>
            </div>
          </div>
          <label style={{ fontSize: 12, opacity: enabled ? 1 : 0.55 }}>
            Block at (lifetime strikes)
            <input className="input" type="number" min="1" value={blockAt}
              onChange={e => setBlockAt(e.target.value)} disabled={busy}
              style={{ marginTop: 4, width: '100%' }} />
          </label>
          <div style={{ fontSize: 11, color: 'var(--ink-dim)', lineHeight: 1.5, padding: 10, background: 'var(--surface-2)', borderRadius: 4 }}>
            <strong>Caveat:</strong> the strike counter never decays. With <code>enabled = true</code>,
            an IP that hits <code>block_at</code> stays 403'd until you disable the gate or reset
            it via <code>POST /api/risk/&lt;ip&gt;/reset</code>. For benchmark / risk-decay lifecycle
            tests, leave the gate disabled — the cumulative IP risk thresholds (#3 below) carry
            the contract's accumulation+decay invariant.
            {' '}
            Per-IP strike state is preserved across this edit; flipping the gate off then on
            re-applies any IPs already at-or-over the threshold.
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

// 2026-05-10 — moved from PageSettings into Traffic Gates so all
// per-IP-risk knobs (strike threshold, cumulative challenge_at,
// cumulative block_at) sit on one page. The two thresholds gate
// the challenge ladder for the *cumulative* per-IP score (decays
// over time); the strike-block threshold above gates the lifetime
// strike counter (never decays). Wired to /api/risk/thresholds
// via window.useRiskThresholdsApi + window.settingsRiskThresholdsPut
// — the same hooks Settings used to call.
function CumulativeIpRiskCard() {
  const riskApi = window.useRiskThresholdsApi();
  const [allow, setAllow] = useStateP(0);
  const [challenge, setChallenge] = useStateP(0);
  // Linear decay rate (points/hour) — editable; synced from the live API below.
  const [perHour, setPerHour] = useStateP(30);
  const [riskBusy, setRiskBusy] = useStateP(false);
  // 2026-05-21 — master on/off for the whole cumulative gate.
  // Defaults to enabled until the API answers (the live value syncs in
  // the effect below). When off, accumulated score never gates traffic.
  const gateEnabled = riskApi.data?.enabled !== false;

  // Sync local sliders with whatever the live API reports —
  // first load, hot-reload, or another operator's PUT.
  useEffectP(() => {
    if (!riskApi.data) return;
    const ca = Number(riskApi.data.challenge_at);
    const ba = Number(riskApi.data.block_at);
    if (Number.isFinite(ca)) setAllow(Math.max(0, ca - 1));
    if (Number.isFinite(ba)) setChallenge(Math.max(0, ba - 1));
    const ph = Number(riskApi.data.trust_per_hour);
    if (Number.isFinite(ph)) setPerHour(ph);
  }, [riskApi.data?.challenge_at, riskApi.data?.block_at, riskApi.data?.trust_per_hour]);

  async function putThresholds(body, okMsg) {
    if (riskBusy) return;
    setRiskBusy(true);
    try {
      const r = await window.settingsRiskThresholdsPut(body);
      if (r && r.ok) {
        window.aegisToast(okMsg, 'ok');
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

  // Flip the gate on/off without touching the numeric thresholds —
  // the backend merges unspecified fields from the current config.
  async function toggleGate() {
    const next = !gateEnabled;
    await putThresholds({ enabled: next }, `Cumulative IP risk gate ${next ? 'ENABLED' : 'DISABLED'}`);
  }

  async function saveRiskThresholds() {
    const ph = Math.max(0, Math.round(Number(perHour) || 0));
    await putThresholds(
      {
        enabled: gateEnabled,
        challenge_at: allow + 1,
        block_at: challenge + 1,
        max: Number(riskApi.data?.max) || 100,
        trust_per_hour: ph,
      },
      `Risk thresholds → challenge ≥ ${allow + 1} · block ≥ ${challenge + 1} · decay ${ph}/hr`,
    );
  }

  return (
    <div id="cum-ip-risk-card" className="card" style={{ marginBottom: 12 }}>
      <div className="card-head" style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 12 }}>
        <window.SectionHeader
          title="3. Cumulative IP risk thresholds"
          sub="Per-RiskKey-bucket decaying score — challenge then block, recovers when score decays. Buckets are keyed by {ip, device_fp?, session?}; thresholds below are tracker-wide and apply to every bucket."
        />
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexShrink: 0 }}>
          <span className={`pill ${gateEnabled ? 'ok' : 'warn'}`} style={{ fontSize: 10 }}>
            {gateEnabled ? 'ON' : 'OFF'}
          </span>
          <div
            className={`toggle ${gateEnabled ? 'on' : ''}`}
            onClick={riskBusy ? undefined : toggleGate}
            title={gateEnabled
              ? 'Cumulative IP-risk gate is ON — accumulated bucket score can challenge/block. Click to disable.'
              : 'Cumulative IP-risk gate is OFF — accumulated score never gates traffic (still recorded for forensics). Click to enable.'}
            style={{ cursor: riskBusy ? 'wait' : 'pointer' }}
          />
        </div>
      </div>
      <div style={{ padding: 16, opacity: gateEnabled ? 1 : 0.55 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap', marginBottom: 10 }}>
          <span className={`pill ${riskApi.error ? 'warn' : 'ok'}`} style={{ fontSize: 11 }}>
            {riskApi.error ? 'fetch failed' : 'live'}
          </span>
          {!gateEnabled && (
            <span className="pill warn" style={{ fontSize: 11 }}>
              gate disabled — thresholds below are inert until re-enabled
            </span>
          )}
          {riskApi.data && (
            <span style={{ fontSize: 11, color: 'var(--ink-dim)' }}>
              currently: challenge ≥ <strong>{riskApi.data.challenge_at}</strong> · block ≥ <strong>{riskApi.data.block_at}</strong>
              {' · '}decays <span className="num">{riskApi.data?.trust_per_hour ?? 30}</span>/hr
            </span>
          )}
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12, marginBottom: 6 }}>
              <span>Allow score (0 – {allow}) — let the request through, no gate</span><span className="num">{allow}</span>
            </div>
            <input type="range" min="0" max="100" value={allow} disabled={riskBusy} onChange={e => setAllow(+e.target.value)} style={{ width: '100%', accentColor: 'var(--brand-yellow)' }} />
          </div>
          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12, marginBottom: 6 }}>
              <span>Challenge score ({allow + 1} – {challenge}) — JS / CAPTCHA before allowing</span><span className="num">{challenge}</span>
            </div>
            <input type="range" min={allow+1} max="100" value={challenge} disabled={riskBusy} onChange={e => setChallenge(+e.target.value)} style={{ width: '100%', accentColor: 'var(--brand-yellow)' }} />
          </div>
          {/* Decay rate — how fast a bucket's score ages back toward zero. */}
          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12, marginBottom: 6 }}>
              <span>Decay rate — how fast score ages back to zero</span>
              <span><input
                type="number" min="0" max="10000" step="5" value={perHour} disabled={riskBusy}
                onChange={e => setPerHour(e.target.value)}
                style={{ width: 64, fontSize: 12, textAlign: 'right', background: 'var(--surface-2)', color: 'var(--ink)', border: '1px solid var(--border)', borderRadius: 4, padding: '2px 6px' }}
              /> <span className="num">/hr</span></span>
            </div>
            <input type="range" min="0" max="200" step="5" value={Math.min(perHour, 200)} disabled={riskBusy} onChange={e => setPerHour(+e.target.value)} style={{ width: '100%', accentColor: 'var(--brand-yellow)' }} />
            <div style={{ fontSize: 11, color: 'var(--ink-faint)', marginTop: 4 }}>
              Points removed per hour of elapsed time (applied on read). Higher = forgive faster;
              lower = remember longer. <strong>0 = never decay</strong> (score only resets on
              <code> /api/risk/&lt;ip&gt;/reset</code> or 1h idle eviction).
              {(Number(perHour) || 0) > 0 && (
                <> At <strong>{Math.round(Number(perHour))}/hr</strong>, a maxed bucket (100) clears in
                  {' '}<strong>{(100 / Math.max(Number(perHour), 1)).toFixed(1)}h</strong>. Strikes never decay.</>
              )}
            </div>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 12 }}>
            <div style={{ fontSize: 12, color: 'var(--ink-mute)' }}>
              Block score: <span className="num" style={{ color: 'var(--down)' }}>≥ {challenge + 1}</span> — refuse further requests from this bucket until score decays
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

        {/* How decay works — operators ask "why is a quiet IP still at 100?".
            State the linear, time-based, decay-on-read model + a worked example
            using the live rate, and that strikes are the one thing that sticks. */}
        {(() => {
          const perHour = riskApi.data?.trust_per_hour ?? 30;
          const blockAt = Number(riskApi.data?.block_at) || (challenge + 1);
          const hoursToClear = perHour > 0 ? (blockAt / perHour) : Infinity;
          return (
            <div style={{
              marginTop: 14, padding: '12px 14px', borderRadius: 6,
              background: 'var(--surface-2)', borderLeft: '3px solid var(--brand-yellow)',
              fontSize: 12, color: 'var(--ink)', lineHeight: 1.55,
            }}>
              <strong>How the score decays.</strong> A bucket's score falls <strong>{perHour} points per hour</strong>,
              linearly, based on wall-clock time since its last request. The decay is applied <strong>on read</strong> —
              so a source that floods and then goes quiet ages toward zero on its own; it does <em>not</em> stay
              pinned at its peak until it sends more traffic.
              {Number.isFinite(hoursToClear) && (
                <> A bucket sitting at the block line ({blockAt}) clears in about <strong>{hoursToClear.toFixed(1)}h</strong> of silence.</>
              )}
              {' '}
              <span style={{ color: 'var(--ink-mute)' }}>
                One exception: <strong>strikes never decay</strong> — once a source is strike-blocked for repeat
                offences, score recovery does not release it (that gate is separate, on this page).
              </span>
            </div>
          );
        })()}
      </div>
      <GateExplain
        rows={[
          ['How it fires', <span key="hf">Each detector hit adds weight to the request's RiskKey bucket score (sum of signals). Crossing <code>challenge_at</code> serves a JS/CAPTCHA challenge; crossing <code>block_at</code> refuses requests at the gate. Bucket is keyed by <code>{`{ip, device_fp?, session?}`}</code> — two browsers on the same NAT'd IP each accumulate independently.</span>],
          ['Decay', <span key="c"><strong>Linear, time-based, applied on read.</strong> The score falls at <code>{riskApi.data?.trust_per_hour ?? 30}</code> points/hour of wall-clock time (config <code>risk.trust_recovery.per_hour</code>), evaluated every time the score is read — so a bucket that stops attracting hits ages toward zero even with no further traffic, and the gate decision + <code>/api/risk</code> view both reflect the aged value.</span>],
          ['Response', <span key="rsp">429 + <code>X-WAF-Action: challenge</code> when above challenge_at; 403 + <code>X-WAF-Action: block</code> + <code>X-WAF-Rule-Id: risk-score</code> when above block_at. <code>X-WAF-Risk-Score</code> reports this same (decayed) accumulated score, satisfying the contract's accumulation+decay invariant.</span>],
          ['Recovery', <span key="r">Automatic — score decays toward zero as time passes without new hits (see "How the score decays" above). <strong>Strikes are the exception</strong>: the repeat-offender strike-block never decays.</span>],
          ['Tunable', <span key="t">Sliders above — thresholds <em>and</em> the decay rate (<code>trust_recovery.per_hour</code>). Audit-mutated <code>PUT /api/risk/thresholds</code>; takes effect on the next request, persists across restart, and converges across cluster nodes.</span>],
          ['Distinct from', <span key="d">The per-request <em>tier risk threshold</em> (50/70/80/90 by tier) which blocks <em>this</em> request based on its detector hits. That one lives on <a href="#/detectors" style={{ color: 'var(--accent)' }}>Detectors &amp; Tiers</a> → Edit tier.</span>],
        ]}
      />
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
  const [busy, setBusy] = useStateP(false);

  // 2026-06-22 — inline enable/disable toggle (DDoS-parity). PUTs the flipped
  // `enabled` alongside the current limit/window so the durable config doc and
  // the live limiter converge on the next request. Disabling skips the gate
  // entirely (no 429s); orthogonal to the enforce/log_only interop mode.
  const enabled = cfg ? cfg.enabled !== false : true;
  async function toggleEnabled() {
    if (!cfg || busy) return;
    setBusy(true);
    try {
      const r = await window.csrfMutate('/api/rate-limit', {
        method: 'PUT',
        body: { enabled: !enabled, limit: cfg.limit, window_seconds: cfg.window_seconds },
      });
      if (r && r.ok !== false && (r.status === undefined || (r.status >= 200 && r.status < 300))) {
        window.aegisToast && window.aegisToast(`Rate limit ${!enabled ? 'enabled' : 'disabled'}`, 'ok');
        rl.reload && rl.reload();
      } else {
        const msg = (r && (r.message || r.error || r.reason)) || `status ${r?.status ?? '?'}`;
        window.aegisToast && window.aegisToast(`Rate-limit toggle failed: ${msg}`, 'err');
      }
    } catch (e) {
      window.aegisToast && window.aegisToast(`Rate-limit toggle failed: ${e.message || e}`, 'err');
    } finally {
      setBusy(false);
    }
  }

  return (
    <div id="rate-limit-card" className="card" style={{ marginBottom: 12 }}>
      <window.SectionHeader
        title="4. Rate Limit"
        sub="Per-RiskKey-bucket token-counter — returns 429 + X-WAF-Action: rate_limit when window exceeded. Allows retry after window. Buckets are keyed by {ip, device_fp?, session?} — two sessions on the same NAT'd IP each get their own quota."
      />
      <div style={{ padding: 16 }}>
        {!cfg ? (
          <div style={{ fontSize: 12, color: 'var(--ink-dim)', fontStyle: 'italic' }}>Loading…</div>
        ) : (
          <>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 12, marginBottom: 12 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <span className={`pill ${enabled ? 'ok' : 'neutral'}`} style={{ fontSize: 10, fontWeight: 700, letterSpacing: 0.5 }}>
                  {enabled ? 'ENABLED' : 'DISABLED'}
                </span>
                <span style={{ fontSize: 11, color: 'var(--ink-dim)' }}>
                  {enabled ? 'gate active' : 'gate off — no 429s, no bucket tracking'}
                </span>
              </div>
              <MaskSwitch on={enabled} busy={busy} onToggle={toggleEnabled} label="Toggle rate-limit gate" />
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 12, marginBottom: 12, opacity: enabled ? 1 : 0.5 }}>
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
                Effective rate: <strong>{(cfg.limit / Math.max(cfg.window_seconds, 1)).toFixed(2)} req/s per bucket</strong>.
                Hot-reloadable — edits take effect on the next request without restart.
              </div>
              <button className="btn primary" onClick={() => setEditing(true)} style={{ fontSize: 11, padding: '4px 12px' }}>
                Edit
              </button>
            </div>
          </>
        )}
      </div>
      <GateExplain
        rows={[
          ['How it fires', <span key="hf">Per-RiskKey-bucket counter on a sliding window. When the count exceeds <code>limit</code> within <code>window</code>, the request is denied. Bucket is keyed by <code>{`{ip, device_fp?, session?}`}</code> so two sessions on the same NAT'd IP each get their own quota — attacker A's flood doesn't 429 legit user B.</span>],
          ['Counter', <span key="c">In-process per-bucket timestamp deque (per node). <strong>Window slides → automatic recovery.</strong></span>],
          ['Response', '429 + ', <code key="rc">X-WAF-Action: rate_limit</code>, ' + ', <code key="rid">X-WAF-Rule-Id: ip-rate-limit</code>, '. Misbehaving clients can back off and retry.'],
          ['Recovery', 'Automatic — bucket allowed again as soon as the window slides past old timestamps.'],
          ['Tunable', <span key="t">Edit modal on this card. Audit-mutated <code>PUT /api/rate-limit</code>; per-bucket timestamp state preserved.</span>],
          ['When to use', '"Steady-state per-bucket budget" — APIs with rate fairness. For sustained-burst quarantine (DDoS-grade, keyed by TCP peer IP regardless of session), use the DDoS gate (#5) instead.'],
        ]}
      />
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
  const [enabled, setEnabled] = useStateP(current?.enabled !== false);
  const [limit, setLimit] = useStateP(current?.limit ?? 1000);
  const [windowSeconds, setWindowSeconds] = useStateP(current?.window_seconds ?? 60);
  const [busy, setBusy] = useStateP(false);
  const [err, setErr] = useStateP(null);

  async function save() {
    setBusy(true); setErr(null);
    try {
      const r = await window.csrfMutate('/api/rate-limit', {
        method: 'PUT',
        body: { enabled, limit: parseInt(limit, 10), window_seconds: parseInt(windowSeconds, 10) },
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
          <label style={{ fontSize: 12, display: 'flex', alignItems: 'center', gap: 8 }}>
            <input type="checkbox" checked={enabled} onChange={e => setEnabled(e.target.checked)} disabled={busy} />
            <span><strong>Enabled</strong> — uncheck to skip the gate entirely (no 429s, no per-bucket tracking).</span>
          </label>
          <label style={{ fontSize: 12, opacity: enabled ? 1 : 0.5 }}>
            Limit (requests per window)
            <input className="input" type="number" min="1" value={limit}
              onChange={e => setLimit(e.target.value)} disabled={busy || !enabled}
              style={{ marginTop: 4, width: '100%' }} />
          </label>
          <label style={{ fontSize: 12, opacity: enabled ? 1 : 0.5 }}>
            Window (seconds)
            <input className="input" type="number" min="1" value={windowSeconds}
              onChange={e => setWindowSeconds(e.target.value)} disabled={busy || !enabled}
              style={{ marginTop: 4, width: '100%' }} />
          </label>
          <div style={{ fontSize: 11, color: 'var(--ink-dim)', lineHeight: 1.5 }}>
            Effective: <strong>{(limit / Math.max(parseInt(windowSeconds, 10), 1)).toFixed(2)} req/s per bucket</strong>.
            Per-bucket timestamp state is preserved across the edit — flooding sources don't get a free reset.
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

// 5. DDoS gate — full operator surface. Per-IP sliding-window
// burst counter + EWMA spike-mode ticker. Returns 403 +
// X-WAF-Action: block on burst-exceed (different from rate-limit
// gate which returns 429). Hot-reloadable via PUT /api/gates/ddos
// — per-IP StateBackend window state preserved across edits.
function DdosGateCard() {
  const ddos = window.useApi ? window.useApi('/api/gates/ddos', { intervalMs: 5000, fallback: null }) : { data: null };
  const [editing, setEditing] = useStateP(false);
  const data = ddos.data;

  if (!data || !data.enabled) {
    // `data.enabled = false` now only happens when the dashboard
    // is consuming a test-bundle `DashboardServices` that booted
    // without the proxy wiring the runtime. Production always
    // installs it (2026-05-19) and exposes a hot-flippable
    // `cfg.enabled` instead — see the `hotDisabled` branch below.
    return (
      <div id="ddos-card" className="card" style={{ marginBottom: 12 }}>
        <window.SectionHeader
          title="5. DDoS Gate"
          sub="Per-IP sliding-window burst gate + EWMA spike mode — runtime not wired"
        />
        <div style={{ padding: 16 }}>
          <div style={{ fontSize: 12, color: 'var(--ink-dim)', lineHeight: 1.5 }}>
            <span className="pill neutral" style={{ fontSize: 11, marginRight: 8 }}>runtime not wired</span>
            The DDoS runtime wasn't installed at proxy boot — this is a test bundle.
            Production deployments install it unconditionally and expose a hot-flippable Enabled toggle on this card.
          </div>
        </div>
      </div>
    );
  }

  const cfg = data.config;
  // 2026-05-19 — `cfg.enabled` is now hot-flippable from the dashboard
  // (PUT /api/gates/ddos). When disabled, every check_with_tier
  // short-circuits to unblocked + the EWMA freezes, so showing
  // ENFORCING / NORMAL would be a lie. Surface a distinct DISABLED
  // state that visually neutralises both pills and dims the live
  // telemetry tiles.
  const hotDisabled = cfg.enabled === false;
  // 2026-05-22 — a set_profile log_only on the ddos feature suppresses
  // the 503 just like the config observe_only flag, so the badge must
  // reflect it too (was previously config-only and falsely showed
  // ENFORCING under a global/feature log_only).
  const ddosLogOnly = data.effective_mode === 'log_only';
  const modeStyle = hotDisabled
    ? { bg: 'rgba(160,160,160,0.18)', fg: 'var(--ink-dim)', label: 'DISABLED' }
    : ddosLogOnly
      ? { bg: 'rgba(240,185,11,0.14)', fg: 'var(--warn)', label: 'LOG-ONLY (set_profile)' }
      : cfg.observe_only
        ? { bg: 'rgba(240,185,11,0.14)', fg: 'var(--warn)', label: 'OBSERVE-ONLY' }
        : { bg: 'rgba(14,203,129,0.14)', fg: 'var(--up)', label: 'ENFORCING' };
  const spikeStyle = hotDisabled
    ? { bg: 'rgba(160,160,160,0.18)', fg: 'var(--ink-dim)', label: '—' }
    : data.spike_active
      ? { bg: 'rgba(246,70,93,0.14)', fg: 'var(--down)', label: '⚠ SPIKE ACTIVE' }
      : { bg: 'rgba(14,203,129,0.14)', fg: 'var(--up)', label: 'NORMAL' };

  // 2026-06-21 — derived "trip ceiling" maths so the card can state the LIVE
  // effective cap in plain language. The gate is trip-and-quarantine, not a
  // per-request throttle: crossing the per-window count jails the whole IP for
  // block_ttl_s. `tightened_per_ip_rps` is an RPS that converts to a per-window
  // count (× window) and only applies while spike is active (tighten-only).
  const ddosWin = Math.max(cfg.per_ip_window_s, 1);
  const normalCapWindow = cfg.per_ip_limit;
  const spikeCapWindow = Math.min(cfg.per_ip_limit, cfg.tightened_per_ip_rps * ddosWin);
  const spikeNow = !hotDisabled && data.spike_active;
  const activeCapWindow = spikeNow ? spikeCapWindow : normalCapWindow;
  const activeCapRps = activeCapWindow / ddosWin;
  const spikeCapRps = spikeCapWindow / ddosWin;

  return (
    <div id="ddos-card" className="card" style={{ marginBottom: 12 }}>
      <window.SectionHeader
        title="5. DDoS Gate"
        sub="Per-IP sliding-window burst gate + EWMA spike mode — returns 403 + X-WAF-Action: block on burst-exceed (auto-blocks IP for block_ttl_s). Intentionally keyed by TCP peer IP, NOT the composite RiskKey — a flooding source can't escape by rotating session cookies."
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

        {/* Behavior callout — the mental model operators trip over: this gate
            QUARANTINES the whole IP on trip, it does not throttle per request. */}
        <div style={{
          display: 'flex', flexDirection: 'column', gap: 8,
          padding: '12px 14px', marginBottom: 16, borderRadius: 6,
          background: 'var(--surface-2)', borderLeft: '3px solid var(--brand-yellow)',
        }}>
          <div style={{ fontSize: 12, color: 'var(--ink)', lineHeight: 1.55 }}>
            <strong>Trip &amp; quarantine — not a per-request throttle.</strong> When a single IP
            sends more than its cap within the rolling <code>{cfg.per_ip_window_s}s</code> window, that
            <strong> whole IP is blocked with 403 for {cfg.block_ttl_s}s</strong>. Every request after the
            trip is dropped until the timer expires — even slow ones. It does <em>not</em> reject only the
            one overflow request, so a flood that trips the gate shows up as <em>all</em> of its requests
            blocked, not just the excess.
          </div>
          <div style={{
            display: 'flex', alignItems: 'baseline', gap: 8, flexWrap: 'wrap',
            paddingTop: 8, borderTop: '1px solid var(--border)',
          }}>
            <span style={{ fontSize: 10, color: 'var(--ink-dim)', textTransform: 'uppercase', letterSpacing: 0.5 }}>
              Active cap right now
            </span>
            {hotDisabled ? (
              <span style={{ fontSize: 13, fontWeight: 600, color: 'var(--ink-dim)' }}>
                gate disabled — no IP is blocked
              </span>
            ) : (
              <span style={{ fontSize: 13, color: 'var(--ink)' }}>
                <strong style={{ color: spikeNow ? 'var(--down)' : 'var(--up)' }}>
                  {activeCapWindow.toLocaleString()} req / {cfg.per_ip_window_s}s
                </strong>
                <span style={{ color: 'var(--ink-faint)' }}> ({activeCapRps.toFixed(1)}/s) </span>
                per IP before block
                <span style={{
                  marginLeft: 8, fontSize: 11, padding: '1px 7px', borderRadius: 4,
                  background: spikeNow ? 'rgba(246,70,93,0.14)' : 'rgba(14,203,129,0.14)',
                  color: spikeNow ? 'var(--down)' : 'var(--up)', fontWeight: 600,
                }}>
                  {spikeNow ? 'spike cap active' : 'normal cap'}
                </span>
              </span>
            )}
          </div>
          {!hotDisabled && !spikeNow && (
            <div style={{ fontSize: 11, color: 'var(--ink-faint)' }}>
              If a traffic spike engages, this tightens to <strong>{spikeCapWindow.toLocaleString()} req / {cfg.per_ip_window_s}s</strong> ({spikeCapRps.toFixed(1)}/s) per IP.
            </div>
          )}
        </div>

        {/* Live telemetry — current/baseline RPS + spike threshold */}
        <div style={{ fontSize: 10, color: 'var(--ink-dim)', textTransform: 'uppercase', letterSpacing: 0.5, marginBottom: 6 }}>
          Live Telemetry
          {hotDisabled && (
            <span style={{ marginLeft: 8, fontSize: 10, fontWeight: 400, color: 'var(--ink-faint)', textTransform: 'none', letterSpacing: 0 }}>
              (frozen — gate disabled)
            </span>
          )}
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 12, marginBottom: 16, opacity: hotDisabled ? 0.55 : 1 }}>
          <div style={{ padding: 12, background: 'var(--surface-2)', borderRadius: 4 }}>
            <div style={{ fontSize: 10, color: 'var(--ink-dim)', textTransform: 'uppercase', letterSpacing: 0.5 }}>Current RPS</div>
            <div style={{ fontSize: 24, fontWeight: 700, marginTop: 4 }}>{hotDisabled ? '—' : data.current_rps}</div>
            <div style={{ fontSize: 10, color: 'var(--ink-faint)', marginTop: 2 }}>
              {cfg.spike_scope === 'fleet'
                ? <>node window · fleet <strong>{hotDisabled ? '—' : data.fleet_rps}</strong> rps</>
                : 'this 1-second window'}
            </div>
          </div>
          <div style={{ padding: 12, background: 'var(--surface-2)', borderRadius: 4 }}>
            <div style={{ fontSize: 10, color: 'var(--ink-dim)', textTransform: 'uppercase', letterSpacing: 0.5 }}>Baseline RPS</div>
            <div style={{ fontSize: 24, fontWeight: 700, marginTop: 4 }}>{hotDisabled ? '—' : data.baseline_rps}</div>
            <div style={{ fontSize: 10, color: 'var(--ink-faint)', marginTop: 2 }}>EWMA, 0.9 / 0.1 weights</div>
          </div>
          <div style={{ padding: 12, background: 'var(--surface-2)', borderRadius: 4 }}>
            <div style={{ fontSize: 10, color: 'var(--ink-dim)', textTransform: 'uppercase', letterSpacing: 0.5 }}>Spike Threshold</div>
            <div style={{ fontSize: 24, fontWeight: 700, marginTop: 4 }}>
              {hotDisabled ? '—' : Math.round(data.baseline_rps * cfg.spike_multiplier)}
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
            <div style={{ fontSize: 10, color: 'var(--ink-faint)' }}>trip ceiling / IP / window (normal)</div>
          </div>
          <div style={{ padding: 8, background: 'var(--surface-2)', borderRadius: 4 }}>
            <div style={{ fontSize: 10, color: 'var(--ink-dim)' }}>per_ip_window_s</div>
            <div style={{ fontSize: 16, fontWeight: 600, fontFamily: 'monospace' }}>{cfg.per_ip_window_s}s</div>
            <div style={{ fontSize: 10, color: 'var(--ink-faint)' }}>sliding window</div>
          </div>
          <div style={{ padding: 8, background: 'var(--surface-2)', borderRadius: 4 }}>
            <div style={{ fontSize: 10, color: 'var(--ink-dim)' }}>block_ttl_s</div>
            <div style={{ fontSize: 16, fontWeight: 600, fontFamily: 'monospace' }}>{cfg.block_ttl_s}s</div>
            <div style={{ fontSize: 10, color: 'var(--ink-faint)' }}>IP fully blocked after a trip</div>
          </div>
          <div style={{ padding: 8, background: 'var(--surface-2)', borderRadius: 4 }}>
            <div style={{ fontSize: 10, color: 'var(--ink-dim)' }}>spike_multiplier</div>
            <div style={{ fontSize: 16, fontWeight: 600, fontFamily: 'monospace' }}>{cfg.spike_multiplier}×</div>
            <div style={{ fontSize: 10, color: 'var(--ink-faint)' }}>spike trigger</div>
          </div>
          <div style={{ padding: 8, background: 'var(--surface-2)', borderRadius: 4 }}>
            <div style={{ fontSize: 10, color: 'var(--ink-dim)' }}>tightened_per_ip_rps</div>
            <div style={{ fontSize: 16, fontWeight: 600, fontFamily: 'monospace' }}>{cfg.tightened_per_ip_rps}/s</div>
            <div style={{ fontSize: 10, color: 'var(--ink-faint)' }}>spike trip ceiling = {spikeCapWindow.toLocaleString()}/window</div>
          </div>
          <div style={{ padding: 8, background: 'var(--surface-2)', borderRadius: 4 }}>
            <div style={{ fontSize: 10, color: 'var(--ink-dim)' }}>spike_engage_ticks</div>
            <div style={{ fontSize: 16, fontWeight: 600, fontFamily: 'monospace' }}>{cfg.spike_engage_ticks}</div>
            <div style={{ fontSize: 10, color: 'var(--ink-faint)' }}>ticks to engage (~{cfg.spike_engage_ticks}s)</div>
          </div>
          <div style={{ padding: 8, background: 'var(--surface-2)', borderRadius: 4 }}>
            <div style={{ fontSize: 10, color: 'var(--ink-dim)' }}>spike_release_ticks</div>
            <div style={{ fontSize: 16, fontWeight: 600, fontFamily: 'monospace' }}>{cfg.spike_release_ticks}</div>
            <div style={{ fontSize: 10, color: 'var(--ink-faint)' }}>ticks to release (~{cfg.spike_release_ticks}s)</div>
          </div>
          <div style={{ padding: 8, background: 'var(--surface-2)', borderRadius: 4 }}>
            <div style={{ fontSize: 10, color: 'var(--ink-dim)' }}>spike_scope</div>
            <div style={{ fontSize: 16, fontWeight: 600, fontFamily: 'monospace' }}>{cfg.spike_scope || 'per_node'}</div>
            <div style={{ fontSize: 10, color: 'var(--ink-faint)' }}>{cfg.spike_scope === 'fleet' ? 'fleet-wide RPS signal' : 'this node only'}</div>
          </div>
          <div style={{ padding: 8, background: 'var(--surface-2)', borderRadius: 4 }}>
            <div style={{ fontSize: 10, color: 'var(--ink-dim)' }}>normal trip rate</div>
            <div style={{ fontSize: 16, fontWeight: 600, fontFamily: 'monospace' }}>
              {(cfg.per_ip_limit / ddosWin).toFixed(1)}/s
            </div>
            <div style={{ fontSize: 10, color: 'var(--ink-faint)' }}>per IP · {spikeCapRps.toFixed(1)}/s during spike</div>
          </div>
        </div>

      </div>
      <GateExplain
        rows={[
          ['The model', <span key="m"><strong>Trip → quarantine.</strong> This is NOT a per-request throttle (that's the Rate Limit gate, #4, which 429s the excess). Here, the moment an IP's request count crosses its cap inside the window, the <strong>entire IP</strong> is auto-blocked for <code>block_ttl_s</code> — every later request is 403'd until the timer expires.</span>],
          ['How it fires', <span key="f">A per-IP sliding-window counter holds the last <code>per_ip_window_s</code> seconds of requests. When that count reaches the cap (<strong>per_ip_limit</strong> normally; the tightened cap during a spike), the IP is added to the auto-block keyspace. The breaching request itself is the first 403.</span>],
          ['Worked example', <span key="ex">With <code>per_ip_window_s={cfg.per_ip_window_s}</code> and the {spikeNow ? 'spike' : 'normal'} cap of <strong>{activeCapWindow.toLocaleString()} req/window</strong>: an IP sending {(activeCapRps + 1).toFixed(0)}/s reaches {activeCapWindow.toLocaleString()} part-way through the window, trips, and is then 403'd for the remaining {cfg.block_ttl_s}s — so you'd see roughly <em>all</em> of its traffic blocked, not one request.</span>],
          ['Spike tighten', <span key="st">EWMA spike mode watches overall RPS. When it exceeds <strong>spike_multiplier × baseline</strong> the per-IP cap drops from {normalCapWindow.toLocaleString()} to <strong>{spikeCapWindow.toLocaleString()} req/window</strong> (tighten-only). Hysteresis: engages after <code>spike_engage_ticks</code> over-threshold ticks, releases after <code>spike_release_ticks</code> under-threshold ticks — a brief blip never throttles everyone.</span>],
          ['Response', '403 + ', <code key="rc">X-WAF-Action: block</code>, ' + ', <code key="rid">X-WAF-Rule-Id: ddos</code>, '. Keyed by TCP peer IP, not the RiskKey — rotating cookies can\'t dodge it.'],
          ['Recovery', <span key="r"><strong>TTL'd</strong> — the IP is rejected for <code>block_ttl_s</code> ({cfg.block_ttl_s}s), then automatically allowed again. To watch a trip release fast while testing, set <code>block_ttl_s</code> low.</span>],
          ['Tunable', <span key="t">Edit modal on this card. Audit-mutated <code>PUT /api/gates/ddos</code>; the per-IP window state is preserved across edits.</span>],
          ['When to use', '"Sustained-burst quarantine" — DDoS-grade protection. For "API rate fairness" (serve up to a cap, 429 the rest) use Rate Limit (#4) instead; the two are complementary.'],
        ]}
      />
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
  const [engageTicks, setEngageTicks] = useStateP(current?.spike_engage_ticks ?? 2);
  const [releaseTicks, setReleaseTicks] = useStateP(current?.spike_release_ticks ?? 8);
  // Fleet RPS aggregation P3 — spike scope. Seeded from the live config so a
  // save round-trips it (the PUT defaults an omitted scope to per_node, which
  // would clobber a YAML `fleet`).
  const [spikeScope, setSpikeScope] = useStateP(current?.spike_scope ?? 'per_node');
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
          spike_engage_ticks: parseInt(engageTicks, 10),
          spike_release_ticks: parseInt(releaseTicks, 10),
          spike_scope: spikeScope,
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
              <div style={{ fontSize: 10, color: 'var(--ink-faint)', marginTop: 2 }}>spike trigger (× baseline RPS), {'>'} 1.0</div>
            </label>
            <label style={{ fontSize: 12, gridColumn: 'span 2' }}>
              tightened_per_ip_rps
              <input className="input" type="number" min="1" value={tightenedRps}
                onChange={e => setTightenedRps(e.target.value)} disabled={busy}
                style={{ marginTop: 4, width: '100%' }} />
              <div style={{ fontSize: 10, color: 'var(--ink-faint)', marginTop: 2 }}>per-IP cap during spike (= {(parseInt(tightenedRps, 10) || 0) * (parseInt(perIpWindowS, 10) || 1)} req/window when spike-active)</div>
            </label>
            <label style={{ fontSize: 12 }}>
              spike_engage_ticks
              <input className="input" type="number" min="1" value={engageTicks}
                onChange={e => setEngageTicks(e.target.value)} disabled={busy}
                style={{ marginTop: 4, width: '100%' }} />
              <div style={{ fontSize: 10, color: 'var(--ink-faint)', marginTop: 2 }}>consecutive over-threshold ticks (~1s each) before spike engages</div>
            </label>
            <label style={{ fontSize: 12 }}>
              spike_release_ticks
              <input className="input" type="number" min="1" value={releaseTicks}
                onChange={e => setReleaseTicks(e.target.value)} disabled={busy}
                style={{ marginTop: 4, width: '100%' }} />
              <div style={{ fontSize: 10, color: 'var(--ink-faint)', marginTop: 2 }}>consecutive under-threshold ticks before spike releases (anti-flap)</div>
            </label>
            <label style={{ fontSize: 12 }}>
              spike_scope
              <select className="input" value={spikeScope}
                onChange={e => setSpikeScope(e.target.value)} disabled={busy}
                style={{ marginTop: 4, width: '100%' }}>
                <option value="per_node">per_node</option>
                <option value="fleet">fleet</option>
              </select>
              <div style={{ fontSize: 10, color: 'var(--ink-faint)', marginTop: 2 }}>per_node = this node's RPS; fleet = sum across the cluster (needs a shared state backend)</div>
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

  // 2026-05-19 — Configuration backup. Hits the new
  // /api/config/backup.yaml endpoint which streams the
  // source-of-truth waf.yaml byte-for-byte. Different shape from
  // the Compliance snapshot above: this is a drop-in replacement
  // for the host's waf.yaml (operators clone it to a new node
  // and the config-watcher reloads in place); Compliance snapshot
  // is a forensic JSON bundle including live mask state.
  async function downloadConfigBackup() {
    setBusyId('config-backup');
    try {
      const r = await fetch('/api/config/backup.yaml', { credentials: 'same-origin' });
      if (r.status === 404) {
        const body = await r.json().catch(() => ({}));
        window.aegisToast(
          body.message
            || 'WAF booted from a non-file config source — no waf.yaml to back up',
          'warn',
        );
        return;
      }
      if (!r.ok) throw new Error(`status ${r.status}`);
      const blob = await r.blob();
      downloadBlob(`aegis-config-${ts()}.yaml`, blob);
      window.aegisToast('Configuration backup downloaded', 'ok');
    } catch (err) {
      window.aegisToast(`Configuration backup failed: ${err.message || err}`, 'err');
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
    // LOW-ADM-02 (2026-05-12) — the audit ring is capped at 200
    // events, so `?limit=1000` returns the same payload as
    // `?limit=200`. Collapse to a single honest card; a wider
    // export will land when cold-tier streaming ships.
    {
      id: 'audit-ring',
      title: 'Audit trail (full ring · last 200 events)',
      sub: 'CSV of every chained event — request decisions + config mutations. Ring is capped at 200 in this build; wider exports require cold-tier streaming (deferred).',
      kind: 'href',
      href: '/api/reports/audit.csv?limit=200',
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
      sub: 'Active runtime config + detector mask, JSON snapshot — sourced from /api/config + /api/detectors. Forensic / audit-attestation use.',
      kind: 'click',
      onClick: downloadComplianceSnapshot,
      label: 'Download JSON',
    },
    // 2026-05-19 — drop-in waf.yaml backup. Different shape from
    // Compliance snapshot: this is the source-of-truth file
    // suitable for cloning to a new node. Secret refs preserved
    // as-is (${secret:env:…}, ${secret:file:…}) — no plaintext
    // credentials are emitted.
    {
      id: 'config-backup',
      title: 'Configuration backup (YAML)',
      sub: 'Drop-in replacement for waf.yaml — clone the LIVE runtime state to a new node. Reflects dashboard PUTs: AI enabled, detector mask (base + per-tier), DDoS knobs. Secret references (${secret:*}) preserved as-is.',
      kind: 'click',
      onClick: downloadConfigBackup,
      label: 'Download YAML',
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
        {/* `align-items: stretch` (grid default) makes every card fill the row
            height; each card is a flex column so the download button anchors to
            the bottom (`margin-top: auto`) → buttons align across cards even
            though the descriptions differ in length. */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(260px, 1fr))', gap: 12 }}>
          {cards.map(card => {
            // Shared button styling so the href (CSV) and click variants render
            // identically and sit flush at the card bottom, full-width.
            const btnStyle = {
              marginTop: 'auto',
              width: '100%',
              justifyContent: 'center',
              textDecoration: 'none',
            };
            return (
              <div
                key={card.id}
                className="card"
                style={{ padding: 12, display: 'flex', flexDirection: 'column' }}
              >
                <div style={{ fontSize: 13, fontWeight: 600 }}>{card.title}</div>
                <div style={{ fontSize: 11, color: 'var(--ink-dim)', margin: '4px 0 12px', lineHeight: 1.5 }}>{card.sub}</div>
                {card.kind === 'href' ? (
                  <a className="btn primary" href={card.href} download style={btnStyle}>
                    <window.I.Download /> {card.label || 'Download CSV'}
                  </a>
                ) : (
                  <button
                    className="btn primary"
                    onClick={card.onClick}
                    disabled={busyId === card.id}
                    style={btnStyle}
                  >
                    <window.I.Download /> {busyId === card.id ? 'Preparing…' : (card.label || 'Download')}
                  </button>
                )}
              </div>
            );
          })}
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
  // SCOPE-P1a — both views are fleet-merged when fleet view is active
  // (Identifier always; Composite RiskKey display-only since the risk
  // fleet-merge — note reset stays node-scoped).
  const scopeBadge = window.useScopeBadge ? window.useScopeBadge() : () => null;
  // 2026-05-19 — two view modes share the same page so operators
  // have one mental model for "who's worth investigating". The
  // legacy `identifier` view consumes /api/attacks/top
  // (AttacksAggregator, keyed by IP / fp:<ja4> / etc.); the new
  // `riskkey` view consumes /api/risk (RiskTracker per-bucket
  // scores, one row per composite RiskKey). Deep-link via
  // `#/top-attackers?view=riskkey`.
  const [view, setView] = useStateP(() => {
    try {
      const q = (location.hash.split('?')[1] || '').split('&');
      const v = q.find(s => s.startsWith('view='));
      if (v && v.slice(5) === 'riskkey') return 'riskkey';
    } catch (_) { /* ignore */ }
    return 'identifier';
  });
  const windowSeconds = TOP_ATTACKERS_WINDOWS[win] ?? 3600;
  const top = window.useApi
    ? window.useApi(
        `/api/attacks/top?window=${windowSeconds}&limit=50`,
        { intervalMs: 5000, fallback: null },
      )
    : { data: null };
  const risk = window.useApiScoped
    ? window.useApiScoped(
        '/api/risk?limit=50',
        { intervalMs: 5000, fallback: null },
      )
    : { data: null };
  const attackers = top.data?.attackers ?? [];
  const buckets = risk.data?.clients ?? [];
  const geoLoaded = top.data?.geoip_loaded === true;
  const [busyId, setBusyId] = useStateP(null);
  const [collapseByIp, setCollapseByIp] = useStateP(false);
  const [resetBusy, setResetBusy] = useStateP(null);

  // Keep the URL in sync with the active view so a refresh or
  // bookmark survives the choice. Only touches the query portion
  // of the route hash; the path stays /top-attackers.
  useEffectP(() => {
    const target = view === 'riskkey' ? '?view=riskkey' : '';
    const cur = location.hash || '#/top-attackers';
    const [pathPart] = cur.split('?');
    const next = `${pathPart}${target}`;
    if (cur !== next) {
      history.replaceState(null, '', next);
    }
  }, [view]);

  async function surgicalReset(row) {
    const id = `${row.ip}|${row.device_fp ?? ''}|${row.session ?? ''}`;
    setResetBusy(id);
    try {
      // 2026-05-19 — uses `window.csrfMutate` (the dashboard's
      // standard helper from data.jsx) so the request carries the
      // CSRF cookie + header pair the admin gate validates. The
      // earlier raw-fetch + `window.getCsrfToken` shape silently
      // 403'd every reset (the helper doesn't exist), making the
      // button decorative; a tester-skill functional test caught
      // that before merge.
      const r = await window.csrfMutate('/api/risk/reset_key', {
        method: 'POST',
        body: JSON.stringify({
          ip: row.ip,
          device_fp: row.device_fp ?? null,
          session: row.session ?? null,
        }),
      });
      // csrfMutate returns `{status, ...body}` — not a Response.
      if (r.status >= 200 && r.status < 300 && r.ok !== false) {
        window.aegisToast(`Reset bucket ${id}`, 'ok');
        risk.reload && risk.reload();
      } else {
        window.aegisToast(
          `Reset failed: ${r.message || r.reason || `status ${r.status}`}`,
          'err',
        );
      }
    } catch (e) {
      window.aegisToast(`Reset error: ${e.message || e}`, 'err');
    } finally {
      setResetBusy(null);
    }
  }

  // RiskKey-view "Group by IP" — collapses composite rows
  // sharing an IP into one summary row. Useful when an operator
  // just wants the legacy IP-keyed read of the same data.
  const groupedBuckets = collapseByIp
    ? Object.values(
        buckets.reduce((acc, row) => {
          if (!acc[row.ip]) {
            acc[row.ip] = {
              ip: row.ip,
              device_fp: null,
              session: null,
              score: 0,
              strikes: 0,
              idle_seconds: row.idle_seconds,
              level: row.level,
              strike_blocked: row.strike_blocked,
              _bucket_count: 0,
            };
          }
          const g = acc[row.ip];
          g.score = Math.max(g.score, row.score || 0);
          g.strikes = Math.max(g.strikes, row.strikes || 0);
          g.idle_seconds = Math.min(g.idle_seconds, row.idle_seconds);
          if (row.level === 'block' || g.level !== 'block') g.level = row.level;
          if (row.strike_blocked) g.strike_blocked = true;
          g._bucket_count += 1;
          return acc;
        }, {}),
      )
    : buckets;

  async function blockAttacker(identifier) {
    if (!identifier) return;
    if (!confirm(`Block ${identifier}? Adds to /api/blacklist · audit-chained.`)) return;
    setBusyId(identifier);
    try {
      const id = `top-attacker-${identifier.replace(/[^A-Za-z0-9]+/g, '-')}-${Date.now().toString(36)}`;
      // HIGH-SO-01 (2026-05-12) — include `bypass: []` so the
      // server's AccessListEntry deserializer accepts the body.
      // Without this the POST 400s with `missing field bypass`
      // and the entire SOC "block this attacker" workflow is
      // broken end-to-end. The server-side belt
      // (`#[serde(default)]` on the field) ships in the same PR
      // so future callers can't trip the same wire.
      const created_at = new Date().toISOString();
      const body = identifier.startsWith('fp:')
        ? { id, kind: 'fingerprint', value: identifier, note: `blocked from Top Attackers · last 1h`, bypass: [], created_at }
        : { id, kind: identifier.includes('/') ? 'cidr' : 'ip', value: identifier, note: `blocked from Top Attackers · last 1h`, bypass: [], created_at };
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
      <SecOpsPostureCard />
      <div className="page-head">
        <div>
          <h1 className="page-title">
            Top Attackers
            <window.PageTitleRefresh
              onClick={() => {
                if (view === 'riskkey') risk.reload && risk.reload();
                else top.reload && top.reload();
              }}
              label="Refresh top attackers"
            />
            <span style={{ marginLeft: 8 }}>{scopeBadge(true)}</span>
          </h1>
          <p className="page-subtitle">
            {view === 'identifier' ? (
              <>
                Ranked by hits in the last {win} · pivot or block in one click
                {geoLoaded ? '' : ' · GeoIP DB not loaded — country / ASN columns will be empty until make geoip-link runs'}
              </>
            ) : (
              <>
                One row per composite RiskKey ({'{'}IP, device_fp, session{'}'}) · live from <code>/api/risk</code>
                {' '}· surgical reset wipes exactly one bucket
              </>
            )}
          </p>
        </div>
        <div className="page-actions" style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
          {/* 2026-05-19 — view toggle. Identifier view consumes
              the AttacksAggregator (keyed by IP / fp:<ja4>); the
              Composite RiskKey view consumes the RiskTracker
              top-N. Deep-linkable via ?view=riskkey. */}
          <div role="tablist" style={{ display: 'inline-flex', border: '1px solid var(--hairline)', borderRadius: 6, overflow: 'hidden' }}>
            <button
              role="tab"
              aria-selected={view === 'identifier'}
              className="btn btn-sm"
              onClick={() => setView('identifier')}
              style={{
                background: view === 'identifier' ? 'var(--surface-2)' : 'transparent',
                color: view === 'identifier' ? 'var(--ink)' : 'var(--ink-dim)',
                border: 'none',
                borderRadius: 0,
                fontWeight: view === 'identifier' ? 600 : 400,
              }}
              title="AttacksAggregator — one row per IP / fp:<ja4> with hits, country, ASN, blocking detectors"
            >
              Identifier view
            </button>
            <button
              role="tab"
              aria-selected={view === 'riskkey'}
              className="btn btn-sm"
              onClick={() => setView('riskkey')}
              style={{
                background: view === 'riskkey' ? 'var(--surface-2)' : 'transparent',
                color: view === 'riskkey' ? 'var(--ink)' : 'var(--ink-dim)',
                border: 'none',
                borderRadius: 0,
                fontWeight: view === 'riskkey' ? 600 : 400,
              }}
              title="RiskTracker — one row per composite RiskKey {ip, device_fp?, session?} with score, strikes, level"
            >
              Composite RiskKey view
            </button>
          </div>
          {view === 'identifier' && (
            <select
              className="input select"
              value={win}
              onChange={e => setWin(e.target.value)}
              style={{ width: 90 }}
              title="Time window (Identifier view only — RiskKey view is always live)"
            >
              {Object.keys(TOP_ATTACKERS_WINDOWS).map(v => <option key={v}>{v}</option>)}
            </select>
          )}
        </div>
      </div>

      {view === 'identifier' ? (
        /* Identifier view (legacy) — AttacksAggregator: one row
           per IP / fp:<ja4> ranked by hits in the time window.
           Same shape and copy as before this refactor. */
        attackers.length === 0 ? (
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
                        // LOW-SO-03 (2026-05-12) — explicit onClick
                        // anchors the navigation even when an ancestor
                        // event handler tries to preventDefault on
                        // bubbling clicks. Matches the row's Pivot
                        // button so the underlined identifier is a
                        // shortcut to the same place.
                        <a
                          href={`#/investigation?pivot=${encodeURIComponent(a.identifier)}&kind=ip`}
                          onClick={(e) => {
                            e.preventDefault();
                            location.hash = `/investigation?pivot=${encodeURIComponent(a.identifier)}&kind=ip`;
                          }}
                          style={{ color: 'var(--accent)', cursor: 'pointer' }}
                          title={`Pivot Investigation on ${a.identifier}`}
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
      )
      ) : (
        /* 2026-05-19 — Composite RiskKey view. Reads /api/risk
           (RiskTracker top-N). One row per
           {ip, device_fp?, session?} bucket; per-row surgical
           reset wipes exactly one bucket. */
        <div className="card" style={{ padding: 16 }}>
          <div style={{ display: 'flex', gap: 12, alignItems: 'center', marginBottom: 12 }}>
            <label style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 11, cursor: 'pointer' }}>
              <input
                type="checkbox"
                checked={collapseByIp}
                onChange={e => setCollapseByIp(e.target.checked)}
              />
              <span>Group by IP</span>
              <span style={{ color: 'var(--ink-dim)' }}>
                (collapses composite-key rows into one summary row per IP)
              </span>
            </label>
            <div style={{ flex: 1 }} />
            <span style={{ fontSize: 11, color: 'var(--ink-dim)' }}>
              {buckets.length} bucket{buckets.length === 1 ? '' : 's'}
            </span>
          </div>
          {buckets.length === 0 ? (
            <div style={{ padding: 12, fontSize: 12, color: 'var(--ink-dim)', textAlign: 'center' }}>
              {risk.data === null
                ? 'Loading risk buckets…'
                : 'No tracked clients yet — drive some traffic to populate the table.'}
            </div>
          ) : (
            <table className="tbl tbl-compact">
              <thead>
                <tr>
                  <th style={{ width: 140 }}>IP</th>
                  <th style={{ width: 110 }}>device_fp</th>
                  <th style={{ width: 110 }}>session</th>
                  <th style={{ width: 60 }}>Score</th>
                  <th style={{ width: 70 }}>Strikes</th>
                  <th style={{ width: 80 }}>Level</th>
                  <th style={{ width: 90 }}>Idle</th>
                  <th style={{ width: 130 }}></th>
                </tr>
              </thead>
              <tbody>
                {groupedBuckets.map((row, i) => {
                  const id = `${row.ip}|${row.device_fp ?? ''}|${row.session ?? ''}`;
                  const levelColour =
                    row.level === 'block' ? 'var(--down)'
                    : row.level === 'challenge' ? 'var(--warn)'
                    : 'var(--ink-dim)';
                  const dfShort = row.device_fp ? row.device_fp.slice(0, 8) : null;
                  const sessShort = row.session ? row.session.slice(0, 8) : null;
                  return (
                    <tr key={`${id}-${i}`}>
                      <td className="mono">
                        <a
                          href={`#/investigation?pivot=${encodeURIComponent(row.ip)}&kind=ip`}
                          onClick={(e) => {
                            e.preventDefault();
                            location.hash = `/investigation?pivot=${encodeURIComponent(row.ip)}&kind=ip`;
                          }}
                          style={{ color: 'var(--accent)', cursor: 'pointer' }}
                          title={`Pivot Investigation on ${row.ip}`}
                        >{row.ip}</a>
                      </td>
                      <td
                        className="mono dim"
                        title={row.device_fp || 'no TLS fingerprint (plain HTTP)'}
                      >
                        {dfShort ? `${dfShort}…` : <span style={{ opacity: 0.5 }}>—</span>}
                      </td>
                      <td
                        className="mono dim"
                        title={row.session || 'no session cookie'}
                      >
                        {sessShort ? `${sessShort}…` : <span style={{ opacity: 0.5 }}>—</span>}
                      </td>
                      <td className="num">{row.score}</td>
                      <td className="num">{row.strikes}</td>
                      <td>
                        <span
                          className="pill"
                          style={{ color: levelColour, border: `1px solid ${levelColour}` }}
                        >
                          {row.strike_blocked ? '🔒 ' : ''}
                          {row.level}
                        </span>
                      </td>
                      <td className="dim">{row.idle_seconds}s</td>
                      <td>
                        {collapseByIp ? (
                          <span style={{ fontSize: 10, color: 'var(--ink-faint)' }}>
                            {row._bucket_count} bucket{row._bucket_count === 1 ? '' : 's'}
                          </span>
                        ) : (
                          <button
                            className="btn btn-sm"
                            onClick={() => surgicalReset(row)}
                            disabled={resetBusy === id}
                            title="POST /api/risk/reset_key — wipes exactly this composite-key bucket; siblings on the same IP keep their state."
                          >
                            {resetBusy === id ? '…' : 'Reset bucket'}
                          </button>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
          <div style={{ fontSize: 10, color: 'var(--ink-faint)', marginTop: 8 }}>
            IP-only reset (wipe every bucket sharing an IP) still
            available via <code>PUT /api/risk/&lt;ip&gt;/reset</code>;
            this view uses the <code>POST /api/risk/reset_key</code>{' '}
            surgical variant.
          </div>
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
// routing-upstream #1 (2026-06-04) — live member health helpers. The
// /api/upstreams summary carries per-pool { healthy, total,
// members:[{addr,healthy,status}], circuit } (api/upstreams.rs). These
// render that as dots / chips / a circuit badge.
//
// 2026-06-18 (upstream "up" badge report) — members now carry a tri-state
// `status` (up/down/unknown). `unknown` = no health signal yet (a pool with
// no `health:` block before its TCP probe runs), shown grey as "unverified"
// rather than a false green "up". A member with an active health check or a
// completed TCP probe shows the verified up/down.
const HEALTH_COLOR = { ok: 'var(--up)', warn: '#d6a700', down: 'var(--down)', unknown: 'var(--ink-dim)' };

// Normalise a member entry to a tri-state status string, tolerating older
// snapshots that only carried the `healthy` boolean.
function memberStatus(m) {
  if (m && (m.status === 'up' || m.status === 'down' || m.status === 'unknown')) return m.status;
  if (m && typeof m.healthy === 'boolean') return m.healthy ? 'up' : 'down';
  return 'unknown';
}

function MemberDot({ status }) {
  const s = status || 'unknown';
  const color = s === 'up' ? HEALTH_COLOR.ok : s === 'down' ? HEALTH_COLOR.down : HEALTH_COLOR.unknown;
  const title = s === 'up' ? 'reachable (passing active health check or TCP probe)'
    : s === 'down' ? 'unreachable / failing'
    : 'not health-checked yet — status unverified';
  return (
    <span
      title={title}
      style={{
        display: 'inline-block', width: 8, height: 8, borderRadius: '50%',
        background: color, marginRight: 6, verticalAlign: 'middle',
      }}
    />
  );
}

function PoolHealthChip({ h }) {
  if (!h || typeof h.total !== 'number') return null;
  // Prefer per-member tri-state when the snapshot carries it; fall back to
  // the legacy healthy/total counts for older payloads.
  const members = Array.isArray(h.members) && h.members.length ? h.members : null;
  let up, down, unknown;
  if (members) {
    const statuses = members.map(memberStatus);
    up = statuses.filter(s => s === 'up').length;
    down = statuses.filter(s => s === 'down').length;
    unknown = statuses.filter(s => s === 'unknown').length;
  } else {
    up = h.healthy; down = Math.max(h.total - h.healthy, 0); unknown = 0;
  }
  // Tone: any down -> warn (some up) or down (none up); else all-unknown
  // -> unknown; else ok.
  const tone = down > 0 ? (up > 0 ? 'warn' : 'down')
    : (unknown > 0 && up === 0) ? 'unknown'
    : 'ok';
  const label = (unknown > 0 && up === 0 && down === 0)
    ? `${h.total} unverified`
    : `${up}/${h.total} up${unknown > 0 ? ` · ${unknown} unverified` : ''}`;
  return (
    <span
      title='live member health — verified by an active health check or TCP probe; "unverified" means no health signal yet (e.g. a pool with no health: block before its first probe)'
      style={{
        display: 'inline-flex', alignItems: 'center', fontSize: 10,
        padding: '1px 6px', borderRadius: 10, marginLeft: 6,
        border: '1px solid var(--hairline)', color: HEALTH_COLOR[tone],
      }}
    >
      <span style={{
        display: 'inline-block', width: 7, height: 7, borderRadius: '50%',
        background: HEALTH_COLOR[tone], marginRight: 5,
      }} />
      {label}
    </span>
  );
}

function CircuitBadge({ state }) {
  if (!state || state === 'closed') return null;
  const tone = state === 'open' ? 'down' : 'warn';
  return (
    <span
      title={`circuit breaker ${state}`}
      style={{
        fontSize: 9, marginLeft: 6, padding: '0 6px', borderRadius: 10,
        border: `1px solid ${HEALTH_COLOR[tone]}`, color: HEALTH_COLOR[tone],
      }}
    >
      ⚡ {state === 'half_open' ? 'half-open' : 'open'}
    </span>
  );
}

// Look up a member's live status within a pool summary entry (matched by
// addr). Returns a tri-state 'up' | 'down' | 'unknown', or undefined when
// the summary has no per-member detail (e.g. the static fallback provider)
// — the UI then shows no dot.
function memberHealth(h, addr) {
  if (!h || !Array.isArray(h.members)) return undefined;
  const m = h.members.find(x => x.addr === addr);
  return m ? memberStatus(m) : undefined;
}

// routing-upstream #3 — route priority + shadow detection. Compare the
// `<host>.<path-kind>.<segs>.<method>.<declared>.<yaml-pos>` priority
// tuple numerically (component-wise), highest first = evaluated first.
function cmpPriorityDesc(a, b) {
  const pa = (a.priority || '').split('.').map(Number);
  const pb = (b.priority || '').split('.').map(Number);
  const n = Math.max(pa.length, pb.length);
  for (let i = 0; i < n; i++) {
    const x = pa[i] || 0;
    const y = pb[i] || 0;
    if (x !== y) return y - x;
  }
  return 0;
}

// A route R is "shadowed" when a higher-priority (earlier-evaluated)
// enabled route E already matches every request R would — so R is
// unreachable. Conservative: only flags genuine coverage (catch-all,
// prefix that covers R's path at a segment boundary, or an exact
// duplicate) with a host superset + method superset. regex/glob routes
// are never treated as shadowers (can't reason about them safely).
function computeShadowMap(allRoutes) {
  const sorted = [...(allRoutes || [])].sort(cmpPriorityDesc);
  const norm = s => (s || '').trim().toLowerCase();
  const hostSuperset = (E, R) => {
    const eh = norm(E.host);
    return !eh || eh === '*' || eh === 'any' || eh === norm(R.host);
  };
  const methodSuperset = (E, R) => {
    const em = E.methods || [];
    const rm = R.methods || [];
    if (em.length === 0) return true;     // E accepts any method
    if (rm.length === 0) return false;    // R accepts any but E doesn't
    return rm.every(m => em.includes(m));
  };
  const pathCovers = (E, R) => {
    if (E.default) return true;           // catch-all for its host scope
    const ep = E.path || '/';
    const rp = R.path || '/';
    if (E.match_type === 'prefix') {
      return rp === ep || rp.startsWith(ep.endsWith('/') ? ep : ep + '/');
    }
    if (E.match_type === 'exact') {
      return R.match_type === 'exact' && rp === ep; // true duplicate
    }
    return false;                          // regex / glob — don't reason
  };
  const shadow = {};
  for (let i = 0; i < sorted.length; i++) {
    const R = sorted[i];
    if (R.enabled === false) continue;     // disabled rows are "off", not "shadowed"
    for (let j = 0; j < i; j++) {
      const E = sorted[j];
      if (E.enabled === false) continue;
      if (hostSuperset(E, R) && pathCovers(E, R) && methodSuperset(E, R)) {
        shadow[R.id] = E.id;
        break;
      }
    }
  }
  return shadow;
}

function RoutesTable({ poolNames, routesApi, pools, health, onEditPool, onDeletePool, onMutated, cfgReload, routeOverlay }) {
  // Optimistic overlay (instant route add/edit/delete): staged changes
  // show before the async config-plane apply lands; the parent reconciles
  // them away on the next post-apply reload.
  const routes = routeOverlay
    ? window.applyOverlayList(routesApi.data?.routes || [], routeOverlay.overlay, r => r.id)
    : (routesApi.data?.routes || []);
  // routing-upstream #3 — map of shadowed route id → the higher-priority
  // route that already matches its traffic (computed over ALL routes, not
  // just the filtered view).
  const shadowMap = computeShadowMap(routes);
  const [editor, setEditor] = useStateP(null);
  const [deleteModal, setDeleteModal] = useStateP(null);
  const [busy, setBusy] = useStateP(false);
  const [search, setSearch] = useStateP('');
  const [expandedRouteId, setExpandedRouteId] = useStateP(null);
  // P5 (2026-05-11) — per-route activity in last 60s. Polled every
  // 10s; the data plane increments the counter atomically on
  // every resolved route. The pill tone is derived from the
  // sample count rendered into the route table below.
  const activityApi = window.useApi
    ? window.useApi('/api/analytics/route-activity', { intervalMs: 10000, fallback: { routes: [] } })
    : { data: { routes: [] } };
  const activityMap = (() => {
    const m = {};
    for (const r of (activityApi.data?.routes || [])) {
      m[r.route] = r;
    }
    return m;
  })();
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

  // MED-02 (2026-05-11) — modal-anchored save error. The earlier
  // shape toasted save failures bottom-right while the modal
  // body kept rendering a *separate* "pool name already exists"
  // inline hint — the two surfaces could disagree (toast: catch-
  // all collision; inline: pool name collision) and the operator
  // had to read both to figure out the real cause. Now the modal
  // owns its own error block; the local hint stays purely
  // advisory.
  const [saveError, setSaveError] = useStateP(null);
  const openAdd = () => { setSaveError(null); setEditor({ mode: 'add', draft: emptyRouteDraft() }); };
  const openEdit = (route) => { setSaveError(null); setEditor({ mode: 'edit', draft: routeToDraft(route) }); };
  const closeEditor = () => { setSaveError(null); setEditor(null); };

  async function saveRoute(draft) {
    setBusy(true);
    setSaveError(null);
    try {
      // MED-RU-03 (2026-05-12) — Add Route no longer creates a
      // pool as a side-effect. The "+ Create new pool" affordance
      // in RouteEditModal opens a child PoolEditModal that writes
      // the pool independently (audit-chained) before the route
      // is submitted here, so by this point the pool already
      // exists in the live config. The previous MED-04
      // compensating-delete logic is retired along with the
      // inline-backend path; if the operator wants to clean up an
      // unused pool they use "Pools without routes" → Delete.
      const body = routeBodyFromDraft(draft);
      // Optimistic: the route row reflects the edit instantly.
      if (routeOverlay) routeOverlay.stageUpsert(draft.id, { id: draft.id, ...body });
      const before = await window.currentConfigVersion();
      const r = await window.routeUpsert(draft.id, body);
      if (r.status === 200 && r.ok) {
        window.aegisToast(`Route "${draft.id}" saved`, 'ok');
        setSaveError(null);
        setEditor(null);
        // Refresh routes + pools + health together (reloadAfterApply waits
        // for the async config-plane apply first) so no dependent view is
        // left stale until a manual refresh. Pass the doc version this
        // PUT produced so the wait keys on applied-version convergence.
        if (onMutated) await onMutated(before, r.version);
        if (routeOverlay) setTimeout(() => routeOverlay.forget(draft.id), 3000);
      } else {
        if (routeOverlay) routeOverlay.forget(draft.id);
        const msg = r.message || r.error || r.reason || `HTTP ${r.status}`;
        setSaveError(`Save failed: ${msg}`);
      }
    } catch (e) {
      if (routeOverlay) routeOverlay.forget(draft.id);
      setSaveError(`Save failed: ${e.message || e}`);
    } finally {
      setBusy(false);
    }
  }

  async function confirmDelete() {
    if (!deleteModal) return;
    const { id } = deleteModal;
    setBusy(true);
    try {
      const before = await window.currentConfigVersion();
      const r = await window.routeDelete(id);
      if (r.status === 200 && r.ok) {
        // Hide the route instantly; reconciled once the reload drops it.
        if (routeOverlay) routeOverlay.stageRemoval(id);
        window.aegisToast(`Route "${id}" removed`, 'ok');
        setDeleteModal(null);
        if (onMutated) await onMutated(before, r.version);
        if (routeOverlay) setTimeout(() => routeOverlay.forget(id), 3000);
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
                      {/* P5 (2026-05-11) — sliding-window activity
                          pulse. Green > 1 req/min, amber 0-1
                          req/min, red 0 req/min for ≥ 5 min,
                          neutral when the route has never matched
                          since boot. Tooltip carries the
                          last-request age in seconds. */}
                      {(() => {
                        const a = activityMap[r.id];
                        if (!a) {
                          return (
                            <div
                              style={{ marginTop: 4 }}
                              title="No requests have hit this route since process boot. Verify the host/path/method match the traffic you expect."
                            >
                              <span className="pill neutral" style={{ fontSize: 9, padding: '0 6px' }}>idle</span>
                            </div>
                          );
                        }
                        const cnt = a.last_60s_count || 0;
                        const ageS = a.last_seen_age_s;
                        let tone, label;
                        if (cnt > 60) { tone = 'ok'; label = `${cnt}/min`; }
                        else if (cnt > 0) { tone = 'ok'; label = `${cnt}/min`; }
                        else if (ageS != null && ageS < 300) { tone = 'warn'; label = `${Math.floor(ageS)}s ago`; }
                        else { tone = 'err'; label = ageS != null ? `${Math.floor(ageS / 60)}m ago` : 'silent'; }
                        const tip = `last 60s: ${cnt} req` + (ageS != null ? ` · last seen ${ageS}s ago` : '');
                        return (
                          <div style={{ marginTop: 4 }} title={tip}>
                            <span className={`pill ${tone}`} style={{ fontSize: 9, padding: '0 6px' }}>{label}</span>
                          </div>
                        );
                      })()}
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
                        {r.mode === 'log_only' && <span className="pill warn" style={{ marginLeft: 6, fontSize: 9, padding: '1px 6px' }} title="Monitor mode: WAF detector/risk blocks are downgraded to log-only on this route (forward + audit). Blacklist still enforces.">monitor</span>}
                        {/* routing-upstream #3 — unreachable: a higher-priority route already matches this traffic. */}
                        {r.enabled !== false && shadowMap[r.id] && (
                          <span
                            className="pill err"
                            style={{ marginLeft: 6, fontSize: 9, padding: '1px 6px' }}
                            title={`Unreachable: the higher-priority route "${shadowMap[r.id]}" already matches every request this route would. Re-scope the host/path/method or remove the duplicate.`}
                          >⚠ shadowed</span>
                        )}
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
                          ? <>{r.upstream}{' '}<span style={{ color: 'var(--ink-dim)', fontSize: 11 }}>({scheme} · {members.length} member{members.length === 1 ? '' : 's'})</span><PoolHealthChip h={health?.[r.upstream]} /><CircuitBadge state={health?.[r.upstream]?.circuit} /></>
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
                              <PoolHealthChip h={health?.[r.upstream]} />
                              <CircuitBadge state={health?.[r.upstream]?.circuit} />
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
                                  <th style={{ width: 90 }}>Status</th>
                                  <th>Member</th>
                                  <th title="`host_header:` override drives outbound Host + TLS SNI">Host header</th>
                                  <th style={{ width: 60 }}>Weight</th>
                                  <th style={{ width: 80 }}>Zone</th>
                                </tr>
                              </thead>
                              <tbody>
                                {members.map((m, i) => {
                                  // routing-upstream #1 — live health for this
                                  // member (undefined when the summary carries
                                  // no per-member detail).
                                  const mh = memberHealth(health?.[r.upstream], m.addr);
                                  return (
                                  <tr key={`${m.addr}-${i}`}>
                                    <td style={{ fontSize: 11 }}>
                                      {mh === undefined
                                        ? <span style={{ color: 'var(--ink-dim)' }}>—</span>
                                        : <><MemberDot status={mh} />{mh === 'up'
                                            ? <span style={{ color: 'var(--up)' }}>up</span>
                                            : mh === 'down'
                                              ? <span style={{ color: 'var(--down)' }}>down</span>
                                              : <span style={{ color: 'var(--ink-dim)' }}>unverified</span>}</>}
                                    </td>
                                    <td className="mono" style={{ fontSize: 12 }}>{m.addr}</td>
                                    <td className="mono" style={{ fontSize: 11, color: m.host_header ? 'inherit' : 'var(--ink-dim)' }}>
                                      {m.host_header || '—'}
                                    </td>
                                    <td className="num">{m.weight ?? 1}</td>
                                    <td style={{ color: 'var(--ink-dim)', fontSize: 11 }}>{m.zone || '—'}</td>
                                  </tr>
                                  );
                                })}
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
          onCancel={closeEditor}
          busy={busy}
          saveError={saveError}
          clearSaveError={() => setSaveError(null)}
          cfgReload={cfgReload}
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

// HIGH-RU-01 (2026-05-12) — derive the legacy `tls` flag from
// the canonical `scheme`. The server's `UpstreamScheme::uses_tls`
// already treats `tls` as advisory when `scheme` is explicit,
// but the saved wire shape `{scheme: "https", tls: false}` reads
// as a contradiction to operators inspecting the API. Keep the
// two fields in lock-step at the dashboard boundary.
//
// `auto` honours the user-controlled `tls` checkbox; every other
// scheme derives from the protocol semantics.
function tlsFromScheme(scheme, fallbackTls) {
  switch (scheme) {
    case 'https':
    case 'grpc':
      return true;
    case 'http':
    case 'h2c':
    case 'tcp':
      return false;
    case 'auto':
    default:
      return !!fallbackTls;
  }
}

// MED-RU-03 (2026-05-12) — `poolBodyFromInlineForm` retired.
// The Add Route modal no longer collects backend-address +
// scheme inline; pool creation goes through the same
// `PoolEditModal` + `poolConfigFromForm` path as standalone
// "+ Add pool". That keeps the wire shape canonical (one
// builder instead of two that drift) and the audit chain
// honest (each pool create is its own `POOL_UPSERT` event).

// Form-shape helpers — `methods` is an **array** in the form draft so
// the checkbox UI can read / write it naturally. `routeBodyFromDraft`
// accepts either shape (legacy comma-string OR fresh array) so older
// callers keep working.
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
    default: false,
    enabled: true,
    // 2026-05-12 — strip the route prefix on forward by default.
    // Mirrors the server-side default and the operator-friendly
    // mount-point semantics.
    strip_prefix: true,
    // 2026-06-19 — per-route enforcement mode. 'enforce' (default)
    // blocks/challenges as resolved; 'log_only' is monitor mode
    // (forward to upstream, downgrade WAF blocks to log-only).
    mode: 'enforce',
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
    default: !!r.default,
    enabled: r.enabled !== false, // default to true if missing
    // 2026-05-12 — `strip_prefix` defaults to `true` server-side
    // for routes saved before this field existed, but the patch
    // serializer emits it explicitly for fresh routes. Reads as
    // `true` when the field is missing.
    strip_prefix: r.strip_prefix !== false,
    // 2026-06-19 — server emits 'enforce'|'log_only'; older routes
    // saved before this field read as 'enforce'.
    mode: r.mode === 'log_only' ? 'log_only' : 'enforce',
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
  const body = {
    id: d.id.trim(),
    path: d.path.trim() || '/',
    match_type: d.match_type,
    upstream: d.upstream,
    default: !!d.default,
    enabled: d.enabled !== false,
    // 2026-05-12 — always send `strip_prefix` so a flip from true
    // to false round-trips through the audit-mutated PUT.
    strip_prefix: d.strip_prefix !== false,
  };
  if (d.host.trim()) body.host = d.host.trim();
  if (methods.length > 0) body.methods = methods;
  // PR2/tier-rename — tier_override is always set in the modal
  // (defaulting to 'low'), so always send it. Backend accepts
  // critical | high | medium | low (with catch_all kept as alias).
  if (d.tier_override) body.tier_override = d.tier_override;
  // 2026-06-19 — always send mode so a flip enforce↔log_only round-trips.
  body.mode = d.mode === 'log_only' ? 'log_only' : 'enforce';
  return body;
}

// HTTP methods to expose as checkboxes — covers the practical
// surface (GET / POST / PUT / DELETE / PATCH / HEAD / OPTIONS).
// Operators rarely need anything else; if they do, fall back to
// editing YAML.
const ROUTE_METHOD_CHOICES = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS'];

function RouteEditModal({ mode, draft: initial, existingIds, poolNames, onSave, onCancel, busy, saveError, clearSaveError, cfgReload }) {
  const [d, setD] = useStateP(() => ({
    ...initial,
    methods: typeof initial.methods === 'string'
      ? initial.methods.split(',').map(s => s.trim().toUpperCase()).filter(Boolean)
      : (initial.methods || []),
  }));
  const isAdd = mode === 'add';
  const idClash = isAdd && existingIds.includes(d.id.trim());

  // MED-RU-03 (2026-05-12) — Add Route used to also create a pool
  // as a hidden side-effect of the "type a backend inline" path.
  // That made the failure modes confusing ("did the pool fail or
  // the route?") and left orphan pools on operator cancels or
  // route validation errors. Decouple: pool creation now lives
  // in a CHILD PoolEditModal opened via "+ Create new pool",
  // and the Add Route modal authors only the route. Audit chain
  // gets two distinct events (`POOL_UPSERT` + `ROUTE_CREATE`)
  // when a fresh pool is involved, which is also better forensics.
  const [createPoolOpen, setCreatePoolOpen] = useStateP(false);
  const [createPoolBusy, setCreatePoolBusy] = useStateP(false);

  // When the child modal creates a pool we call cfgReload(), but that
  // GET roundtrip lands a beat later — so the freshly created pool was
  // briefly absent from the dropdown (and flagged "no longer in the
  // live config — refresh") for the ~1–2s until the refetch resolved.
  // Track names created this session so the option list, validation,
  // and the selected-pool hint all reflect them instantly; the reload
  // reconciles shortly after and the sorted union dedupes the overlap.
  const [optimisticPools, setOptimisticPools] = useStateP([]);
  const mergedPoolNames = useMemoP(
    () => Array.from(new Set([...poolNames, ...optimisticPools])).sort(),
    [poolNames, optimisticPools],
  );

  // MED-02 (2026-05-11) — clear the save error whenever the
  // operator edits anything. The previous shape kept the toast +
  // inline hint visible until the next save; now the error
  // disappears as soon as the operator starts addressing it.
  const setWithErrorClear = (updater) => {
    if (clearSaveError) clearSaveError();
    setD(updater);
  };

  const [showAdvanced, setShowAdvanced] = useStateP(
    !isAdd && (
      (d.match_type && d.match_type !== 'prefix') ||
      d.tier_override ||
      d.mode === 'log_only'
    )
  );

  const idValid = d.id.trim().length > 0 && !idClash;
  const pathValid = d.path.trim().startsWith('/');
  const upstreamValid = mergedPoolNames.includes(d.upstream);
  // `!createPoolBusy` keeps route Save disabled while a freshly-created
  // child pool is still propagating to this node (BUG-create-route-pool-not-found-race).
  const canSave = idValid && pathValid && upstreamValid && !busy && !createPoolBusy;

  const set = (k, v) => setWithErrorClear({ ...d, [k]: v });
  const toggleSet = (k, v) => {
    const cur = new Set(d[k] || []);
    cur.has(v) ? cur.delete(v) : cur.add(v);
    setWithErrorClear({ ...d, [k]: Array.from(cur) });
  };

  // MED-RU-03 — handle a saved-from-child pool. The child modal
  // already wrote it (audit-chained); we just select the new
  // name in the dropdown and refresh the parent's pool list.
  // Errors stay surfaced inside the child modal's own toast path;
  // by the time onSave fires here the write is committed.
  async function handleChildPoolSave({ name, body }) {
    setCreatePoolBusy(true);
    try {
      // Capture the config version before the pool write so we can wait
      // for it to land on this node before re-enabling the route Save.
      const before = await window.currentConfigVersion();
      const r = await window.poolUpsert(name, body);
      if (r.status === 200 && r.ok) {
        window.aegisToast(`Pool "${name}" saved`, 'ok');
        // Optimistically surface + select the new pool immediately for
        // instant feedback…
        setOptimisticPools(prev => prev.includes(name) ? prev : [...prev, name]);
        setD(prev => ({ ...prev, upstream: name }));
        setCreatePoolOpen(false);
        // …but keep the route Save gated (createPoolBusy stays true via
        // the surrounding try) until the pool's config version has
        // landed on this node, so route validation can resolve it. The
        // server now also validates the upstream against the active
        // config doc, so a wait timeout is non-fatal — we just proceed.
        // BUG-create-route-pool-not-found-race.
        await window.waitForVersion(before + 1, 10000);
        if (cfgReload) cfgReload();
      } else {
        const msg = r.message || r.error || r.reason || `HTTP ${r.status}`;
        window.aegisToast(`Pool save failed: ${msg}`, 'err');
      }
    } finally {
      setCreatePoolBusy(false);
    }
  }

  // One-line preview always visible at the bottom of the form.
  const matchPreview = (() => {
    const ms = (d.methods || []).length > 0 ? d.methods.join(',') : 'ANY';
    const host = d.host.trim() || '*';
    const path = d.path.trim() || '/';
    const pool = d.upstream || '<pick a pool>';
    const stripNote = d.strip_prefix && (d.match_type === 'prefix' || d.match_type === 'exact') && path !== '/'
      ? '  · strip prefix'
      : '';
    return `${ms}  ${host}${path}  →  ${pool}${stripNote}`;
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
              placeholder="my-route" />
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

          {/* MED-RU-03 (2026-05-12) — Forward to: pick an existing
              pool, or click "+ Create new pool" to open a child
              modal. The modal authors only the route now; pool
              creation is an explicit audit-chained step.  Pools
              that exist without routes show up in "Pools without
              routes" on the page — same lifecycle as the standalone
              "+ Add pool" entry. */}
          <div className="form-row" style={{ marginTop: 14, paddingTop: 12, borderTop: '1px solid var(--hairline)' }}>
            <label>Forward to <span className="req">*</span></label>
            <div style={{ display: 'flex', gap: 8, alignItems: 'stretch' }}>
              <select
                className="ip"
                style={{ flex: 1 }}
                value={d.upstream}
                onChange={e => set('upstream', e.target.value)}
              >
                <option value="">{mergedPoolNames.length === 0 ? '— no pools yet —' : '— pick a pool —'}</option>
                {mergedPoolNames.map(n => <option key={n} value={n}>{n}</option>)}
              </select>
              <button
                type="button"
                className="btn"
                onClick={() => { if (clearSaveError) clearSaveError(); setCreatePoolOpen(true); }}
                title="Open the full pool editor to author a new upstream (members, scheme, TLS, health, circuit breaker). Saves immediately and audit-chains as a separate event from this route."
                style={{ fontSize: 12, whiteSpace: 'nowrap' }}
              >+ Create new pool</button>
            </div>
            {mergedPoolNames.length === 0 && (
              <div className="form-hint">
                No pools yet — click <strong>+ Create new pool</strong> to author one.
              </div>
            )}
            {d.upstream && (
              <div style={{ fontSize: 11, color: 'var(--ink-dim)', marginTop: 4 }}>
                Selected: <code>{d.upstream}</code>{' '}
                {(() => {
                  const p = mergedPoolNames.includes(d.upstream);
                  return p ? '· existing pool' : '· (pool no longer in the live config — refresh)';
                })()}
              </div>
            )}
          </div>

          {/* 2026-05-12 — strip-prefix toggle. The forwarder
              precomputes whether to strip at compile time based on
              this flag + match_type + path, so the only gating
              choice the operator has to make is "mount-point style"
              vs "path-preserving". Default `true` matches the
              nginx/traefik/envoy mental model. */}
          {(() => {
            const matchType = d.match_type || 'prefix';
            const path = (d.path || '').trim();
            const supportsStrip = (matchType === 'prefix' || matchType === 'exact') && path !== '/';
            const upstreamPathPreview = (() => {
              const incoming = path && path.startsWith('/') ? `${path}/article.html` : '/example';
              if (!supportsStrip || !d.strip_prefix) return incoming;
              return incoming.startsWith(path) && incoming.length > path.length
                ? incoming.slice(path.length) || '/'
                : '/';
            })();
            return (
              <div className="form-row" style={{ marginTop: 14, paddingTop: 12, borderTop: '1px solid var(--hairline)' }}>
                <label style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                  <input
                    type="checkbox"
                    checked={!!d.strip_prefix}
                    disabled={!supportsStrip}
                    onChange={e => set('strip_prefix', e.target.checked)}
                  />
                  <span>
                    Strip route prefix when forwarding
                    {!supportsStrip && (
                      <span style={{ color: 'var(--ink-dim)', fontSize: 11, marginLeft: 4 }}>
                        — n/a for {matchType === 'regex' || matchType === 'glob'
                          ? <>match-type <code>{matchType}</code></>
                          : <>catch-all route <code>/</code></>}
                      </span>
                    )}
                  </span>
                </label>
                <div style={{ fontSize: 11, color: 'var(--ink-dim)', marginTop: 4 }}>
                  {supportsStrip ? (
                    <>
                      With strip on, the upstream sees the request path with{' '}
                      <code>{path}</code> removed. With it off, the upstream
                      sees the full path verbatim.
                      <br />
                      <span style={{ fontFamily: 'var(--mono)' }}>
                        Example: <code>{path}/article.html</code> →{' '}
                        upstream gets <code>{upstreamPathPreview}</code>
                      </span>
                    </>
                  ) : matchType === 'regex' || matchType === 'glob' ? (
                    <>Regex / glob matches have no single literal prefix to strip — leave the field off.</>
                  ) : (
                    <>The catch-all route forwards every path verbatim — stripping <code>/</code> would leave the request without a path component.</>
                  )}
                </div>
              </div>
            );
          })()}

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
              {/* 2026-06-12 — per-route "Required client identity"
                  (auth_required) removed; client mTLS is now owned by the
                  unified Zero Trust page (plane-level cert verification). */}

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

              {/* 2026-06-19 — per-route monitor (log-only) mode. */}
              <div className="form-row" style={{ display: 'flex', gap: 16, alignItems: 'flex-start', marginTop: 8 }}>
                <label style={{ display: 'flex', gap: 6, alignItems: 'flex-start', fontSize: 11, cursor: 'pointer', flex: 1 }}>
                  <input
                    type="checkbox"
                    checked={d.mode === 'log_only'}
                    onChange={e => set('mode', e.target.checked ? 'log_only' : 'enforce')}
                    style={{ marginTop: 2 }}
                  />
                  <span>
                    <strong>Monitor only (log, don't block)</strong>
                    <div style={{ color: 'var(--ink-dim)', fontWeight: 400, marginTop: 2, lineHeight: 1.4 }}>
                      Run the full WAF pipeline and forward every request to
                      the upstream, but <em>downgrade WAF detector/risk blocks
                      to log-only</em> on this route — the audit feed shows what
                      <em> would</em> have been blocked (<code>X-WAF-Mode: log_only</code>).
                      Ideal for onboarding a real backend before flipping to
                      enforce. Explicit blacklist blocks still apply.
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

          {/* MED-02 (2026-05-11) — server-error block, modal-
              anchored. Replaces the older bottom-right toast so
              the operator's eye doesn't need to ping two
              corners of the page. Pre-wrap preserves the
              compensating-delete addendum that MED-04 emits
              when a rolled-back pool can't be removed. */}
          {saveError && (
            <div style={{
              marginTop: 12,
              padding: '10px 12px',
              border: '1px solid var(--danger, #b9425a)',
              background: 'rgba(185, 66, 90, 0.12)',
              borderRadius: 4,
              fontSize: 12,
              color: 'var(--ink)',
              whiteSpace: 'pre-wrap',
            }} role="alert">
              <strong style={{ display: 'block', marginBottom: 4 }}>Save failed</strong>
              {saveError.replace(/^Save failed:\s*/, '')}
            </div>
          )}

        </div>
        <div className="modal-foot">
          <button className="btn" onClick={onCancel} disabled={busy}>Cancel</button>
          <button className="btn primary" disabled={!canSave} onClick={() => {
            // MED-RU-03 (2026-05-12) — the route modal no longer
            // creates pools as a side-effect. The "newPool" sentinel
            // stays `null` so the parent's saveRoute skips the
            // inline-pool branch and only emits a ROUTE_CREATE.
            onSave({ ...d, newPool: null });
          }}>
            {busy ? 'Saving…' : (isAdd ? 'Create route' : 'Save')}
          </button>
        </div>
      </div>
      {/* MED-RU-03 (2026-05-12) — child PoolEditModal for the
          "+ Create new pool" flow. Saves immediately (audit-chained);
          on success the new pool is selected in the route's
          dropdown. Operator cancel of the child modal is a no-op
          (no API call). Operator cancel of the PARENT route modal
          after creating a pool leaves the pool intact (matches
          the standalone "+ Add pool" semantics — pools can exist
          without routes by design). */}
      {createPoolOpen && (
        <PoolEditModal
          mode="add"
          existingNames={mergedPoolNames}
          initialName=""
          initialPool={null}
          onCancel={() => setCreatePoolOpen(false)}
          onSave={handleChildPoolSave}
          busy={createPoolBusy}
        />
      )}
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

// ===========================================================================
// ===========================================================================
// Copilot chat widget (2026-06-05) — a floating launcher + big popup that
// brings the Copilot to every page. Mounted globally in App. The launcher
// only renders when the copilot is actually enabled; enablement is probed
// for FREE via `GET /api/copilot/ask` with no `q` — the handler returns 503
// when disabled and 400 (missing question) when enabled, so we learn the
// state without spending a token. The popup hosts: a live WAF posture panel
// (sourced from existing free telemetry APIs, never a billable call), quick
// actions (Generate brief / Find campaigns — the same LLM calls as the
// Copilot page), and a free-form chat thread (the ask endpoint).
// ===========================================================================
// Minimal, XSS-safe Markdown → React nodes for model output. We BUILD
// elements (React escapes all text children) and never touch innerHTML, so
// an untrusted LLM response can't inject markup. Supports the shapes the
// copilot actually emits: headings, bold/italic, inline + fenced code,
// links (http/https only), and unordered/ordered lists.
function renderInline(text, keyPrefix) {
  const nodes = [];
  let rest = String(text);
  let k = 0;
  const re = /(`[^`]+`)|(\*\*[^*]+\*\*)|(\*[^*]+\*|_[^_]+_)|(\[[^\]]+\]\([^)]+\))/;
  let guard = 0;
  while (rest && guard++ < 2000) {
    const m = re.exec(rest);
    if (!m) { nodes.push(rest); break; }
    if (m.index > 0) nodes.push(rest.slice(0, m.index));
    const tok = m[0];
    if (tok.startsWith('`')) {
      nodes.push(<code key={`${keyPrefix}-${k++}`} className="md-code">{tok.slice(1, -1)}</code>);
    } else if (tok.startsWith('**')) {
      nodes.push(<strong key={`${keyPrefix}-${k++}`}>{tok.slice(2, -2)}</strong>);
    } else if (tok.startsWith('[')) {
      const mm = /^\[([^\]]+)\]\(([^)]+)\)$/.exec(tok);
      const label = mm ? mm[1] : tok;
      const url = mm ? mm[2] : '';
      if (/^https?:\/\//i.test(url) || url.startsWith('#/')) {
        nodes.push(<a key={`${keyPrefix}-${k++}`} href={url} target="_blank" rel="noreferrer">{label}</a>);
      } else {
        nodes.push(label);
      }
    } else {
      nodes.push(<em key={`${keyPrefix}-${k++}`}>{tok.replace(/^[*_]/, '').replace(/[*_]$/, '')}</em>);
    }
    rest = rest.slice(m.index + tok.length);
  }
  return nodes;
}

function renderMarkdown(text) {
  if (!text) return null;
  const lines = String(text).replace(/\r\n/g, '\n').split('\n');
  const out = [];
  let i = 0, key = 0;
  let list = null; // { ordered, items: [] }
  const flushList = () => {
    if (!list) return;
    const Tag = list.ordered ? 'ol' : 'ul';
    const items = list.items;
    out.push(
      <Tag key={`md-${key++}`} className="md-list">
        {items.map((it, idx) => <li key={idx}>{renderInline(it, `li-${key}-${idx}`)}</li>)}
      </Tag>,
    );
    list = null;
  };
  while (i < lines.length) {
    const line = lines[i];
    if (/^```/.test(line.trim())) {
      flushList();
      const buf = [];
      i++;
      while (i < lines.length && !/^```/.test(lines[i].trim())) { buf.push(lines[i]); i++; }
      i++;
      out.push(<pre key={`md-${key++}`} className="md-pre"><code>{buf.join('\n')}</code></pre>);
      continue;
    }
    const h = /^(#{1,3})\s+(.*)$/.exec(line);
    if (h) {
      flushList();
      out.push(<div key={`md-${key++}`} className={`md-h md-h${h[1].length}`}>{renderInline(h[2], `h-${key}`)}</div>);
      i++; continue;
    }
    const ul = /^\s*[-*•]\s+(.*)$/.exec(line);
    const ol = /^\s*\d+[.)]\s+(.*)$/.exec(line);
    if (ul || ol) {
      const ordered = !!ol;
      if (!list || list.ordered !== ordered) { flushList(); list = { ordered, items: [] }; }
      list.items.push(ul ? ul[1] : ol[1]);
      i++; continue;
    }
    if (line.trim() === '') { flushList(); i++; continue; }
    flushList();
    out.push(<p key={`md-${key++}`} className="md-p">{renderInline(line, `p-${key}`)}</p>);
    i++;
  }
  flushList();
  return out;
}

function CopilotWidget() {
  // null = unknown (probing), true = enabled, false = disabled/absent.
  const [enabled, setEnabled] = useStateP(null);
  const [open, setOpen] = useStateP(false);
  const [minutes, setMinutes] = useStateP('60');
  // Chat thread persists across open/close. Each turn:
  //   { role: 'user'|'assistant'|'brief'|'campaigns'|'error', ... }
  const [messages, setMessages] = useStateP([]);
  const [input, setInput] = useStateP('');
  // Which LLM action is in flight ('ask'|'brief'|'campaigns') or null.
  const [busy, setBusy] = useStateP(null);

  // Free enablement probe — no token spend (see header note).
  useEffectP(() => {
    let cancelled = false;
    fetch('/api/copilot/ask', { credentials: 'same-origin' })
      .then(r => { if (!cancelled) setEnabled(r.status !== 503); })
      .catch(() => { if (!cancelled) setEnabled(false); });
    return () => { cancelled = true; };
  }, []);

  // Global open hook so anything (e.g. Overview's "Open Copilot" button)
  // can pop the chat: `window.openCopilot()`. The listener is registered
  // unconditionally (before the enabled early-return) so the hook exists
  // while probing; if the copilot is disabled it nudges with a toast
  // instead of opening a panel that can't answer.
  useEffectP(() => {
    window.openCopilot = () => window.dispatchEvent(new CustomEvent('aegis:copilot-open'));
    const onOpen = () => {
      if (enabled === true) setOpen(true);
      else if (enabled === false) {
        window.aegisToast && window.aegisToast(
          'Copilot is disabled — set LLM_ENABLED + provider keys to enable', 'warn',
        );
      }
    };
    window.addEventListener('aegis:copilot-open', onOpen);
    return () => window.removeEventListener('aegis:copilot-open', onOpen);
  }, [enabled]);

  function pushMsg(msg) {
    setMessages(m => [...m, { id: Math.random().toString(36).slice(2), ...msg }]);
  }

  // Shared 503 handler — if the copilot got disabled out from under us,
  // flip the widget off rather than spamming errors.
  function handleDisabled() {
    setEnabled(false);
    setOpen(false);
  }

  async function runAsk(raw) {
    const question = (raw ?? input).trim();
    if (!question || busy) return;
    pushMsg({ role: 'user', text: question });
    setInput('');
    setBusy('ask');
    try {
      const r = await fetch(
        `/api/copilot/ask?q=${encodeURIComponent(question)}&minutes=${encodeURIComponent(minutes)}`,
        { credentials: 'same-origin' },
      );
      const j = await r.json().catch(() => ({}));
      if (r.status === 503) { handleDisabled(); return; }
      if (!r.ok) { pushMsg({ role: 'error', text: j.error || `HTTP ${r.status}` }); return; }
      pushMsg({
        role: 'assistant', text: j.text,
        meta: `${j.model} · ${(j.input_tokens || 0) + (j.output_tokens || 0)} tokens`,
      });
    } catch (e) {
      pushMsg({ role: 'error', text: String(e && e.message ? e.message : e) });
    } finally {
      setBusy(null);
    }
  }

  async function runBrief() {
    if (busy) return;
    pushMsg({ role: 'user', text: `Generate brief · last ${minutes} min`, kind: 'action' });
    setBusy('brief');
    try {
      const r = await fetch(
        `/api/copilot/summary?minutes=${encodeURIComponent(minutes)}`,
        { credentials: 'same-origin' },
      );
      const j = await r.json().catch(() => ({}));
      if (r.status === 503) { handleDisabled(); return; }
      if (!r.ok) { pushMsg({ role: 'error', text: j.error || `HTTP ${r.status}` }); return; }
      pushMsg({
        role: 'brief', text: j.text, snapshot: j.snapshot,
        meta: `${j.model} · ${(j.input_tokens || 0) + (j.output_tokens || 0)} tokens`,
      });
    } catch (e) {
      pushMsg({ role: 'error', text: String(e && e.message ? e.message : e) });
    } finally {
      setBusy(null);
    }
  }

  async function runCampaigns() {
    if (busy) return;
    pushMsg({ role: 'user', text: `Find campaigns · last ${minutes} min`, kind: 'action' });
    setBusy('campaigns');
    try {
      const r = await fetch(
        `/api/copilot/suggestions?minutes=${encodeURIComponent(minutes)}`,
        { credentials: 'same-origin' },
      );
      const j = await r.json().catch(() => ({}));
      if (r.status === 503) { handleDisabled(); return; }
      if (!r.ok) { pushMsg({ role: 'error', text: j.error || `HTTP ${r.status}` }); return; }
      pushMsg({ role: 'campaigns', data: j, meta: `${j.model} · ${(j.input_tokens || 0) + (j.output_tokens || 0)} tokens` });
    } catch (e) {
      pushMsg({ role: 'error', text: String(e && e.message ? e.message : e) });
    } finally {
      setBusy(null);
    }
  }

  // Hidden entirely until we confirm the copilot is enabled.
  if (enabled !== true) return null;

  return (
    <>
      <button
        type="button"
        className="copilot-fab"
        aria-label={open ? 'Close Copilot' : 'Open Copilot'}
        title="Copilot — ask, brief, and triage from anywhere"
        onClick={() => setOpen(o => !o)}
      >
        {open ? '×' : <window.I.Sparkles />}
      </button>
      {open && (
        <CopilotPanel
          minutes={minutes}
          setMinutes={setMinutes}
          messages={messages}
          input={input}
          setInput={setInput}
          busy={busy}
          onAsk={runAsk}
          onBrief={runBrief}
          onCampaigns={runCampaigns}
          onClear={() => setMessages([])}
          onClose={() => setOpen(false)}
        />
      )}
    </>
  );
}

// Live WAF posture — free telemetry only (no LLM). Mounted inside the open
// panel so its polling hooks only run while the popup is visible.
function CopilotPosture({ minutes }) {
  const win = Math.max(60, Number(minutes) * 60 || 900);
  const stats = window.useStatsApi ? window.useStatsApi() : { data: null };
  const byDet = window.useAttacksByDetectorApi ? window.useAttacksByDetectorApi(win) : { data: null };
  const top = window.useAttacksTopApi ? window.useAttacksTopApi(win, 5) : { data: null };
  const incidents = window.useIncidentsApi ? window.useIncidentsApi() : { data: null };

  const s = stats.data || {};
  const detectors = (byDet.data?.detectors || []).slice(0, 5);
  const attackers = (top.data?.attackers || []).slice(0, 5);
  const firing = Array.isArray(incidents.data?.incidents)
    ? incidents.data.incidents.filter(i => i.status === 'firing').length
    : (incidents.data?.raw_alerts?.firing?.length || 0);

  const Stat = ({ label, value, tone }) => (
    <div style={{ flex: 1, minWidth: 0 }}>
      <div style={{ fontSize: 9, textTransform: 'uppercase', letterSpacing: 0.5, color: 'var(--ink-dim)' }}>{label}</div>
      <div className="num" style={{ fontSize: 18, color: tone || 'var(--ink)' }}>{value}</div>
    </div>
  );

  return (
    <div className="copilot-posture">
      <div style={{ fontSize: 11, fontWeight: 600, textTransform: 'uppercase', letterSpacing: 0.5, color: 'var(--ink-dim)', marginBottom: 10 }}>
        Live posture
      </div>

      <div style={{ display: 'flex', gap: 10, marginBottom: 16 }}>
        <Stat label="Req rate" value={s.request_rate != null ? `${s.request_rate}/s` : '—'} />
        <Stat label="Block rate" value={s.block_rate_pct != null ? `${s.block_rate_pct}%` : '—'} tone={Number(s.block_rate_pct) > 20 ? 'var(--down)' : undefined} />
      </div>
      <div style={{ display: 'flex', gap: 10, marginBottom: 16 }}>
        <Stat label="Blocked" value={(s.blocks_total ?? 0).toLocaleString()} />
        <Stat label="Active alerts" value={firing} tone={firing > 0 ? 'var(--down)' : undefined} />
      </div>

      <div style={{ fontSize: 10, textTransform: 'uppercase', letterSpacing: 0.5, color: 'var(--ink-dim)', margin: '4px 0 6px' }}>Top attack types</div>
      {detectors.length ? detectors.map(d => (
        <div key={d.name} style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12, padding: '3px 0' }}>
          <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{d.name}</span>
          <span className="num" style={{ color: 'var(--ink-mute)' }}>{d.value}</span>
        </div>
      )) : <div style={{ fontSize: 12, color: 'var(--ink-dim)' }}>none in window</div>}

      <div style={{ fontSize: 10, textTransform: 'uppercase', letterSpacing: 0.5, color: 'var(--ink-dim)', margin: '14px 0 6px' }}>Top attackers</div>
      {attackers.length ? attackers.map(a => (
        <div key={a.identifier} style={{ display: 'flex', justifyContent: 'space-between', gap: 8, fontSize: 12, padding: '3px 0' }}>
          <span className="mono" style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
            {a.identifier}{a.country ? ` · ${a.country}` : ''}
          </span>
          <span className={`pill ${Number(a.risk) >= 80 ? 'down' : 'neutral'}`} style={{ fontSize: 10, flexShrink: 0 }}>{a.risk ?? a.hits ?? '—'}</span>
        </div>
      )) : <div style={{ fontSize: 12, color: 'var(--ink-dim)' }}>none in window</div>}
    </div>
  );
}

// The big popup: posture (left) + chat thread with quick actions (right).
function CopilotPanel({ minutes, setMinutes, messages, input, setInput, busy, onAsk, onBrief, onCampaigns, onClear, onClose }) {
  const threadRef = useRefP(null);
  // Auto-scroll the thread to the newest message.
  useEffectP(() => {
    const el = threadRef.current;
    if (el) el.scrollTop = el.scrollHeight;
  }, [messages.length, busy]);
  // Esc closes.
  useEffectP(() => {
    const onKey = (e) => { if (e.key === 'Escape') onClose(); };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, []);

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="copilot-panel" onClick={e => e.stopPropagation()}>
        <div className="copilot-panel-head">
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <span className="copilot-spark"><window.I.Sparkles /></span>
            <span style={{ fontWeight: 600 }}>Copilot</span>
            <span style={{ fontSize: 10, color: 'var(--ink-dim)' }}>advisory · billable LLM calls</span>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <label style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: 11, color: 'var(--ink-dim)' }}>
              Window
              <select className="input select" value={minutes} onChange={e => setMinutes(e.target.value)} style={{ width: 104 }}>
                <option value="15">15 min</option>
                <option value="60">60 min</option>
                <option value="360">6 h</option>
                <option value="1440">24 h</option>
              </select>
            </label>
            <button type="button" className="btn" style={{ fontSize: 11, padding: '4px 10px' }} onClick={onClear} disabled={messages.length === 0}>Clear</button>
            <button type="button" className="icon-btn" aria-label="Close Copilot" onClick={onClose}>×</button>
          </div>
        </div>

        <div className="copilot-panel-body">
          <CopilotPosture minutes={minutes} />

          <div className="copilot-chat">
            <div className="copilot-thread" ref={threadRef}>
              {messages.length === 0 && (
                <div style={{ color: 'var(--ink-dim)', fontSize: 13, lineHeight: 1.6, maxWidth: 460, margin: '24px auto', textAlign: 'center' }}>
                  Ask anything about the last {minutes} minutes of traffic, or use a quick action below.
                  Every reply is grounded in this WAF's own telemetry and is advisory — verify before acting.
                </div>
              )}
              {messages.map(m => <CopilotMessage key={m.id} m={m} />)}
              {busy && (
                <div className="copilot-bubble assistant" style={{ color: 'var(--ink-dim)', fontStyle: 'italic' }}>
                  {busy === 'brief' ? 'Generating brief…' : busy === 'campaigns' ? 'Finding campaigns…' : 'Thinking…'}
                </div>
              )}
            </div>

            <div className="copilot-actions">
              <button type="button" className="chip-btn" onClick={onBrief} disabled={!!busy} title="LLM situational brief over the window">
                <window.I.Sparkles /> Generate brief
              </button>
              <button type="button" className="chip-btn" onClick={onCampaigns} disabled={!!busy} title="Cluster recent events into campaigns + candidate rules">
                <window.I.Search /> Find campaigns
              </button>
            </div>

            <div className="copilot-input">
              <input
                className="input"
                value={input}
                onChange={e => setInput(e.target.value)}
                onKeyDown={e => { if (e.key === 'Enter') onAsk(); }}
                placeholder="Ask the copilot… e.g. which IP is hitting us hardest, and why?"
                aria-label="Ask the copilot"
                disabled={!!busy}
                style={{ flex: 1 }}
              />
              <button type="button" className="btn primary" onClick={() => onAsk()} disabled={!!busy || !input.trim()}>
                {busy === 'ask' ? '…' : 'Ask'}
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

// One rendered chat turn. Plain text only for any model output (never HTML).
function CopilotMessage({ m }) {
  if (m.role === 'user') {
    return <div className="copilot-bubble user">{m.text}</div>;
  }
  if (m.role === 'error') {
    return <div className="copilot-bubble assistant" style={{ color: 'var(--down)' }}>{m.text}</div>;
  }
  if (m.role === 'campaigns') {
    const sugg = m.data?.suggestions || [];
    return (
      <div className="copilot-bubble assistant">
        <div style={{ fontSize: 10, textTransform: 'uppercase', letterSpacing: 0.5, color: 'var(--ink-dim)', marginBottom: 6 }}>Smart-catch triage</div>
        {sugg.length ? sugg.map(s => (
          <div key={s.id} style={{ borderTop: '1px solid var(--hairline)', paddingTop: 8, marginTop: 8 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 8 }}>
              <span style={{ fontWeight: 600, fontSize: 13 }}>{s.cluster}</span>
              <span className={`pill ${s.confidence === 'high' ? 'down' : s.confidence === 'medium' ? 'warn' : 'neutral'}`}>{s.confidence || '?'}</span>
            </div>
            <div style={{ fontSize: 12, color: 'var(--ink-dim)', marginTop: 4 }}>{s.explanation}</div>
            {s.suggested_rule && (
              <code style={{ display: 'block', whiteSpace: 'pre-wrap', background: 'var(--canvas-2)', padding: '6px 8px', borderRadius: 4, marginTop: 6, fontSize: 11 }}>
                {s.suggested_rule}
              </code>
            )}
          </div>
        )) : (m.data?.unparsed
          ? <div style={{ whiteSpace: 'pre-wrap', fontSize: 13 }}>{m.data.unparsed}</div>
          : <div style={{ fontSize: 12, color: 'var(--ink-dim)' }}>No notable campaigns in this window.</div>)}
        {m.meta && <div style={{ marginTop: 8, fontSize: 10, color: 'var(--ink-mute)' }}>{m.meta} · review before promoting</div>}
      </div>
    );
  }
  // assistant + brief
  return (
    <div className="copilot-bubble assistant">
      {m.role === 'brief' && (
        <div style={{ fontSize: 10, textTransform: 'uppercase', letterSpacing: 0.5, color: 'var(--ink-dim)', marginBottom: 6 }}>Situational brief</div>
      )}
      <div className="md-body">{renderMarkdown(m.text)}</div>
      {m.meta && <div style={{ marginTop: 6, fontSize: 10, color: 'var(--ink-mute)' }}>{m.meta} · verify before acting</div>}
    </div>
  );
}

Object.assign(window, {
  CopilotWidget,
  PageOverview, PageLiveFeed, PageAttackEvents, PageAnalytics, PageAuditLog,
  PageRuleManager, PageTierConfig, ListPage, PageSettings, PageTracking,
  PageUpstreams, CacheStatsCard,
  // Zero Trust (P3) — unified mutual-TLS page (both directions).
  PageZeroTrust,
  // SC-T2 — Scaling page (L1 workers + L2 cluster + L3 state).
  PageScaling,
  // Phase 2 — merged Access Lists, plus Phase 3 stubs.
  // PageHelp is owned by help.jsx (loaded after this file).
  PageAccessLists,
  PageIncidents, PageInvestigation,
  PageTopAttackers,
  PageReports,
  // 2026-05-09 — Traffic Gates page surfaces the four request-flow
  // gates (access list, strike-block, rate-limit, DDoS) with
  // telemetry + cross-links. New page slot in Policy menu group.
  PageTrafficGates,
});
