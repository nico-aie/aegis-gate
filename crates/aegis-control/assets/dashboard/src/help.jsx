/* global React */
const { useState: useStateH } = React;

function PageHelp() {
  const [tab, setTab] = useStateH('start');

  return (
    <>
      <div className="page-head">
        <div>
          <h1 className="page-title">Help &amp; Guide</h1>
          <p className="page-subtitle">Onboarding for new operators · last updated 2026-04-28 · v1.4.2</p>
        </div>
        <div className="page-actions">
          <button className="btn"><window.I.External /> Full docs</button>
          <button className="btn primary"><window.I.Bell /> Contact on-call</button>
        </div>
      </div>

      <div style={{ display: 'flex', borderBottom: '1px solid var(--hairline)', marginBottom: 14, gap: 0 }}>
        {[
          { id: 'start', label: 'Quickstart' },
          { id: 'glossary', label: 'Glossary' },
          { id: 'workflows', label: 'Common workflows' },
          { id: 'shortcuts', label: 'Shortcuts' },
        ].map(t => (
          <button key={t.id} onClick={() => setTab(t.id)} style={{
            padding: '10px 18px', background: 'transparent', border: 'none',
            color: tab === t.id ? 'var(--brand-yellow)' : 'var(--ink-mute)',
            borderBottom: tab === t.id ? '2px solid var(--brand-yellow)' : '2px solid transparent',
            fontSize: 13, fontWeight: 600, cursor: 'pointer',
          }}>{t.label}</button>
        ))}
      </div>

      {tab === 'start' && (
        <div className="grid-12">
          {[
            { n: 1, t: 'Watch the live feed', d: 'Open Live Feed to see every request the WAF is evaluating. Each row shows the IP, path, risk score, and the action that was taken. Use this when investigating an incident.', cta: 'Open Live Feed →', to: '#/live' },
            { n: 2, t: 'Block an attacker', d: 'Click any row in Live Feed or Top Attackers to open the inspector drawer, then hit Block IP. The IP is added to the global blacklist with an audit-chained reason.', cta: 'See Blacklist →', to: '#/blacklist' },
            { n: 3, t: 'Test a new rule safely', d: 'Toggle Shadow Mode in Settings — the WAF will log every detection without enforcing. Watch Live Feed for false positives, then disable shadow mode to enforce.', cta: 'Open Settings →', to: '#/settings' },
            { n: 4, t: 'Validate before deploy', d: 'In Rule Manager, edit the DSL and click Validate. The 1h dry-run shows how many requests in production would have matched. Save & deploy commits with a hash-chained audit entry.', cta: 'Open Rule Manager →', to: '#/rules' },
            { n: 5, t: 'Track operational health', d: 'Tracking surfaces SLO burn, upstream pool health, cluster peers, GitOps sync, and cert freshness. Alerts firing here have linked runbooks.', cta: 'Open Tracking →', to: '#/tracking' },
            { n: 6, t: 'Audit any change', d: 'Audit Log is a hash-chained, witnessed record of every config change and detection. Filter by actor, target, or hash; verify the chain on demand.', cta: 'Open Audit Log →', to: '#/audit' },
          ].map(s => (
            <div key={s.n} className="col-4 card" style={{ padding: 16 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 8 }}>
                <span style={{ width: 28, height: 28, borderRadius: 6, background: 'var(--brand-yellow)', color: '#0B0E11', display: 'inline-flex', alignItems: 'center', justifyContent: 'center', fontWeight: 700, fontSize: 13 }}>{s.n}</span>
                <div style={{ fontSize: 13, fontWeight: 600 }}>{s.t}</div>
              </div>
              <div style={{ fontSize: 12, color: 'var(--ink-mute)', lineHeight: 1.6, marginBottom: 12 }}>{s.d}</div>
              <a href={s.to} className="btn sm" style={{ textDecoration: 'none' }}>{s.cta}</a>
            </div>
          ))}
        </div>
      )}

      {tab === 'glossary' && (
        <div className="card" style={{ padding: 0 }}>
          <table className="tbl tbl-compact">
            <thead><tr><th style={{ width: 200 }}>Term</th><th>Meaning</th></tr></thead>
            <tbody>
              {[
                ['Tier', 'A pipeline assignment for a route. Each tier defines a TLS profile, rate-limit profile, challenge ladder, and detector set. Higher tiers = stricter posture.'],
                ['Risk score', 'A 0–100 number assigned per request based on detector firings and signal aggregation. Compared against the Allow / Challenge / Block thresholds set in Settings.'],
                ['Action', 'Final disposition: allow (pass-through), challenge (JS / CAPTCHA / PoW), block (closed connection or 403).'],
                ['Detector', 'A class of analyzer (sqli, xss, ssrf, recon, …). Each rule belongs to one detector.'],
                ['Rule', 'A single match definition: field × operator × pattern → action + risk delta. Built-in rules ship with releases; custom rules live in your config repo.'],
                ['Shadow mode', 'A global switch that logs detections without blocking. Use it to validate new rules in production traffic without customer impact.'],
                ['Fingerprint', 'A stable hash of TLS / HTTP characteristics (JA4, header order, etc.) — useful for identifying actors that rotate IPs.'],
                ['Honeypot', 'A path that should never receive legitimate traffic (/.env, /.git/config). Hits are an immediate high-risk signal.'],
                ['Audit chain', 'Append-only hash-chained log of every config change and detection. Each entry includes the previous hash; an external witness signs batches.'],
                ['GitOps drift', 'Difference between the running config and the HEAD of the config repo. The control plane auto-pulls and reports drift.'],
                ['SLO burn', 'How fast you are spending your error budget for a given SLO. Burn > 1× means you will exhaust the budget before the window resets.'],
                ['Upstream pool', 'A logical group of origin servers behind a load-balancing strategy. Each pool has a circuit-breaker state.'],
              ].map(([t, d]) => (
                <tr key={t}><td className="mono" style={{ color: 'var(--brand-yellow)' }}>{t}</td><td className="dim">{d}</td></tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {tab === 'workflows' && (
        <div className="grid-12">
          {[
            { t: 'Block an attacker mid-incident', steps: ['Open Live Feed and filter by the IP or path of interest.', 'Click any matching row to open the request inspector.', 'Press Block IP in the drawer footer — the IP is added to the global blacklist immediately.', 'The change is recorded in Audit Log under blacklist.add.'] },
            { t: 'Test a new rule before enforcing', steps: ['Settings → toggle Shadow Mode ON.', 'Rule Manager → New rule. Write the DSL and click Validate.', 'The 1h dry-run shows the would-have-matched count against live traffic.', 'Save & deploy. Watch Live Feed for false positives over 30–60 min.', 'Toggle Shadow Mode OFF to enforce.'] },
            { t: 'Investigate a 5xx spike on upstream', steps: ['Tracking → Upstream pools. Look for circuit-breaker state of half-open or open.', 'Drill into the pool to see member health and p99 latency.', 'Cross-reference Live Feed for matching upstream errors.', 'If circuit is open, fix the upstream then click Reset breaker.'] },
            { t: 'Renew a certificate', steps: ['Tracking → Cert freshness. Identify cert with < 7 days remaining (red).', 'For ACME-managed certs, click Renew — it reorders inline.', 'For static certs, follow the runbook linked in the alert.'] },
            { t: 'Geo-block a country', steps: ['Blacklist → Add entry → Type: Country.', 'Pick the ISO code and choose action (block or challenge).', 'Optionally scope to a specific tier or route (e.g. /api/admin only).', 'Save. The change is hash-chained into the audit log.'] },
            { t: 'Trust a partner network', steps: ['Whitelist → Add entry → Type: CIDR or ASN.', 'Choose which protections to bypass (rate-limit, specific detector, all).', 'Set an expiry if temporary (e.g. for a pen-test engagement).', 'Add a clear reason — your auditors will read it.'] },
          ].map((w, i) => (
            <div key={i} className="col-6 card" style={{ padding: 16 }}>
              <div style={{ fontSize: 13, fontWeight: 600, marginBottom: 10 }}>{w.t}</div>
              <ol style={{ margin: 0, paddingLeft: 18, fontSize: 12, lineHeight: 1.8, color: 'var(--ink-mute)' }}>
                {w.steps.map((s, j) => <li key={j}>{s}</li>)}
              </ol>
            </div>
          ))}
        </div>
      )}

      {tab === 'shortcuts' && (
        <div className="grid-12">
          <div className="col-6 card" style={{ padding: 16 }}>
            <div style={{ fontSize: 13, fontWeight: 600, marginBottom: 12 }}>Global</div>
            {[
              ['⌘K / Ctrl+K', 'Open command palette'],
              ['ESC', 'Close palette / drawer'],
              ['G then O', 'Go to Overview'],
              ['G then L', 'Go to Live Feed'],
              ['G then R', 'Go to Rule Manager'],
              ['G then S', 'Go to Settings'],
              ['G then T', 'Go to Tracking'],
            ].map(([k, l]) => (
              <div key={k} style={{ display: 'flex', alignItems: 'center', gap: 12, fontSize: 12, padding: '7px 0', borderBottom: '1px solid var(--hairline)' }}>
                <span className="kbd" style={{ minWidth: 110, display: 'inline-block', textAlign: 'center' }}>{k}</span>
                <span style={{ color: 'var(--ink-mute)' }}>{l}</span>
              </div>
            ))}
          </div>
          <div className="col-6 card" style={{ padding: 16 }}>
            <div style={{ fontSize: 13, fontWeight: 600, marginBottom: 12 }}>Live Feed</div>
            {[
              ['Space', 'Pause / resume stream'],
              ['/', 'Focus filter input'],
              ['↑ / ↓', 'Move between rows'],
              ['Enter', 'Open request inspector'],
              ['B', 'Block IP from selected row'],
              ['W', 'Whitelist IP from selected row'],
              ['C', 'Copy as cURL'],
            ].map(([k, l]) => (
              <div key={k} style={{ display: 'flex', alignItems: 'center', gap: 12, fontSize: 12, padding: '7px 0', borderBottom: '1px solid var(--hairline)' }}>
                <span className="kbd" style={{ minWidth: 110, display: 'inline-block', textAlign: 'center' }}>{k}</span>
                <span style={{ color: 'var(--ink-mute)' }}>{l}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </>
  );
}

Object.assign(window, { PageHelp });
