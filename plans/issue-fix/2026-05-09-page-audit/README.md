# Dashboard page audit — hardcoded data + operator usability (2026-05-09)

> **Trigger:** operator review found Threat Intel and Compliance pages
> "look hardcoded for now". Comprehensive audit of all 19 dashboard
> pages against the actual `/api/*` endpoints + Rust source-of-truth.
>
> **Branch:** `develop`. Findings + small fixes ship in this PR; bigger
> feature gaps tracked as separate plan items.

---

## TL;DR

| Severity | Count | Examples |
|---|---:|---|
| **🔴 Misleading** (UI implies behaviour that doesn't exist in code) | **1** | Compliance Profile per-mode pinning table |
| **🟡 Empty-state-by-config** (page works correctly but renders empty when feature not configured in YAML) | **3** | Threat Intel (no feeds), AI metrics (no model), mTLS (no client_auth) |
| **🟢 Real APIs, real data** | 15 | Overview, Live Feed, Incidents, Investigation, Top Attackers, Rules, Detectors, Access Lists, Routing & Upstreams, Traffic Gates, Performance, Health & SLOs, Audit Trail, Scaling, Settings, Reports |

The user-reported "hardcoded for now" perception comes from two genuinely-different root causes:

1. **Compliance page** is **misleading** — it renders a per-mode pinning table (PCI vs HIPAA vs SOC2 vs GDPR vs FIPS pin different detector sets) that doesn't match the Rust truth. The actual `COMPLIANCE_PINNED` constant in `crates/aegis-control/src/api/detectors.rs:99` pins the same 4 classes (sqli, xss, path_traversal, ssrf) regardless of which mode is active. **Fix in this PR.**

2. **Threat Intel page** is **honest but empty in dev** — it correctly polls `/api/threat-intel/{hits,feeds}` and `/api/geoip/status`, all of which return real data once feeds are configured. The dev config doesn't ship with TAXII feeds, so the page renders the documented empty state. **Not a bug; the existing inline help is correct.** A future feature (audit-mutated feed CRUD UI) is a real gap but not in scope here.

---

## Detailed findings

### 🔴 Critical: Compliance page invents per-mode pinning

**File:** `crates/aegis-control/assets/dashboard/src/pages.jsx:7965`

The page renders a 5-row table mapping each compliance mode to a different list of pinned detector classes:

```js
const COMPLIANCE_CLAMPS = {
  pci_dss: ['sqli', 'xss', 'path_traversal', 'header_injection'],
  hipaa:   ['sqli', 'xss', 'ssrf', 'header_injection'],
  soc2:    ['sqli', 'xss', 'path_traversal', 'header_injection', 'recon'],
  gdpr:    ['sqli', 'xss'],
  fips:    ['sqli', 'xss', 'path_traversal', 'header_injection', 'ssrf'],
};
```

The actual Rust source (`crates/aegis-control/src/api/detectors.rs:99`):

```rust
const COMPLIANCE_PINNED: &[DetectorClass] = &[
    DetectorClass::Sqli,
    DetectorClass::Xss,
    DetectorClass::PathTraversal,
    DetectorClass::Ssrf,
];

pub fn is_locked(class: DetectorClass, modes: &[ComplianceMode]) -> bool {
    !modes.is_empty() && COMPLIANCE_PINNED.contains(&class)
}
```

The function pins the same 4 classes whenever **any** mode is active. There's no per-mode differentiation in code. The dashboard table implies regulatory granularity that doesn't exist.

**Why this is misleading:**
- A SOC operator running PCI sees "PCI pins these 4: sqli, xss, path_traversal, header_injection" — but `header_injection` is **not** actually pinned at the Rust level.
- A HIPAA operator sees "HIPAA pins ssrf" — true that ssrf is pinned, but it's pinned for ANY mode, not specifically HIPAA.
- An auditor reviewing the screenshot would conclude the WAF has per-regime detector mandates, when it really has one cluster-wide "any compliance active → these 4 classes locked" rule.

**Fix in this PR:** replace the per-mode table with a truthful "Pinned detector classes" panel showing the 4-class list with a one-line note that ANY active mode locks these. Remove the per-mode invention.

**Aspirational follow-up (tracked here, not in this PR):** if operators genuinely want per-regime pinning (PCI 6.5 vs HIPAA §164.312 mandate slightly different detector classes when read strictly), implement real per-mode pinning in `aegis-control/src/api/detectors.rs` — change `COMPLIANCE_PINNED` from a flat list to a `match mode { Pci => &[...], Hipaa => &[...], ... }`. Then expose the canonical clamp table via `GET /api/compliance/clamps` so the dashboard reads from the source-of-truth instead of duplicating it. **Effort: ~3 hours. Out of scope for this audit PR.**

---

### 🟡 Empty-state-by-config: Threat Intel

**File:** `crates/aegis-control/assets/dashboard/src/pages.jsx:7545`

The page polls real endpoints — `/api/threat-intel/hits`, `/api/threat-intel/feeds`, `/api/geoip/status`. All three return correct data once configured. The dev YAML doesn't ship with TAXII feeds or a MaxMind .mmdb path, so the page renders empty cards.

**The page already explains this correctly** — there's a "What you'll see here" panel that fires when both feeds and GeoIP are absent, plus per-section empty states with YAML setup hints. The user perception of "hardcoded for now" is the empty-state rendering being mistaken for fake placeholder data.

**No fix needed in this PR.** The page is honest and behaves correctly.

**Future feature gap (not a bug):** there's no audit-mutated feed CRUD UI. Operators can't add a TAXII feed via the dashboard — they edit YAML and reload. A feed-management page (`PUT /api/threat-intel/feeds`) would close this gap but requires backend work (the TAXII/MISP fetcher stays the same; just adding a CRUD layer). **Effort: ~1 day. Tracked separately.**

### 🟡 Empty-state-by-config: AI Detector metrics

**File:** `pages.jsx::AiDetectorRow` (Detectors page).

When `cfg.ai.enabled = false` (the default — most operators don't ship an ONNX model), the AI panel shows "feature off" pill and the metrics card shows zeros. This is correct behaviour — the AI detector isn't running, so there are no metrics to show. The empty state is well-labelled.

### 🟡 Empty-state-by-config: mTLS connection / failure trackers

**File:** `pages.jsx::PageSettings` mTLS section.

When `cfg.tls.client_auth` is unset (the default for HTTP-only dev), the mTLS connection tracker is `None` and the page shows "mTLS not configured". Correct.

---

### 🟢 Real APIs (no action needed)

Spot-checked these and confirmed they read from real endpoints with appropriate empty-state handling:

| Page | Endpoints |
|---|---|
| Overview | `/api/about`, `/api/stats`, `/api/timeseries`, `/api/upstreams/summary`, `/api/attacks/top` |
| Live Feed | `/dashboard/sse` (SSE), audit-bus broadcast |
| Incidents | `/api/incidents`, `/api/alerts` |
| Investigation | `/api/audit/since` (filtered) |
| Top Attackers | `/api/attacks/top`, `/api/attacks/distribution` |
| Rules | `/api/rules`, `/api/rules/{id}/stats` |
| Detectors | `/api/detectors` (with score_table), `/api/ai/enabled` |
| Access Lists | `/api/blacklist`, `/api/whitelist` |
| Routing & Upstreams | `/api/routes`, `/api/upstreams`, `/api/upstreams/config` |
| Traffic Gates | `/api/blacklist`, `/api/whitelist`, `/api/risk`, `/api/gates/ddos` |
| Performance | `/api/timeseries`, `/api/route-latency`, `/api/detector-latency` |
| Health & SLOs | `/api/slo`, `/api/cluster`, `/api/upstreams/health` |
| Audit Trail | `/api/audit/since` (paginated) |
| Scaling | `/api/runtime`, `/api/cluster`, `/api/state` |
| Settings | `/api/config`, `/api/mode`, `/api/risk/thresholds`, `/api/loadmode`, etc. |
| Reports | `/api/audit/since`, `/api/attacks/top`, server-rendered CSV |

Hardcoded UI constants (`CAT_COLOR`, `MASK_CLASSES`, `LB_OPTIONS`, `RECEIVER_KIND_LABELS`, etc.) are colour palettes / dropdown options / display labels — appropriate UI-only; not source-of-truth issues.

---

## What this PR does

1. **Fix Compliance page honesty** — replace `COMPLIANCE_CLAMPS` per-mode invention with a truthful "Pinned classes" panel reflecting the actual Rust `COMPLIANCE_PINNED` (4 classes, any active mode).
2. **Add a one-line link from Compliance page to the source code** so operators can verify the truth themselves.
3. **This audit doc** (the file you're reading) tracking findings + future follow-ups.

## Future work tracked here (not in this PR)

| # | Item | Effort | Reason for deferral |
|---|---|---|---|
| 1 | Real per-regime pinning (PCI vs HIPAA vs SOC2 vs GDPR vs FIPS map to different detector lists) | ~3 hr | Operator hasn't asked for it; honesty fix above is sufficient until they do. |
| 2 | TAXII / MISP feed CRUD UI | ~1 day | Backend wiring needed for audit-mutated feed add/remove; bigger than a quick fix. |
| 3 | Compliance page modes editor (toggle PCI on/off without YAML + restart) | ~half day | Hot-reload of `cfg.compliance.modes` doesn't exist; would need backend swap path. |
| 4 | Rate-limit summary endpoint `/api/rate-limit` so the Traffic Gates rate-limit card lights up | ~1 hr | Currently the Traffic Gates page renders an empty-state hint for that card. |
| 5 | DDoS hot-reload of thresholds | ~half day | Currently YAML + restart only. ArcSwap wrap of `DdosConfig` would close it. |

Cross-link these as separate PRs if/when prioritised.

---

## Cross-refs

- [`docs/control-plane/dashboard.md`](../../../docs/control-plane/dashboard.md) — page-by-page surface map
- [`crates/aegis-control/src/api/detectors.rs:99`](../../../crates/aegis-control/src/api/detectors.rs) — `COMPLIANCE_PINNED` source-of-truth
- [`crates/aegis-control/assets/dashboard/src/pages.jsx`](../../../crates/aegis-control/assets/dashboard/src/pages.jsx) — Page* components
- [`docs/operator/traffic-gates.md`](../../../docs/operator/traffic-gates.md) — recently-added operator guide for the Traffic Gates page
