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

| # | Item | Effort | Status |
|---|---|---|---|
| 1 | Real per-regime pinning (PCI vs HIPAA vs SOC2 vs GDPR vs FIPS map to different detector lists) | ~3 hr | Open — operator hasn't asked for it; honesty fix above is sufficient until they do. |
| 2 | TAXII / MISP feed CRUD UI | ~1 day | Open — backend wiring needed for audit-mutated feed add/remove. |
| 3 | Compliance page modes editor (toggle PCI on/off without YAML + restart) | ~half day | Open — hot-reload of `cfg.compliance.modes` doesn't exist; would need backend swap path. |
| 4 | Rate-limit summary endpoint + hot-reload | ~1 hr | ✅ **Shipped 2026-05-09 (later commit)** — `GET /api/rate-limit` + audit-mutated `PUT /api/rate-limit` + Traffic Gates edit modal |
| 5 | DDoS hot-reload of thresholds | ~half day | ✅ **Shipped 2026-05-09 (later commit)** — `DdosDetector::config` wrapped in ArcSwap, audit-mutated `PUT /api/gates/ddos`, Traffic Gates edit modal |
| 6 | Tier `block_threshold` (req/s) field is dead UI | ~30 min | ✅ **Shipped 2026-05-09 (later commit)** — hidden from Edit-tier modal; pointer added to the Traffic Gates page where real per-IP limits live |

### Tier `block_threshold` finding (added 2026-05-09)

The Detectors page Edit-tier modal showed a "Block threshold (req/s)" input that's purely descriptive — not enforced anywhere. Source comment in `crates/aegis-control/src/api/tiers.rs:36-44`:

> Note that the pipeline field today is **descriptive metadata only** — the data plane gates detectors via the detector mask (`is_enabled_id`), not by walking this string list. ... Real tier-scoped execution is a follow-up.

Same applies to `block_threshold`. Operators tuning the field believed they were configuring a per-tier rate cap; in reality the field was stored and rendered but had zero runtime effect. Real per-IP rate limits live in `cfg.rate_limit.buckets` (with hot-reload via the new Traffic Gates Rate Limit card).

**Fix shipped:** hide the input from the Edit-tier modal + remove the `block ≥ X/s` chip from the tier list view + add an inline note "per-IP volumetric limits live on the Traffic Gates page". The `block_threshold` value is still POSTed (for audit-stream stability) but operators no longer waste time tuning it.

### Hot-reload story now consistent across all four gates (added 2026-05-09)

All four request-flow gates now hot-reload through audit-mutated PUT endpoints:

| Gate | Endpoint | Hot-reload? |
|---|---|---|
| Access list | `POST /api/blacklist`, `POST /api/whitelist` | ✅ |
| Strike-block | `PUT /api/risk/thresholds` | ✅ |
| Rate-limit | `PUT /api/rate-limit` | ✅ (new 2026-05-09) |
| DDoS gate | `PUT /api/gates/ddos` | ✅ (new 2026-05-09) |

Per-IP state is preserved across edits in all four — flooding sources don't get a free reset when operators tighten thresholds mid-attack.

Cross-link these as separate PRs if/when prioritised.

---

## Cross-refs

- [`docs/control-plane/dashboard.md`](../../../docs/control-plane/dashboard.md) — page-by-page surface map
- [`crates/aegis-control/src/api/detectors.rs:99`](../../../crates/aegis-control/src/api/detectors.rs) — `COMPLIANCE_PINNED` source-of-truth
- [`crates/aegis-control/assets/dashboard/src/pages.jsx`](../../../crates/aegis-control/assets/dashboard/src/pages.jsx) — Page* components
- [`docs/operator/traffic-gates.md`](../../../docs/operator/traffic-gates.md) — recently-added operator guide for the Traffic Gates page
