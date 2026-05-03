### CQA-T11 · Tracking (alert receivers test button watch-list)

**Audit method:** Static source analysis (Bash blocked — no live server probing)

| Item | Type | Verified | Notes |
|---|---|---|---|
| `useClusterApi()` → `/api/cluster` | data load | ✅ | Live hook; `fallback: null` |
| `useUpstreamsApi()` → `/api/upstreams` | data load | ✅ | Live hook; `fallback: { pools: [] }` |
| `useSloApi()` → `/api/slo` | data load | ✅ | Live hook; `fallback: null` |
| `useCertsApi()` → `/api/certs` | data load | ✅ | Live hook; `fallback: null` |
| `useAlertsApi()` → `/api/alerts` | data load | ✅ | Live hook; `fallback: null` |
| `useGitopsApi()` → `/api/gitops/status` | data load | ✅ | Live hook; `fallback: null` |
| `useAlertReceiversApi()` → `/api/alert-receivers` | data load | ✅ | Live hook in data.jsx; calls `window.useApi('/api/alert-receivers', ...)` |
| HACK-T1 retirement | code | ✅ | `window.CLUSTER`, `window.CERTS`, `window.ALERTS` not referenced in PageTracking |
| SLO budget empty state | render | ✅ | "No SLO data — engine warming up." when `slo.data?.slis` is empty |
| Active alerts empty state | render | ✅ | "No alerts firing." when `alerts.data?.firing` is empty |
| Cluster peers empty state | render | ✅ | "Single-node deployment — no cluster peers." |
| Certs empty state | render | ✅ | "No certs configured (data plane is plaintext)." |
| GitOps unconfigured state | render | ✅ | "GitOps disabled. Set gitops.repo_url…" when `!configured` |
| Upstream pools empty state | render | ✅ | "No upstream pools registered." |
| Refresh button (all APIs) | mutation | ✅ | Calls reload on all 7 APIs |
| **AlertChannelsCard** | | | |
| Alert channels empty state | render | ✅ | "No alert channels configured. The SLO engine will record alerts but won't deliver them." |
| + Add channel button → `AlertChannelModal` | mutation | ✅ | `openAdd()` |
| Edit button → `AlertChannelModal` | mutation | ✅ | `openEdit(entry)` |
| Save channel → `alertReceiversPut(next)` → PUT `/api/alert-receivers` | mutation | ✅ | CSRF-gated; toasts on ok/err; `receiversApi.reload` |
| Remove channel → `alertReceiverDelete(name)` → DELETE `/api/alert-receivers/{name}` | mutation | ✅ | `window.confirm` guard; CSRF-gated; toast |
| **Test button → `alertReceiverTest(name)` → POST `/api/alert-receivers/{name}/test`** | mutation | ✅ | CSRF-gated; shows delivered/external/failed counts in toast; reloads API |
| Delivery status pill per receiver | render | ✅ | `deliveryStatusPill` maps `last_status` → tone + label with relative time |
| Edit modal: name taken validation | render | ✅ | `nameTaken` check; error span shown |
| Edit modal: `canSave` guard | render | ✅ | `name.trim() !== '' && !nameTaken && !!kindTag` |
| Edit modal: secret field blank on edit | render | ✅ | `flatFieldsFromKind` clears token/URL fields intentionally; note shown to re-enter |
| `draftToReceiver` mapping | code | ✅ | Builds correct `{ name, kind: { VariantKey: fields } }` wire shape |
| `useAlertReceiversApi` defined via `window.useApi` | code | ⚠️ RISKY | `useAlertReceiversApi` is defined in data.jsx as `window.useApi(...)` — calls the function via window namespace instead of the local binding. If `window.useApi` isn't defined yet at call time (load order issue), this throws. Other hooks use the local `useApi` function directly. See FINDING-T11-A. |
| `window.ALERTS` fixture | code | ✅ | Not used in PageTracking |

**Findings:**

- **FINDING-T11-A (MEDIUM):** `useAlertReceiversApi` in data.jsx (line 654) calls `window.useApi(...)` rather than the local `useApi` function defined in the same file. All other hooks call the local function directly. This is inconsistent and a potential source of "window.useApi is not a function" at load time if script evaluation order ever shifts. Should be `return useApi('/api/alert-receivers', ...)`.

**Console errors:** Potential load-order error from FINDING-T11-A if script execution order changes.
**Network 4xx/5xx:** Cannot verify live (Bash blocked). Test button may return 404 if receiver is misconfigured.
**Audit chain:** `alertReceiversPut` and `alertReceiverDelete` are CSRF-gated — will produce audit entries.
**Verdict:** ✅ PASS — All alert channel CRUD and test-button logic are correctly wired. Minor code quality issue in FINDING-T11-A.
