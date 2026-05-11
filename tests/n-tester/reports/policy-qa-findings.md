# Aegis WAF · Policy Section QA Findings
**Scope:** Policy pages — Rules, Detectors & Tiers, Access Lists, Routing & Upstreams, Traffic Gates  
**Mode:** Functional QC (SOC-analyst end-user lens)  
**Date:** 2026-05-11  
**Tester:** Claude (Aegis-WAF-Tester skill)  
**Build:** v0.1.0 · Session uptime ~58 min at wrap

---

## Executive Summary

All five Policy pages mount cleanly with no error-boundary crashes. Data across every page is live and consistent with API responses — no fake data, no stale placeholders, no dead routes. The overall UX quality is high, especially for Routing & Upstreams and Traffic Gates, which contain excellent in-context documentation and safety caveats.

**One HIGH-severity bug** blocks a core workflow: the Rules Simulator sends a successful API request but the result panel never renders, making the tool completely unusable in the UI. Beyond that, four MEDIUM issues reduce operator confidence or create unsafe failure modes.

| Severity | Count |
|---|---|
| HIGH | 1 |
| MEDIUM | 4 |
| LOW | 4 |
| INFO / UX Suggestion | 4 |

---

## Findings

---

### F-01 · HIGH — Rules Simulator result never renders

**Page:** Policy → Rules → Simulate tab  
**Repro:** Open Rules → click "Simulate" tab → fill Method, Path, Body fields → click "Run simulation" button.

The button triggers a POST to `/api/rules/simulate` which returns HTTP 200 with a well-formed JSON body:

```json
{
  "decision_action": "block",
  "rule_id": "sqli",
  "risk_score": 40,
  "detectors_fired": ["sqli"],
  "signals": [{"class": "sqli", "detail": "uri"}],
  "tier": "low",
  "muted_detectors": ["brute_force"]
}
```

Despite the successful response, the result panel in the UI never updates. It remains blank. The simulation output (`decision_action`, `risk_score`, `detectors_fired`) is never displayed to the operator.

**Confirmed via:** network request monitoring (`read_network_requests`) + direct `fetch()` in `javascript_tool` both returned valid JSON. The UI component is not consuming or rendering the response.

**Impact:** The Simulate tab is the primary tool for testing whether a new rule will actually block/allow a given request before deployment. With it broken, operators must deploy rules blind and rely on live traffic to verify correctness — increasing risk of both false-positives and missed blocks.

**Recommendation:** Fix the React state update in the Simulate panel's `onSuccess` handler. Ensure the result object from the API is bound to the display state. Add a test that checks the result panel's DOM contents after a successful simulate call.

---

### F-02 · MEDIUM — Silent validation failure on empty required fields

**Pages:** Policy → Rules (Rule ID field), Policy → Access Lists (Value field)  
**Repro:**  
- Rules: open "Add rule" → leave Rule ID empty → click Save  
- Access Lists: open "Add entry" → leave Value empty → click Submit

In both cases, the submit button appears to do nothing. The form does not submit, but zero feedback is shown to the operator — no inline error message, no border highlight, no toast notification. Inspection confirms `validationMessage` is empty and no error CSS classes are applied.

**Impact:** SOC analysts will click Submit, see nothing happen, and have no idea whether the form failed, is loading, or has a bug. This is especially confusing on a dark theme where the missing visual feedback is hard to notice.

**Recommendation:** On invalid submission attempt, show an inline error beside the empty field (e.g., red border + "Rule ID is required") and focus the first invalid input. This applies to all required fields across the Policy section, not just these two.

---

### F-03 · MEDIUM — Audit Log deep-link from Rules Stats tab loses context

**Page:** Policy → Rules → Stats tab  
**Repro:** Navigate to Rules → click "Stats" tab → click "Audit Log" link/button.

Navigation goes to `#/audit` (the Audit Trail page), but the `rule_id` filter field is left empty. The analyst lands on an unfiltered audit view with thousands of rows and must manually re-enter the rule ID they just came from.

**Expected:** The link should deep-link to `#/audit?rule_id=<current-rule-id>` (or equivalent hash parameter) so the Audit Trail page pre-fills the filter for that rule.

**Impact:** Medium friction for any investigative workflow that starts from "how many times has rule X fired?" — a very common SOC use case.

**Recommendation:** When constructing the "Audit Log" link in the Stats tab, append the current rule's ID as a query/hash parameter and have the Audit Trail page read it on mount to pre-populate its filter.

---

### F-04 · MEDIUM — AI/ML detector Enable shows no ONNX model warning

**Page:** Policy → Detectors & Tiers  
**Repro:** Scroll to the AI/ML detector card (grayed out) → click "Enable".

The badge immediately flips to ENABLED. There is no check or warning about whether the required `.onnx` classifier model file is present on disk. If the model file is absent, the detector will silently fail (either passing all traffic or erroring internally) with no visible indication in the dashboard.

**Impact:** An operator who enables the AI detector without the model file may believe attack detection is running when it is not.

**Recommendation:** On Enable, call a preflight check (or read from a `/api/detectors/ai/status` endpoint) to verify the ONNX model is loaded. If it is not, show a warning: *"No ONNX model found at the configured path. AI detection will be disabled until the model file is present."* Block the toggle or show a persistent warning badge while the model is absent.

---

### F-05 · MEDIUM — Compliance mode flip has no confirmation or rollback path

**Page:** Policy → Detectors & Tiers → Compliance tab  
**Repro:** Select a compliance profile (e.g., PCI-DSS) from the dropdown.

The profile is applied immediately with no confirmation dialog. Some compliance profiles lock specific detector classes (e.g., forcing SQLI to always-on regardless of the base mask). There is no "Revert to previous profile" option visible in the UI.

**Impact:** An accidental profile change during an incident response could silently alter the WAF's detection posture. The operator has no one-click rollback.

**Recommendation:** Add a confirmation dialog: *"Switching to PCI-DSS will lock 3 detectors and may change active tier thresholds. Continue?"* Also add an audit entry noting the previous profile so it can be restored.

---

### F-06 · LOW — Detector Disable has no confirmation guard

**Page:** Policy → Detectors & Tiers  
**Repro:** Click "Disable" on any active detector.

The detector is immediately disabled with no confirmation prompt. Compare this to the Rules page, where Delete opens a styled confirmation modal. The inconsistency means disabling a detector (a policy change with broad traffic impact) is less protected than deleting a single rule.

**Recommendation:** Add a one-click "Are you sure?" confirmation for Disable, consistent with the Rules Delete pattern. Message should name the detector class and note the traffic impact (e.g., *"Disabling SQLI detection will stop blocking SQL injection attempts."*).

---

### F-07 · LOW — Access Lists Remove button uses native browser confirm()

**Page:** Policy → Access Lists (Blacklist and Whitelist tabs)  
**Repro:** Click the "Remove" button on any blacklist or whitelist entry.

The browser displays a native `window.confirm()` dialog with the message "Remove blacklist entry ip:10.0.0.1?". Confirmed by intercepting `window.confirm` in the browser console.

**Issue:** The native dialog bypasses the app's dark-themed styling, looks jarring on a polished SOC dashboard, and can be disabled/auto-dismissed by browser settings. The Rules page, by contrast, uses a styled in-app modal for Delete confirmation — inconsistent UX pattern.

**Recommendation:** Replace `window.confirm()` with the same styled confirmation modal used elsewhere (or a small inline confirmation state on the row). The modal should show the entry's type, value, and a "Remove" / "Cancel" button pair styled to match the rest of the app.

---

### F-08 · LOW — "Add entry" button icon persists on Cancel state

**Page:** Policy → Access Lists (both tabs)  
**Repro:** Click "+ Add entry" to open the inline form.

The button label changes from "+ Add entry" to "+ Cancel" — but retains the `+` icon on a Cancel action. A `+` icon semantically means "create/add"; showing it next to "Cancel" is contradictory and may cause a moment of hesitation for the operator.

**Recommendation:** Change the icon to `×` or remove it entirely when the button is in its Cancel state: just "Cancel" or "× Cancel".

---

## UX Observations & Suggestions

These are not bugs but are flagged per the "comfort as a SOC analyst" lens.

---

### U-01 · INFO — Gate 3 Challenge threshold slider appears stuck

**Page:** Policy → Traffic Gates → Gate 3 (Cumulative IP Risk)  
**Observation:** The Challenge IP score slider label reads "(99998 – 99998)" — a 1-point-wide range. This is mathematically correct when the Allow threshold slider is at its maximum value (99997), but visually it looks like the slider is broken or stuck.

**Suggestion:** Add a tooltip or inline note: *"Move the Allow threshold left to widen the challenge zone."* Or show a banner when thresholds collapse to a 1-unit range: *"Challenge zone is 1 point wide — consider lowering the Allow threshold."*

---

### U-02 · INFO — DDoS Gate tightened_per_ip_rps displayed but not editable

**Page:** Policy → Traffic Gates → Gate 5 (DDoS Gate)  
**Observation:** The Configured Thresholds grid shows `tightened_per_ip_rps = 20 (cap during spike)`. This field was not visible in the "Edit DDoS gate thresholds" modal during testing.

**Question for dev team:** Is `tightened_per_ip_rps` a derived value (auto-computed from other fields) or is it independently configurable? If configurable, it should appear in the edit form. If derived, add a note next to it like *"derived: effective_rate ÷ spike_multiplier"* to explain the calculation.

---

### U-03 · INFO — Rules Simulator state lost on navigation

**Page:** Policy → Rules → Simulate tab  
**Observation:** If the operator navigates away from the Rules page (e.g., to check Access Lists) and returns, the Simulate tab reverts to its empty state — all fields cleared, any previous result gone.

**Suggestion:** Persist the simulator form state in component memory or sessionStorage so operators can multi-task without losing their test case.

---

### U-04 · POSITIVE — Routing & Upstreams "Test route" tool is excellent

**Page:** Policy → Routing & Upstreams  
**Observation:** The "Test route" panel (▼/▲ toggle) allows operators to input a synthetic Host + Method + Path and immediately see which route would match, which pool it forwards to, and the effective tier — all without generating an audit entry. This is a standout UX feature that will save significant debugging time when routing rules overlap.

**Also positive:** The "Edit pool" modal subtitle — `audit-mutated · CSRF-gated · hot-swap (no restart)` — transparently communicates three important operational properties of any pool edit. Excellent in-context documentation.

---

## Page Coverage Matrix

| Page | Mounts | Data vs API | Controls | Empty States | Issues |
|---|---|---|---|---|---|
| Rules | ✅ | ✅ (0 rules = 0 total) | ⚠️ Simulate broken (F-01), silent validation (F-02), Audit link (F-03) | ✅ | F-01, F-02, F-03 |
| Detectors & Tiers | ✅ | ✅ (brute_force=false matches UI) | ⚠️ No Disable confirm (F-06), AI warning (F-04), Compliance (F-05) | ✅ | F-04, F-05, F-06 |
| Access Lists | ✅ | ✅ (counts match API) | ⚠️ Native confirm (F-07), + icon on Cancel (F-08) | ✅ "No entries." | F-07, F-08 |
| Routing & Upstreams | ✅ | ✅ (1 route → stub-pool → 127.0.0.1:9999) | ✅ All controls functional | ✅ "No routes match X." + Clear | — |
| Traffic Gates | ✅ | ✅ (0 BL/WL entries, 0 risk tracked) | ✅ All 5 gate Edit forms functional | n/a | U-01, U-02 |

---

## API Verification Summary

All displayed data cross-checked against live API responses during the test run. No discrepancies found outside of the Simulate result rendering bug (F-01).

| UI Element | API Endpoint | Match |
|---|---|---|
| Rules "0 total" | `GET /api/rules` → `{"rules":[]}` | ✅ |
| Detector brute_force strikethrough | `GET /api/detectors` → `mask.brute_force: false` | ✅ |
| Blacklist "0 entries LIVE" | `GET /api/blacklist` → 0 entries | ✅ |
| Whitelist "0 entries LIVE" | `GET /api/whitelist` → 0 entries | ✅ |
| Route "#1 catch-all / → stub-pool · 127.0.0.1:9999" | `GET /api/routes` + `/api/upstreams/config` | ✅ |
| Strike-Block "0 of 0 tracked IPs" | `GET /api/risk` → `total_tracked: 0` | ✅ |
| Traffic Gates BL/WL entry counts | `GET /api/blacklist`, `/api/whitelist` | ✅ |

---

*End of report — 5/5 pages tested, 8 findings filed, 4 UX observations.*
