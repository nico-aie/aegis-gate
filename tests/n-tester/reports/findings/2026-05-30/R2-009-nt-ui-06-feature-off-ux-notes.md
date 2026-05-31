---
id: 2026-05-30-nt-ui-06-feature-off-ux-notes
date: 2026-05-30T20:55Z
severity: LOW
area: dashboard
component: detectors-page / AI row (feature_off state)
status: open
test_mode: full-qc
---

# NT-UI-06 passes with three small UX notes on the feature-off rendering

## Summary

NT-UI-06 expects the AI row, in the feature-off state, to surface a
disabled threshold input, a disabled Save button, the 🔒 pill, and
a rebuild hint. Live test on a binary that has `--features ai` built
in but no ONNX model linked (so `feature_present: false`) reveals:

- The 🔒 pill renders ✓
- The rebuild hint renders ✓ — and helpfully names `cfg.ai.model_path`
  + `make ai-link MODEL=<path>` (good)
- The threshold input is **not rendered at all** (vs playbook's
  "disabled and visible")
- The Save button is **not rendered at all** (consistent with input absence)
- The Enable button **is rendered disabled** ✓

So this UI hides the controls rather than disabling them. That's
defensible UX (no broken affordance to confuse the operator), but
diverges from the playbook spec. Three small sub-findings worth
tightening before they bite a real operator:

### Sub-finding A — input + Save hidden rather than disabled-and-visible

The playbook's expectation is reasonable: a disabled input showing
the cfg default lets the operator see "0.85" without rebuilding
anything. The hidden-controls variant requires the operator to read
the (currently truncated by container layout) rebuild hint to know
the default exists.

**Fix:** render the input read-only with the cfg default as the
value, OR add a one-line "current default: 0.85" caption next to
the rebuild hint.

### Sub-finding B — disabled Enable button has no title / aria-label / aria-disabled

```js
{ disabled: true, title: null, aria_label: null, aria_disabled: null,
  cursor: "pointer" }
```

The native `disabled` attribute prevents clicks, but a screen reader
gets no semantic context for *why*. The button's `cursor:` is also
`pointer` (not `not-allowed`), which on hover wrongly implies the
button is actionable. Minor a11y miss flagged as part of NT-UI-07's
intent.

**Fix:** add `title="AI feature not built — see hint below"` and
`aria-disabled="true"` (in addition to `disabled`), and set
`cursor: not-allowed` in the disabled-state CSS.

### Sub-finding C — server-side feature-off message mis-references the gate

`PUT /api/ai/enabled` while feature_present is false returns:

```json
{
  "ok": false,
  "reason": "feature_off",
  "message": "AI detector not wired — rebuild with FEATURES=\"… ai\" and set cfg.ai.enabled = true"
}
```

But the gate that drove `feature_present: false` on this binary is
**`cfg.ai.model_path` being unset**, not `cfg.ai.enabled`. The
binary already has `--features ai`. Following the message verbatim
("rebuild with … ai") wastes 10 minutes; the actual fix is
`make ai-link MODEL=<path>` + setting `cfg.ai.model_path`.

The dashboard's own hint message (the one rendered next to the row,
visible on the Detectors page) is correct — it names
`cfg.ai.model_path` and `make ai-link`. The server-side error
message is stale.

**Fix:** in `handle_ai_enabled_put`'s feature_off branch, replace
the suggestion with the same wording the UI already uses
("rebuild with --features ai and set cfg.ai.model_path to a valid
ONNX file") — and ideally check the binary's feature flag at
runtime (it's `cfg!(feature = "ai")` at compile time, exposed via
`/api/about`?) so the message can be precise: if `ai` feature is
present but model_path is unset, say so; if `ai` feature isn't
present, say *that*.

## Repro

```sh
# Binary built --features "redis geoip alerts ai affinity",
# cluster-a.yaml has no `ai:` block (so model_path unset).
curl -s http://127.0.0.1:9443/api/ai/confidence \
  -b /tmp/login-jar | jq
# → { "confidence_threshold": 0.85, "default": 0.85, "feature_present": false }

# Try Enable bypassing the disabled UI:
curl -s -X PUT http://127.0.0.1:9443/api/ai/enabled \
  -H 'content-type: application/json' \
  -H "x-csrf-token: $CSRF" -b /tmp/login-jar \
  -d '{"enabled": true}'
# → 409 {"ok":false,"reason":"feature_off","message":"AI detector not wired —
#         rebuild with FEATURES=\"… ai\" and set cfg.ai.enabled = true"}
# Note the message recommends an irrelevant action for this binary.
```

## Severity rationale

LOW because each sub-finding is a small polish item, none of them
break the core flow (operator can still read the row hint, see
🔒 feature off, and figure it out). The combined nudge would
genuinely help a first-time integrator.

The playbook's overall Pass criteria are met:

- [x] Pill reads "🔒 feature off"
- [x] Threshold control is non-editable (by omission — see sub-A)
- [x] Default visible (in the hint, not in an input — see sub-A)
- [x] Save disabled (by omission)
- [x] Rebuild hint visible
- [x] Enable button doesn't 500 — returns clean 409 with a reason
