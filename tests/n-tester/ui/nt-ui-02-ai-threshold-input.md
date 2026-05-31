# NT-UI-02 · AI confidence_threshold input — Save updates the live value

**Covers:** AI threshold adjust (commit `e77d379`) ·
**Prereq:** cluster running, Chrome logged in to http://127.0.0.1:9443 ·
**Expected duration:** ~4 min · **Severity if failing:** **Critical**

## Test

**Given** the dashboard is open and the binary is built with
`--features ai` (so the AI detector row is active, not a "feature off"
banner).

**When** the operator opens the **Detectors** page, finds the **AI (ml)**
row, expands it via the "▸ details" link, adjusts the **Confidence
threshold** input to a new in-range value, and clicks **Save**.

**Then** a green toast appears with the new value, the **live** label
updates to the new value within ~10 s, and a follow-up GET on
`/api/ai/confidence` from a terminal returns the same number.

## Paste-to-Claude (copy verbatim)

> Drive Chrome to http://127.0.0.1:9443/. In the left sidebar, click
> "Detectors". On the page, scroll until you see the AI row — the cell
> on the left says **AI (ml)**. If the row says "feature off" or the
> status pill says "🔒 feature off", STOP and tell me; this binary
> wasn't built with `--features ai`.
>
> Otherwise, click the **▸ details** link on the right side of the row
> to expand it. You should see a "Confidence threshold" label with a
> numeric input next to it. Tell me:
>
> 1. The current value in the input box.
> 2. The "default: X" number printed below the label.
> 3. The "live: X" number printed to the right of the Save button.
>
> Then clear the input, type `0.50`, and click **Save**. Wait up to 10
> seconds. Tell me:
>
> 4. The toast message that appeared (top-right of the page).
> 5. The new "live: X" number after the toast.
> 6. Whether the "default: X" number changed (it should NOT — it's the
>    cfg-loaded value, not the live one).
>
> Take a screenshot of the AI row in its expanded state after the save.

(Optional terminal sanity check, in parallel — verifies the live value
matches what Claude saw:)

```sh
COOKIE=$(curl -ksi -X POST http://127.0.0.1:9443/admin/login \
  -H 'content-type: application/json' \
  -d '{"user":"admin","password":"aegis-test-1234"}' \
  | grep -i 'set-cookie: aegis_session=' | sed -E 's/.*aegis_session=([^;]+).*/\1/' | tr -d '\r')
curl -ks http://127.0.0.1:9443/api/ai/confidence \
  -H "Cookie: aegis_session=$COOKIE" | jq
# Expect: { "confidence_threshold": 0.5, "default": 0.85, "feature_present": true }
```

## Pass criteria

- [ ] The input pre-fills with the **live** value (not blank, not the
      default — unless those happen to be equal at boot).
- [ ] The default label shows the cfg value (typically `0.85`).
- [ ] Clicking Save with a valid in-range value produces a green toast
      reading **"Confidence threshold set to 0.50"** (or whatever was
      typed).
- [ ] "live" updates to the new number **within 10 s**.
- [ ] "default" does NOT change.
- [ ] The terminal curl agrees with what Claude reported.

## Findings template

- Before / after values seen.
- Toast text + colour.
- Screenshot file name.
- Any > 10 s convergence (warn-level, not fail unless > 30 s).
