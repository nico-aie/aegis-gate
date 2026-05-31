# NT-UI-01 · Scaling page shows two nodes + ConfigVersionCard tracks version

**Covers:** cluster config plane (`plans/archive/cluster-config-sync-and-scaling.md`) ·
**Prereq:** cluster running, Chrome logged in to http://127.0.0.1:9443 ·
**Expected duration:** ~3 min · **Severity if failing:** High

## Test

**Given** the WAF cluster is running with 2 nodes (A on 9443, B on 9543)
and the operator is logged in to the dashboard at A.

**When** the operator opens the Scaling page and inspects the
ConfigVersionCard.

**Then** the card lists **both nodes** with their per-node ACK version,
and the **active version** number matches what `GET /api/config` returns
on either node. After a config change (any folded toggle), the card
updates within ~5 s.

## Paste-to-Claude (copy verbatim)

> Drive Chrome to http://127.0.0.1:9443/. The page should already be
> the admin dashboard (logged in). In the left sidebar, click "Scaling".
> Find the panel/card titled "Config version" or "ConfigVersionCard"
> (it's near the top of the page). Tell me:
>
> 1. The **active version** number shown on the card.
> 2. The list of **nodes** (node IDs) with their **applied version**.
> 3. Whether any node is flagged as the **leader**.
>
> Then take a screenshot of the card. After that, I'll make a config
> change in a terminal — wait for me to say "changed", then re-read the
> card and tell me the new active version + applied versions.

(While Claude waits, in a terminal:)

```sh
COOKIE=$(curl -ksi -X POST http://127.0.0.1:9443/admin/login \
  -H 'content-type: application/json' \
  -d '{"user":"admin","password":"aegis-test-1234"}' \
  | grep -i 'set-cookie: aegis_session=' | sed -E 's/.*aegis_session=([^;]+).*/\1/' | tr -d '\r')
CSRF=$(curl -ksi -X POST http://127.0.0.1:9443/admin/login \
  -H 'content-type: application/json' \
  -d '{"user":"admin","password":"aegis-test-1234"}' \
  | grep -i 'set-cookie: aegis_csrf=' | sed -E 's/.*aegis_csrf=([^;]+).*/\1/' | tr -d '\r')
curl -ks -X PUT http://127.0.0.1:9443/api/response-filter \
  -H "Cookie: aegis_session=$COOKIE; aegis_csrf=$CSRF" \
  -H "x-csrf-token: $CSRF" -H 'content-type: application/json' \
  -d '{"scrub_stack_traces": false}'
# Tell Claude "changed".
```

## Pass criteria

- [ ] **2 distinct node IDs** appear in the ConfigVersionCard.
- [ ] Each node has an **applied version** number (not "—" or null).
- [ ] **Exactly one** node is marked as leader (or "n/a" if the lease
      layer isn't active — note which).
- [ ] After the terminal change + "changed" prompt, the card's active
      version increments **within 10 s**, and both nodes' applied
      versions catch up.

## Findings template (for the QC run note)

- What the card showed before / after.
- Screenshot file name (drop into `tests/n-tester/reports/`).
- Any node stuck at an old applied version > 10 s after the change.
