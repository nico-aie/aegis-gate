# BUG — config-plane rejects `audit.sinks` map form (`!`-tag mismatch) → all dashboard/PUT config changes fail

- **Type:** BUG
- **Severity:** High — blocks the entire config plane (detector toggles, AI toggle,
  DDoS/risk edits, any `PUT /api/config`) for **any** deployment whose config has an
  `audit.sinks` entry — which **includes the shipped profiles**.
- **Status:** ✅ FIXED — PR #14 (commit `aa25b21`), merged to `develop` 2026-06-10.
  `load_config_str` now validates through figment's `Yaml::string` provider (same
  deserializer as boot), so both the map form (`- jsonl: { … }`) and the tag form
  (`- !jsonl { … }`) round-trip through the config plane. Regression tests
  `load_config_str_accepts_audit_sink_map_form` +
  `load_config_str_still_accepts_audit_sink_tag_form` pass (`aegis-core`).
  Archived — kept for history. (Original triage below; workaround no longer needed.)
- **Affects:** `aegis-proxy` config-plane mutate path + `aegis-core` config enums.
  Found on branch `pre-prod`.

## Symptom (user-reported)
Toggling a detector in the dashboard (Detectors page) returns:
```
Toggle failed: patched config failed validation: config: invalid config:
audit.sinks[0]: invalid type: map, expected a YAML tag starting with '!' at line 121 column 5
```
Line 121 is the audit sink in the running `waf.yaml`:
```yaml
audit:
  sinks:
    - jsonl: { path: "/tmp/aegis-audit.jsonl" }   # ← rejected by the config-plane validator
  chain: { enabled: true }
```

## Expected vs actual
- **Expected:** a config written in the form the **file loader and the shipped
  profiles use** (`- jsonl: { ... }`) round-trips through the config plane; detector
  toggles succeed.
- **Actual:** the config-plane validation deserializes the patched doc with a
  representation that requires the externally-tagged-enum **YAML tag** form
  (`- !jsonl { ... }`) and rejects the map form → every config-plane mutation fails.

## Reproduction
1. Run a node with any config containing `audit.sinks` in map form (e.g. copy
   `config/profiles/prod-balanced.yaml`, or `deploy/waf.contract.yaml`).
2. `./waf validate --config ./waf.yaml` → **`config OK`** (boot path accepts it).
3. In the dashboard, toggle any detector (or `PUT /api/config` / `/api/detectors`).
4. → `patched config failed validation: … audit.sinks[0]: invalid type: map,
   expected a YAML tag starting with '!'`.

## Root cause — two YAML deserialization paths disagree on enum representation

`AuditSinkConfig` is an **externally-tagged enum**
(`crates/aegis-core/src/config.rs:3352`, `#[serde(rename_all = "snake_case")]`;
same shape for `AccessLogSink` at `:3297`). Under **serde_yaml 0.9** (the workspace
pin, `Cargo.toml:35` → `serde_yaml 0.9.34`), externally-tagged enums serialize/
deserialize as a **YAML tag** `!jsonl { … }`, *not* a single-key map `jsonl: { … }`.

The two paths use different deserializers:

| Path | Deserializer | Accepts `jsonl:` (map)? | Accepts `!jsonl` (tag)? |
|---|---|---|---|
| **Boot / `waf validate`** | **figment** YAML provider → serde | ✅ yes | ✅ yes |
| **Config plane** (`PUT`/dashboard) | **raw `serde_yaml::from_str`** | ❌ **no** (the bug) | ✅ yes |

- Boot: `crates/aegis-proxy/src/run.rs` loads via figment, whose value model treats
  the single-key map as the enum variant → map form works (verified: `config OK`).
- Config plane: `crates/aegis-control/src/api/config.rs:105`
  `serde_yaml::from_str(on_disk_yaml)` + re-serialize (`:175`), and the patched doc
  is re-validated into `Config` in `crates/aegis-proxy/src/admin_mutate.rs`
  (`:304/:413/:519/:2057/:2173` "patched config failed validation"). Raw serde_yaml
  0.9 requires the `!jsonl` tag for the externally-tagged enum → map form rejected.

So the **shipped profiles** (`config/profiles/prod-balanced.yaml:150`,
`config/dev.yaml:299`) and `deploy/waf.contract.yaml` — all of which use the map
form — boot fine but **cannot be edited through the config plane**.

### Verified
- `./waf validate` accepts **both** `- jsonl: { … }` and `- !jsonl { … }` → `config OK`.
- Dashboard/PUT accepts **only** `- !jsonl { … }`.

## Impact
- Any node configured with `audit.sinks` (i.e. the documented/shipped way) **cannot
  use the config plane** — detector enable/disable, AI toggle, DDoS/risk threshold
  edits, profile changes all 400 with the validation error.
- Cluster-wide: the config plane is how policy converges across nodes, so this
  effectively **freezes runtime policy** for a standard deployment.
- Likely the same class of issue silently affects the **audit chain not writing**
  (see `multi-node-consistency.md` C-4 / the audit-sink wiring): the audit sink
  representation is inconsistent across the codebase.

## Workaround (operator)
Write `audit.sinks` in the **YAML-tag form** — accepted by **both** boot and the
config plane (verified):
```yaml
audit:
  sinks:
    - !jsonl { path: "/tmp/aegis-audit.jsonl" }
  chain: { enabled: true }
```
Apply to every node's config + reseed the shared config doc (the config plane caches
the running doc), then detector toggles work. ⚠️ This **diverges from the shipped
profiles**, so it's a band-aid, not the fix.

## Suggested fix (dev)
Pick one, in order of preference:
1. **Make enum representation consistent across both paths.** Either annotate
   `AuditSinkConfig`/`AccessLogSink` with an **internally-tagged** representation
   (`#[serde(tag = "type")]`, e.g. `{ type: jsonl, path: … }`) — unambiguous in both
   figment and serde_yaml — and migrate the shipped profiles + docs; **or** add a
   `#[serde(untagged)]`/custom deser that accepts the single-key map under serde_yaml
   too.
2. **Validate via the same loader as boot.** Have the config plane deserialize the
   patched doc through **figment** (the boot path) instead of raw `serde_yaml`, so
   "validates at boot" ⇒ "validates on PUT". Removes the whole class of drift.
3. **Normalize on write.** When the config plane re-serializes the doc
   (`config.rs:175`), emit enums in the form the validator expects *and* the boot
   loader accepts — and update the shipped profiles to that canonical form so files
   and the config plane never disagree.

Add a regression test that **round-trips every shipped profile through the
config-plane validator** (boot-OK ⇒ PUT-OK), and a test that the dashboard detector
toggle succeeds against `prod-balanced.yaml` + `deploy/waf.contract.yaml`.

## Related
- `plans/issues/archived/multi-node-consistency.md` (audit/observability gaps; C-4 audit log).
- The audit-chain jsonl sink not producing a file in this deploy (same audit-sink
  area — worth checking together).
