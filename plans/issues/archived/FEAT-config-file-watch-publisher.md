# FEAT — file watcher becomes a publisher into `config:waf:doc` (end dual authority)

- **Type:** FEAT (config plane / hot reload)
- **Status:** 🟢 Shipped — PR #77, merged to `develop` 2026-06-23.
- **Wave:** Wave 1 of [`../../implementation-sequence.md`](../../implementation-sequence.md);
  Horizon 1 · **P1+P2** of [`../../future/config-single-source-of-truth.md`](../../future/config-single-source-of-truth.md).
- **Effort:** M.
- **Area:** `crates/aegis-core/src/config.rs` (`ConfigPlaneConfig` + `FileWatchMode`);
  `crates/aegis-proxy/src/supervisor.rs` (watcher rewrite); `crates/aegis-proxy/src/run.rs` (spawn wiring).

## Problem

The file watcher and the shared-store (Redis) watcher both wrote the **same**
live `cfg_swap` with no precedence — the dual authority behind the "I change one
key and another moves" report (failure modes A/B/D of the plan). The file watcher
also omitted `apply_cfg_change_to_receivers`, an apply-path asymmetry the
shared-store structural guard didn't cover.

## What shipped

- **`config_plane.file_watch`** flag (`publish` default | `off`), new
  `ConfigPlaneConfig` section, `#[serde(default)]` so existing YAMLs parse.
- **File watcher inverted to a publisher** (`supervisor.rs`): on a file change it
  validates (`load_config`), reads the verbatim blob, **dedups** against the
  active `config:waf:doc`, and `activate`s a new version. It no longer touches
  `cfg_swap` or calls any `apply_cfg_change_to_*` helper. ~470 lines of inline
  apply logic + the 9 apply-target params removed; `spawn_config_watcher` is now
  `(path, ConfigStore, bus)`.
- **Single applier:** the shared-store watcher's `apply_and_swap` is the only
  thing that swaps the live data plane → its structural guard
  (`redis_source.rs`) now covers every section (fixes the `receivers` asymmetry).
- **Log-and-converge** on CAS `Conflict` (a peer/API edit won; the applier
  applies the winner — no retry). `off` mode = bootstrap-only (no watcher spawned).
- **run.rs** builds a `ConfigStore` from the state backend for the publisher and
  gates the spawn on the flag; dropped the now-unused `folded_targets`.

## Tests

- `publish_activates_new_version_on_change`, `publish_skips_when_file_matches_active_doc`
  (dedup), `publish_rejects_invalid_config_and_keeps_active` (NACK + audit),
  `reload_on_file_change_publishes_new_version` (end-to-end watcher → publish).
- The 8 old `hot_reload_*` apply tests were removed — that apply behaviour is
  covered at the applier layer (`config_source::reload` route/tls/rate/risk/
  compliance tests + `redis_source::apply_and_swap_invokes_every_reload_helper`).
- `aegis-proxy` lib **968+ green** (one unrelated pre-existing flake:
  `upstream::forward::pooled_keep_alive_reuses_tcp_connection`, passes 3/3 in
  isolation); `aegis-core` 318 green; clippy clean for the new code.

## Follow-ups (not in this change)

- H2a structural `BootstrapConfig`/`DynamicConfig` type split; H2b etcd backend.
- Optional: wire the config-plane nudge into the file publisher so the applier
  converges in ~ms instead of the ≤3 s poll (today: log-and-converge via poll).
</content>
