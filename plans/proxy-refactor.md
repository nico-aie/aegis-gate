# aegis-proxy/src/lib.rs split — `PRE-T*`

> **Status:** Plan only — awaiting confirmation. Operator
> flagged file size during MTLS-T6 wiring (5569 lines, ~7×
> the 800-line guideline). Next slice before more handlers go
> in. Track ID prefix `PRE-T<n>` (Proxy REfactor).

## 0 · Why now

`crates/aegis-proxy/src/lib.rs` accreted ~5500 lines through:

- Phase B (HA / scaling / state backends)
- DD-T* (dashboard redesign + admin endpoints)
- CI-T* (live API integration — every dashboard endpoint added a
  handler in lib.rs)
- CC-T* (config-page mutations)
- ETCD-T1 / OTEL-T*
- CC-T hot-reload pluming (shared cfg-reload helpers + watcher
  spawn)
- MTLS-T1 + MTLS-T6 (mTLS schema + observability handlers)

Each slice was small ("just one more handler") but cumulatively
this has produced an unreviewable 5569-line file. The next mTLS
slices (T2 rustls wiring, T3 identity extraction, T4 policy
integration, T7 SAN allowlist mutations, T8 mode toggle, …) all
add more handler bodies. Splitting now means **every subsequent
slice lands in a focused submodule** rather than further
inflating the same file.

## 1 · Scope

**This is a pure structural refactor — zero behaviour change.**
- Same external API surface (`pub async fn run`, `pub use` types
  from submodules).
- All existing tests pass without modification.
- Zero new code paths, zero deletions of logic.

## 2 · Target structure

```
crates/aegis-proxy/src/
├── lib.rs                      ~150 lines — module decls + pub re-exports
├── run.rs                      ~700 lines — pub async fn run boot orchestration
├── responses.rs                ~120 lines — json_body_response, error helpers
├── data_plane.rs               ~700 lines — handle_data_request / forward_allow_to_upstream
├── admin/
│   ├── mod.rs                  ~150 lines — admin GET/PUT dispatch + accept loop
│   ├── get_handlers.rs         ~1200 lines — every GET handler
│   ├── mutation_handlers.rs    ~1500 lines — every audit-mutated PUT/POST/DELETE
│   ├── login.rs                ~400 lines — admin/login + admin/logout
│   └── sse.rs                  ~300 lines — dashboard/sse streaming
├── (existing modules unchanged)
└── tests embedded in each module
```

Approximate target line counts based on current `lib.rs`
content. None over the 800-line guideline.

## 3 · Slices (smallest first)

### PRE-T1 — Extract `responses.rs` (~30 min, ~120 lines)

Smallest, highest-leverage. Takes `json_body_response`,
`error_response`, the CSP/cookie helpers — every other split
depends on these. Pure code move with `pub(crate)` visibility.

### PRE-T2 — Extract `data_plane.rs` (~1 h, ~700 lines)

`handle_data_request` + `handle_data_request_inner` +
`forward_allow_to_upstream`. Self-contained with one cross-
boundary signature touch (the public dispatch in `run.rs`).
Tests (`run_binds_and_serves_200`, etc.) move with the code.

### PRE-T3 — Extract `admin/sse.rs` (~30 min, ~300 lines)

`/dashboard/sse` is well-isolated; clean first slice from the
admin surface.

### PRE-T4 — Extract `admin/login.rs` (~30 min, ~400 lines)

`/admin/login`, `/admin/logout`, `/admin/csrf` — already its
own conceptual block.

### PRE-T5 — Extract `admin/get_handlers.rs` (~1.5 h, ~1200 lines)

Every `GET /api/*` handler arm. The big chunk. The dispatch
match in `admin/mod.rs` calls into specific functions in
`get_handlers.rs`. Each handler stays the same internally; only
the path-to-function dispatch moves.

### PRE-T6 — Extract `admin/mutation_handlers.rs` (~1.5 h, ~1500 lines)

Every audit-mutated handler (rules / blacklist / mode /
detectors / risk thresholds / upstreams / alert-receivers /
…). Same dispatch pattern as PRE-T5.

### PRE-T7 — Extract `run.rs` (~1 h, ~700 lines)

The remaining `pub async fn run` body lifts into its own
module. `lib.rs` becomes a thin facade: module declarations,
`pub use ConfigReloadSource`, and `pub async fn run(...)` as a
one-line delegator.

### PRE-T8 — Verify (~30 min)

- `wc -l` on every file → all under 800.
- `cargo build -p aegis-bin --features production` → clean.
- `cargo clippy --features etcd --lib -- -D warnings` → clean.
- All 420 / 457 / 855 / 41 / 888 / 163 tests still pass.
- `git diff --stat` shows only file moves (no logic changes).

## 4 · Risks + mitigations

- **Hidden private coupling.** The current file has many
  closures + private helpers that share state with handlers
  via lexical scope. Mitigation: do the extraction as moves +
  `pub(crate) use` re-exports — no signature changes mid-slice.
  If a closure can't be lifted cleanly, leave it inline and
  extract only the helper.
- **Test coupling.** Some tests reach into `super::` to call
  private functions. Mitigation: tests move with their target
  function, not stay in the host module.
- **Borrow-checker churn from re-exporting types.** Mitigation:
  re-export through `pub(crate) use` rather than re-defining;
  the borrow shape stays identical.
- **Merge conflicts during the refactor.** Mitigation: do all 8
  slices in one PR (or one short branch). Don't interleave
  with feature work.

## 5 · Out of scope

- **No new modularization beyond what's listed.** Per-handler
  files would make navigation worse (1500 tiny files), not
  better.
- **No public API redesign.** Same `pub async fn run`, same
  `ConfigReloadSource`, same module visibility outside the
  crate.
- **No test consolidation.** Tests stay scoped to the module
  they test; no shared fixtures unless trivially helpful.

## 6 · Success criteria

After PRE-T8:

- [ ] `aegis-proxy/src/lib.rs` ≤ 200 lines.
- [ ] No file in `aegis-proxy/src/` over 800 lines.
- [ ] `cargo build -p aegis-bin --features production` clean.
- [ ] `cargo clippy --features etcd --lib -- -D warnings` clean.
- [ ] All test counts identical (420 default, 457 etcd).
- [ ] `git log --stat` shows file moves with minimal in-file
  diffs (the goal is "I can review this PR in 30 minutes").

## 7 · After PRE-T8 lands

Continue MTLS-T2 / T3 / T7+ etc. with handlers landing in
`admin/get_handlers.rs` / `admin/mutation_handlers.rs` —
each new mTLS slice adds maybe 100-200 lines to a focused
file rather than 100-200 lines to a 5500-line file.
