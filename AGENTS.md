# AGENTS.md — orientation for AI assistants & new contributors

> Cross-tool agent guide (Claude Code, Cursor, etc. auto-load this).
> It is a **map**, not the full protocol — the authoritative working
> guide is [`plans/plan.md`](./plans/plan.md). Read that before writing code.

Aegis-Gate is a production-grade **Web Application Firewall / security
gateway in Rust** — a full reverse proxy that inspects every request
through a tiered security pipeline before it reaches the upstream.

## Read these first (in order)

1. [`README.md`](./README.md) — what it does + crate responsibilities.
2. [`Implement-Progress.md`](./Implement-Progress.md) — living snapshot:
   last completed task, next task, carry-overs.
3. [`plans/README.md`](./plans/README.md) — track status board
   (active / queued / closed; deferred work lives in `plans/future/`).
4. [`plans/plan.md`](./plans/plan.md) — the working protocol (session
   startup, progress-file rules, prompt template). **Authoritative.**
5. [`Architecture.md`](./Architecture.md) — 27-section system design,
   cross-referenced to source paths.
6. The `docs/<category>/…` doc for the subsystem you're touching — each
   has a `> **Status:**` banner; [`docs/README.md`](./docs/README.md) is the index.

## Workspace (5 crates)

| Crate | Owns |
|-------|------|
| `aegis-core` | config schema, pipeline contract, shared domain types |
| `aegis-proxy` (M1) | listeners, routing, upstream pools, TLS, data plane, config hot-reload |
| `aegis-security` (M2) | detectors, risk engine, gates (DDoS / rate-limit / strike / bots), challenge |
| `aegis-control` (M3) | admin API, dashboard (JSX→`app.js`), audit, SLO, interop contract |
| `aegis-bin` | the `waf` binary (`run` / `validate` / `admin` subcommands) |

## Common commands (Makefile is the canonical entry)

```bash
make build              # release build (features: redis geoip alerts ai); rebundles dashboard if JSX changed
make build-debug        # faster debug build for iteration
make dashboard          # rebuild the dashboard JSX → app.js bundle (app.js is embedded at compile time)
make run-dev            # boot dev profile (auto-starts Redis + mock upstream)
make bench-dev          # boot with the v2.x binary contract (./waf + ./waf.yaml in cwd)
make validate-all       # validate dev + all three production profiles
make help               # full target list
cargo test              # workspace tests
cargo test -p aegis-control --lib api::attacks   # a single module's tests
```

The single binary serves both the data plane and the admin/dashboard
plane. Config is hot-reloadable — see
[`config/REFERENCE.md`](./config/REFERENCE.md#hot-reload-vs-restart) for
which fields apply on file-save vs need a restart.

## Conventions & gotchas

- **Commits:** Conventional Commits (`feat`/`fix`/`docs`/`refactor`/…).
  Author attribution is disabled globally — do not add `Co-Authored-By`.
- **Dashboard:** edit `crates/aegis-control/assets/dashboard/src/*.jsx`,
  then `make dashboard`. `app.js` is a minified single-line bundle —
  diff the JSX, not the bundle. It is `include_bytes!`-embedded, so a
  release binary needs a rebuild after `make dashboard` (debug builds
  hot-reload it from disk).
- **`waf.yaml` is gitignored** — it's the local runtime config staged by
  `make bench-dev`. Edit `config/*.yaml` profiles for tracked changes.
- **Interop contract:** the live contract is
  [`Hackathon_Doc/EN_waf_interop_contract_v2.5.md`](./Hackathon_Doc/EN_waf_interop_contract_v2.5.md);
  `/__waf_control/*` is loopback-gated. Tiers / path-heuristics / bot
  classification are internal/bonus, not part of the contract.
- **Plans:** active work in `plans/`, deferred in `plans/future/`,
  shipped/closed in `plans/archive/` (read-only history — don't restart it).
