# Aegis-Gate

> **For AI Assistants — read this section first, then continue with the rest of the file.**
>
> **Quick-start (4 files to read before writing any code):**
> 1. This file (`README.md`) — project overview, crate responsibilities, layout.
> 2. `Implement-Progress.md` — which task is next and what was last completed.
> 3. `plans/plan.md` — shared types (§2), cross-crate traits (§3), boot sequence (§4), conventions (§5).
> 4. The crate sub-plan for your task:
>    - `plans/proxy.md` for proxy tasks (M1-*)
>    - `plans/security.md` for security tasks (M2-*)
>    - `plans/control.md` for control tasks (M3-*)
>
> **After finishing a task:** overwrite `Implement-Progress.md` with the template in `plans/plan.md §0.3`.
> **Verification:** `cargo test -p <crate> && cargo clippy -p <crate> -- -D warnings`

---

A production-grade Web Application Firewall and security gateway
written in Rust. Aegis-Gate sits in front of arbitrary HTTP/HTTPS
backends as a full reverse proxy, inspecting every request and
response through a tiered security pipeline before traffic reaches
the application.

Targeted at enterprise environments (fintech, healthcare, public
sector) with high availability, multi-tenancy, compliance, and
observability demands comparable to F5 BIG-IP ASM, Imperva, Akamai
Kona, and Cloudflare Enterprise.

## Status

Pre-implementation. The specification, architecture, and implementation
plan are complete and reviewed. Code lands under `crates/` once the
workspace is bootstrapped (Week 1).

## Repository Layout

```
aegis-gate/
├── Requirement.md         # Functional + non-functional requirements
├── Architecture.md        # System architecture and design decisions
├── Implement-Progress.md  # Current implementation progress (updated after each task)
├── plans/
│   ├── plan.md            # Foundation: AI guide, shared types, traits, boot, coverage matrix
│   ├── proxy.md           # aegis-proxy tasks W1–W5 (M1-*)
│   ├── security.md        # aegis-security tasks W1–W5 (M2-*)
│   └── control.md         # aegis-control tasks W1–W5 (M3-*)
├── docs/                  # Per-feature specifications (~55 files)
│   ├── README.md          # Feature index + ownership map
│   ├── cli.md             # Authoritative `waf` CLI reference
│   └── ...                # ddos-protection, detection-sqli, rate-limiting, ...
├── deploy/                # Docker-Compose files for dev and test stacks
│   ├── dependencies.md    # External services: required/optional matrix
│   ├── docker-compose.dev.yml
│   └── docker-compose.test.yml
├── tests/                 # Out-of-process load and security tests
│   ├── load/              # k6 scripts (baseline, mixed-tiers, ddos-burst)
│   └── security/          # attack corpora + nuclei/ZAP runners
└── crates/                # Rust workspace (created during M1 week 1)
    ├── aegis-core/        # Shared types and traits
    ├── aegis-proxy/       # M1 — data plane (TLS, routing, upstreams, state)
    ├── aegis-security/    # M2 — security pipeline (rules, detectors, risk)
    ├── aegis-control/     # M3 — control plane (dashboard, local auth, audit)
    └── aegis-bin/         # `waf` binary, wires the three crates
```

## Getting Started

> Once `crates/` exists.

```sh
# Build
cargo build --workspace --release

# Validate a config without binding listeners
./target/release/waf validate --config config/waf.yaml

# Run the gateway
./target/release/waf run --config config/waf.yaml
```

See [`docs/cli.md`](docs/cli.md) for the full subcommand reference.

## Reading Order

If you are new to the project, read in this order:

1. [`Requirement.md`](Requirement.md) — what we are building and why.
2. [`Architecture.md`](Architecture.md) — how it fits together.
3. [`Implement-Progress.md`](Implement-Progress.md) — current progress and next task.
4. [`plans/plan.md`](plans/plan.md) — shared types, traits, boot sequence. **Read §0 (AI Guide) first.**
5. The crate sub-plan for your area: [`plans/proxy.md`](plans/proxy.md), [`plans/security.md`](plans/security.md), or [`plans/control.md`](plans/control.md).
6. The relevant feature specs in [`docs/`](docs/README.md).

## Crate Responsibilities

| Crate            | Scope |
|------------------|-------|
| `aegis-proxy`    | TLS, protocols, routing, upstream pools, state backend, service discovery, secrets, hot reload |
| `aegis-security` | Rule engine, rate limiting, DDoS, OWASP detectors, risk scoring, challenge ladder, DLP, API security |
| `aegis-control`  | Observability, audit chain, SIEM sinks, dashboard, local dashboard auth (argon2id + HMAC session + CSRF), GitOps, compliance |
| `aegis-core`     | Shared types and traits — requires PR sign-off before changes |
| `aegis-bin`      | `./waf` binary — wires all crates together |

## Documentation Conventions

- **`plans/plan.md §2–§3` is law for inter-crate types and traits.**
  Any change must be made there first and reviewed before implementation.
- **`docs/cli.md` is law for `waf` subcommands.** New commands must
  be added there in the same PR that implements them.
- Per-feature specs in `docs/` are owned by the crate that
  implements them; the ownership map lives in `docs/README.md`.
- Architecture-level decisions live in `Architecture.md`.

## License

TBD.
