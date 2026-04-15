# Aegis-Gate

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

Pre-implementation. The specification, architecture, and per-member
implementation plans are complete and reviewed. Code lands under
`crates/` once the workspace is bootstrapped (M1 week 1).

## Repository Layout

```
aegis-gate/
├── Requirement.md         # Functional + non-functional requirements
├── Architecture.md        # System architecture and design decisions
├── plans/                 # Per-member implementation plans
│   ├── shared-contract.md # SINGLE SOURCE OF TRUTH for cross-crate types
│   ├── member-1-proxy-core.md
│   ├── member-2-security-pipeline.md
│   └── member-3-control-plane.md
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
3. [`plans/shared-contract.md`](plans/shared-contract.md) — the
   types and traits every crate depends on. **Always read this
   before touching another plan or crate.**
4. The member plan you are implementing (`plans/member-N-*.md`).
5. The relevant feature specs in [`docs/`](docs/README.md).

## Team Split

Three engineers own one crate each, coordinating through
`shared-contract.md`:

| Member | Crate            | Scope |
|--------|------------------|-------|
| M1     | `aegis-proxy`    | TLS, protocols, routing, upstream pools, state backend, service discovery, secrets, hot reload |
| M2     | `aegis-security` | Rule engine, rate limiting, DDoS, OWASP detectors, risk scoring, challenge ladder, DLP, API security |
| M3     | `aegis-control`  | Observability, audit chain, SIEM sinks, dashboard, local dashboard auth (argon2id + HMAC session + CSRF), GitOps, compliance. (OIDC/SSO, RBAC roles, and multi-tenancy are deferred — see `docs/deferred/`.) |

Cross-cutting work (`aegis-core`, `aegis-bin`) requires PR review
from all three members.

## Documentation Conventions

- **`shared-contract.md` is law.** Any change to inter-crate types
  or traits must land there first, in a PR reviewed by all three
  members.
- **`docs/cli.md` is law for `waf` subcommands.** New commands must
  be added there in the same PR that implements them.
- Per-feature specs in `docs/` are owned by the crate that
  implements them; the ownership map lives in `docs/README.md`.
- Architecture-level decisions live in `Architecture.md`. Where it
  conflicts with `shared-contract.md`, the contract wins.

## License

TBD.
