# Aegis-Gate Implementation Progress

## Last Completed
- Task: M2-T1.5 — Tier classifier
- Crate: aegis-security
- Files changed: rules/ast.rs, rules/parser.rs, rules/linter.rs, rules/eval.rs, rules/mod.rs, pipeline.rs, lib.rs
- Status: DONE
- Date: 2026-04-24

## Next Task
- Task: W2 — Rate Limit, DDoS, OWASP Detectors (M2-T2.x)
- Plan: plans/security.md (W2)
- Status: IN PROGRESS — code written, needs clippy pass + unused import cleanup
- Files created (not yet committed):
  - `crates/aegis-security/src/rate_limit/mod.rs` — re-exports
  - `crates/aegis-security/src/rate_limit/sliding.rs` — M2-T2.1 sliding window rate limit
  - `crates/aegis-security/src/rate_limit/bucket.rs` — M2-T2.2 token bucket
  - `crates/aegis-security/src/ddos.rs` — M2-T2.3 DDoS per-IP burst + cluster spike
  - `crates/aegis-security/src/detectors/mod.rs` — detector trait, url_decode helper, run_all
  - `crates/aegis-security/src/detectors/sqli.rs` — SQLi (30 patterns, 30+30 tests)
  - `crates/aegis-security/src/detectors/xss.rs` — XSS (30 patterns, 29+30 tests)
  - `crates/aegis-security/src/detectors/path_traversal.rs` — path traversal (16 patterns, 30+30 tests)
  - `crates/aegis-security/src/detectors/ssrf.rs` — SSRF (16 patterns, 30+30 tests)
  - `crates/aegis-security/src/detectors/header_injection.rs` — header injection (12 patterns, 11+11 tests)
  - `crates/aegis-security/src/detectors/body_abuse.rs` — body oversize + deep JSON nesting
  - `crates/aegis-security/src/detectors/recon.rs` — recon path + scanner UA detection
  - `crates/aegis-security/src/lib.rs` — updated to register ddos, detectors, rate_limit modules
- Tests: 417 pass, 0 fail
- Remaining before commit:
  1. Run `cargo clippy -p aegis-security -- -D warnings` and fix any warnings (likely unused import in rules/mod.rs)
  2. Update progress file to mark W2 DONE
  3. Commit

## Completed Tasks Log
| Task | Crate | Date |
|------|-------|------|
| M1-T1.1 Workspace + `./waf run` skeleton | aegis-bin, aegis-proxy, aegis-core | 2026-04-22 |
| M1-T1.5 NoopPipeline + bus wiring | aegis-security (pre-existing), aegis-bin | 2026-04-22 |
| M1-T1.2 Config loader (figment + validation) | aegis-core | 2026-04-22 |
| M1-T1.3 Hot reload (notify + ArcSwap) | aegis-proxy | 2026-04-22 |
| M1-T1.4 Dual listener model | aegis-proxy | 2026-04-22 |
| M1-T2.1 Host matcher | aegis-proxy | 2026-04-22 |
| M1-T2.2 Path trie | aegis-proxy | 2026-04-22 |
| M1-T2.3 RouteTable::build + resolve | aegis-proxy | 2026-04-22 |
| M1-T2.4 Upstream Pool + LB strategies | aegis-proxy | 2026-04-22 |
| M1-T2.5 Active health checks | aegis-proxy | 2026-04-22 |
| M1-T2.6 Circuit breaker | aegis-proxy | 2026-04-22 |
| M1-T2.7 Wire routing + upstream into proxy.rs | aegis-proxy | 2026-04-22 |
| M1-T3.1 DynamicResolver + CertStore | aegis-proxy | 2026-04-24 |
| M1-T3.2 HTTP/2 on both sides | aegis-proxy | 2026-04-24 |
| M1-T3.3 WebSocket upgrade passthrough | aegis-proxy | 2026-04-24 |
| M1-T3.4 gRPC trailer-preserving forward | aegis-proxy | 2026-04-24 |
| M1-T3.5 mTLS to upstream | aegis-proxy | 2026-04-24 |
| M1-T3.6 ACME (feature acme) | aegis-proxy | 2026-04-24 |
| M1-T3.7 OCSP stapling | aegis-proxy | 2026-04-24 |
| M1-T4.1 Per-route quotas | aegis-proxy, aegis-core | 2026-04-24 |
| M1-T4.2 Transformations + CORS | aegis-proxy | 2026-04-24 |
| M1-T4.3 Canary split + header/cookie steering | aegis-proxy | 2026-04-24 |
| M1-T4.4 Retries with budget | aegis-proxy | 2026-04-24 |
| M1-T4.5 Shadow mirroring | aegis-proxy | 2026-04-24 |
| M1-T4.6 Session affinity | aegis-proxy | 2026-04-24 |
| M1-T4.7 Worker supervisor + graceful drain | aegis-proxy | 2026-04-24 |
| M1-T4.8 Hot binary reload (SIGUSR2) | aegis-proxy | 2026-04-24 |
| M1-T4.9 Tier-aware smart cache | aegis-proxy | 2026-04-24 |
| M1-T5.1 InMemoryBackend polish | aegis-proxy | 2026-04-24 |
| M1-T5.2 RedisBackend (feature redis) | aegis-proxy | 2026-04-24 |
| M1-T5.3 Adaptive load shedder (Gradient2) | aegis-proxy | 2026-04-24 |
| M1-T5.4 Secrets resolver | aegis-proxy | 2026-04-24 |
| M1-T5.5 DR snapshot/restore | aegis-proxy | 2026-04-24 |
| M1-T5.6 Service discovery | aegis-proxy | 2026-04-24 |
| M1-T5.7 Cluster membership | aegis-proxy | 2026-04-24 |
| M2-T1.1 Rule AST + parser | aegis-security | 2026-04-24 |
| M2-T1.2 Linter | aegis-security | 2026-04-24 |
| M2-T1.3 Evaluator | aegis-security | 2026-04-24 |
| M2-T1.4 RuleSet hot reload | aegis-security | 2026-04-24 |
| M2-T1.5 Tier classifier | aegis-security | 2026-04-24 |