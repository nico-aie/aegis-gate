//! Live-Redis parity test for `B1-T1`.
//!
//! Pits `InMemoryBackend` and `RedisBackend` against the same
//! sequence of operations and asserts identical observable
//! behaviour for `incr_window`, `token_bucket`, `auto_block`, and
//! `consume_nonce` — the four ops the task acceptance calls out.
//!
//! ### Running
//!
//! ```sh
//! # Bring up the dev compose redis (or any local redis)
//! docker compose -f deploy/docker-compose.dev.yml up -d redis
//!
//! AEGIS_REDIS_URL=redis://127.0.0.1:6379 \
//!   cargo test -p aegis-proxy --features redis \
//!     --test redis_parity -- --nocapture
//! ```
//!
//! Without `AEGIS_REDIS_URL` set, every test prints "skipped"
//! and returns Ok. CI runs them with the env var set against the
//! `aegis-redis` service that already exists in
//! `deploy/docker-compose.dev.yml`.

#![cfg(feature = "redis")]

use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use aegis_core::state::StateBackend;
use aegis_proxy::state::{InMemoryBackend, RedisBackend, RedisConfig};

fn redis_url() -> Option<String> {
    std::env::var("AEGIS_REDIS_URL").ok()
}

async fn redis_backend() -> Option<RedisBackend> {
    let url = redis_url()?;
    let cfg = RedisConfig {
        url,
        pool_size: 4,
        timeout: Duration::from_secs(2),
        cluster: false,
    };
    let backend = RedisBackend::connect(cfg).expect("pool builds");

    // Confirm Redis is actually reachable. If not, the env var
    // points at a dead instance — surface that as a panic so CI
    // doesn't silently skip.
    match backend.get("__aegis_parity_probe__").await {
        Ok(_) => Some(backend),
        Err(e) => panic!(
            "AEGIS_REDIS_URL is set but Redis is unreachable: {e}.\n\
             Either bring Redis up or unset the var to skip parity tests."
        ),
    }
}

fn skip_msg(test: &str) {
    eprintln!("[redis_parity::{test}] skipped — set AEGIS_REDIS_URL to run");
}

/// Pick a per-process unique key prefix so concurrent test runs
/// against the same Redis don't collide.
fn unique_prefix(test: &str) -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let n = N.fetch_add(1, Ordering::Relaxed);
    format!("__test:{test}:{nanos}:{n}")
}

#[tokio::test]
async fn parity_incr_window_under_limit() {
    let Some(redis) = redis_backend().await else {
        skip_msg("incr_window_under_limit");
        return;
    };
    let mem = InMemoryBackend::new();
    let key = unique_prefix("sw_under");

    for expected in 1..=5_u64 {
        let m = mem
            .incr_window(&key, Duration::from_secs(60), 10)
            .await
            .unwrap();
        let r = redis
            .incr_window(&key, Duration::from_secs(60), 10)
            .await
            .unwrap();

        assert_eq!(m.count, expected, "in-memory count");
        assert_eq!(r.count, expected, "redis count");
        assert!(m.allowed && r.allowed);
    }
}

#[tokio::test]
async fn parity_incr_window_exceeds_limit() {
    let Some(redis) = redis_backend().await else {
        skip_msg("incr_window_exceeds_limit");
        return;
    };
    let mem = InMemoryBackend::new();
    let key = unique_prefix("sw_over");

    // Ramp both backends to the same count past the limit.
    for _ in 0..3 {
        mem.incr_window(&key, Duration::from_secs(60), 2).await.unwrap();
        redis.incr_window(&key, Duration::from_secs(60), 2).await.unwrap();
    }

    let m = mem
        .incr_window(&key, Duration::from_secs(60), 2)
        .await
        .unwrap();
    let r = redis
        .incr_window(&key, Duration::from_secs(60), 2)
        .await
        .unwrap();

    assert_eq!(m.count, 4);
    assert_eq!(r.count, 4);
    assert!(!m.allowed && !r.allowed);
    assert!(m.retry_after.is_some() && r.retry_after.is_some());
}

#[tokio::test]
async fn parity_token_bucket_consumes_within_burst() {
    let Some(redis) = redis_backend().await else {
        skip_msg("token_bucket_consumes_within_burst");
        return;
    };
    let mem = InMemoryBackend::new();
    let key = unique_prefix("tb_burst");

    // burst=3 → first three calls consume.
    for _ in 0..3 {
        assert!(mem.token_bucket(&key, 1, 3).await.unwrap());
        assert!(redis.token_bucket(&key, 1, 3).await.unwrap());
    }
    // Fourth call may be denied (deterministic for redis given
    // the same monotonic clock; in-memory uses Instant so it
    // also denies before the next refill tick).
    let m = mem.token_bucket(&key, 1, 3).await.unwrap();
    let r = redis.token_bucket(&key, 1, 3).await.unwrap();
    assert!(!m, "in-memory should deny after burst");
    assert!(!r, "redis should deny after burst");
}

#[tokio::test]
async fn parity_auto_block_round_trip() {
    let Some(redis) = redis_backend().await else {
        skip_msg("auto_block_round_trip");
        return;
    };
    let mem = InMemoryBackend::new();
    let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 42));

    assert!(!mem.is_auto_blocked(ip).await.unwrap());
    assert!(!redis.is_auto_blocked(ip).await.unwrap());

    mem.auto_block(ip, Duration::from_secs(60)).await.unwrap();
    redis.auto_block(ip, Duration::from_secs(60)).await.unwrap();

    assert!(mem.is_auto_blocked(ip).await.unwrap());
    assert!(redis.is_auto_blocked(ip).await.unwrap());
}

#[tokio::test]
async fn parity_nonce_put_and_consume() {
    let Some(redis) = redis_backend().await else {
        skip_msg("nonce_put_and_consume");
        return;
    };
    let mem = InMemoryBackend::new();
    let nonce_mem = unique_prefix("nonce_mem");
    let nonce_red = unique_prefix("nonce_red");

    // Put once → succeeds on both.
    assert!(mem.put_nonce(&nonce_mem, Duration::from_secs(60)).await.unwrap());
    assert!(redis
        .put_nonce(&nonce_red, Duration::from_secs(60))
        .await
        .unwrap());

    // Put again → fails on both (atomic SET NX semantics).
    assert!(!mem.put_nonce(&nonce_mem, Duration::from_secs(60)).await.unwrap());
    assert!(!redis
        .put_nonce(&nonce_red, Duration::from_secs(60))
        .await
        .unwrap());

    // Consume succeeds once.
    assert!(mem.consume_nonce(&nonce_mem).await.unwrap());
    assert!(redis.consume_nonce(&nonce_red).await.unwrap());

    // Second consume fails.
    assert!(!mem.consume_nonce(&nonce_mem).await.unwrap());
    assert!(!redis.consume_nonce(&nonce_red).await.unwrap());
}

#[tokio::test]
async fn parity_get_set_del() {
    let Some(redis) = redis_backend().await else {
        skip_msg("get_set_del");
        return;
    };
    let mem = InMemoryBackend::new();
    let key_mem = unique_prefix("kv_mem");
    let key_red = unique_prefix("kv_red");

    assert!(mem.get(&key_mem).await.unwrap().is_none());
    assert!(redis.get(&key_red).await.unwrap().is_none());

    mem.set(&key_mem, b"hello", Duration::from_secs(60)).await.unwrap();
    redis.set(&key_red, b"hello", Duration::from_secs(60)).await.unwrap();

    assert_eq!(mem.get(&key_mem).await.unwrap(), Some(b"hello".to_vec()));
    assert_eq!(redis.get(&key_red).await.unwrap(), Some(b"hello".to_vec()));

    mem.del(&key_mem).await.unwrap();
    redis.del(&key_red).await.unwrap();

    assert!(mem.get(&key_mem).await.unwrap().is_none());
    assert!(redis.get(&key_red).await.unwrap().is_none());
}
