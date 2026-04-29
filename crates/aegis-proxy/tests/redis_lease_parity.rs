//! Live-Redis parity test for `B1-T3` lease store.
//!
//! Pits `InProcessLease` and `RedisLease` against the same
//! sequence of operations and asserts identical observable
//! behaviour for `acquire`, `renew`, `release`, and `holder`.
//!
//! ### Running
//!
//! ```sh
//! docker compose -f deploy/docker-compose.dev.yml up -d redis
//!
//! AEGIS_REDIS_URL=redis://127.0.0.1:6379 \
//!   cargo test -p aegis-proxy --features redis \
//!     --test redis_lease_parity -- --nocapture
//! ```
//!
//! Without `AEGIS_REDIS_URL`, every test prints "skipped" and
//! returns Ok.

#![cfg(feature = "redis")]

use std::sync::Arc;
use std::time::Duration;

use aegis_core::cluster::{LeaseStore, NodeId};
use aegis_proxy::cluster_lease::{InProcessLease, RedisLease};
use aegis_proxy::state::RedisConfig;

fn redis_url() -> Option<String> {
    std::env::var("AEGIS_REDIS_URL").ok()
}

fn redis_lease(self_id: &str) -> Option<RedisLease> {
    let url = redis_url()?;
    let cfg = RedisConfig {
        url,
        pool_size: 4,
        timeout: Duration::from_secs(2),
        cluster: false,
    };
    Some(RedisLease::connect(cfg, NodeId::new(self_id)).expect("pool builds"))
}

fn skip(test: &str) {
    eprintln!("[redis_lease_parity::{test}] skipped — set AEGIS_REDIS_URL to run");
}

/// Per-process unique key prefix so concurrent tests don't
/// collide on the shared Redis.
fn unique_key(test: &str) -> String {
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
async fn parity_acquire_first_returns_handle() {
    let Some(red) = redis_lease("node-A") else {
        skip("acquire_first_returns_handle");
        return;
    };
    let mem = InProcessLease::new(NodeId::new("node-A"));
    let key = unique_key("acquire_first");

    let m = mem.acquire(&key, Duration::from_secs(30)).await.unwrap();
    let r = red.acquire(&key, Duration::from_secs(30)).await.unwrap();

    assert!(m.is_some());
    assert!(r.is_some());
    assert_eq!(m.unwrap().holder, NodeId::new("node-A"));
    assert_eq!(r.unwrap().holder, NodeId::new("node-A"));
}

#[tokio::test]
async fn parity_acquire_blocked_by_other_holder() {
    let Some(red_a) = redis_lease("node-A") else {
        skip("blocked_by_other_holder");
        return;
    };
    let red_b = {
        let cfg = RedisConfig {
            url: redis_url().unwrap(),
            pool_size: 2,
            timeout: Duration::from_secs(2),
            cluster: false,
        };
        RedisLease::connect(cfg, NodeId::new("node-B")).unwrap()
    };
    let mem_a = InProcessLease::new(NodeId::new("node-A"));
    let mem_b = mem_a.cloned_with_node(NodeId::new("node-B"));
    let key = unique_key("blocked");

    let _ = mem_a.acquire(&key, Duration::from_secs(30)).await.unwrap();
    let _ = red_a.acquire(&key, Duration::from_secs(30)).await.unwrap();

    assert!(
        mem_b.acquire(&key, Duration::from_secs(30)).await.unwrap().is_none()
    );
    assert!(
        red_b.acquire(&key, Duration::from_secs(30)).await.unwrap().is_none()
    );
}

#[tokio::test]
async fn parity_renew_returns_true_for_holder() {
    let Some(red) = redis_lease("node-A") else {
        skip("renew_for_holder");
        return;
    };
    let mem = InProcessLease::new(NodeId::new("node-A"));
    let key = unique_key("renew_holder");

    let h_m = mem.acquire(&key, Duration::from_secs(30)).await.unwrap().unwrap();
    let h_r = red.acquire(&key, Duration::from_secs(30)).await.unwrap().unwrap();

    assert!(mem.renew(&h_m, Duration::from_secs(30)).await.unwrap());
    assert!(red.renew(&h_r, Duration::from_secs(30)).await.unwrap());
}

#[tokio::test]
async fn parity_renew_returns_false_after_release() {
    let Some(red) = redis_lease("node-A") else {
        skip("renew_after_release");
        return;
    };
    let mem = InProcessLease::new(NodeId::new("node-A"));
    let key = unique_key("renew_after_release");

    let h_m = mem.acquire(&key, Duration::from_secs(30)).await.unwrap().unwrap();
    let h_r = red.acquire(&key, Duration::from_secs(30)).await.unwrap().unwrap();

    mem.release(&h_m).await.unwrap();
    red.release(&h_r).await.unwrap();

    assert!(!mem.renew(&h_m, Duration::from_secs(30)).await.unwrap());
    assert!(!red.renew(&h_r, Duration::from_secs(30)).await.unwrap());
}

#[tokio::test]
async fn parity_holder_returns_node_when_held() {
    let Some(red) = redis_lease("node-A") else {
        skip("holder_returns_node");
        return;
    };
    let mem = InProcessLease::new(NodeId::new("node-A"));
    let key = unique_key("holder_known");

    let _ = mem.acquire(&key, Duration::from_secs(30)).await.unwrap();
    let _ = red.acquire(&key, Duration::from_secs(30)).await.unwrap();

    assert_eq!(
        mem.holder(&key).await.unwrap().unwrap(),
        NodeId::new("node-A")
    );
    assert_eq!(
        red.holder(&key).await.unwrap().unwrap(),
        NodeId::new("node-A")
    );
}

#[tokio::test]
async fn parity_expired_lease_taken_by_other() {
    let Some(red_a) = redis_lease("node-A") else {
        skip("expired_takeover");
        return;
    };
    let red_b = {
        let cfg = RedisConfig {
            url: redis_url().unwrap(),
            pool_size: 2,
            timeout: Duration::from_secs(2),
            cluster: false,
        };
        RedisLease::connect(cfg, NodeId::new("node-B")).unwrap()
    };
    let mem_a = InProcessLease::new(NodeId::new("node-A"));
    let mem_b = mem_a.cloned_with_node(NodeId::new("node-B"));
    let key = unique_key("expired_takeover");

    // 1ms TTL, then sleep past it.
    let _ = mem_a.acquire(&key, Duration::from_millis(1)).await.unwrap();
    let _ = red_a.acquire(&key, Duration::from_millis(50)).await.unwrap();

    tokio::time::sleep(Duration::from_millis(150)).await;

    let h_m = mem_b.acquire(&key, Duration::from_secs(30)).await.unwrap();
    let h_r = red_b.acquire(&key, Duration::from_secs(30)).await.unwrap();

    assert!(h_m.is_some(), "expired in-mem lease should be reacquirable");
    assert!(h_r.is_some(), "expired redis lease should be reacquirable");
    assert_eq!(h_m.unwrap().holder, NodeId::new("node-B"));
    assert_eq!(h_r.unwrap().holder, NodeId::new("node-B"));
}

#[tokio::test]
async fn parity_three_nodes_only_one_winner() {
    let Some(red_a) = redis_lease("node-1") else {
        skip("three_nodes_one_winner");
        return;
    };
    let mk = |id: &str| {
        let cfg = RedisConfig {
            url: redis_url().unwrap(),
            pool_size: 2,
            timeout: Duration::from_secs(2),
            cluster: false,
        };
        RedisLease::connect(cfg, NodeId::new(id)).unwrap()
    };
    let red_b = mk("node-2");
    let red_c = mk("node-3");

    let mem_1 = Arc::new(InProcessLease::new(NodeId::new("node-1")));
    let mem_2 = mem_1.cloned_with_node(NodeId::new("node-2"));
    let mem_3 = mem_1.cloned_with_node(NodeId::new("node-3"));

    let key_mem = unique_key("3way_mem");
    let key_red = unique_key("3way_red");

    let mut mem_winners = 0;
    for store in [mem_1.as_ref(), &mem_2, &mem_3] {
        if store.acquire(&key_mem, Duration::from_secs(30)).await.unwrap().is_some() {
            mem_winners += 1;
        }
    }

    let mut red_winners = 0;
    for store in [&red_a, &red_b, &red_c] {
        if store.acquire(&key_red, Duration::from_secs(30)).await.unwrap().is_some() {
            red_winners += 1;
        }
    }

    assert_eq!(mem_winners, 1, "exactly one in-mem winner");
    assert_eq!(red_winners, 1, "exactly one redis winner");
}
