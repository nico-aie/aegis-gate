//! SC-1 Phase 1 — Redis pub/sub cache-purge fan-out (multi-node).
//!
//! `flush_cache` on any node evicts that node's L1 immediately, then publishes
//! a purge to a Redis channel; every node (including the publisher) runs a
//! subscriber that evicts its own L1 on receipt. This makes a purge fleet-wide
//! **without putting Redis on the request hot path** — the cache stays
//! in-process. It rides the control-plane Redis we already run (the `redis`
//! state backend), not a separate cache store.
//!
//! Best-effort by design: a publish/subscribe failure degrades to a local-only
//! flush + TTL expiry on the other nodes, never an error to the caller.
//!
//! Only compiled with `--features redis`; without it `flush_cache` is
//! local-only (the previous behavior).

use std::sync::Arc;
use std::time::Duration;

use super::ResponseCache;

/// The channel every node publishes purges to and subscribes on.
pub const CHANNEL: &str = "aegis:cache:purge";

/// Reconnect backoff for the subscriber loop.
const RECONNECT_DELAY: Duration = Duration::from_secs(2);

/// Publish a purge to the fleet. `scope` is `"all"` or `"pool:<name>"`.
/// Best-effort — a failure is logged at debug and swallowed (local eviction +
/// TTL still bound staleness).
pub async fn publish(urls: &[String], scope: &str) {
    let Some(url) = urls.first() else {
        return;
    };
    if let Err(e) = publish_once(url, scope).await {
        tracing::debug!(
            error = %e,
            "cache purge publish failed; fleet fan-out skipped (local flush + TTL still apply)",
        );
    }
}

async fn publish_once(url: &str, scope: &str) -> redis::RedisResult<()> {
    let client = redis::Client::open(url)?;
    let mut conn = client.get_multiplexed_async_connection().await?;
    redis::cmd("PUBLISH")
        .arg(CHANNEL)
        .arg(scope)
        .query_async::<()>(&mut conn)
        .await
}

/// Spawn a reconnecting subscriber that evicts this node's L1 on every purge
/// message. Idempotent: receiving our own publish just re-invalidates (no-op).
pub fn spawn_subscriber(urls: Vec<String>, cache: Arc<ResponseCache>) {
    let Some(url) = urls.into_iter().next() else {
        return;
    };
    tokio::spawn(async move {
        loop {
            if let Err(e) = run_subscriber(&url, &cache).await {
                tracing::warn!(
                    error = %e,
                    "cache purge subscriber dropped; reconnecting in {}s",
                    RECONNECT_DELAY.as_secs(),
                );
            }
            tokio::time::sleep(RECONNECT_DELAY).await;
        }
    });
    tracing::info!(
        channel = CHANNEL,
        "cache purge subscriber wired — flush_cache is now fleet-wide",
    );
}

async fn run_subscriber(url: &str, cache: &Arc<ResponseCache>) -> redis::RedisResult<()> {
    use futures::StreamExt;
    let client = redis::Client::open(url)?;
    let mut pubsub = client.get_async_pubsub().await?;
    pubsub.subscribe(CHANNEL).await?;
    let mut stream = pubsub.on_message();
    while let Some(msg) = stream.next().await {
        let scope: String = msg.get_payload().unwrap_or_default();
        match scope.strip_prefix("pool:") {
            Some(pool) if !pool.is_empty() => cache.invalidate(Some(pool)),
            _ => cache.invalidate(None),
        }
        tracing::debug!(scope = %scope, "cache purge received; evicted local L1");
    }
    Ok(())
}
