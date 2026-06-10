//! Redis-backed [`FleetBus`] for the cross-node event feed
//! (cluster plan Phase 2, §2b). Feature-gated `redis`.
//!
//! Uses a **dedicated** `redis::Client` + connections, entirely
//! separate from the `deadpool-redis` command pool that backs
//! `StateBackend`, so a slow pub/sub consumer can never stall a
//! state-backend op (cluster plan §7 hot-path contract). Pub/sub is
//! fire-and-forget: publish errors are logged + swallowed, the
//! subscriber reconnects with a fixed backoff.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use futures::StreamExt;
use redis::AsyncCommands;
use tokio::sync::{mpsc, Mutex};

use aegis_core::fleet::FleetBus;

/// Backoff between pub/sub (re)connect attempts. Fixed + short — the
/// feed is a monitor, so we favour fast recovery over jitter.
const RECONNECT_BACKOFF: Duration = Duration::from_secs(1);

/// Redis pub/sub transport. Cheap to clone-share via `Arc`.
pub struct RedisFleetBus {
    client: redis::Client,
    /// Cached multiplexed connection for `PUBLISH`, rebuilt on error.
    /// Separate from the state-backend pool by construction.
    publish_conn: Arc<Mutex<Option<redis::aio::MultiplexedConnection>>>,
}

impl RedisFleetBus {
    /// Build from a single Redis URL (the first of the configured
    /// `state.redis.urls`). Lazy — no connection until first use.
    pub fn connect(url: &str) -> aegis_core::error::Result<Self> {
        let client = redis::Client::open(url).map_err(|e| {
            aegis_core::error::WafError::State(format!("fleet redis client: {e}"))
        })?;
        Ok(Self {
            client,
            publish_conn: Arc::new(Mutex::new(None)),
        })
    }
}

#[async_trait]
impl FleetBus for RedisFleetBus {
    async fn publish(&self, channel: &str, payload: Vec<u8>) {
        let mut guard = self.publish_conn.lock().await;
        if guard.is_none() {
            match self.client.get_multiplexed_async_connection().await {
                Ok(c) => *guard = Some(c),
                Err(e) => {
                    tracing::debug!(error = %e, "fleet publish: connect failed (dropping event)");
                    return;
                }
            }
        }
        let conn = guard.as_mut().expect("just ensured Some");
        let res: redis::RedisResult<()> = conn.publish(channel, payload).await;
        if let Err(e) = res {
            tracing::debug!(error = %e, "fleet publish failed; will reconnect next time");
            // Drop the cached connection so the next publish rebuilds
            // it (handles Redis restart / broken pipe).
            *guard = None;
        }
    }

    fn subscribe(&self, channel: &str, bound: usize) -> mpsc::Receiver<Vec<u8>> {
        let (tx, rx) = mpsc::channel::<Vec<u8>>(bound);
        let client = self.client.clone();
        let channel = channel.to_string();
        tokio::spawn(async move {
            loop {
                if tx.is_closed() {
                    return;
                }
                let mut pubsub = match client.get_async_pubsub().await {
                    Ok(p) => p,
                    Err(e) => {
                        tracing::debug!(error = %e, "fleet subscribe: connect failed; retrying");
                        tokio::time::sleep(RECONNECT_BACKOFF).await;
                        continue;
                    }
                };
                if let Err(e) = pubsub.subscribe(&channel).await {
                    tracing::debug!(error = %e, channel, "fleet subscribe failed; retrying");
                    tokio::time::sleep(RECONNECT_BACKOFF).await;
                    continue;
                }
                let mut stream = pubsub.on_message();
                while let Some(msg) = stream.next().await {
                    let payload: Vec<u8> = match msg.get_payload() {
                        Ok(p) => p,
                        Err(e) => {
                            tracing::debug!(error = %e, "fleet message payload decode failed");
                            continue;
                        }
                    };
                    match tx.try_send(payload) {
                        Ok(()) => {}
                        Err(mpsc::error::TrySendError::Full(_)) => {
                            // Lossy monitor feed: drop on backpressure
                            // rather than block the pub/sub connection.
                            tracing::debug!("fleet subscribe buffer full; dropping event");
                        }
                        Err(mpsc::error::TrySendError::Closed(_)) => return,
                    }
                }
                // Stream ended (disconnect) — reconnect after backoff.
                if tx.is_closed() {
                    return;
                }
                tokio::time::sleep(RECONNECT_BACKOFF).await;
            }
        });
        rx
    }
}
