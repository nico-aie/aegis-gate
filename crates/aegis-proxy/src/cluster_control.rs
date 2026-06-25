//! C-1 (multi-node consistency) — control-plane convergence poller.
//!
//! Mirrors the leader-view poller in [`crate::accept`]: a single
//! background task per node that reads the shared control keys
//! (`control:waf:*`) from the `StateBackend` every couple of seconds
//! and applies any peer-published change to this node's local state.
//!
//! Two things converge:
//!
//! - **Modes** — when the published [`ClusterModeDoc`] generation
//!   exceeds the last one this node applied, the snapshot is pushed
//!   into the local `ModeStore`, so `set_profile` on any node moves
//!   every node's `X-WAF-Mode`.
//! - **Reset epoch** — when the shared reset counter advances, this
//!   node runs its *local* reset chain (the originating node already
//!   wiped the shared backend fleet-wide), closing the "other nodes'
//!   local trackers stay warm" gap.
//!
//! The originating node also observes its own publish on the next
//! tick; applying an identical snapshot is a no-op, and the local
//! reset chain is idempotent, so the redundant pass is harmless.

use std::sync::Arc;

use aegis_control::interop::InteropRuntime;
use aegis_core::config_backend::ConfigBackend;

/// Poll cadence. Matches the leader-view poller — fast enough that
/// fleet convergence stays inside the ~3s the config plane already
/// targets, cheap enough to run forever.
const POLL_INTERVAL: std::time::Duration = std::time::Duration::from_secs(2);

/// One operator access list converged by the poller, with the local
/// store to push peer-published snapshots into.
pub(crate) struct AccessListTarget {
    pub label: &'static str,
    pub store: Arc<aegis_control::api::blacklist::AccessListStore>,
}

/// Spawn the convergence poller. Returns immediately; the task runs
/// for the lifetime of the process.
pub(crate) fn spawn_poller(
    rt: Arc<InteropRuntime>,
    state: Arc<dyn ConfigBackend>,
    access_lists: Vec<AccessListTarget>,
) {
    tokio::spawn(async move {
        use aegis_control::interop::cluster_sync;

        // Modes: start at 0 so the FIRST poll adopts whatever the
        // cluster currently has (a freshly booted node converges to the
        // live mode map instead of its `Mode::Enforce` default).
        let mut applied_gen: u64 = 0;
        // HIGH-2 — per-list applied generation; start at 0 so a freshly
        // booted node adopts the cluster's current access lists on its
        // first poll instead of staying empty until the next mutation.
        let mut applied_access_gen: std::collections::HashMap<&'static str, u64> =
            access_lists.iter().map(|t| (t.label, 0u64)).collect();
        // Reset epoch: seed with the CURRENT value so a new node does
        // not replay historical resets — it only acts on resets issued
        // after it joined.
        let mut seen_epoch: u64 = cluster_sync::read_reset_epoch(&state).await;

        let mut tick = tokio::time::interval(POLL_INTERVAL);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        // Phase 5 (§3) — optional pub/sub nudge: when wired, a peer's
        // config/control mutation publishes a 1-byte bump that wakes
        // this loop for an immediate re-poll (convergence ms instead of
        // up to POLL_INTERVAL). Polling stays the backstop — if the
        // nudge channel is absent or closes, the interval alone drives
        // convergence, so a dropped bump never breaks correctness.
        let mut bump_rx = rt.control.cluster_nudge().map(|watch| watch.watch(64));

        loop {
            // Wake on the interval tick OR a nudge, whichever comes first.
            if let Some(rx) = bump_rx.as_mut() {
                tokio::select! {
                    _ = tick.tick() => {}
                    msg = rx.recv() => {
                        if msg.is_none() {
                            // Channel closed (e.g. a no-op bus) — drop
                            // the nudge and fall back to interval-only.
                            bump_rx = None;
                        }
                    }
                }
            } else {
                tick.tick().await;
            }

            // --- modes ---
            if let Some(doc) = cluster_sync::read_modes(&state).await {
                if doc.generation > applied_gen {
                    rt.control.apply_remote_snapshot(doc.to_snapshot());
                    applied_gen = doc.generation;
                    tracing::debug!(
                        generation = applied_gen,
                        "cluster control: applied peer-published modes"
                    );
                }
            }

            // --- reset epoch ---
            let epoch = cluster_sync::read_reset_epoch(&state).await;
            if epoch > seen_epoch {
                rt.control.reset_local();
                seen_epoch = epoch;
                tracing::info!(
                    epoch,
                    "cluster control: peer reset_state — flushed local trackers"
                );
            }

            // --- access lists (HIGH-2) ---
            for target in &access_lists {
                if let Some(doc) = cluster_sync::read_access_list(&state, target.label).await {
                    let applied = applied_access_gen.entry(target.label).or_insert(0);
                    if doc.generation > *applied {
                        let count = doc.entries.len();
                        target.store.replace_entries(doc.entries);
                        *applied = doc.generation;
                        tracing::debug!(
                            label = target.label,
                            generation = *applied,
                            entries = count,
                            "cluster control: applied peer-published access list"
                        );
                    }
                }
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_control::interop::cluster_sync;
    use aegis_control::interop::headers::Mode;
    use aegis_control::interop::mode::ModeStore;

    fn backend() -> Arc<dyn ConfigBackend> {
        // H2b — the control plane rides the ConfigBackend seam; wrap an
        // in-memory state backend (the shared_state path) for the tests.
        aegis_core::config_backend::SharedStateConfigBackend::arc(Arc::new(
            crate::state::in_memory::InMemoryBackend::new(),
        ))
    }

    // Node A publishes a mode map through the shared backend; node B's
    // poll loop (read_modes → apply) converges on the same effective
    // mode. This is the core C-1 guarantee: set_profile on one node
    // moves every node's X-WAF-Mode.
    #[tokio::test]
    async fn published_modes_converge_to_a_second_node() {
        let state = backend();

        // Node A flips one feature to log_only and publishes.
        let node_a = ModeStore::new(Mode::Enforce);
        node_a.set_feature("sqli", Mode::LogOnly);
        let gen = cluster_sync::publish_modes(&state, &node_a.current()).await;
        assert_eq!(gen, Some(1), "first publish is generation 1");

        // Node B starts clean (enforce everywhere) and applies the doc.
        let node_b = ModeStore::new(Mode::Enforce);
        assert_eq!(node_b.resolve("sqli", None), Mode::Enforce);
        let doc = cluster_sync::read_modes(&state)
            .await
            .expect("published doc is readable");
        node_b.set_snapshot(doc.to_snapshot());
        assert_eq!(
            node_b.resolve("sqli", None),
            Mode::LogOnly,
            "node B converged on the peer-published mode"
        );
    }

    // Generation is monotonic so a poller's `doc.generation > applied`
    // gate fires exactly once per publish.
    #[tokio::test]
    async fn generation_advances_each_publish() {
        let state = backend();
        let modes = ModeStore::new(Mode::Enforce);
        let g1 = cluster_sync::publish_modes(&state, &modes.current()).await;
        let g2 = cluster_sync::publish_modes(&state, &modes.current()).await;
        assert_eq!(g1, Some(1));
        assert_eq!(g2, Some(2));
    }

    // reset_state bumps the shared epoch; a peer that seeded `seen` at
    // the pre-reset value observes the increase and would flush local.
    #[tokio::test]
    async fn reset_epoch_increments_and_is_observable() {
        let state = backend();
        let seen_before = cluster_sync::read_reset_epoch(&state).await;
        assert_eq!(seen_before, 0);

        let e1 = cluster_sync::publish_reset_epoch(&state).await;
        assert_eq!(e1, Some(1));
        assert!(cluster_sync::read_reset_epoch(&state).await > seen_before);

        let e2 = cluster_sync::publish_reset_epoch(&state).await;
        assert_eq!(e2, Some(2));
    }

    // -----------------------------------------------------------------
    // HIGH-2 — operator access-list convergence
    // -----------------------------------------------------------------

    use aegis_control::api::blacklist::{AccessListEntry, AccessListStore};

    fn entry(id: &str, value: &str) -> AccessListEntry {
        AccessListEntry {
            id: id.into(),
            kind: "ip".into(),
            value: value.into(),
            note: String::new(),
            expires_at: None,
            bypass: Vec::new(),
            created_at: chrono::Utc::now(),
        }
    }

    // The core HIGH-2 guarantee: a blacklist entry added on one node
    // (published to the shared backend) is enforced on a second node
    // after it polls + applies — no longer node-local.
    #[tokio::test]
    async fn published_blacklist_converges_to_a_second_node() {
        let state = backend();
        let ip: std::net::IpAddr = "203.0.113.7".parse().unwrap();

        // Node A blocks the IP and publishes.
        let gen = cluster_sync::publish_access_list_upsert(
            &state,
            "blacklist",
            &entry("bl-1", "203.0.113.7"),
        )
        .await;
        assert_eq!(gen, Some(1), "first publish is generation 1");

        // Node B starts clean — the IP is NOT blocked yet.
        let node_b = AccessListStore::new();
        assert_eq!(node_b.matches(ip, None), None);

        // Node B polls + applies the published doc → now enforced.
        let doc = cluster_sync::read_access_list(&state, "blacklist")
            .await
            .expect("published doc is readable");
        node_b.replace_entries(doc.entries);
        assert_eq!(
            node_b.matches(ip, None),
            Some("bl-1".to_string()),
            "node B converged on the peer-published blacklist entry"
        );
    }

    // A removal on one node lifts the block on a peer after convergence.
    #[tokio::test]
    async fn blacklist_removal_propagates() {
        let state = backend();
        let ip: std::net::IpAddr = "203.0.113.7".parse().unwrap();

        cluster_sync::publish_access_list_upsert(&state, "blacklist", &entry("bl-1", "203.0.113.7"))
            .await;

        // Node B has converged on the entry.
        let node_b = AccessListStore::new();
        let doc = cluster_sync::read_access_list(&state, "blacklist").await.unwrap();
        node_b.replace_entries(doc.entries);
        assert_eq!(node_b.matches(ip, None), Some("bl-1".to_string()));

        // Operator un-blocks on node A.
        let gen = cluster_sync::publish_access_list_remove(&state, "blacklist", "bl-1").await;
        assert_eq!(gen, Some(2), "removal advances the generation");

        // Node B applies the newer doc → block lifted.
        let doc = cluster_sync::read_access_list(&state, "blacklist").await.unwrap();
        node_b.replace_entries(doc.entries);
        assert_eq!(node_b.matches(ip, None), None, "node B lifted the block");
    }

    // Delta-on-latest publishing: concurrent upserts of DIFFERENT ids
    // merge instead of clobbering (the reason we read-modify-CAS the
    // published doc rather than pushing a whole local snapshot).
    #[tokio::test]
    async fn distinct_upserts_merge_by_id() {
        let state = backend();
        cluster_sync::publish_access_list_upsert(&state, "blacklist", &entry("a", "1.1.1.1")).await;
        cluster_sync::publish_access_list_upsert(&state, "blacklist", &entry("b", "2.2.2.2")).await;

        let doc = cluster_sync::read_access_list(&state, "blacklist").await.unwrap();
        let mut ids: Vec<&str> = doc.entries.iter().map(|e| e.id.as_str()).collect();
        ids.sort_unstable();
        assert_eq!(ids, vec!["a", "b"], "both entries survive — no clobber");
        assert_eq!(doc.generation, 2);
    }

    // Blacklist and whitelist are independent keys — a blacklist publish
    // does not bleed into the whitelist doc.
    #[tokio::test]
    async fn lists_are_keyed_independently() {
        let state = backend();
        cluster_sync::publish_access_list_upsert(&state, "blacklist", &entry("a", "1.1.1.1")).await;
        assert!(cluster_sync::read_access_list(&state, "whitelist").await.is_none());
        let bl = cluster_sync::read_access_list(&state, "blacklist").await.unwrap();
        assert_eq!(bl.entries.len(), 1);
    }
}
