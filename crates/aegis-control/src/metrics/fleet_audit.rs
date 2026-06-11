//! F6 (2026-06-11 cluster QC) — leaderless fleet **audit tail** for the
//! Live Feed / Audit Trail backfill.
//!
//! The SSE live feed is already fleet-wide (every node's events fan out
//! to every console), but `GET /api/audit/since` only ever returned the
//! LOCAL node's ring — so on a page refresh the cross-node rows seen
//! live vanished. This module mirrors the [`crate::metrics::fleet_snapshot`]
//! publish/scan/merge pattern for audit rows:
//!
//! - Each node publishes a **bounded** tail (newest [`AUDIT_TAIL_LIMIT`]
//!   events) of its own ring to a self-owned, short-TTL key
//!   `fleet:audit:<node_id>`.
//! - Any node's console scans `fleet:audit:*`, concatenates the tails,
//!   sorts newest-first, truncates, and holds the result in a
//!   [`FleetAuditCache`] (`ArcSwap`) the **synchronous** admin GET
//!   handler reads without `.await`.
//!
//! It's a backfill aid, not a durable cross-node log — bounded by design
//! so the per-node key stays small (≈ a few tens of KB). Deep history
//! stays per-node (`collect-audit.sh`). Each physical event lives on
//! exactly one node's ring, so the merge is a plain concatenate + sort:
//! no cross-node de-duplication is needed. `node_id` (stamped at ring
//! ingest — see [`crate::dashboard_services`]) carries the attribution.

use std::sync::Arc;

use arc_swap::ArcSwap;

use aegis_core::audit::AuditEvent;

use crate::api::audit::{AuditFilter, AuditSinceEntry, AuditSinceResponse};

/// State-key prefix for per-node audit tails. The read path scans this.
pub const FLEET_AUDIT_PREFIX: &str = "fleet:audit:";

/// How many of the newest events each node publishes. Operator-confirmed
/// N=200 (2026-06-11): enough for a refresh to show the recent
/// cross-node feed, small enough that the per-node key stays cheap to
/// scan + decode every publish tick.
pub const AUDIT_TAIL_LIMIT: usize = 200;

/// Build the audit-tail key for a node id.
pub fn audit_key(node_id: &str) -> String {
    format!("{FLEET_AUDIT_PREFIX}{node_id}")
}

/// Merge per-node tails newest-first, truncated to `limit`. Each event
/// lives on exactly one node, so this is a concatenate + sort — no
/// de-dup. Ties on `ts` break by `node_id` then `request_id` for a
/// stable order across calls.
pub fn merge_tails(tails: &[Vec<AuditEvent>], limit: usize) -> Vec<AuditEvent> {
    let mut all: Vec<AuditEvent> = tails.iter().flat_map(|t| t.iter().cloned()).collect();
    all.sort_by(|a, b| {
        b.ts
            .cmp(&a.ts)
            .then_with(|| node_id_of(b).cmp(node_id_of(a)))
            .then_with(|| b.request_id.cmp(&a.request_id))
    });
    all.truncate(limit);
    all
}

/// Read `fields.node_id` (stamped at ring ingest), or `""` if absent.
fn node_id_of(ev: &AuditEvent) -> &str {
    ev.fields.get("node_id").and_then(|v| v.as_str()).unwrap_or("")
}

/// Render the merged fleet tail in the same shape `GET /api/audit/since`
/// returns, so the dashboard renders fleet rows through its existing
/// code path. Cross-node sequence numbers aren't comparable, so the
/// cursor fields are inert (`0`) and `seq` is a synthetic descending
/// index — the fleet view is a newest-first backfill, not a cursor-paged
/// stream (live updates still arrive via the fleet-wide SSE). `filter`
/// is applied post-merge so Investigation's pivots work fleet-wide too.
pub fn render_fleet_since(events: &[AuditEvent], limit: u32, filter: &AuditFilter) -> String {
    let limit = limit.clamp(1, AUDIT_TAIL_LIMIT as u32) as usize;
    let rows: Vec<AuditSinceEntry> = events
        .iter()
        .filter(|ev| filter.matches(ev))
        .take(limit)
        .enumerate()
        .map(|(i, ev)| AuditSinceEntry {
            // Synthetic, strictly-descending so the client's newest-first
            // render order is preserved; not a real cross-node cursor.
            seq: (events.len() - i) as u64,
            event: ev.clone(),
        })
        .collect();
    let resp = AuditSinceResponse {
        cursor: 0,
        next_cursor: 0,
        events: rows,
        gap: false,
    };
    serde_json::to_string(&resp).unwrap_or_else(|_| String::from("{}"))
}

/// Scan every live `fleet:audit:*` key, decode each tail, and
/// [`merge_tails`] them. Dead nodes' keys have TTL'd out. Decode
/// failures are skipped (a peer on a newer schema shouldn't poison the
/// whole view).
pub async fn scan_and_merge_audit(
    backend: &dyn aegis_core::state::StateBackend,
    limit: usize,
) -> Vec<AuditEvent> {
    let mut tails: Vec<Vec<AuditEvent>> = Vec::new();
    if let Ok(keys) = backend.scan_prefix(FLEET_AUDIT_PREFIX).await {
        for k in keys {
            if let Ok(Some(bytes)) = backend.get(&k).await {
                if let Ok(t) = serde_json::from_slice::<Vec<AuditEvent>>(&bytes) {
                    tails.push(t);
                }
            }
        }
    }
    merge_tails(&tails, limit)
}

/// PB / F6 (2026-06-11) — merge peers' audit tails by a KNOWN node roster
/// (one `GET fleet:audit:<node>` per id) instead of a whole-keyspace
/// `SCAN MATCH`. Bounded O(nodes): fits a tight Redis timeout, is immune to
/// keyspace growth (the busy shared keyspace no longer gates the merge),
/// and works on a sharded/cluster Redis where a single-connection `SCAN`
/// only sees one shard. A node whose key has TTL'd out (dead) returns
/// `None` and is skipped, so the roster may be slightly stale.
pub async fn merge_audit_from_roster(
    backend: &dyn aegis_core::state::StateBackend,
    node_ids: &[String],
    limit: usize,
) -> Vec<AuditEvent> {
    let mut tails: Vec<Vec<AuditEvent>> = Vec::new();
    for id in node_ids {
        let key = audit_key(id);
        if let Ok(Some(bytes)) = backend.get(&key).await {
            if let Ok(t) = serde_json::from_slice::<Vec<AuditEvent>>(&bytes) {
                tails.push(t);
            }
        }
    }
    merge_tails(&tails, limit)
}

/// `ArcSwap`-backed cache of the latest merged fleet audit tail. The
/// publish task refreshes it each tick; the synchronous
/// `GET /api/audit/since?scope=fleet` handler reads it without `.await`.
/// `None` until the first merge (read path then falls back to the local
/// ring, i.e. today's behaviour).
#[derive(Clone, Default)]
pub struct FleetAuditCache {
    inner: Arc<ArcSwap<Option<Vec<AuditEvent>>>>,
}

impl FleetAuditCache {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(ArcSwap::from_pointee(None)),
        }
    }

    /// Replace the cached merged tail (called on each publish tick).
    pub fn store(&self, events: Vec<AuditEvent>) {
        self.inner.store(Arc::new(Some(events)));
    }

    /// Latest merged tail, or `None` before the first merge.
    pub fn load(&self) -> Option<Vec<AuditEvent>> {
        (**self.inner.load()).clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_core::audit::AuditClass;

    fn ev(node: &str, request_id: &str, ts_ms: i64) -> AuditEvent {
        AuditEvent {
            schema_version: 1,
            ts: chrono::DateTime::<chrono::Utc>::from_timestamp_millis(ts_ms).unwrap(),
            request_id: request_id.into(),
            class: AuditClass::Detection,
            tenant_id: None,
            tier: None,
            action: "block".into(),
            reason: "test".into(),
            client_ip: "1.2.3.4".into(),
            route_id: None,
            rule_id: None,
            risk_score: Some(80),
            method: None,
            path: None,
            mode: None,
            fields: serde_json::json!({ "node_id": node }),
        }
    }

    #[test]
    fn merge_orders_newest_first_across_nodes() {
        let a = vec![ev("waf-1", "a1", 100), ev("waf-1", "a2", 300)];
        let b = vec![ev("waf-2", "b1", 200), ev("waf-2", "b2", 400)];
        let merged = merge_tails(&[a, b], 10);
        let order: Vec<i64> = merged.iter().map(|e| e.ts.timestamp_millis()).collect();
        assert_eq!(order, vec![400, 300, 200, 100], "newest-first across nodes");
    }

    #[test]
    fn merge_truncates_to_limit() {
        let a: Vec<AuditEvent> = (0..150).map(|i| ev("waf-1", &format!("a{i}"), i)).collect();
        let b: Vec<AuditEvent> = (0..150).map(|i| ev("waf-2", &format!("b{i}"), 1000 + i)).collect();
        let merged = merge_tails(&[a, b], AUDIT_TAIL_LIMIT);
        assert_eq!(merged.len(), AUDIT_TAIL_LIMIT);
        // 300 events truncated to 200 newest-first: all 150 of waf-2
        // (ts 1000+) win, plus the 50 newest of waf-1 (ts 100..149).
        let waf2 = merged.iter().filter(|e| node_id_of(e) == "waf-2").count();
        let waf1 = merged.iter().filter(|e| node_id_of(e) == "waf-1").count();
        assert_eq!(waf2, 150, "all newer waf-2 rows retained");
        assert_eq!(waf1, 50, "only the 50 newest waf-1 rows retained");
    }

    #[test]
    fn merge_keeps_distinct_same_request_id_rows() {
        // A detection + a block row can share a request_id within a node;
        // both must survive (no de-dup).
        let a = vec![ev("waf-1", "shared", 100), ev("waf-1", "shared", 101)];
        let merged = merge_tails(&[a], 10);
        assert_eq!(merged.len(), 2);
    }

    #[test]
    fn render_applies_filter_and_synthetic_seq() {
        let events = vec![ev("waf-1", "keep", 300), ev("waf-2", "drop", 200)];
        let filter = AuditFilter {
            request_id: Some("keep".into()),
            ..Default::default()
        };
        let json = render_fleet_since(&events, 50, &filter);
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        let rows = v["events"].as_array().unwrap();
        assert_eq!(rows.len(), 1, "filter applied post-merge");
        assert_eq!(rows[0]["request_id"], "keep");
        assert_eq!(v["cursor"], 0);
        assert_eq!(v["gap"], false);
    }

    #[test]
    fn cache_round_trips() {
        let cache = FleetAuditCache::new();
        assert!(cache.load().is_none());
        cache.store(vec![ev("waf-1", "x", 1)]);
        assert_eq!(cache.load().unwrap().len(), 1);
    }

    // PB / F6 — roster-driven audit merge: GET each known node's tail key,
    // no whole-keyspace SCAN. Minimal backend (only `get`/`set` are hit).
    struct MockBackend {
        kv: std::sync::Mutex<std::collections::HashMap<String, Vec<u8>>>,
    }

    #[async_trait::async_trait]
    impl aegis_core::state::StateBackend for MockBackend {
        async fn get(&self, key: &str) -> aegis_core::Result<Option<Vec<u8>>> {
            Ok(self.kv.lock().unwrap().get(key).cloned())
        }
        async fn set(&self, key: &str, val: &[u8], _: std::time::Duration) -> aegis_core::Result<()> {
            self.kv.lock().unwrap().insert(key.to_string(), val.to_vec());
            Ok(())
        }
        async fn del(&self, _: &str) -> aegis_core::Result<()> {
            Ok(())
        }
        async fn incr_window(
            &self,
            _: &str,
            _: std::time::Duration,
            _: u64,
        ) -> aegis_core::Result<aegis_core::state::SlidingWindowResult> {
            Ok(aegis_core::state::SlidingWindowResult {
                count: 0,
                allowed: true,
                retry_after: None,
            })
        }
        async fn token_bucket(&self, _: &str, _: u32, _: u32) -> aegis_core::Result<bool> {
            Ok(true)
        }
        async fn get_risk(&self, _: &aegis_core::risk::RiskKey) -> aegis_core::Result<u32> {
            Ok(0)
        }
        async fn add_risk(&self, _: &aegis_core::risk::RiskKey, _: i32, _: u32) -> aegis_core::Result<u32> {
            Ok(0)
        }
        async fn auto_block(&self, _: std::net::IpAddr, _: std::time::Duration) -> aegis_core::Result<()> {
            Ok(())
        }
        async fn is_auto_blocked(&self, _: std::net::IpAddr) -> aegis_core::Result<bool> {
            Ok(false)
        }
        async fn put_nonce(&self, _: &str, _: std::time::Duration) -> aegis_core::Result<bool> {
            Ok(true)
        }
        async fn consume_nonce(&self, _: &str) -> aegis_core::Result<bool> {
            Ok(true)
        }
    }

    #[tokio::test]
    async fn merge_audit_from_roster_unions_known_nodes() {
        use aegis_core::state::StateBackend as _;
        let backend = MockBackend {
            kv: std::sync::Mutex::new(std::collections::HashMap::new()),
        };
        let a = vec![ev("waf-1", "a1", 100), ev("waf-1", "a2", 300)];
        let b = vec![ev("waf-2", "b1", 200), ev("waf-2", "b2", 400)];
        for (node, tail) in [("waf-1", &a), ("waf-2", &b)] {
            let bytes = serde_json::to_vec(tail).unwrap();
            backend
                .set(&audit_key(node), &bytes, std::time::Duration::from_secs(10))
                .await
                .unwrap();
        }
        // Roster knows both nodes → union, newest-first.
        let ids = vec!["waf-1".to_string(), "waf-2".to_string()];
        let merged = merge_audit_from_roster(&backend, &ids, 10).await;
        let order: Vec<i64> = merged.iter().map(|e| e.ts.timestamp_millis()).collect();
        assert_eq!(order, vec![400, 300, 200, 100]);

        // A rostered id with no key (dead) is skipped; an unrostered node's
        // key is never read.
        let ids = vec!["waf-1".to_string(), "ghost".to_string()];
        let merged = merge_audit_from_roster(&backend, &ids, 10).await;
        assert_eq!(merged.len(), 2, "only the live, rostered node's tail");
        assert!(merged.iter().all(|e| node_id_of(e) == "waf-1"));
    }
}
