//! `/api/blacklist` + `/api/whitelist` shared store (D-M4-T4.5).
//!
//! Both endpoints share the same value type (`AccessListEntry`) and
//! the same in-memory store — the page differences are policy
//! (whitelist `bypass: ["all"]` triggers extra confirm) not data
//! shape. This module hosts the storage + bulk-import logic; the
//! whitelist module re-exports a typed alias.

#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use dashmap::DashMap;
use serde::{Deserialize, Serialize};

/// P4 (2026-05-11) — per-entry hit-counter window. Each entry
/// in the list gets a small ring of 1-hour buckets covering the
/// last 24 hours so the dashboard can render `HITS · 1h` and
/// `HITS · 24h` without operator-supplied window arithmetic.
///
/// Ring shape: 24 buckets × 1-hour granularity. The dashboard
/// currently asks for 1h / 24h windows; finer granularity would
/// need bucket size + count adjustments. Wall-clock seconds are
/// the addressable unit (`SystemTime::now()`).
///
/// Memory: 24 × 8 bytes per ring + DashMap overhead = ~256 bytes
/// per entry. A list with 10k entries → 2.5 MB. Fine.
const HIT_BUCKET_COUNT: usize = 24;
const HIT_BUCKET_SECS: u64 = 3600;

struct EntryHitRing {
    buckets: [AtomicU64; HIT_BUCKET_COUNT],
    last_bucket_ts: AtomicU64,
}

impl EntryHitRing {
    fn new() -> Self {
        Self {
            buckets: std::array::from_fn(|_| AtomicU64::new(0)),
            last_bucket_ts: AtomicU64::new(0),
        }
    }

    fn bucket_idx(secs: u64) -> usize {
        ((secs / HIT_BUCKET_SECS) as usize) % HIT_BUCKET_COUNT
    }

    fn record(&self, now_secs: u64) {
        let idx = Self::bucket_idx(now_secs);
        let prev_ts = self.last_bucket_ts.swap(now_secs, Ordering::Relaxed);
        let prev_bucket = now_secs / HIT_BUCKET_SECS;
        let prev_bucket_prev = prev_ts / HIT_BUCKET_SECS;
        let span = HIT_BUCKET_COUNT as u64;
        if prev_bucket.saturating_sub(prev_bucket_prev) >= span {
            // Ring fully expired; reset every bucket.
            for b in &self.buckets {
                b.store(0, Ordering::Relaxed);
            }
        } else if prev_bucket != prev_bucket_prev {
            // Rolled into a new bucket — reset only the one we're
            // about to write so older buckets remain summable
            // until their turn rotates.
            self.buckets[idx].store(0, Ordering::Relaxed);
        }
        self.buckets[idx].fetch_add(1, Ordering::Relaxed);
    }

    /// Sum the buckets covering the last `window_secs` seconds.
    /// `window_secs` is rounded UP to the next bucket boundary
    /// because the ring's granularity is `HIT_BUCKET_SECS`.
    fn snapshot(&self, now_secs: u64, window_secs: u64) -> u64 {
        let last = self.last_bucket_ts.load(Ordering::Relaxed);
        let last_bucket = last / HIT_BUCKET_SECS;
        let now_bucket = now_secs / HIT_BUCKET_SECS;
        // How many buckets back to read (inclusive of current).
        let mut want = (window_secs + HIT_BUCKET_SECS - 1) / HIT_BUCKET_SECS;
        if want == 0 {
            want = 1;
        }
        if want > HIT_BUCKET_COUNT as u64 {
            want = HIT_BUCKET_COUNT as u64;
        }
        let oldest_bucket = now_bucket.saturating_sub(want - 1);
        if last_bucket < oldest_bucket {
            // No hits inside the window.
            return 0;
        }
        let mut total = 0u64;
        for b in (oldest_bucket..=now_bucket).rev() {
            let idx = (b as usize) % HIT_BUCKET_COUNT;
            // We can't tell "this bucket holds data for B" vs
            // "for B - HIT_BUCKET_COUNT" from the bucket itself,
            // so use `last_bucket_ts` to bound: any bucket whose
            // expected time is older than `last_bucket -
            // HIT_BUCKET_COUNT` is implicitly empty.
            if last_bucket.saturating_sub(b) < HIT_BUCKET_COUNT as u64 {
                total = total.saturating_add(self.buckets[idx].load(Ordering::Relaxed));
            }
        }
        total
    }
}

impl EntryHitRing {
    /// 2026-05-27 (Phase C) — report every live bucket as
    /// `(absolute_bucket_ts, count)` for the metrics flush, where
    /// `absolute_bucket_ts` is the hour-bucket's start second. As in
    /// `RouteRing::drain_buckets`, lazy reset guarantees a bucket's
    /// count belongs to its most-recent residue-matching hour within
    /// the last `HIT_BUCKET_COUNT` hours; a fully-stale ring reports
    /// nothing.
    fn drain_buckets(&self, now_secs: u64) -> Vec<(u64, u64)> {
        let last = self.last_bucket_ts.load(Ordering::Relaxed);
        let last_bucket = last / HIT_BUCKET_SECS;
        let now_bucket = now_secs / HIT_BUCKET_SECS;
        let span = HIT_BUCKET_COUNT as u64;
        if last == 0 || now_bucket.saturating_sub(last_bucket) >= span {
            return Vec::new();
        }
        let mut out = Vec::new();
        for (idx, b) in self.buckets.iter().enumerate() {
            let count = b.load(Ordering::Relaxed);
            if count == 0 {
                continue;
            }
            let back = (last_bucket % span + span - idx as u64) % span;
            let bucket_no = last_bucket.saturating_sub(back);
            out.push((bucket_no * HIT_BUCKET_SECS, count));
        }
        out
    }
}

fn current_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs()
}

impl crate::metrics::window_flush::BucketSource for AccessListStore {
    fn drain_buckets(&self, now_secs: u64) -> Vec<(String, Vec<(u64, u64)>)> {
        self.drain_hit_buckets(now_secs)
    }
}

/// Per-list per-entry hit counter. Built once when the
/// `AccessListStore` is constructed; the data plane increments
/// inside `matches()` so callers don't have to remember.
#[derive(Default, Clone)]
struct AccessListHits {
    rings: Arc<DashMap<String, Arc<EntryHitRing>>>,
}

impl AccessListHits {
    fn record(&self, entry_id: &str) {
        let now = current_secs();
        let entry = self
            .rings
            .entry(entry_id.to_string())
            .or_insert_with(|| Arc::new(EntryHitRing::new()));
        entry.record(now);
    }

    fn snapshot_window(&self, window_secs: u64) -> HashMap<String, u64> {
        let now = current_secs();
        self.rings
            .iter()
            .map(|kv| (kv.key().clone(), kv.value().snapshot(now, window_secs)))
            .collect()
    }

    fn drain_all(&self, now_secs: u64) -> Vec<(String, Vec<(u64, u64)>)> {
        self.rings
            .iter()
            .map(|kv| (kv.key().clone(), kv.value().drain_buckets(now_secs)))
            .filter(|(_, b)| !b.is_empty())
            .collect()
    }

    fn forget(&self, entry_id: &str) {
        self.rings.remove(entry_id);
    }
}

/// Boundary trait the access-list matcher consults for
/// `kind: country` entries. Implemented in `aegis-proxy` by
/// a thin wrapper around `aegis_security::geoip::GeoIpLookup`
/// when the `geoip` feature is on; `None` otherwise so country
/// entries silently miss.
pub trait AccessListCountryLookup: Send + Sync {
    /// ISO-3166-1 alpha-2 country code for `peer`, uppercase,
    /// or `None` when MaxMind couldn't resolve.
    fn country_of(&self, peer: std::net::IpAddr) -> Option<String>;
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct AccessListEntry {
    pub id: String,
    /// `ip` (single IP), `cidr` (range), or `asn` (ASN number).
    pub kind: String,
    pub value: String,
    pub note: String,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    /// For whitelist: list of detector / action names to bypass.
    /// `vec!["all"]` triggers an extra confirm in the UI.
    ///
    /// HIGH-SO-01 (2026-05-12) — `#[serde(default)]` so the
    /// no-bypass case (an empty `Vec`) can be omitted on the
    /// wire. The dashboard's Top Attackers Block POST shipped
    /// without this field for a while and the resulting
    /// `missing field bypass` 400 broke the SOC's primary
    /// "click Block on attacker" workflow end-to-end. The
    /// dashboard fix in the same PR explicitly sends `bypass: []`;
    /// this belt protects future callers from tripping the same
    /// wire.
    #[serde(default)]
    pub bypass: Vec<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// Trust granted by a matched WHITELIST entry, derived from its
/// `bypass` field.
///
/// 2026-06-22 (BUG-whitelist-risk-gate) — the data plane consults this to
/// decide how far a whitelist hit reaches. Previously a whitelist match only
/// skipped the detector chain; the cumulative IP-risk gate ran regardless, so
/// an IP that had already accumulated risk kept getting `risk-score` 403s even
/// after being whitelisted (the operator's "trust this source" never took).
/// `Full` trust now also exempts the IP from that gate, which is what makes the
/// previously-inert `bypass` column actually change runtime behavior.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WhitelistTrust {
    /// Empty `bypass` (the dashboard's default "Add to whitelist") or an
    /// explicit `bypass: ["all"]`. Trust the source unconditionally: skip the
    /// detector chain AND exempt it from the cumulative IP-risk gate.
    Full,
    /// Specific detector classes (e.g. `["sqli", "xss"]`). Suppress those
    /// detectors, but the source is only partially trusted — the cumulative
    /// IP-risk gate still enforces on accumulated reputation.
    Detectors(Vec<String>),
}

impl WhitelistTrust {
    /// Classify a whitelist entry's `bypass` list. Empty, or containing `all`
    /// (case-insensitive), → [`WhitelistTrust::Full`]; any other non-empty list
    /// → [`WhitelistTrust::Detectors`].
    pub fn from_bypass(bypass: &[String]) -> Self {
        if bypass.is_empty() || bypass.iter().any(|b| b.eq_ignore_ascii_case("all")) {
            WhitelistTrust::Full
        } else {
            WhitelistTrust::Detectors(bypass.to_vec())
        }
    }

    /// Whether this trust level exempts the IP from the cumulative IP-risk gate.
    /// Only [`WhitelistTrust::Full`] does.
    pub fn is_full(&self) -> bool {
        matches!(self, WhitelistTrust::Full)
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct ListResponse {
    pub entries: Vec<AccessListEntry>,
}

#[derive(Clone, Debug, Serialize)]
pub struct BulkOutcome {
    pub line: u32,
    pub ok: bool,
    pub error: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct BulkResponse {
    pub applied: u32,
    pub failed: u32,
    pub outcomes: Vec<BulkOutcome>,
}

/// Compliance profile clamps `expires_at` so PCI / HIPAA TTL caps
/// can't be bypassed via the dashboard.
#[derive(Clone, Copy, Debug, Default)]
pub struct ComplianceClamp {
    pub max_ttl_seconds: Option<u64>,
}

#[derive(Default)]
struct AccessListState {
    entries: HashMap<String, AccessListEntry>,
}

#[derive(Clone, Default)]
pub struct AccessListStore {
    inner: Arc<Mutex<AccessListState>>,
    /// Compliance clamp applied to every put / bulk insert.
    pub clamp: ComplianceClamp,
    /// P4 (2026-05-11) — per-entry hit counter. Recorded inside
    /// `matches()` so callers can't forget to increment. Read by
    /// the `/api/blacklist/hits?window=N` + `/api/whitelist/hits`
    /// endpoints.
    hits: AccessListHits,
}

impl AccessListStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_clamp(clamp: ComplianceClamp) -> Self {
        Self {
            inner: Arc::new(Mutex::new(AccessListState::default())),
            clamp,
            hits: AccessListHits::default(),
        }
    }

    /// P4 — windowed per-entry hit snapshot. Returns
    /// `{entry_id: count}` over the last `window_secs` seconds,
    /// rounded up to the 1-hour bucket granularity. Entries with
    /// zero recorded hits since boot are omitted.
    ///
    /// **Node-local view.** On a cluster, use
    /// [`Self::hit_counts_aggregated`] when a shared state backend is
    /// wired so the dashboard sums every node's hits.
    pub fn hit_counts(&self, window_secs: u64) -> HashMap<String, u64> {
        self.hits.snapshot_window(window_secs)
    }

    /// 2026-05-27 (Phase C) — drain every entry's live hour-buckets as
    /// `(entry_id, [(absolute_bucket_ts, count)])` for the metrics
    /// flush task. `key_prefix` (e.g. `waf:hits:bl`) is set on the
    /// `WindowFlush`, not here.
    pub fn drain_hit_buckets(&self, now_secs: u64) -> Vec<(String, Vec<(u64, u64)>)> {
        self.hits.drain_all(now_secs)
    }

    pub fn list(&self) -> Vec<AccessListEntry> {
        let s = self.inner.lock().expect("access list poisoned");
        let mut v: Vec<AccessListEntry> = s.entries.values().cloned().collect();
        v.sort_by(|a, b| a.id.cmp(&b.id));
        v
    }

    pub fn get(&self, id: &str) -> Option<AccessListEntry> {
        let s = self.inner.lock().expect("access list poisoned");
        s.entries.get(id).cloned()
    }

    /// Apply compliance clamp to `expires_at` then upsert. Returns
    /// `Err` if validation fails.
    pub fn put(&self, mut entry: AccessListEntry) -> Result<AccessListEntry, String> {
        validate_entry(&entry)?;
        if let Some(max_ttl) = self.clamp.max_ttl_seconds {
            let cap =
                chrono::Utc::now() + chrono::Duration::seconds(max_ttl as i64);
            entry.expires_at = match entry.expires_at {
                Some(ts) if ts > cap => Some(cap),
                Some(ts) => Some(ts),
                None => Some(cap),
            };
        }
        let mut s = self.inner.lock().expect("access list poisoned");
        s.entries.insert(entry.id.clone(), entry.clone());
        Ok(entry)
    }

    pub fn delete(&self, id: &str) -> bool {
        let removed = {
            let mut s = self.inner.lock().expect("access list poisoned");
            s.entries.remove(id).is_some()
        };
        if removed {
            // Forget the hit history too — keeping it around would
            // surface stale counts if an operator added an entry,
            // it racked up hits, removed it, and re-added with the
            // same id.
            self.hits.forget(id);
        }
        removed
    }

    /// HIGH-2 (2026-06-13 preprod feature run) — replace the entire
    /// entry set with a cluster-converged snapshot. Called by the
    /// convergence poller when a peer publishes a newer access-list
    /// generation, so an operator add/remove on any node enforces
    /// fleet-wide instead of staying node-local.
    ///
    /// Entries are taken verbatim (the published doc is the already-
    /// merged authority); no compliance clamp is re-applied because the
    /// originating node clamped on `put`. Hit counters for ids that
    /// vanish are forgotten (same rationale as [`Self::delete`]); ids
    /// that survive keep their local hit history.
    pub fn replace_entries(&self, entries: Vec<AccessListEntry>) {
        let new_ids: std::collections::HashSet<&str> =
            entries.iter().map(|e| e.id.as_str()).collect();
        let dropped: Vec<String> = {
            let mut s = self.inner.lock().expect("access list poisoned");
            let dropped = s
                .entries
                .keys()
                .filter(|id| !new_ids.contains(id.as_str()))
                .cloned()
                .collect::<Vec<_>>();
            s.entries = entries.into_iter().map(|e| (e.id.clone(), e)).collect();
            dropped
        };
        for id in dropped {
            self.hits.forget(&id);
        }
    }

    /// Runtime check: does ANY entry in the list match the given
    /// `peer` IP? Operators add entries via the dashboard and
    /// expect the data plane to enforce them — this is the
    /// hot-path matcher.
    ///
    /// `country_lookup` is consulted for `kind: country` entries.
    /// Pass `None` when no GeoIP reader is wired (build w/o the
    /// `geoip` feature, or operator hasn't configured the .mmdb)
    /// — country entries silently miss in that case.
    ///
    /// Returns the FIRST matching entry's `id` for audit, or
    /// None when nothing matched. Expired entries are skipped.
    pub fn matches(
        &self,
        peer: std::net::IpAddr,
        country_lookup: Option<&dyn AccessListCountryLookup>,
    ) -> Option<String> {
        self.first_match(peer, country_lookup, |entry| entry.id.clone())
    }

    /// WHITELIST-only sibling of [`Self::matches`]: returns the matched entry's
    /// [`WhitelistTrust`] classification instead of just its id, so the data
    /// plane can decide whether the hit also exempts the IP from the cumulative
    /// IP-risk gate (full trust) or only suppresses detectors (partial trust).
    ///
    /// Records the hit identically to `matches` — use one OR the other per
    /// request, never both, or the entry's hit counter double-counts.
    pub fn match_whitelist_trust(
        &self,
        peer: std::net::IpAddr,
        country_lookup: Option<&dyn AccessListCountryLookup>,
    ) -> Option<WhitelistTrust> {
        self.first_match(peer, country_lookup, |entry| {
            WhitelistTrust::from_bypass(&entry.bypass)
        })
    }

    /// Shared hot-path match loop. Returns `project(entry)` for the FIRST
    /// matching, non-expired entry — recording its hit before returning — or
    /// `None` when nothing matched. Both [`Self::matches`] and
    /// [`Self::match_whitelist_trust`] funnel through here so the kind/expiry
    /// matching and hit-recording logic live in exactly one place.
    fn first_match<R>(
        &self,
        peer: std::net::IpAddr,
        country_lookup: Option<&dyn AccessListCountryLookup>,
        project: impl Fn(&AccessListEntry) -> R,
    ) -> Option<R> {
        let s = self.inner.lock().expect("access list poisoned");
        let now = chrono::Utc::now();
        // Cache the country lookup so we only resolve once per
        // call regardless of how many country entries the list
        // has. None = "didn't try / couldn't resolve".
        let mut cached_country: Option<Option<String>> = None;
        for entry in s.entries.values() {
            if let Some(exp) = entry.expires_at {
                if now >= exp {
                    continue;
                }
            }
            let matched = match entry.kind.as_str() {
                "ip" => entry.value.parse::<std::net::IpAddr>().ok() == Some(peer),
                "cidr" => entry
                    .value
                    .parse::<ipnet::IpNet>()
                    .ok()
                    .map(|n| n.contains(&peer))
                    .unwrap_or(false),
                "asn" => false, // ASN matching needs a separate lookup; not wired in v1
                "country" => {
                    let lookup = match country_lookup {
                        Some(l) => l,
                        None => continue,
                    };
                    if cached_country.is_none() {
                        cached_country = Some(lookup.country_of(peer));
                    }
                    matches!(cached_country.as_ref().unwrap().as_deref(), Some(cc) if cc == entry.value)
                }
                _ => false,
            };
            if matched {
                // P4 — record the hit inside the matcher so callers
                // can't forget to increment.
                self.hits.record(&entry.id);
                return Some(project(entry));
            }
        }
        None
    }

    /// Validate every entry first; on success, apply atomically.
    /// On any validation failure return per-line outcomes and
    /// don't mutate the store.
    pub fn bulk_insert(&self, entries: Vec<AccessListEntry>) -> BulkResponse {
        let mut outcomes = Vec::with_capacity(entries.len());
        let mut all_ok = true;
        for (i, entry) in entries.iter().enumerate() {
            match validate_entry(entry) {
                Ok(()) => outcomes.push(BulkOutcome {
                    line: (i + 1) as u32,
                    ok: true,
                    error: None,
                }),
                Err(e) => {
                    all_ok = false;
                    outcomes.push(BulkOutcome {
                        line: (i + 1) as u32,
                        ok: false,
                        error: Some(e),
                    });
                }
            }
        }
        if !all_ok {
            return BulkResponse {
                applied: 0,
                failed: outcomes.iter().filter(|o| !o.ok).count() as u32,
                outcomes,
            };
        }
        // All validated → apply.
        let mut applied = 0u32;
        for mut entry in entries {
            if let Some(max_ttl) = self.clamp.max_ttl_seconds {
                let cap =
                    chrono::Utc::now() + chrono::Duration::seconds(max_ttl as i64);
                entry.expires_at = match entry.expires_at {
                    Some(ts) if ts > cap => Some(cap),
                    Some(ts) => Some(ts),
                    None => Some(cap),
                };
            }
            let mut s = self.inner.lock().expect("access list poisoned");
            s.entries.insert(entry.id.clone(), entry);
            applied += 1;
        }
        BulkResponse {
            applied,
            failed: 0,
            outcomes,
        }
    }
}

fn validate_entry(e: &AccessListEntry) -> Result<(), String> {
    if e.id.trim().is_empty() {
        return Err("id is required".into());
    }
    match e.kind.as_str() {
        "ip" | "cidr" | "asn" => {}
        // FIX 2026-05-03 — country-code support. Operator
        // populates `value` with an ISO-3166-1 alpha-2 code
        // (`CN`, `RU`, `KP`, …); the access-list evaluator
        // resolves the request's source IP via the GeoIP
        // reader and matches on the resulting country.
        // Validation here only checks shape (2 letters,
        // ASCII alpha, uppercase). Whether the country is
        // resolvable at runtime depends on the loaded
        // MaxMind DB.
        "country" => {
            let cc = e.value.trim();
            if cc.len() != 2
                || !cc.bytes().all(|b| b.is_ascii_uppercase())
            {
                return Err(format!(
                    "country code must be ISO-3166-1 alpha-2 (2 uppercase letters), got '{cc}'",
                ));
            }
            return Ok(());
        }
        other => return Err(format!("unknown kind: {other} (expected ip / cidr / asn / country)")),
    }
    if e.value.trim().is_empty() {
        return Err("value is required".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entry_hit_ring_drain_reconstructs_hour_buckets() {
        // 2026-05-27 (Phase C) — drain yields (hour_bucket_start_secs, count).
        let r = EntryHitRing::new();
        r.record(3600 * 100 + 5); // hour-bucket 100 → abs_ts 360000
        r.record(3600 * 100 + 9); // same bucket → count 2
        r.record(3600 * 101 + 1); // hour-bucket 101 → abs_ts 363600, count 1
        let mut got = r.drain_buckets(3600 * 101 + 10);
        got.sort();
        assert_eq!(got, vec![(3600 * 100, 2), (3600 * 101, 1)]);
    }

    #[test]
    fn entry_hit_ring_drain_empty_when_stale() {
        let r = EntryHitRing::new();
        r.record(3600 * 100);
        // 25 hours later — older than the 24-bucket window.
        assert!(r.drain_buckets(3600 * 125).is_empty());
    }

    fn entry(id: &str, kind: &str, value: &str) -> AccessListEntry {
        AccessListEntry {
            id: id.into(),
            kind: kind.into(),
            value: value.into(),
            note: String::new(),
            expires_at: None,
            bypass: vec![],
            created_at: chrono::Utc::now(),
        }
    }

    #[test]
    fn deserialize_accepts_body_without_bypass_field() {
        // HIGH-SO-01 (2026-05-12) — the dashboard's Top Attackers
        // Block POST shipped for a while without `bypass`. The
        // server-side belt is `#[serde(default)]` so future
        // callers omitting the no-bypass case don't trip a 400.
        let raw = r#"{
            "id": "qa",
            "kind": "ip",
            "value": "203.0.113.99",
            "note": "no bypass field",
            "created_at": "2026-05-12T00:00:00Z"
        }"#;
        let e: AccessListEntry = serde_json::from_str(raw)
            .expect("body without `bypass` must deserialize");
        assert!(e.bypass.is_empty(), "missing bypass should default to []");
    }

    #[test]
    fn put_rejects_empty_id() {
        let s = AccessListStore::new();
        let r = s.put(entry("", "ip", "1.1.1.1"));
        assert!(r.is_err());
    }

    #[test]
    fn put_rejects_unknown_kind() {
        let s = AccessListStore::new();
        let r = s.put(entry("a", "wat", "1.1.1.1"));
        assert!(r.is_err());
        let msg = r.unwrap_err();
        assert!(
            msg.contains("expected ip / cidr / asn / country"),
            "error should list valid kinds, got: {msg}",
        );
    }

    #[test]
    fn put_accepts_country_kind_with_iso_alpha2() {
        let s = AccessListStore::new();
        s.put(entry("cn", "country", "CN")).expect("CN should validate");
        s.put(entry("ru", "country", "RU")).expect("RU should validate");
        s.put(entry("kp", "country", "KP")).expect("KP should validate");
        assert_eq!(s.list().len(), 3);
    }

    /// Test stub for the AccessListCountryLookup trait.
    struct StaticCountryLookup(std::collections::HashMap<std::net::IpAddr, String>);
    impl AccessListCountryLookup for StaticCountryLookup {
        fn country_of(&self, peer: std::net::IpAddr) -> Option<String> {
            self.0.get(&peer).cloned()
        }
    }

    #[test]
    fn matches_ip_kind_exact() {
        let s = AccessListStore::new();
        s.put(entry("a", "ip", "203.0.113.7")).unwrap();
        assert_eq!(
            s.matches("203.0.113.7".parse().unwrap(), None),
            Some("a".to_string()),
        );
        assert_eq!(s.matches("203.0.113.8".parse().unwrap(), None), None);
    }

    #[test]
    fn matches_cidr_kind_contains() {
        let s = AccessListStore::new();
        s.put(entry("net", "cidr", "10.0.0.0/8")).unwrap();
        assert!(s.matches("10.5.5.5".parse().unwrap(), None).is_some());
        assert!(s.matches("11.0.0.1".parse().unwrap(), None).is_none());
    }

    #[test]
    fn matches_country_kind_resolves_via_lookup() {
        let s = AccessListStore::new();
        s.put(entry("cn", "country", "CN")).unwrap();
        let mut map = std::collections::HashMap::new();
        let bad: std::net::IpAddr = "118.26.104.78".parse().unwrap();
        let good: std::net::IpAddr = "8.8.8.8".parse().unwrap();
        map.insert(bad, "CN".to_string());
        map.insert(good, "US".to_string());
        let lookup = StaticCountryLookup(map);
        assert_eq!(s.matches(bad, Some(&lookup)), Some("cn".to_string()));
        assert_eq!(s.matches(good, Some(&lookup)), None);
    }

    #[test]
    fn matches_country_silently_misses_when_lookup_is_none() {
        let s = AccessListStore::new();
        s.put(entry("cn", "country", "CN")).unwrap();
        // No GeoIP wired (build w/o feature OR operator hasn't
        // configured the .mmdb) → country entries silently miss.
        assert_eq!(s.matches("118.26.104.78".parse().unwrap(), None), None);
    }

    #[test]
    fn matches_skips_expired_entries() {
        let s = AccessListStore::new();
        let mut e = entry("ip", "ip", "1.1.1.1");
        e.expires_at = Some(chrono::Utc::now() - chrono::Duration::seconds(1));
        s.put(e).unwrap();
        assert_eq!(s.matches("1.1.1.1".parse().unwrap(), None), None);
    }

    // ---- BUG-whitelist-risk-gate (2026-06-22): WhitelistTrust ----

    #[test]
    fn whitelist_trust_full_for_empty_bypass() {
        // The dashboard's default "Add to whitelist" sends `bypass: []`.
        // That means "trust this source unconditionally" → Full.
        assert_eq!(WhitelistTrust::from_bypass(&[]), WhitelistTrust::Full);
        assert!(WhitelistTrust::from_bypass(&[]).is_full());
    }

    #[test]
    fn whitelist_trust_full_for_all_keyword_case_insensitive() {
        assert_eq!(
            WhitelistTrust::from_bypass(&["all".to_string()]),
            WhitelistTrust::Full,
        );
        assert_eq!(
            WhitelistTrust::from_bypass(&["ALL".to_string()]),
            WhitelistTrust::Full,
        );
        // `all` anywhere in the list wins (full trust dominates).
        assert_eq!(
            WhitelistTrust::from_bypass(&["sqli".to_string(), "All".to_string()]),
            WhitelistTrust::Full,
        );
    }

    #[test]
    fn whitelist_trust_detectors_for_specific_list() {
        let t = WhitelistTrust::from_bypass(&["sqli".to_string(), "xss".to_string()]);
        assert_eq!(
            t,
            WhitelistTrust::Detectors(vec!["sqli".to_string(), "xss".to_string()]),
        );
        // Partial trust does NOT exempt the cumulative IP-risk gate.
        assert!(!t.is_full());
    }

    #[test]
    fn match_whitelist_trust_classifies_matched_entry() {
        let s = AccessListStore::new();
        // Full-trust entry (empty bypass) — the user's exact case.
        s.put(entry("wl", "ip", "192.177.62.55")).unwrap();
        let trust = s.match_whitelist_trust("192.177.62.55".parse().unwrap(), None);
        assert_eq!(trust, Some(WhitelistTrust::Full));
    }

    #[test]
    fn match_whitelist_trust_returns_detectors_for_partial_entry() {
        let s = AccessListStore::new();
        let mut e = entry("wl", "ip", "203.0.113.7");
        e.bypass = vec!["sqli".to_string()];
        s.put(e).unwrap();
        let trust = s.match_whitelist_trust("203.0.113.7".parse().unwrap(), None);
        assert_eq!(trust, Some(WhitelistTrust::Detectors(vec!["sqli".to_string()])));
    }

    #[test]
    fn match_whitelist_trust_returns_none_on_miss() {
        let s = AccessListStore::new();
        s.put(entry("wl", "ip", "203.0.113.7")).unwrap();
        assert_eq!(
            s.match_whitelist_trust("203.0.113.8".parse().unwrap(), None),
            None,
        );
    }

    #[test]
    fn match_whitelist_trust_records_hit_like_matches() {
        // Parity with `matches`: a hit increments the entry's counter so the
        // dashboard's "HITS · 1H" column reflects whitelist traffic.
        let s = AccessListStore::new();
        s.put(entry("wl", "ip", "203.0.113.7")).unwrap();
        let _ = s.match_whitelist_trust("203.0.113.7".parse().unwrap(), None);
        let counts = s.hit_counts(3600);
        assert_eq!(counts.get("wl").copied(), Some(1));
    }

    #[test]
    fn matches_returns_first_hit_for_audit_traceability() {
        let s = AccessListStore::new();
        s.put(entry("a", "cidr", "10.0.0.0/8")).unwrap();
        s.put(entry("b", "ip", "10.5.5.5")).unwrap();
        // Both match 10.5.5.5; the first-listed (HashMap order
        // is stable enough for tests on a single insert order).
        let result = s.matches("10.5.5.5".parse().unwrap(), None);
        assert!(result == Some("a".to_string()) || result == Some("b".to_string()));
    }

    #[test]
    fn put_rejects_country_kind_with_lowercase_or_wrong_length() {
        let s = AccessListStore::new();
        let cases: &[(&str, &str)] = &[
            ("lower",      "cn"),    // lowercase
            ("three",      "USA"),   // 3 letters
            ("one",        "U"),     // 1 letter
            ("digits",     "12"),    // not alpha
            ("mixed_case", "Us"),    // mixed case
            ("empty",      ""),      // empty
        ];
        for (id, value) in cases {
            let r = s.put(entry(id, "country", value));
            assert!(
                r.is_err(),
                "country={value:?} should be rejected by validator",
            );
            let msg = r.unwrap_err();
            assert!(
                msg.contains("ISO-3166-1 alpha-2"),
                "error should mention the standard, got: {msg}",
            );
        }
    }

    #[test]
    fn put_get_delete_roundtrip() {
        let s = AccessListStore::new();
        s.put(entry("a", "ip", "1.1.1.1")).unwrap();
        s.put(entry("b", "cidr", "10.0.0.0/8")).unwrap();
        assert_eq!(s.list().len(), 2);
        assert!(s.get("a").is_some());
        assert!(s.delete("a"));
        assert_eq!(s.list().len(), 1);
    }

    #[test]
    fn compliance_clamp_caps_expires_at() {
        let s = AccessListStore::with_clamp(ComplianceClamp {
            max_ttl_seconds: Some(60),
        });
        let mut e = entry("a", "ip", "1.1.1.1");
        e.expires_at = Some(chrono::Utc::now() + chrono::Duration::days(7));
        let stored = s.put(e).unwrap();
        let cap = chrono::Utc::now() + chrono::Duration::seconds(60);
        assert!(stored.expires_at.unwrap() <= cap + chrono::Duration::seconds(2));
    }

    #[test]
    fn compliance_clamp_fills_missing_expires_at() {
        let s = AccessListStore::with_clamp(ComplianceClamp {
            max_ttl_seconds: Some(60),
        });
        let stored = s.put(entry("a", "ip", "1.1.1.1")).unwrap();
        assert!(stored.expires_at.is_some());
    }

    #[test]
    fn bulk_insert_atomic_on_failure() {
        // One bad entry must prevent any from being inserted.
        let s = AccessListStore::new();
        let r = s.bulk_insert(vec![
            entry("a", "ip", "1.1.1.1"),
            entry("b", "wat", "x"),    // bad kind
            entry("c", "ip", "2.2.2.2"),
        ]);
        assert_eq!(r.applied, 0);
        assert_eq!(r.failed, 1);
        assert_eq!(s.list().len(), 0);
    }

    #[test]
    fn bulk_insert_applies_when_all_valid() {
        let s = AccessListStore::new();
        let r = s.bulk_insert(vec![
            entry("a", "ip", "1.1.1.1"),
            entry("b", "cidr", "10.0.0.0/8"),
            entry("c", "asn", "AS13335"),
        ]);
        assert_eq!(r.applied, 3);
        assert_eq!(r.failed, 0);
        assert_eq!(s.list().len(), 3);
    }

    // ---- cross-list conflict detection (2026-07-02) --------------------
    //
    // Same (kind, value) on both the blacklist and whitelist is a
    // contradictory config. The data plane resolves it deterministically
    // (blacklist wins — checked first), but nothing warned the operator.
    // `find_by_value` powers a non-blocking warning on add.

    #[test]
    fn find_by_value_returns_matching_entry() {
        let s = AccessListStore::new();
        s.put(entry("a", "ip", "203.0.113.7")).unwrap();
        let hit = s.find_by_value("ip", "203.0.113.7");
        assert_eq!(hit.map(|e| e.id), Some("a".to_string()));
    }

    #[test]
    fn find_by_value_requires_kind_match() {
        // Same textual value under a different kind is NOT a conflict —
        // an `ip` "10" and an `asn` "10" are different things.
        let s = AccessListStore::new();
        s.put(entry("a", "asn", "AS10")).unwrap();
        assert!(s.find_by_value("ip", "AS10").is_none());
        assert!(s.find_by_value("asn", "AS10").is_some());
    }

    #[test]
    fn find_by_value_trims_and_matches_country_case_insensitively() {
        let s = AccessListStore::new();
        s.put(entry("cn", "country", "CN")).unwrap();
        // Trimmed input matches; country codes are canonical-uppercase.
        assert!(s.find_by_value("country", " CN ").is_some());
        assert!(s.find_by_value("country", "cn").is_some());
        // A different country doesn't.
        assert!(s.find_by_value("country", "RU").is_none());
    }

    #[test]
    fn find_by_value_absent_returns_none() {
        let s = AccessListStore::new();
        s.put(entry("a", "ip", "1.1.1.1")).unwrap();
        assert!(s.find_by_value("ip", "2.2.2.2").is_none());
    }

    // The conflict builder names the SIBLING entry and always reports the
    // blacklist as the winner (fail-closed precedence), regardless of
    // which list the operator just added to.

    #[test]
    fn conflict_for_add_reports_blacklist_wins_when_adding_to_whitelist() {
        let blacklist = AccessListStore::new();
        blacklist.put(entry("bad-7", "ip", "203.0.113.7")).unwrap();
        // Operator just added 203.0.113.7 to the WHITELIST; the sibling
        // (blacklist) already has it.
        let c = conflict_for_add("whitelist", "ip", "203.0.113.7", &blacklist)
            .expect("conflict detected");
        assert_eq!(c.list, "blacklist");
        assert_eq!(c.id, "bad-7");
        assert!(
            c.effect.contains("blacklist wins"),
            "effect must name blacklist as the winner: {}",
            c.effect,
        );
    }

    #[test]
    fn conflict_for_add_reports_blacklist_wins_when_adding_to_blacklist() {
        let whitelist = AccessListStore::new();
        whitelist.put(entry("trust-7", "ip", "203.0.113.7")).unwrap();
        // Operator just added 203.0.113.7 to the BLACKLIST; sibling
        // (whitelist) has it. Winner is STILL the blacklist (the one just
        // added), so the effect names the whitelist entry as the no-op.
        let c = conflict_for_add("blacklist", "ip", "203.0.113.7", &whitelist)
            .expect("conflict detected");
        assert_eq!(c.list, "whitelist");
        assert_eq!(c.id, "trust-7");
        assert!(c.effect.contains("blacklist wins"), "effect: {}", c.effect);
    }

    #[test]
    fn conflict_for_add_none_without_sibling_match() {
        let sibling = AccessListStore::new();
        sibling.put(entry("other", "ip", "9.9.9.9")).unwrap();
        assert!(conflict_for_add("whitelist", "ip", "203.0.113.7", &sibling).is_none());
    }
}
