//! `/api/blacklist` + `/api/whitelist` shared store (D-M4-T4.5).
//!
//! Both endpoints share the same value type (`AccessListEntry`) and
//! the same in-memory store — the page differences are policy
//! (whitelist `bypass: ["all"]` triggers extra confirm) not data
//! shape. This module hosts the storage + bulk-import logic; the
//! whitelist module re-exports a typed alias.

#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AccessListEntry {
    pub id: String,
    /// `ip` (single IP), `cidr` (range), or `asn` (ASN number).
    pub kind: String,
    pub value: String,
    pub note: String,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    /// For whitelist: list of detector / action names to bypass.
    /// `vec!["all"]` triggers an extra confirm in the UI.
    pub bypass: Vec<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
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
}

impl AccessListStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_clamp(clamp: ComplianceClamp) -> Self {
        Self {
            inner: Arc::new(Mutex::new(AccessListState::default())),
            clamp,
        }
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
        let mut s = self.inner.lock().expect("access list poisoned");
        s.entries.remove(id).is_some()
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
}
