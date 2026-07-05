//! MaxMind `.mmdb` reader.
//!
//! Wraps the `maxminddb` crate and adapts it to the
//! [`super::GeoIpLookup`] trait. Each DB is independently
//! optional — the operator can wire just country, just ASN,
//! both, or neither.
//!
//! # Hot reload
//!
//! Call [`MaxMindReader::reload_country`] / [`reload_asn`] to
//! swap the underlying file. Existing references obtained from
//! `country()` / `asn()` are unaffected because the reader is
//! `Arc`-swapped internally.

use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use arc_swap::ArcSwapOption;
use maxminddb::geoip2;
use maxminddb::Reader;

use super::GeoIpLookup;

/// Errors when loading or refreshing a `.mmdb`.
#[derive(Debug)]
pub enum GeoIpError {
    /// Underlying `maxminddb` error (corrupt DB, missing field, …).
    Db(maxminddb::MaxMindDBError),
    /// IO error reading the file.
    Io(std::io::Error),
}

impl std::fmt::Display for GeoIpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GeoIpError::Db(e) => write!(f, "geoip db error: {e}"),
            GeoIpError::Io(e) => write!(f, "geoip io error: {e}"),
        }
    }
}

impl std::error::Error for GeoIpError {}

impl From<maxminddb::MaxMindDBError> for GeoIpError {
    fn from(e: maxminddb::MaxMindDBError) -> Self {
        GeoIpError::Db(e)
    }
}

impl From<std::io::Error> for GeoIpError {
    fn from(e: std::io::Error) -> Self {
        GeoIpError::Io(e)
    }
}

/// MaxMind-backed [`GeoIpLookup`].
///
/// Both DBs are independently optional. Construct with
/// [`MaxMindReader::open`] (one-shot) or
/// [`MaxMindReader::empty`] + [`reload_country`] /
/// [`reload_asn`] (hot-reload).
pub struct MaxMindReader {
    country: ArcSwapOption<Reader<Vec<u8>>>,
    asn: ArcSwapOption<Reader<Vec<u8>>>,
    country_path: ArcSwapOption<PathBuf>,
    asn_path: ArcSwapOption<PathBuf>,
}

impl MaxMindReader {
    /// Empty reader — both DBs unset. Useful when the operator
    /// wants only ASN, or when DBs will be wired in via
    /// `reload_*` later.
    pub fn empty() -> Self {
        Self {
            country: ArcSwapOption::from(None),
            asn: ArcSwapOption::from(None),
            country_path: ArcSwapOption::from(None),
            asn_path: ArcSwapOption::from(None),
        }
    }

    /// Open both DBs at once. Pass `None` to skip a DB.
    pub fn open(
        country_db: Option<&Path>,
        asn_db: Option<&Path>,
    ) -> Result<Self, GeoIpError> {
        let r = Self::empty();
        if let Some(p) = country_db {
            r.reload_country(p)?;
        }
        if let Some(p) = asn_db {
            r.reload_asn(p)?;
        }
        Ok(r)
    }

    /// Replace the country DB. The new file is read into memory
    /// and atomically swapped — concurrent lookups never see a
    /// half-written reader.
    pub fn reload_country(&self, path: &Path) -> Result<(), GeoIpError> {
        let bytes = std::fs::read(path)?;
        let reader = Reader::from_source(bytes)?;
        self.country.store(Some(Arc::new(reader)));
        self.country_path.store(Some(Arc::new(path.to_path_buf())));
        Ok(())
    }

    /// Replace the ASN DB. Same swap semantics as
    /// [`reload_country`].
    pub fn reload_asn(&self, path: &Path) -> Result<(), GeoIpError> {
        let bytes = std::fs::read(path)?;
        let reader = Reader::from_source(bytes)?;
        self.asn.store(Some(Arc::new(reader)));
        self.asn_path.store(Some(Arc::new(path.to_path_buf())));
        Ok(())
    }

    /// Path the country DB was last loaded from.
    pub fn country_path(&self) -> Option<PathBuf> {
        self.country_path.load_full().map(|p| (*p).clone())
    }

    /// Path the ASN DB was last loaded from.
    pub fn asn_path(&self) -> Option<PathBuf> {
        self.asn_path.load_full().map(|p| (*p).clone())
    }

    /// True iff a country DB is currently loaded.
    pub fn has_country(&self) -> bool {
        self.country.load().is_some()
    }

    /// True iff an ASN DB is currently loaded.
    pub fn has_asn(&self) -> bool {
        self.asn.load().is_some()
    }
}

impl Default for MaxMindReader {
    fn default() -> Self {
        Self::empty()
    }
}

impl GeoIpLookup for MaxMindReader {
    fn country(&self, ip: IpAddr) -> Option<String> {
        let reader = self.country.load_full()?;
        // MaxMind's `Country` struct exposes the ISO code at
        // `country.iso_code`.
        //
        // 2026-05-03 fix — the previous shape deliberately
        // skipped `registered_country` "for routing-honesty",
        // but for SOC dashboards (Top Attackers / Investigation
        // / threat-intel) the registered country is the right
        // answer: anycast IPs (1.1.1.1 / 9.9.9.9 / many CDN
        // edges) have an empty `country` block in GeoLite2-
        // Country and ONLY a `registered_country`.  Returning
        // None for those left the dashboard's Country column
        // blank for the busiest attackers.  Now we prefer
        // `country` then fall back to `registered_country` —
        // matches the classic "where is this IP registered"
        // operator question.
        let entry: geoip2::Country = reader.lookup(ip).ok()?;
        let from_country = entry
            .country
            .as_ref()
            .and_then(|c| c.iso_code)
            .map(|s| s.to_string());
        if from_country.is_some() {
            return from_country;
        }
        entry
            .registered_country
            .as_ref()
            .and_then(|c| c.iso_code)
            .map(|s| s.to_string())
    }

    fn asn(&self, ip: IpAddr) -> Option<u32> {
        let reader = self.asn.load_full()?;
        let entry: geoip2::Asn = reader.lookup(ip).ok()?;
        entry.autonomous_system_number
    }

    /// PE-2 — sum of search-tree node counts across the loaded DBs
    /// (the mmdb metadata's `node_count`). `None` when neither DB
    /// is loaded, so `/api/geoip/status` renders `null` instead of
    /// the old hardcoded `0`.
    fn indicator_count(&self) -> Option<u64> {
        let country = self.country.load_full().map(|r| u64::from(r.metadata.node_count));
        let asn = self.asn.load_full().map(|r| u64::from(r.metadata.node_count));
        match (country, asn) {
            (None, None) => None,
            (c, a) => Some(c.unwrap_or(0) + a.unwrap_or(0)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_reader_returns_none_for_both() {
        let r = MaxMindReader::empty();
        assert!(r.country("1.2.3.4".parse().unwrap()).is_none());
        assert!(r.asn("1.2.3.4".parse().unwrap()).is_none());
        assert!(!r.has_country());
        assert!(!r.has_asn());
        assert!(r.country_path().is_none());
        assert!(r.asn_path().is_none());
        // PE-2 — no DB loaded → no count, never a fake 0.
        assert_eq!(r.indicator_count(), None);
    }

    #[test]
    fn open_with_no_paths_yields_empty() {
        let r = MaxMindReader::open(None, None).unwrap();
        assert!(!r.has_country());
        assert!(!r.has_asn());
    }

    #[test]
    fn reload_missing_country_path_errors() {
        let r = MaxMindReader::empty();
        let err = r
            .reload_country(Path::new("/nonexistent/path/to/country.mmdb"))
            .err()
            .expect("missing path errors");
        assert!(matches!(err, GeoIpError::Io(_)), "got {err}");
    }

    #[test]
    fn reload_invalid_mmdb_errors() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bogus.mmdb");
        std::fs::write(&path, b"not a real mmdb").unwrap();
        let r = MaxMindReader::empty();
        let err = r.reload_country(&path).err().expect("bad mmdb errors");
        assert!(matches!(err, GeoIpError::Db(_)), "got {err}");
    }

    /// Live integration test. Run with:
    ///
    ///   AEGIS_GEOIP_INTEGRATION_TEST=1 \
    ///   AEGIS_GEOIP_COUNTRY_DB=/path/to/GeoLite2-Country.mmdb \
    ///   AEGIS_GEOIP_ASN_DB=/path/to/GeoLite2-ASN.mmdb \
    ///   AEGIS_GEOIP_TEST_IP=8.8.8.8 \
    ///   cargo test -p aegis-security --features geoip --lib \
    ///       geoip::reader::tests::live_lookup -- --nocapture
    #[test]
    fn live_lookup() {
        if std::env::var("AEGIS_GEOIP_INTEGRATION_TEST").is_err() {
            eprintln!("skipping live_lookup — set AEGIS_GEOIP_INTEGRATION_TEST=1 to run");
            return;
        }
        let country_db = std::env::var("AEGIS_GEOIP_COUNTRY_DB").ok();
        let asn_db = std::env::var("AEGIS_GEOIP_ASN_DB").ok();
        let test_ip: IpAddr = std::env::var("AEGIS_GEOIP_TEST_IP")
            .unwrap_or_else(|_| "8.8.8.8".to_string())
            .parse()
            .expect("AEGIS_GEOIP_TEST_IP must parse");
        let r = MaxMindReader::open(
            country_db.as_deref().map(Path::new),
            asn_db.as_deref().map(Path::new),
        )
        .expect("DBs open");
        eprintln!(
            "live: ip={} country={:?} asn={:?}",
            test_ip,
            r.country(test_ip),
            r.asn(test_ip)
        );
    }
}
