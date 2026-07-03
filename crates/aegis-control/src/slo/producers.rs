//! SLO-P5 — pure transition detectors behind the alert producers.
//!
//! Each subsystem (passive upstream health, cert inventory, DDoS
//! gate) observes raw state on its own cadence; the functions here
//! decide which [`AlertEvent`]s a state change emits, and carry the
//! per-producer memory so every alert fires **once per transition**
//! (never once per sweep). Pure and clock-free — unit-testable
//! without the owning runtime; the proxy wires their outputs into
//! the alert dispatch channel.

use chrono::{DateTime, Utc};
use std::collections::HashMap;

use super::AlertEvent;

// ---------------------------------------------------------------------------
// Upstream pool health
// ---------------------------------------------------------------------------

/// One pool's health as observed by a passive-health sweep.
#[derive(Clone, Debug)]
pub struct PoolHealthObservation {
    pub pool: String,
    pub healthy: u32,
    pub total: u32,
    /// Address of a currently-down member (the first one the
    /// sweep saw), for the alert body. `None` when fully healthy.
    pub first_down: Option<String>,
}

/// Per-pool degradation memory. One instance lives in the
/// passive-health monitor task.
#[derive(Debug, Default)]
pub struct PoolAlertState {
    degraded: HashMap<String, bool>,
}

impl PoolAlertState {
    /// Fold one sweep's observations: emits
    /// [`AlertEvent::UpstreamPoolDegraded`] when a pool drops
    /// below full healthy membership, and
    /// [`AlertEvent::UpstreamPoolRecovered`] when it returns to
    /// fully healthy — once per transition each.
    pub fn observe(
        &mut self,
        observations: &[PoolHealthObservation],
        now: DateTime<Utc>,
    ) -> Vec<AlertEvent> {
        let _ = (observations, now);
        todo!("SLO-P5: implement after RED is validated")
    }
}

// ---------------------------------------------------------------------------
// Cert expiry bands
// ---------------------------------------------------------------------------

/// Expiry band a cert can be in. Band *worsening* is what alerts;
/// a renewal (band improving) silently clears the memory so a
/// future expiry alerts again.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum CertBand {
    /// ≥ 30 days remaining.
    Ok,
    /// 7–29 days remaining → Ticket (via `AlertEvent::severity`).
    Warning,
    /// < 7 days remaining → Page.
    Critical,
}

/// Band for a days-remaining figure.
pub fn cert_band(days_remaining: u32) -> CertBand {
    let _ = days_remaining;
    todo!("SLO-P5: implement after RED is validated")
}

/// One cert as observed by the inventory sweep.
#[derive(Clone, Debug)]
pub struct CertObservation {
    pub host: String,
    pub days_remaining: u32,
    pub not_after: DateTime<Utc>,
}

/// Per-host band memory. One instance lives in the cert sweep.
#[derive(Debug, Default)]
pub struct CertAlertState {
    bands: HashMap<String, CertBand>,
}

impl CertAlertState {
    /// Fold one sweep: emits [`AlertEvent::CertExpiringSoon`]
    /// when a host's band WORSENS (Ok→Warning, Warning→Critical,
    /// Ok→Critical) — once per band per host, not once per
    /// sweep. A band improvement (renewal) clears the memory.
    pub fn observe(
        &mut self,
        certs: &[CertObservation],
        now: DateTime<Utc>,
    ) -> Vec<AlertEvent> {
        let _ = (certs, now);
        todo!("SLO-P5: implement after RED is validated")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::slo::AlertSeverity;

    fn pool(pool: &str, healthy: u32, total: u32, first_down: Option<&str>) -> PoolHealthObservation {
        PoolHealthObservation {
            pool: pool.into(),
            healthy,
            total,
            first_down: first_down.map(Into::into),
        }
    }

    // -- pool transitions ---------------------------------------------------

    #[test]
    fn pool_degrade_fires_once_per_transition_and_recovers() {
        let mut state = PoolAlertState::default();
        let now = Utc::now();

        // Healthy sweep: nothing.
        assert!(state.observe(&[pool("api", 3, 3, None)], now).is_empty());

        // One member drops: exactly one Degraded event.
        let events = state.observe(&[pool("api", 2, 3, Some("10.0.0.2:80"))], now);
        assert_eq!(events.len(), 1);
        match &events[0] {
            AlertEvent::UpstreamPoolDegraded {
                pool, healthy, total, first_down, ..
            } => {
                assert_eq!(pool, "api");
                assert_eq!((*healthy, *total), (2, 3));
                assert_eq!(first_down, "10.0.0.2:80");
            }
            other => panic!("expected Degraded, got {other:?}"),
        }

        // Still degraded next sweep: silent (no re-fire).
        assert!(state
            .observe(&[pool("api", 2, 3, Some("10.0.0.2:80"))], now)
            .is_empty());
        // Degrading FURTHER while already degraded: still silent
        // (the incident is already known; severity escalation is
        // future work).
        assert!(state
            .observe(&[pool("api", 1, 3, Some("10.0.0.2:80"))], now)
            .is_empty());

        // Fully healthy again: exactly one Recovered.
        let events = state.observe(&[pool("api", 3, 3, None)], now);
        assert_eq!(events.len(), 1);
        assert!(matches!(
            &events[0],
            AlertEvent::UpstreamPoolRecovered { pool, .. } if pool == "api"
        ));
        // And it stays silent while healthy.
        assert!(state.observe(&[pool("api", 3, 3, None)], now).is_empty());
    }

    #[test]
    fn pool_full_outage_pages_partial_tickets() {
        let mut state = PoolAlertState::default();
        let now = Utc::now();
        let partial = state
            .observe(&[pool("api", 1, 3, Some("10.0.0.2:80"))], now)
            .remove(0);
        assert_eq!(
            partial.severity(),
            AlertSeverity::Ticket,
            "a pool with healthy members left is a Ticket",
        );

        let mut state = PoolAlertState::default();
        let full = state
            .observe(&[pool("api", 0, 3, Some("10.0.0.1:80"))], now)
            .remove(0);
        assert_eq!(
            full.severity(),
            AlertSeverity::Page,
            "zero healthy members is a Page — the pool is down",
        );
    }

    #[test]
    fn pool_empty_or_single_member_pools_behave() {
        let mut state = PoolAlertState::default();
        let now = Utc::now();
        // A configured-but-empty pool never alerts (nothing to lose).
        assert!(state.observe(&[pool("empty", 0, 0, None)], now).is_empty());
        // Two pools transition independently.
        let events = state.observe(
            &[
                pool("a", 0, 1, Some("10.0.0.1:80")),
                pool("b", 1, 1, None),
            ],
            now,
        );
        assert_eq!(events.len(), 1);
    }

    // -- cert bands -----------------------------------------------------------

    #[test]
    fn cert_bands_partition_days_remaining() {
        assert_eq!(cert_band(45), CertBand::Ok);
        assert_eq!(cert_band(30), CertBand::Ok);
        assert_eq!(cert_band(29), CertBand::Warning);
        assert_eq!(cert_band(7), CertBand::Warning);
        assert_eq!(cert_band(6), CertBand::Critical);
        assert_eq!(cert_band(0), CertBand::Critical);
    }

    fn cert(host: &str, days: u32) -> CertObservation {
        CertObservation {
            host: host.into(),
            days_remaining: days,
            not_after: Utc::now() + chrono::Duration::days(days as i64),
        }
    }

    #[test]
    fn cert_alerts_once_per_band_worsening_and_clears_on_renewal() {
        let mut state = CertAlertState::default();
        let now = Utc::now();

        // Healthy cert: silent.
        assert!(state.observe(&[cert("api.example", 90)], now).is_empty());

        // Drops into Warning: one Ticket-band event.
        let events = state.observe(&[cert("api.example", 20)], now);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].severity(), AlertSeverity::Ticket);

        // Repeated sweeps in the same band: silent (the hourly
        // sweep must not re-page daily-until-renewal — dedup only
        // suppresses for minutes).
        assert!(state.observe(&[cert("api.example", 19)], now).is_empty());

        // Worsens into Critical: one Page-band event.
        let events = state.observe(&[cert("api.example", 3)], now);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].severity(), AlertSeverity::Page);

        // Renewed: silent, and memory cleared…
        assert!(state.observe(&[cert("api.example", 364)], now).is_empty());
        // …so the NEXT expiry cycle alerts again.
        let events = state.observe(&[cert("api.example", 20)], now);
        assert_eq!(events.len(), 1);
    }
}
