//! `/api/alert-receivers` — read-side foundation for the alert
//! channel management surface (CC-T2.1).
//!
//! Exposes the configured `slo::AlertReceiver` list to the
//! Tracking page so operators can see which channels exist,
//! their kinds, and the last-delivery state per receiver. All
//! secrets (bot tokens, webhook URLs, PagerDuty routing keys)
//! are redacted to last-4 chars at the boundary — the raw
//! secret never reaches the wire.
//!
//! The audit-mutated `PUT` / `POST .../test` / `DELETE` handlers
//! land in CC-T2.1.b once the proxy plumbs a
//! `SharedReceivers = Arc<ArcSwap<Vec<AlertReceiver>>>` into
//! the bundle (today receivers are loaded once at boot via
//! `slo::default_receivers()` and held in the dispatch task's
//! closure). The validators + dispatch-outcome ring shipped in
//! this module are the writable surface those handlers will
//! consume.
//!
//! Architecture mirrors `crate::api::upstreams_config`:
//! - View + redaction + validators are pure functions.
//! - [`AlertReceiversHandler`] owns a `provider` closure plugged
//!   in by the proxy boot path so this module doesn't need to
//!   depend on the proxy crate.
//! - [`DispatchOutcomeRing`] is the per-name "last delivery"
//!   record the dispatch task writes to and the GET endpoint
//!   reads from.


use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::Serialize;

use crate::slo::{AlertReceiver, ReceiverKind};

// ---------------------------------------------------------------------------
// Wire view (redacted) — `GET /api/alert-receivers` body
// ---------------------------------------------------------------------------

/// Top-level body. List ordering matches the configured order so
/// the dashboard can rely on positional UI tweaks (drag-to-reorder
/// is a CC-T2.2 follow-up).
#[derive(Clone, Debug, Serialize)]
pub struct AlertReceiversView {
    pub receivers: Vec<ReceiverEntry>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ReceiverEntry {
    pub name: String,
    pub kind: RedactedKind,
    pub status: ReceiverStatus,
    /// SLO-P6 — severity routing filter (empty = all severities).
    /// Not a secret; without it the editor could not show an
    /// existing filter and a save would silently clear it.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub severities: Vec<crate::slo::AlertSeverity>,
}

/// Mirror of [`ReceiverKind`] with secrets sanitised. Tagged
/// JSON so the dashboard's per-kind form binds cleanly.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RedactedKind {
    AlertmanagerWebhook {
        url: String,
    },
    Slack {
        webhook_url_redacted: String,
    },
    PagerDuty {
        routing_key_redacted: String,
    },
    ServiceNow {
        instance: String,
        table: String,
    },
    Jira {
        base_url: String,
        project: String,
    },
    VipTalk {
        bot_token_redacted: String,
        room_ids: Vec<String>,
    },
}

impl RedactedKind {
    /// Build the redacted view from a real [`ReceiverKind`].
    /// Non-secret fields are passed through verbatim; secrets
    /// are squashed to last-4-chars so the operator can still
    /// identify *which* token without leaking the whole thing.
    pub fn from_kind(k: &ReceiverKind) -> Self {
        match k {
            ReceiverKind::AlertmanagerWebhook { url } => Self::AlertmanagerWebhook {
                url: url.clone(),
            },
            ReceiverKind::Slack { webhook_url } => Self::Slack {
                webhook_url_redacted: redact_secret(webhook_url),
            },
            ReceiverKind::PagerDuty { routing_key } => Self::PagerDuty {
                routing_key_redacted: redact_secret(routing_key),
            },
            ReceiverKind::ServiceNow { instance, table } => Self::ServiceNow {
                instance: instance.clone(),
                table: table.clone(),
            },
            ReceiverKind::Jira { base_url, project } => Self::Jira {
                base_url: base_url.clone(),
                project: project.clone(),
            },
            ReceiverKind::VipTalk {
                bot_token,
                room_ids,
            } => Self::VipTalk {
                bot_token_redacted: redact_secret(bot_token),
                room_ids: room_ids.clone(),
            },
        }
    }

    /// Stable kind tag, mirroring the `serde(tag = "type")` value.
    /// The dashboard `<select>` binds against this.
    pub fn tag(&self) -> &'static str {
        match self {
            Self::AlertmanagerWebhook { .. } => "alertmanager_webhook",
            Self::Slack { .. } => "slack",
            Self::PagerDuty { .. } => "pager_duty",
            Self::ServiceNow { .. } => "service_now",
            Self::Jira { .. } => "jira",
            Self::VipTalk { .. } => "vip_talk",
        }
    }
}

/// Per-receiver dispatch status. All fields optional — a brand
/// new receiver has no history yet and reports
/// `last_delivered_at: None`, `consecutive_failures: 0`.
#[derive(Clone, Debug, Default, Serialize, PartialEq, Eq)]
pub struct ReceiverStatus {
    /// Unix seconds (UTC). `None` until the first delivery
    /// attempt completes.
    pub last_delivered_at: Option<i64>,
    /// Stable status code: `"ok"`, `"external"`,
    /// `"skipped_no_feature"`, or `"failed:<reason>"`.
    pub last_status: Option<String>,
    /// Counts only consecutive failures — clears on the next
    /// successful delivery (or `external` / `skipped_no_feature`
    /// since those are non-failure states from this module's
    /// perspective).
    pub consecutive_failures: u32,
}

// ---------------------------------------------------------------------------
// Secret redaction
// ---------------------------------------------------------------------------

const REDACT_PREFIX: &str = "****";

/// Redact a secret to last-4 chars. Returns `****abcd` for
/// secrets of length ≥ 4, `****` for shorter (no last-4 to
/// reveal). Empty input returns `****` so the wire shape is
/// always non-empty.
pub fn redact_secret(s: &str) -> String {
    let n = s.chars().count();
    if n < 4 {
        return REDACT_PREFIX.to_string();
    }
    let last4: String = s.chars().skip(n - 4).collect();
    format!("{REDACT_PREFIX}{last4}")
}

// ---------------------------------------------------------------------------
// Validators
// ---------------------------------------------------------------------------

/// Why a receiver-list update was rejected. Maps to a stable
/// `reason_code` so the dashboard drives targeted toasts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReceiverValidationError {
    /// A receiver had an empty `name`.
    EmptyName,
    /// Two receivers shared the same `name`. The dispatch ring
    /// is name-keyed; collisions corrupt the per-receiver
    /// status display.
    DuplicateName(String),
    /// The kind-specific target field (URL / token / key) was
    /// empty. `field` names which one for the error message.
    EmptyTarget {
        name: String,
        field: &'static str,
    },
    /// VipTalk receiver supplied no `room_ids` (or every entry
    /// was empty). Without at least one room the bot has
    /// nowhere to post.
    EmptyVipTalkRoomIds(String),
}

impl ReceiverValidationError {
    pub fn reason_code(&self) -> &'static str {
        match self {
            Self::EmptyName => "empty_name",
            Self::DuplicateName(_) => "duplicate_name",
            Self::EmptyTarget { .. } => "empty_target",
            Self::EmptyVipTalkRoomIds(_) => "empty_room_ids",
        }
    }
}

impl std::fmt::Display for ReceiverValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyName => f.write_str("receiver name must not be empty"),
            Self::DuplicateName(n) => write!(f, "duplicate receiver name: {n}"),
            Self::EmptyTarget { name, field } => {
                write!(f, "receiver {name}: {field} must not be empty")
            }
            Self::EmptyVipTalkRoomIds(n) => {
                write!(f, "receiver {n}: room_ids must contain at least one entry")
            }
        }
    }
}

impl std::error::Error for ReceiverValidationError {}

/// Validate a candidate receiver list. Returns the *first*
/// failure — the dashboard re-runs after each fix.
pub fn validate_receivers(
    receivers: &[AlertReceiver],
) -> Result<(), ReceiverValidationError> {
    let mut seen: std::collections::HashSet<String> =
        std::collections::HashSet::with_capacity(receivers.len());
    for r in receivers {
        if r.name.trim().is_empty() {
            return Err(ReceiverValidationError::EmptyName);
        }
        if !seen.insert(r.name.clone()) {
            return Err(ReceiverValidationError::DuplicateName(r.name.clone()));
        }
        validate_kind(&r.name, &r.kind)?;
    }
    Ok(())
}

fn validate_kind(name: &str, k: &ReceiverKind) -> Result<(), ReceiverValidationError> {
    match k {
        ReceiverKind::AlertmanagerWebhook { url } => empty_target(name, "url", url),
        ReceiverKind::Slack { webhook_url } => empty_target(name, "webhook_url", webhook_url),
        ReceiverKind::PagerDuty { routing_key } => {
            empty_target(name, "routing_key", routing_key)
        }
        ReceiverKind::ServiceNow { instance, table } => {
            empty_target(name, "instance", instance)?;
            empty_target(name, "table", table)
        }
        ReceiverKind::Jira { base_url, project } => {
            empty_target(name, "base_url", base_url)?;
            empty_target(name, "project", project)
        }
        ReceiverKind::VipTalk {
            bot_token,
            room_ids,
        } => {
            empty_target(name, "bot_token", bot_token)?;
            if room_ids.is_empty() || room_ids.iter().all(|r| r.trim().is_empty()) {
                return Err(ReceiverValidationError::EmptyVipTalkRoomIds(
                    name.to_string(),
                ));
            }
            Ok(())
        }
    }
}

fn empty_target(
    name: &str,
    field: &'static str,
    value: &str,
) -> Result<(), ReceiverValidationError> {
    if value.trim().is_empty() {
        Err(ReceiverValidationError::EmptyTarget {
            name: name.to_string(),
            field,
        })
    } else {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Dispatch outcome ring — per-receiver "last delivery" record
// ---------------------------------------------------------------------------

/// Thread-safe map from receiver name → [`ReceiverStatus`]. The
/// SLO dispatch task records every delivery outcome here; the
/// GET handler reads it. Cheap to clone (Arc-shared).
///
/// The store grows when new receivers appear and never shrinks
/// on its own — stale entries for removed receivers are pruned
/// from the response by name-set intersection in
/// [`AlertReceiversHandler::render`]. Long-running operators
/// can call [`Self::retain_names`] explicitly if they want a
/// hard cleanup after a renaming spree.
#[derive(Clone, Debug, Default)]
pub struct DispatchOutcomeRing {
    inner: Arc<Mutex<HashMap<String, ReceiverStatus>>>,
}

impl DispatchOutcomeRing {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a successful in-process delivery (today: VipTalk
    /// in `--features alerts` builds).
    pub fn record_delivered(&self, name: &str, unix_seconds: i64) {
        let mut g = self.inner.lock().expect("dispatch ring poisoned");
        let entry = g.entry(name.to_string()).or_default();
        entry.last_delivered_at = Some(unix_seconds);
        entry.last_status = Some("ok".to_string());
        entry.consecutive_failures = 0;
    }

    /// Record an "external delivery" — the receiver is one of
    /// the kinds the WAF doesn't deliver in-process (an
    /// off-box dispatcher reads it instead). Counts as a
    /// non-failure for `consecutive_failures` purposes.
    pub fn record_external(&self, name: &str, unix_seconds: i64) {
        let mut g = self.inner.lock().expect("dispatch ring poisoned");
        let entry = g.entry(name.to_string()).or_default();
        entry.last_delivered_at = Some(unix_seconds);
        entry.last_status = Some("external".to_string());
        entry.consecutive_failures = 0;
    }

    /// Record a build that's missing the `alerts` feature —
    /// VipTalk dispatch is a logged no-op in that mode. Treated
    /// as non-failure (the receiver isn't broken; the binary
    /// just isn't compiled to deliver in-process).
    pub fn record_skipped_no_feature(&self, name: &str, unix_seconds: i64) {
        let mut g = self.inner.lock().expect("dispatch ring poisoned");
        let entry = g.entry(name.to_string()).or_default();
        entry.last_delivered_at = Some(unix_seconds);
        entry.last_status = Some("skipped_no_feature".to_string());
        entry.consecutive_failures = 0;
    }

    /// Record a delivery failure. Increments
    /// `consecutive_failures` so the dashboard can pill it
    /// `failed N×`.
    pub fn record_failed(&self, name: &str, unix_seconds: i64, reason: &str) {
        let mut g = self.inner.lock().expect("dispatch ring poisoned");
        let entry = g.entry(name.to_string()).or_default();
        entry.last_delivered_at = Some(unix_seconds);
        entry.last_status = Some(format!("failed:{reason}"));
        entry.consecutive_failures = entry.consecutive_failures.saturating_add(1);
    }

    /// Snapshot the current status for one receiver. Returns
    /// the default empty status when the receiver has no
    /// history yet.
    pub fn status_of(&self, name: &str) -> ReceiverStatus {
        let g = self.inner.lock().expect("dispatch ring poisoned");
        g.get(name).cloned().unwrap_or_default()
    }

    /// Drop history for any receiver whose name isn't in
    /// `keep`. Called after a `PUT` rotates the receiver list
    /// to keep the store from growing unboundedly across
    /// rename storms.
    pub fn retain_names(&self, keep: &[String]) {
        let keep_set: std::collections::HashSet<&str> =
            keep.iter().map(String::as_str).collect();
        let mut g = self.inner.lock().expect("dispatch ring poisoned");
        g.retain(|k, _| keep_set.contains(k.as_str()));
    }
}

// ---------------------------------------------------------------------------
// Write helpers — used by the audit-mutated PUT / DELETE handlers
// ---------------------------------------------------------------------------

/// Result of [`apply_replace`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReplaceOutcome {
    pub names: Vec<String>,
    pub count: usize,
}

/// Why [`apply_delete`] / [`find_receiver`] couldn't find the
/// named receiver. Distinct from [`ReceiverValidationError`] so
/// the caller can map it to a 404 vs 400 status.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DeleteError {
    NotFound(String),
}

impl std::fmt::Display for DeleteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound(n) => write!(f, "no receiver named '{n}'"),
        }
    }
}

impl std::error::Error for DeleteError {}

/// Result of [`apply_delete`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeleteOutcome {
    pub removed: String,
    pub remaining: Vec<String>,
}

/// Apply a whole-list replace to a shared receiver store.
///
/// Validates first via [`validate_receivers`]; on Err the store
/// is untouched. On Ok the store is `.store(Arc::new(next))`-d
/// atomically and the dispatch ring is pruned of any names not
/// in the new list (so stale dispatch-status entries don't
/// linger across a rename).
pub fn apply_replace(
    store: &Arc<arc_swap::ArcSwap<Vec<AlertReceiver>>>,
    ring: &DispatchOutcomeRing,
    next: Vec<AlertReceiver>,
) -> Result<ReplaceOutcome, ReceiverValidationError> {
    validate_receivers(&next)?;
    let names: Vec<String> = next.iter().map(|r| r.name.clone()).collect();
    let count = next.len();
    store.store(Arc::new(next));
    ring.retain_names(&names);
    Ok(ReplaceOutcome { names, count })
}

/// Remove a single receiver by name. Returns `Err(NotFound)`
/// when no receiver with that name exists — the audit-mutated
/// DELETE handler maps this to a 404-class response so the
/// dashboard renders a targeted toast instead of a generic 500.
pub fn apply_delete(
    store: &Arc<arc_swap::ArcSwap<Vec<AlertReceiver>>>,
    ring: &DispatchOutcomeRing,
    name: &str,
) -> Result<DeleteOutcome, DeleteError> {
    let current = (**store.load()).clone();
    let next: Vec<AlertReceiver> = current
        .iter()
        .filter(|r| r.name != name)
        .cloned()
        .collect();
    if next.len() == current.len() {
        return Err(DeleteError::NotFound(name.to_string()));
    }
    let remaining: Vec<String> = next.iter().map(|r| r.name.clone()).collect();
    store.store(Arc::new(next));
    ring.retain_names(&remaining);
    Ok(DeleteOutcome {
        removed: name.to_string(),
        remaining,
    })
}

/// Look up a receiver by name from the shared store. Read-only;
/// the test endpoint uses this to find the target before
/// dispatching a synthetic alert.
pub fn find_receiver(
    store: &Arc<arc_swap::ArcSwap<Vec<AlertReceiver>>>,
    name: &str,
) -> Option<AlertReceiver> {
    (**store.load())
        .iter()
        .find(|r| r.name == name)
        .cloned()
}

// ---------------------------------------------------------------------------
// HTTP handler
// ---------------------------------------------------------------------------

/// Closure type the proxy plugs in at boot — returns the
/// currently-effective receiver list. Today the proxy holds the
/// list in a `default_receivers()` closure; once
/// `SharedReceivers = Arc<ArcSwap<Vec<AlertReceiver>>>` lands
/// (CC-T2.1.b) the closure becomes `move ||
/// (**shared.load()).clone()`.
pub type ReceiverProvider =
    Arc<dyn Fn() -> Vec<AlertReceiver> + Send + Sync + 'static>;

/// Default response cache TTL — matches the other tracking
/// surfaces. `/api/alerts` polls at 2 s in the dashboard.
const DEFAULT_CACHE_TTL: Duration = Duration::from_secs(2);

pub struct AlertReceiversHandler {
    provider: ReceiverProvider,
    ring: DispatchOutcomeRing,
    cache_ttl: Duration,
    cache: Mutex<Option<(Instant, String)>>,
}

impl AlertReceiversHandler {
    pub fn new<F>(provider: F, ring: DispatchOutcomeRing) -> Self
    where
        F: Fn() -> Vec<AlertReceiver> + Send + Sync + 'static,
    {
        Self::with_ttl(provider, ring, DEFAULT_CACHE_TTL)
    }

    pub fn with_ttl<F>(provider: F, ring: DispatchOutcomeRing, cache_ttl: Duration) -> Self
    where
        F: Fn() -> Vec<AlertReceiver> + Send + Sync + 'static,
    {
        Self {
            provider: Arc::new(provider),
            ring,
            cache_ttl,
            cache: Mutex::new(None),
        }
    }

    /// Cheap clone of the dispatch ring so the proxy's SLO
    /// dispatch task can record outcomes without holding a
    /// reference to the whole handler.
    pub fn ring(&self) -> DispatchOutcomeRing {
        self.ring.clone()
    }

    /// Build the JSON body for `GET /api/alert-receivers`.
    /// Cached for [`Self::cache_ttl`] so consecutive Tracking-
    /// page polls don't re-clone the receiver list.
    pub fn render(&self) -> String {
        let now = Instant::now();
        {
            let cache = self.cache.lock().expect("alert-receivers cache poisoned");
            if let Some((stamped, body)) = cache.as_ref() {
                if now.duration_since(*stamped) < self.cache_ttl {
                    return body.clone();
                }
            }
        }
        let body = self.render_uncached();
        let mut cache = self.cache.lock().expect("alert-receivers cache poisoned");
        *cache = Some((now, body.clone()));
        body
    }

    /// Render bypassing the cache. Useful for tests + the post-
    /// PUT response so the caller sees the new state instantly.
    pub fn render_uncached(&self) -> String {
        let view = self.snapshot();
        serde_json::to_string(&view).unwrap_or_else(|_| String::from("{}"))
    }

    /// Typed snapshot — the audit-mutated PUT handler in
    /// CC-T2.1.b uses this to compute the `before` diff
    /// without round-tripping through JSON.
    pub fn snapshot(&self) -> AlertReceiversView {
        let receivers = (self.provider)();
        let entries: Vec<ReceiverEntry> = receivers
            .iter()
            .map(|r| ReceiverEntry {
                name: r.name.clone(),
                kind: RedactedKind::from_kind(&r.kind),
                status: self.ring.status_of(&r.name),
                severities: r.severities.clone(),
            })
            .collect();
        AlertReceiversView {
            receivers: entries,
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::slo::ReceiverKind;

    fn vt_receiver(name: &str, token: &str) -> AlertReceiver {
        AlertReceiver {
            name: name.into(),
            kind: ReceiverKind::VipTalk {
                bot_token: token.into(),
                room_ids: vec!["!room:matrix.example".into()],
            },
            severities: Vec::new(),
        }
    }

    fn slack_receiver(name: &str, url: &str) -> AlertReceiver {
        AlertReceiver {
            name: name.into(),
            kind: ReceiverKind::Slack {
                webhook_url: url.into(),
            },
            severities: Vec::new(),
        }
    }

    // ----- redact_secret ----------------------------------------------------

    #[test]
    fn redact_returns_only_prefix_for_short_secrets() {
        assert_eq!(redact_secret(""), "****");
        assert_eq!(redact_secret("a"), "****");
        assert_eq!(redact_secret("abc"), "****");
    }

    #[test]
    fn redact_reveals_only_last_four_chars() {
        assert_eq!(redact_secret("abcd"), "****abcd");
        assert_eq!(redact_secret("supersecret-123-XYZW"), "****XYZW");
    }

    #[test]
    fn redact_handles_unicode_correctly() {
        // Last-4 *characters*, not bytes — must not slice mid-codepoint.
        assert_eq!(redact_secret("αβγδε"), "****βγδε");
    }

    // ----- RedactedKind -----------------------------------------------------

    #[test]
    fn redacted_kind_keeps_room_ids_clear() {
        let k = ReceiverKind::VipTalk {
            bot_token: "topsecret-EFGH".into(),
            room_ids: vec!["!room1:srv".into(), "!room2:srv".into()],
        };
        match RedactedKind::from_kind(&k) {
            RedactedKind::VipTalk {
                bot_token_redacted,
                room_ids,
            } => {
                assert_eq!(bot_token_redacted, "****EFGH");
                assert_eq!(room_ids, vec!["!room1:srv", "!room2:srv"]);
            }
            other => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn redacted_kind_redacts_slack_webhook() {
        let k = ReceiverKind::Slack {
            webhook_url: "https://hooks.slack.com/services/T0/B0/abcd1234".into(),
        };
        match RedactedKind::from_kind(&k) {
            RedactedKind::Slack {
                webhook_url_redacted,
            } => assert_eq!(webhook_url_redacted, "****1234"),
            other => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn redacted_kind_redacts_pagerduty_routing_key() {
        let k = ReceiverKind::PagerDuty {
            routing_key: "R0123456789abcdefABCD".into(),
        };
        match RedactedKind::from_kind(&k) {
            RedactedKind::PagerDuty {
                routing_key_redacted,
            } => assert_eq!(routing_key_redacted, "****ABCD"),
            other => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn redacted_kind_passes_through_non_secret_fields() {
        let sn = ReceiverKind::ServiceNow {
            instance: "acme.service-now.com".into(),
            table: "incident".into(),
        };
        match RedactedKind::from_kind(&sn) {
            RedactedKind::ServiceNow { instance, table } => {
                assert_eq!(instance, "acme.service-now.com");
                assert_eq!(table, "incident");
            }
            other => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn redacted_kind_passes_alertmanager_url_through() {
        // Alertmanager webhook URL is typically internal — not
        // redacted (operators need to see *which* AM cluster).
        let am = ReceiverKind::AlertmanagerWebhook {
            url: "http://alertmanager:9093/api/v1/alerts".into(),
        };
        match RedactedKind::from_kind(&am) {
            RedactedKind::AlertmanagerWebhook { url } => {
                assert_eq!(url, "http://alertmanager:9093/api/v1/alerts");
            }
            other => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn redacted_kind_tag_is_stable_snake_case() {
        let cases: Vec<(ReceiverKind, &str)> = vec![
            (
                ReceiverKind::AlertmanagerWebhook { url: "u".into() },
                "alertmanager_webhook",
            ),
            (ReceiverKind::Slack { webhook_url: "u".into() }, "slack"),
            (
                ReceiverKind::PagerDuty {
                    routing_key: "k".into(),
                },
                "pager_duty",
            ),
            (
                ReceiverKind::ServiceNow {
                    instance: "i".into(),
                    table: "t".into(),
                },
                "service_now",
            ),
            (
                ReceiverKind::Jira {
                    base_url: "b".into(),
                    project: "p".into(),
                },
                "jira",
            ),
            (
                ReceiverKind::VipTalk {
                    bot_token: "t".into(),
                    room_ids: vec!["r".into()],
                },
                "vip_talk",
            ),
        ];
        for (k, expected) in cases {
            assert_eq!(RedactedKind::from_kind(&k).tag(), expected);
        }
    }

    // ----- validators -------------------------------------------------------

    #[test]
    fn validate_accepts_minimal_well_formed_list() {
        let r = vec![vt_receiver("vt-prod", "tok-1234")];
        assert!(validate_receivers(&r).is_ok());
    }

    #[test]
    fn validate_accepts_empty_list() {
        // Empty list is valid at this layer — the dashboard's
        // last-receiver guard runs in CC-T2.2 (UX-side, not
        // backend), and operators may legitimately want to
        // disable all dispatch. Audit chain still records the
        // change.
        assert!(validate_receivers(&[]).is_ok());
    }

    #[test]
    fn validate_rejects_empty_name() {
        let r = vec![vt_receiver("", "tok-1234")];
        let err = validate_receivers(&r).unwrap_err();
        assert_eq!(err, ReceiverValidationError::EmptyName);
        assert_eq!(err.reason_code(), "empty_name");
    }

    #[test]
    fn validate_rejects_whitespace_only_name() {
        let r = vec![vt_receiver("   ", "tok-1234")];
        assert_eq!(
            validate_receivers(&r).unwrap_err(),
            ReceiverValidationError::EmptyName
        );
    }

    #[test]
    fn validate_rejects_duplicate_names() {
        let r = vec![
            vt_receiver("vt-prod", "tok-1234"),
            vt_receiver("vt-prod", "tok-5678"),
        ];
        let err = validate_receivers(&r).unwrap_err();
        match &err {
            ReceiverValidationError::DuplicateName(n) => assert_eq!(n, "vt-prod"),
            other => panic!("wrong variant: {other:?}"),
        }
        assert_eq!(err.reason_code(), "duplicate_name");
    }

    #[test]
    fn validate_rejects_empty_bot_token() {
        let r = vec![vt_receiver("vt", "")];
        let err = validate_receivers(&r).unwrap_err();
        match &err {
            ReceiverValidationError::EmptyTarget { name, field } => {
                assert_eq!(name, "vt");
                assert_eq!(*field, "bot_token");
            }
            other => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn validate_rejects_empty_viptalk_room_ids() {
        let r = vec![AlertReceiver {
            name: "vt".into(),
            kind: ReceiverKind::VipTalk {
                bot_token: "tok".into(),
                room_ids: vec![],
            },
            severities: Vec::new(),
        }];
        let err = validate_receivers(&r).unwrap_err();
        match &err {
            ReceiverValidationError::EmptyVipTalkRoomIds(n) => assert_eq!(n, "vt"),
            other => panic!("wrong variant: {other:?}"),
        }
        assert_eq!(err.reason_code(), "empty_room_ids");
    }

    #[test]
    fn validate_rejects_viptalk_room_ids_all_whitespace() {
        let r = vec![AlertReceiver {
            name: "vt".into(),
            kind: ReceiverKind::VipTalk {
                bot_token: "tok".into(),
                room_ids: vec!["   ".into(), "\t".into()],
            },
            severities: Vec::new(),
        }];
        assert_eq!(
            validate_receivers(&r).unwrap_err(),
            ReceiverValidationError::EmptyVipTalkRoomIds("vt".into())
        );
    }

    #[test]
    fn validate_rejects_empty_slack_webhook_url() {
        let r = vec![slack_receiver("slk", "")];
        let err = validate_receivers(&r).unwrap_err();
        match err {
            ReceiverValidationError::EmptyTarget { name, field } => {
                assert_eq!(name, "slk");
                assert_eq!(field, "webhook_url");
            }
            other => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn validate_rejects_pagerduty_empty_routing_key() {
        let r = vec![AlertReceiver {
            name: "pd".into(),
            kind: ReceiverKind::PagerDuty {
                routing_key: "".into(),
            },
            severities: Vec::new(),
        }];
        match validate_receivers(&r).unwrap_err() {
            ReceiverValidationError::EmptyTarget { field, .. } => {
                assert_eq!(field, "routing_key")
            }
            other => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn validate_rejects_servicenow_missing_instance_or_table() {
        let r = vec![AlertReceiver {
            name: "sn".into(),
            kind: ReceiverKind::ServiceNow {
                instance: "".into(),
                table: "incident".into(),
            },
            severities: Vec::new(),
        }];
        match validate_receivers(&r).unwrap_err() {
            ReceiverValidationError::EmptyTarget { field, .. } => {
                assert_eq!(field, "instance")
            }
            other => panic!("wrong variant: {other:?}"),
        }

        let r = vec![AlertReceiver {
            name: "sn".into(),
            kind: ReceiverKind::ServiceNow {
                instance: "acme.service-now.com".into(),
                table: "".into(),
            },
            severities: Vec::new(),
        }];
        match validate_receivers(&r).unwrap_err() {
            ReceiverValidationError::EmptyTarget { field, .. } => assert_eq!(field, "table"),
            other => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn validate_rejects_jira_missing_base_or_project() {
        let r = vec![AlertReceiver {
            name: "jr".into(),
            kind: ReceiverKind::Jira {
                base_url: "".into(),
                project: "OPS".into(),
            },
            severities: Vec::new(),
        }];
        match validate_receivers(&r).unwrap_err() {
            ReceiverValidationError::EmptyTarget { field, .. } => {
                assert_eq!(field, "base_url")
            }
            other => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn validate_rejects_alertmanager_empty_url() {
        let r = vec![AlertReceiver {
            name: "am".into(),
            kind: ReceiverKind::AlertmanagerWebhook { url: "".into() },
            severities: Vec::new(),
        }];
        match validate_receivers(&r).unwrap_err() {
            ReceiverValidationError::EmptyTarget { field, .. } => assert_eq!(field, "url"),
            other => panic!("wrong variant: {other:?}"),
        }
    }

    // ----- DispatchOutcomeRing ----------------------------------------------

    #[test]
    fn ring_records_delivered_and_clears_failures() {
        let ring = DispatchOutcomeRing::new();
        ring.record_failed("vt", 1_700_000_000, "timeout");
        ring.record_failed("vt", 1_700_000_010, "5xx");
        assert_eq!(ring.status_of("vt").consecutive_failures, 2);

        ring.record_delivered("vt", 1_700_000_020);
        let s = ring.status_of("vt");
        assert_eq!(s.last_delivered_at, Some(1_700_000_020));
        assert_eq!(s.last_status.as_deref(), Some("ok"));
        assert_eq!(s.consecutive_failures, 0);
    }

    #[test]
    fn ring_records_external_as_non_failure() {
        let ring = DispatchOutcomeRing::new();
        ring.record_failed("pd", 1, "boom");
        ring.record_external("pd", 2);
        let s = ring.status_of("pd");
        assert_eq!(s.last_status.as_deref(), Some("external"));
        assert_eq!(s.consecutive_failures, 0);
    }

    #[test]
    fn ring_records_skipped_no_feature_as_non_failure() {
        let ring = DispatchOutcomeRing::new();
        ring.record_failed("vt", 1, "boom");
        ring.record_skipped_no_feature("vt", 2);
        let s = ring.status_of("vt");
        assert_eq!(s.last_status.as_deref(), Some("skipped_no_feature"));
        assert_eq!(s.consecutive_failures, 0);
    }

    #[test]
    fn ring_failure_message_carries_reason() {
        let ring = DispatchOutcomeRing::new();
        ring.record_failed("vt", 7, "http_503");
        assert_eq!(
            ring.status_of("vt").last_status.as_deref(),
            Some("failed:http_503")
        );
    }

    #[test]
    fn ring_status_for_unknown_name_is_default() {
        let ring = DispatchOutcomeRing::new();
        assert_eq!(ring.status_of("nope"), ReceiverStatus::default());
    }

    #[test]
    fn ring_retain_names_drops_stale_entries() {
        let ring = DispatchOutcomeRing::new();
        ring.record_delivered("a", 1);
        ring.record_delivered("b", 2);
        ring.record_delivered("c", 3);
        ring.retain_names(&["a".into(), "c".into()]);
        assert!(ring.status_of("a").last_delivered_at.is_some());
        assert_eq!(ring.status_of("b"), ReceiverStatus::default()); // dropped
        assert!(ring.status_of("c").last_delivered_at.is_some());
    }

    #[test]
    fn ring_clones_share_underlying_storage() {
        let r1 = DispatchOutcomeRing::new();
        let r2 = r1.clone();
        r1.record_delivered("x", 100);
        assert_eq!(r2.status_of("x").last_delivered_at, Some(100));
    }

    #[test]
    fn ring_consecutive_failures_saturate() {
        let ring = DispatchOutcomeRing::new();
        // Use a smaller proxy via repeated calls; saturating_add
        // means we never overflow.
        for i in 0..5 {
            ring.record_failed("vt", i, "boom");
        }
        assert_eq!(ring.status_of("vt").consecutive_failures, 5);
    }

    // ----- AlertReceiversHandler -------------------------------------------

    fn provider_of(receivers: Vec<AlertReceiver>) -> impl Fn() -> Vec<AlertReceiver> + Clone {
        move || receivers.clone()
    }

    #[test]
    fn handler_renders_redacted_view() {
        let receivers = vec![vt_receiver("vt-prod", "topsecret-WXYZ")];
        let handler = AlertReceiversHandler::new(
            provider_of(receivers),
            DispatchOutcomeRing::new(),
        );
        let body = handler.render_uncached();
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["receivers"][0]["name"], "vt-prod");
        // serde(tag="type", rename_all="snake_case") produces
        // "vip_talk" for the `VipTalk` variant.
        assert_eq!(v["receivers"][0]["kind"]["type"], "vip_talk");
        assert_eq!(
            v["receivers"][0]["kind"]["bot_token_redacted"],
            "****WXYZ"
        );
        assert!(v["receivers"][0]["kind"].get("bot_token").is_none());
    }

    #[test]
    fn handler_includes_status_from_ring() {
        let receivers = vec![vt_receiver("vt", "tok-1234")];
        let ring = DispatchOutcomeRing::new();
        ring.record_delivered("vt", 1_700_000_000);
        let handler =
            AlertReceiversHandler::new(provider_of(receivers), ring.clone());
        let body = handler.render_uncached();
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(
            v["receivers"][0]["status"]["last_delivered_at"],
            1_700_000_000
        );
        assert_eq!(v["receivers"][0]["status"]["last_status"], "ok");
        assert_eq!(v["receivers"][0]["status"]["consecutive_failures"], 0);
    }

    #[test]
    fn handler_returns_default_status_for_receivers_with_no_history() {
        let receivers = vec![vt_receiver("brand-new", "tok-1234")];
        let handler = AlertReceiversHandler::new(
            provider_of(receivers),
            DispatchOutcomeRing::new(),
        );
        let view = handler.snapshot();
        assert_eq!(view.receivers[0].status, ReceiverStatus::default());
    }

    #[test]
    fn handler_caches_within_ttl() {
        // Repeated renders inside the TTL window must reuse the
        // cached body — provider should be invoked at most twice
        // (once per cache miss). We verify by making the
        // provider count its calls.
        use std::sync::atomic::{AtomicUsize, Ordering};
        let calls = Arc::new(AtomicUsize::new(0));
        let calls_inner = Arc::clone(&calls);
        let provider = move || {
            calls_inner.fetch_add(1, Ordering::Relaxed);
            vec![vt_receiver("vt", "tok-1234")]
        };
        let handler = AlertReceiversHandler::with_ttl(
            provider,
            DispatchOutcomeRing::new(),
            Duration::from_secs(60),
        );
        for _ in 0..10 {
            let _ = handler.render();
        }
        assert_eq!(calls.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn handler_render_uncached_bypasses_cache() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let calls = Arc::new(AtomicUsize::new(0));
        let calls_inner = Arc::clone(&calls);
        let provider = move || {
            calls_inner.fetch_add(1, Ordering::Relaxed);
            vec![]
        };
        let handler = AlertReceiversHandler::new(
            provider,
            DispatchOutcomeRing::new(),
        );
        let _ = handler.render_uncached();
        let _ = handler.render_uncached();
        let _ = handler.render_uncached();
        assert_eq!(calls.load(Ordering::Relaxed), 3);
    }

    #[test]
    fn handler_serialises_empty_list_cleanly() {
        let handler =
            AlertReceiversHandler::new(provider_of(vec![]), DispatchOutcomeRing::new());
        let body = handler.render_uncached();
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert!(v["receivers"].as_array().unwrap().is_empty());
    }

    #[test]
    fn handler_preserves_receiver_order() {
        let receivers = vec![
            vt_receiver("c", "tok-1"),
            vt_receiver("a", "tok-2"),
            vt_receiver("b", "tok-3"),
        ];
        let handler = AlertReceiversHandler::new(
            provider_of(receivers),
            DispatchOutcomeRing::new(),
        );
        let v: serde_json::Value =
            serde_json::from_str(&handler.render_uncached()).unwrap();
        let names: Vec<&str> = v["receivers"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["name"].as_str().unwrap())
            .collect();
        // Insertion order — not alphabetical (drag-to-reorder
        // depends on the proxy passing the operator-supplied
        // order through verbatim).
        assert_eq!(names, vec!["c", "a", "b"]);
    }

    // ----- write helpers (apply_replace / apply_delete / find) ------------

    fn fresh_store(
        initial: Vec<AlertReceiver>,
    ) -> Arc<arc_swap::ArcSwap<Vec<AlertReceiver>>> {
        Arc::new(arc_swap::ArcSwap::from_pointee(initial))
    }

    #[test]
    fn apply_replace_swaps_store_on_valid_input() {
        let store = fresh_store(vec![vt_receiver("old", "tok-1234")]);
        let ring = DispatchOutcomeRing::new();
        let out = apply_replace(
            &store,
            &ring,
            vec![
                vt_receiver("new-a", "tok-aaaa"),
                vt_receiver("new-b", "tok-bbbb"),
            ],
        )
        .unwrap();
        assert_eq!(out.count, 2);
        assert_eq!(out.names, vec!["new-a", "new-b"]);
        let live = (**store.load()).clone();
        assert_eq!(live.len(), 2);
        assert_eq!(live[0].name, "new-a");
    }

    #[test]
    fn apply_replace_leaves_store_untouched_on_validation_error() {
        let original = vec![vt_receiver("keep", "tok-1234")];
        let store = fresh_store(original.clone());
        let ring = DispatchOutcomeRing::new();
        // Empty bot_token → validation error.
        let err = apply_replace(&store, &ring, vec![vt_receiver("oops", "")])
            .unwrap_err();
        match &err {
            ReceiverValidationError::EmptyTarget { name, field } => {
                assert_eq!(name, "oops");
                assert_eq!(*field, "bot_token");
            }
            other => panic!("wrong variant: {other:?}"),
        }
        // Store was NOT swapped.
        let live = (**store.load()).clone();
        assert_eq!(live.len(), 1);
        assert_eq!(live[0].name, "keep");
    }

    #[test]
    fn apply_replace_prunes_dispatch_ring_of_stale_names() {
        let store = fresh_store(vec![
            vt_receiver("a", "tok-aaaa"),
            vt_receiver("b", "tok-bbbb"),
        ]);
        let ring = DispatchOutcomeRing::new();
        ring.record_delivered("a", 100);
        ring.record_delivered("b", 200);
        ring.record_failed("c-orphan", 1, "stale"); // should be pruned

        // New list keeps "a", drops "b", adds "c"; "c-orphan"
        // wasn't in current list but is in ring → must be pruned.
        apply_replace(
            &store,
            &ring,
            vec![vt_receiver("a", "tok-aaaa"), vt_receiver("c", "tok-cccc")],
        )
        .unwrap();

        assert_eq!(ring.status_of("a").last_delivered_at, Some(100));
        // "b" was in the ring but isn't in the new list — pruned.
        assert_eq!(ring.status_of("b"), ReceiverStatus::default());
        // "c-orphan" never in any receiver list — pruned.
        assert_eq!(ring.status_of("c-orphan"), ReceiverStatus::default());
        // "c" is new — never had history, returns default.
        assert_eq!(ring.status_of("c"), ReceiverStatus::default());
    }

    #[test]
    fn apply_replace_accepts_empty_list() {
        let store = fresh_store(vec![vt_receiver("a", "tok")]);
        let ring = DispatchOutcomeRing::new();
        ring.record_delivered("a", 1);
        let out = apply_replace(&store, &ring, vec![]).unwrap();
        assert_eq!(out.count, 0);
        assert!(out.names.is_empty());
        assert!((**store.load()).is_empty());
        assert_eq!(ring.status_of("a"), ReceiverStatus::default());
    }

    #[test]
    fn apply_delete_removes_named_receiver() {
        let store = fresh_store(vec![
            vt_receiver("a", "tok-aaaa"),
            vt_receiver("b", "tok-bbbb"),
            vt_receiver("c", "tok-cccc"),
        ]);
        let ring = DispatchOutcomeRing::new();
        ring.record_delivered("a", 1);
        ring.record_delivered("b", 2);
        ring.record_delivered("c", 3);

        let out = apply_delete(&store, &ring, "b").unwrap();
        assert_eq!(out.removed, "b");
        assert_eq!(out.remaining, vec!["a", "c"]);

        let live = (**store.load()).clone();
        assert_eq!(live.len(), 2);
        assert!(live.iter().all(|r| r.name != "b"));
        // "b" pruned from the ring.
        assert_eq!(ring.status_of("b"), ReceiverStatus::default());
        // Others retained.
        assert_eq!(ring.status_of("a").last_delivered_at, Some(1));
        assert_eq!(ring.status_of("c").last_delivered_at, Some(3));
    }

    #[test]
    fn apply_delete_returns_not_found_for_unknown_name() {
        let store = fresh_store(vec![vt_receiver("a", "tok-aaaa")]);
        let ring = DispatchOutcomeRing::new();
        let err = apply_delete(&store, &ring, "ghost").unwrap_err();
        assert_eq!(err, DeleteError::NotFound("ghost".into()));
        // Store untouched.
        assert_eq!((**store.load()).len(), 1);
    }

    #[test]
    fn apply_delete_returns_not_found_for_empty_store() {
        let store = fresh_store(vec![]);
        let ring = DispatchOutcomeRing::new();
        let err = apply_delete(&store, &ring, "anything").unwrap_err();
        assert!(matches!(err, DeleteError::NotFound(_)));
    }

    #[test]
    fn find_receiver_returns_clone_when_present() {
        let store = fresh_store(vec![
            vt_receiver("a", "tok-aaaa"),
            vt_receiver("b", "tok-bbbb"),
        ]);
        let r = find_receiver(&store, "b").expect("present");
        assert_eq!(r.name, "b");
        match r.kind {
            ReceiverKind::VipTalk { bot_token, .. } => assert_eq!(bot_token, "tok-bbbb"),
            _ => panic!("wrong kind"),
        }
    }

    #[test]
    fn find_receiver_returns_none_when_absent() {
        let store = fresh_store(vec![vt_receiver("a", "tok-aaaa")]);
        assert!(find_receiver(&store, "ghost").is_none());
    }

    #[test]
    fn delete_error_displays_human_message() {
        let err = DeleteError::NotFound("vt-prod".into());
        assert_eq!(err.to_string(), "no receiver named 'vt-prod'");
    }

    #[test]
    fn handler_ring_method_returns_shared_clone() {
        let ring = DispatchOutcomeRing::new();
        let handler =
            AlertReceiversHandler::new(provider_of(vec![]), ring.clone());
        let cloned = handler.ring();
        cloned.record_delivered("via-handler", 42);
        assert_eq!(
            ring.status_of("via-handler").last_delivered_at,
            Some(42)
        );
    }
}
