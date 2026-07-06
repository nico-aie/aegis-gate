//! Login brute-force detector. Per-IP + per-user + per-device
//! windowed counters on authentication paths.
//!
//! 2026-05-18 (QC Sprint 2.3 — F-CRITICAL-014): three independent
//! axes track separate attacker shapes:
//!
//! - **per-IP** — classic single-source brute-force. Fires when
//!   one IP makes >`ip_threshold` auth attempts in `window`.
//! - **per-user** — password-spraying detection. Fires when one
//!   username sees auth attempts from >`user_threshold` distinct
//!   IPs in `window`. Catches the credential-stuffing shape where
//!   the attacker rotates IPs across a CIDR but targets a single
//!   high-value account.
//! - **per-device** — distributed credential-stuffing detection.
//!   Fires when one device fingerprint (JA4) appears across
//!   >`device_threshold` distinct IPs in `window`. Catches the
//!   shape where the attacker rotates both IPs and usernames but
//!   reuses the same TLS client library.
//!
//! Method allowlist expanded beyond POST-only: POST, PUT, PATCH,
//! and any method carrying an `Authorization: Basic …` header.
//! Pre-fix, RFC 7617 Basic-auth probes on GET were silently
//! ignored by the brute-force detector — exactly the shape the
//! `hydra` / `medusa` tooling defaults to.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use aegis_core::config::BruteForceCountScope;
use aegis_core::pipeline::RequestView;
use aegis_core::state::StateBackend;

use super::{Detector, Signal};

/// AC-P2-b — ceiling on the fleet-count cache (per-user + per-device keys
/// combined). At the cap an arbitrary entry is evicted, mirroring the
/// other bounded per-key maps in this crate.
const FLEET_CACHE_CAP: usize = 4096;

/// BF-OTP-P1 (2026-07-06) — OTP / second-factor brute-force thresholds.
/// Hardcoded like `user_threshold` / `device_threshold` (no new config, by
/// owner directive). See `plans/issues/FEAT-otp-token-bruteforce-detection-2026-07.md`.
///
/// Axis B (spray): distinct identities (`login_token`) submitting the *same*
/// `otp_code` within the window. Fires above this — the characteristic
/// fixed-code spray that is **IP-independent** and survives IP rotation.
const OTP_SPRAY_THRESHOLD: u32 = 20;
/// Axis A (grind): distinct `otp_code` guesses per identity within the window.
const OTP_GRIND_THRESHOLD: u32 = 10;
/// Score both OTP axes emit — below `scores::brute_force::DEFAULT` (50) so an
/// OTP hit compounds via the risk pipeline rather than blocking on one request.
const OTP_SCORE: u32 = 40;

/// Brute-force detector. Stateful — owns three counter maps.
pub struct BruteForceDetector {
    /// Number of POSTs in `window` from one IP that fires.
    pub threshold: u32,
    /// Number of distinct IPs in `window` per username that
    /// fires (password-spraying).
    pub user_threshold: u32,
    /// Number of distinct IPs in `window` per device fingerprint
    /// that fires (distributed credential stuffing).
    pub device_threshold: u32,
    /// Sliding-window length.
    pub window: Duration,
    /// Score emitted on a hit. Risk-tier is the same as the
    /// other detectors (mid-tens) so a single brute-force
    /// fingerprint plus another signal compounds into a block.
    pub score: u32,
    /// Per-IP counter (classic single-source brute-force).
    state: Mutex<HashMap<IpAddr, Vec<Instant>>>,
    /// Per-username → set of (IP, Instant) tuples observed
    /// within `window` (password-spraying tracker).
    user_state: Mutex<HashMap<String, Vec<(IpAddr, Instant)>>>,
    /// Per-device-fingerprint → same shape as user_state
    /// (distributed credential stuffing tracker).
    device_state: Mutex<HashMap<String, Vec<(IpAddr, Instant)>>>,
    /// AC-P2-b (2026-07-04) — fleet aggregation of the per-user /
    /// per-device distinct-IP axes. A campaign load-balanced across
    /// nodes dilutes each node's local count below threshold; in
    /// `count_scope: fleet` every node contributes its locally-NEW
    /// distinct-IP observations to a shared windowed counter and reads
    /// the fleet total back. All async I/O is fire-and-forget off the
    /// request path (mirrors `ddos::tick_rps_fleet_at` fail-safe): a
    /// backend error simply leaves the cache stale and the local count
    /// governs. `OnceLock` because the chain is built before the state
    /// backend exists; run.rs installs the handle once ready — and only
    /// when cluster propagation is on (no silent "fleet == this node").
    fleet_backend: OnceLock<Arc<dyn StateBackend>>,
    /// Requested scope is `fleet` (hot-reloadable via
    /// `apply_cfg_change_to_brute_force`).
    fleet_scope: AtomicBool,
    /// Log-once guard for "fleet requested but no shared backend".
    fleet_warned: AtomicBool,
    /// axis-key (`user:<canonical>` / `device:<fp>`) → (window bucket,
    /// fleet count) written by the fire-and-forget task, read by
    /// `inspect`. `Arc` so spawned tasks can own a handle. Bounded at
    /// [`FLEET_CACHE_CAP`].
    fleet_counts: Arc<Mutex<HashMap<String, (u64, u64)>>>,
    /// BF-OTP-P1 — Axis B (OTP spray). `code_hash` → distinct
    /// `(identity_hash, Instant)` observed in `window`. Fires when the
    /// distinct-identity count for one code crosses [`OTP_SPRAY_THRESHOLD`].
    otp_code_state: Mutex<HashMap<String, Vec<(String, Instant)>>>,
    /// BF-OTP-P1 — Axis A (OTP grind). `identity_hash` → distinct
    /// `(code_hash, Instant)` observed in `window`. Fires when the
    /// distinct-code count for one identity crosses [`OTP_GRIND_THRESHOLD`].
    otp_token_state: Mutex<HashMap<String, Vec<(String, Instant)>>>,
}

impl Default for BruteForceDetector {
    fn default() -> Self {
        Self::new(
            10,
            Duration::from_secs(60),
            super::scores::brute_force::DEFAULT,
        )
    }
}

impl BruteForceDetector {
    pub fn new(threshold: u32, window: Duration, score: u32) -> Self {
        Self {
            threshold,
            // 2026-05-18 (QC Sprint 2.3): default thresholds for
            // the two new axes. Conservative so we don't fire on
            // legitimate small-team office traffic but tight
            // enough that real credential-stuffers cross within
            // the first minute.
            user_threshold: 5,
            device_threshold: 10,
            window,
            score,
            state: Mutex::new(HashMap::new()),
            user_state: Mutex::new(HashMap::new()),
            device_state: Mutex::new(HashMap::new()),
            fleet_backend: OnceLock::new(),
            fleet_scope: AtomicBool::new(false),
            fleet_warned: AtomicBool::new(false),
            fleet_counts: Arc::new(Mutex::new(HashMap::new())),
            otp_code_state: Mutex::new(HashMap::new()),
            otp_token_state: Mutex::new(HashMap::new()),
        }
    }

    /// AC-P2-b — set the requested count scope (boot + hot-reload via
    /// `apply_cfg_change_to_brute_force`). `fleet` only takes effect once
    /// a shared backend is installed; otherwise the detector logs once
    /// and keeps counting per-node.
    pub fn set_count_scope(&self, scope: BruteForceCountScope) {
        self.fleet_scope
            .store(scope == BruteForceCountScope::Fleet, Ordering::Relaxed);
    }

    /// AC-P2-b — install the shared state backend (boot-time, once the
    /// backend exists AND cluster propagation is confirmed; the caller
    /// owns that gate). Idempotent — later calls are ignored.
    pub fn install_fleet_backend(&self, backend: Arc<dyn StateBackend>) {
        let _ = self.fleet_backend.set(backend);
    }

    /// Reload observability — whether the requested scope is `fleet`
    /// (the reload helper's test asserts the flip took).
    pub fn count_scope_is_fleet(&self) -> bool {
        self.fleet_scope.load(Ordering::Relaxed)
    }

    /// Test accessor — the cached fleet count for an axis-key (raw,
    /// ignoring bucket freshness).
    pub fn fleet_cached(&self, cache_key: &str) -> Option<u64> {
        self.fleet_counts
            .lock()
            .unwrap()
            .get(cache_key)
            .map(|&(_, count)| count)
    }

    fn record_and_check(&self, peer_ip: IpAddr) -> bool {
        let now = Instant::now();
        let cutoff = now.checked_sub(self.window).unwrap_or(now);
        let mut state = self.state.lock().expect("brute-force state poisoned");
        let entry = state.entry(peer_ip).or_default();
        // Prune entries outside the window.
        entry.retain(|&t| t >= cutoff);
        entry.push(now);
        // Cap the per-IP vec length so a single attacker can't
        // grow memory unboundedly while we wait for the window
        // to roll. `threshold * 2` is plenty: anything above
        // threshold is already a hit.
        let cap = (self.threshold * 2).max(20) as usize;
        if entry.len() > cap {
            let drop_n = entry.len() - cap;
            entry.drain(0..drop_n);
        }
        entry.len() as u32 > self.threshold
    }

    /// 2026-05-18 (QC Sprint 2.3 — F-CRITICAL-014, password-
    /// spraying axis): record that `peer_ip` attempted to auth
    /// as `username`. Returns `(fired, newly_distinct)`: `fired` when
    /// the distinct-IP count for this user crosses `user_threshold`
    /// within `window`; `newly_distinct` when this is the first time
    /// THIS node saw `peer_ip` for this user in the window (the event
    /// the fleet channel contributes upstream, AC-P2-b).
    fn record_user_and_check(&self, username: &str, peer_ip: IpAddr) -> (bool, bool) {
        if username.is_empty() {
            return (false, false);
        }
        let now = Instant::now();
        let cutoff = now.checked_sub(self.window).unwrap_or(now);
        let mut state = self.user_state.lock().expect("user state poisoned");
        let entry = state.entry(username.to_string()).or_default();
        entry.retain(|&(_, t)| t >= cutoff);
        // Skip duplicate IP records within the window — we count
        // DISTINCT IPs, not raw attempts.
        let newly_distinct = !entry.iter().any(|(ip, _)| *ip == peer_ip);
        if newly_distinct {
            entry.push((peer_ip, now));
        }
        let cap = (self.user_threshold * 2).max(20) as usize;
        if entry.len() > cap {
            let drop_n = entry.len() - cap;
            entry.drain(0..drop_n);
        }
        let distinct_ips: HashSet<IpAddr> =
            entry.iter().map(|(ip, _)| *ip).collect();
        (distinct_ips.len() as u32 > self.user_threshold, newly_distinct)
    }

    /// 2026-05-18 (QC Sprint 2.3 — F-CRITICAL-014, distributed
    /// credential-stuffing axis): same shape as user-axis but
    /// keyed by device fingerprint. Fires when one device sees
    /// auth attempts from >`device_threshold` distinct IPs in
    /// `window`.
    fn record_device_and_check(&self, device_fp: &str, peer_ip: IpAddr) -> (bool, bool) {
        if device_fp.is_empty() {
            return (false, false);
        }
        let now = Instant::now();
        let cutoff = now.checked_sub(self.window).unwrap_or(now);
        let mut state = self.device_state.lock().expect("device state poisoned");
        let entry = state.entry(device_fp.to_string()).or_default();
        entry.retain(|&(_, t)| t >= cutoff);
        let newly_distinct = !entry.iter().any(|(ip, _)| *ip == peer_ip);
        if newly_distinct {
            entry.push((peer_ip, now));
        }
        let cap = (self.device_threshold * 2).max(20) as usize;
        if entry.len() > cap {
            let drop_n = entry.len() - cap;
            entry.drain(0..drop_n);
        }
        let distinct_ips: HashSet<IpAddr> =
            entry.iter().map(|(ip, _)| *ip).collect();
        (distinct_ips.len() as u32 > self.device_threshold, newly_distinct)
    }

    /// BF-OTP-P1 — Axis B (OTP spray). Record that `identity_hash` submitted
    /// `code_hash` and return whether the distinct-identity count for this code
    /// crosses [`OTP_SPRAY_THRESHOLD`] within `window`. Distinct identities are
    /// deduped so one session retrying the same code doesn't inflate the count.
    /// IP is never consulted — this axis is deliberately IP-independent.
    fn record_otp_spray_and_check(&self, code_hash: &str, identity_hash: &str) -> (bool, bool) {
        // Key on the code, count DISTINCT identities (one session retrying the
        // same code doesn't inflate). IP is never consulted → IP-independent.
        record_distinct_windowed(
            &self.otp_code_state,
            self.window,
            code_hash,
            identity_hash,
            OTP_SPRAY_THRESHOLD,
        )
    }

    /// BF-OTP-P1 — Axis A (OTP grind). Record that `identity_hash` guessed
    /// `code_hash` and return whether the distinct-code count for this identity
    /// crosses [`OTP_GRIND_THRESHOLD`] within `window`. Distinct codes are
    /// deduped so a flaky client double-submitting one code doesn't inflate.
    fn record_otp_grind_and_check(&self, identity_hash: &str, code_hash: &str) -> (bool, bool) {
        // Key on the identity, count DISTINCT codes (a flaky client re-submitting
        // one code doesn't inflate).
        record_distinct_windowed(
            &self.otp_token_state,
            self.window,
            identity_hash,
            code_hash,
            OTP_GRIND_THRESHOLD,
        )
    }

    /// AC-P2-b — the sync, request-path half of the fleet channel.
    /// **Never blocks**: reads the cached fleet count and, on a locally-
    /// new distinct IP, fire-and-forgets the shared-counter update
    /// (mirrors `ddos::tick_rps_fleet_at` fail-safe: any backend error
    /// only leaves the cache stale, so the local count governs).
    ///
    /// The cache is one event behind by construction — the spawned task
    /// lands after `inspect` returns — so the fleet fire arrives on the
    /// attacker's NEXT auth attempt. Known bounded overcount: one IP
    /// load-balanced onto two nodes contributes twice (each node's local
    /// dedup is node-scoped); acceptable for an additive-score signal.
    fn fleet_check(
        &self,
        axis: &'static str,
        key: &str,
        newly_distinct: bool,
        threshold: u32,
    ) -> bool {
        if !self.fleet_scope.load(Ordering::Relaxed) {
            return false;
        }
        let Some(backend) = self.fleet_backend.get() else {
            if !self.fleet_warned.swap(true, Ordering::Relaxed) {
                tracing::warn!(
                    "brute_force count_scope=fleet but no shared backend is \
                     installed (cluster mode off?); counting per-node"
                );
            }
            return false;
        };
        let window_secs = self.window.as_secs().max(1);
        let now_epoch = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let bucket = now_epoch / window_secs;
        let cache_key = format!("{axis}:{key}");

        if newly_distinct {
            // Only locally-new distinct IPs touch the backend — repeat
            // attempts are free, keeping backend chatter bounded by the
            // number of distinct (node, IP, key) triples per window.
            if let Ok(handle) = tokio::runtime::Handle::try_current() {
                let backend = backend.clone();
                let cache = self.fleet_counts.clone();
                let ck = cache_key.clone();
                let ttl = Duration::from_secs(window_secs * 2);
                handle.spawn(async move {
                    if let Err(e) = fleet_record(backend, cache, ck, bucket, ttl).await {
                        tracing::debug!(
                            error = %e,
                            "brute_force fleet count: backend error; per-node fallback",
                        );
                    }
                });
            }
        }

        let counts = self.fleet_counts.lock().unwrap();
        match counts.get(&cache_key) {
            // One bucket of slack: an entry cached just before roll-over
            // (which already summed current + prior) stays usable.
            Some(&(b, count)) if bucket.saturating_sub(b) <= 1 => count > threshold as u64,
            _ => false,
        }
    }
}

/// AC-P2-b — fire-and-forget task body: contribute one locally-new
/// distinct-IP observation to the shared windowed counter and cache the
/// fleet total. The total sums the current AND prior window bucket so a
/// roll-over mid-campaign doesn't zero the signal (same reason
/// `ddos::fleet_current` reads the prior second). Errors propagate to
/// the spawn wrapper, which logs and leaves the cache untouched.
async fn fleet_record(
    backend: Arc<dyn StateBackend>,
    cache: Arc<Mutex<HashMap<String, (u64, u64)>>>,
    cache_key: String,
    bucket: u64,
    ttl: Duration,
) -> aegis_core::Result<()> {
    let cur_key = format!("bf:fleet:{cache_key}:{bucket}");
    let cur = backend.incrby(&cur_key, 1).await?;
    // Best-effort TTL refresh; an expire failure must not lose the sample.
    let _ = backend.expire(&cur_key, ttl).await;
    let prior = backend
        .get_counter(&format!("bf:fleet:{cache_key}:{}", bucket.saturating_sub(1)))
        .await?;
    let total = cur + prior;
    let mut counts = cache.lock().unwrap();
    // Bounded cache: evict an arbitrary entry at the cap (mirrors the
    // other capped per-key maps in this crate).
    if !counts.contains_key(&cache_key) && counts.len() >= FLEET_CACHE_CAP {
        if let Some(k) = counts.keys().next().cloned() {
            counts.remove(&k);
        }
    }
    counts.insert(cache_key, (bucket, total));
    Ok(())
}

/// AC-P2-b — the boot path keeps an `Arc<BruteForceDetector>` so the
/// reload helper (`apply_cfg_change_to_brute_force`) and the late fleet-
/// backend install can reach the SAME instance the chain runs; this
/// delegating impl lets that shared handle sit in the
/// `Vec<Box<dyn Detector>>` chain slot.
impl Detector for Arc<BruteForceDetector> {
    fn id(&self) -> &'static str {
        (**self).id()
    }

    fn inspect(&self, req: &RequestView<'_>) -> Vec<Signal> {
        (**self).inspect(req)
    }
}

impl Detector for BruteForceDetector {
    fn id(&self) -> &'static str {
        "brute_force"
    }

    fn inspect(&self, req: &RequestView<'_>) -> Vec<Signal> {
        // 2026-05-18 (QC Sprint 2.3 — F-CRITICAL-014): method
        // allowlist. Pre-fix only POST counted; that missed Basic-
        // auth probes on GET (default for `hydra` / `medusa`) and
        // PUT/PATCH-style password-change endpoints. The current
        // shape: any auth-path request with an Authorization
        // header OR a method that typically carries credentials
        // (POST / PUT / PATCH) counts.
        let path = req.uri.path();
        // BF-OTP-P1 (2026-07-06) — inspect login paths AND OTP / second-factor
        // verify paths. The OTP axes below only run on OTP paths.
        let auth_path = is_auth_path(path);
        let otp_path = is_otp_path(path);
        if !auth_path && !otp_path {
            return Vec::new();
        }
        let has_auth_header = req.headers.contains_key(http::header::AUTHORIZATION);
        let mutation_method = matches!(
            *req.method,
            http::Method::POST | http::Method::PUT | http::Method::PATCH,
        );
        if !mutation_method && !has_auth_header {
            // GET / HEAD / OPTIONS without Authorization header → page
            // render, not an auth attempt.
            return Vec::new();
        }

        let peer_ip = req.peer.ip();

        // ---- per-IP axis (classic single-source) -------------
        let ip_fired = self.record_and_check(peer_ip);

        // ---- per-user axis (password-spraying) ---------------
        // Parse a `username=` form-body or `Authorization: Basic
        // <base64(user:pass)>` header. Body inspection is cheap
        // — RequestView.body.peek() returns the buffered bytes
        // the detector chain already collected.
        let username = extract_username(req);
        // AC-P1-c (2026-07-03) — canonicalize the KEY only (trim +
        // ASCII-lowercase): `Alice` / `alice` / `alice ` are one
        // account to the upstream auth server, and raw-string keying
        // let a case-rotating sprayer split the distinct-IP count
        // below threshold. The raw wire form stays in `username` for
        // the audit signal below.
        let user_fired = match &username {
            Some(u) => {
                let canonical = u.trim().to_ascii_lowercase();
                let (fired_local, newly_distinct) =
                    self.record_user_and_check(&canonical, peer_ip);
                // AC-P2-b — in fleet scope the shared count can trip the
                // axis while every node's local count sits under threshold.
                fired_local
                    || self.fleet_check("user", &canonical, newly_distinct, self.user_threshold)
            }
            None => false,
        };

        // ---- per-device axis (distributed credential stuffing) -
        // Device fingerprint comes from the TLS layer's JA4 hash.
        // Today the data plane doesn't pipe JA4 into `RequestView`
        // for non-TLS connections (admin port is plaintext); when
        // tls is `None` we skip this axis.
        let device_fp = req
            .tls
            .as_ref()
            .map(|t| t.ja4.clone())
            .filter(|s| !s.is_empty());
        let device_fired = match &device_fp {
            Some(fp) => {
                let (fired_local, newly_distinct) =
                    self.record_device_and_check(fp, peer_ip);
                fired_local
                    || self.fleet_check("device", fp, newly_distinct, self.device_threshold)
            }
            None => false,
        };

        // ---- OTP axes (spray + grind), OTP paths only ---------
        // Axis B (spray): distinct identities submitting the SAME code.
        // Axis A (grind): distinct codes per identity. The identity is the
        // pre-auth `login_token` (→ session cookie → bearer); the `otp_code`
        // is the GUESS and is NEVER used as the identity. Both need an
        // identity AND a code — otherwise only the per-IP axis applies.
        let mut otp_spray_fired = false;
        let mut otp_grind_fired = false;
        let mut otp_code_field = None;
        let mut otp_identity_field = None;
        if otp_path {
            if let (Some(identity), Some(code)) =
                (extract_otp_identity(req), extract_otp_code(req))
            {
                let id_hash = short_hash(&identity);
                let code_hash = short_hash(&code);
                // Axis B (spray): local OR fleet — under `count_scope: fleet` a
                // spray load-balanced across nodes trips the shared counter while
                // every node's local count stays under threshold (IP-rotation
                // resilience). `fleet_check` no-ops in per_node scope.
                let (spray_local, spray_new) =
                    self.record_otp_spray_and_check(&code_hash, &id_hash);
                otp_spray_fired = spray_local
                    || self.fleet_check("otp_spray", &code_hash, spray_new, OTP_SPRAY_THRESHOLD);
                // Axis A (grind): same seam, keyed on the identity.
                let (grind_local, grind_new) =
                    self.record_otp_grind_and_check(&id_hash, &code_hash);
                otp_grind_fired = grind_local
                    || self.fleet_check("otp_grind", &id_hash, grind_new, OTP_GRIND_THRESHOLD);
                otp_code_field = Some(code_hash);
                otp_identity_field = Some(id_hash);
            }
        }

        // Stack signals so an attack matching multiple axes
        // accumulates score. Each axis emits with its own tag so
        // the audit log shows which axis caught the attack.
        let mut signals = Vec::new();
        if ip_fired {
            signals.push(Signal {
                score: self.score,
                tag: "brute_force".into(),
                field: format!("ip:{peer_ip}"),
            });
        }
        if user_fired {
            if let Some(u) = &username {
                signals.push(Signal {
                    score: self.score,
                    tag: "brute_force_user".into(),
                    field: format!("user:{u}"),
                });
            }
        }
        if device_fired {
            if let Some(fp) = &device_fp {
                signals.push(Signal {
                    score: self.score,
                    tag: "brute_force_device".into(),
                    // Truncate JA4 to first 16 chars for the
                    // audit field — full string is in the audit
                    // event's optional fields blob.
                    field: format!("device:{}", &fp[..fp.len().min(16)]),
                });
            }
        }
        // OTP spray (Axis B) — the primary, IP-independent signal. Field
        // carries the code HASH (never the plaintext OTP) so ops can cluster
        // a confirmed spray without leaking the guessed value.
        if otp_spray_fired {
            if let Some(code_hash) = &otp_code_field {
                signals.push(Signal {
                    score: OTP_SCORE,
                    tag: "brute_force_otp_spray".into(),
                    field: format!("otp_spray:code={code_hash}"),
                });
            }
        }
        // OTP grind (Axis A) — one identity, many codes. Field carries the
        // identity HASH (the login_token is a secret; never echo it raw).
        if otp_grind_fired {
            if let Some(id_hash) = &otp_identity_field {
                signals.push(Signal {
                    score: OTP_SCORE,
                    tag: "brute_force_otp".into(),
                    field: format!("otp:id={id_hash}"),
                });
            }
        }
        signals
    }
}

/// 2026-05-18 (QC Sprint 2.3 — F-CRITICAL-014): pull a username
/// out of the request. Two sources, in order:
///
/// 1. `Authorization: Basic <base64>` header — RFC 7617.
/// 2. Body parsing for `username=` in `application/x-www-form-
///    urlencoded` or top-level `"username":"…"` in JSON.
///
/// Returns `None` when no recognisable username appears — always
/// the RAW wire string. Canonicalization (trim + ASCII-lowercase)
/// happens at the per-user KEYING site in `inspect` (AC-P1-c,
/// 2026-07-03): the counter aggregates `Alice`/`alice`/`alice ` as
/// one account, while the audit signal keeps the raw form so ops
/// see exactly what was sent.
fn extract_username(req: &RequestView<'_>) -> Option<String> {
    // 1. Basic auth header.
    if let Some(auth) = req
        .headers
        .get(http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
    {
        if let Some(b64) = auth
            .strip_prefix("Basic ")
            .or_else(|| auth.strip_prefix("basic "))
        {
            // Base64 decode + split on first colon.
            use base64::Engine as _;
            if let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(b64.trim()) {
                if let Ok(s) = std::str::from_utf8(&bytes) {
                    if let Some((user, _)) = s.split_once(':') {
                        if !user.is_empty() {
                            return Some(user.to_string());
                        }
                    }
                }
            }
        }
    }

    // 2. Body parsing — only the first few KB to keep cost
    // bounded. The detector chain has already buffered the body
    // for SSRF / SQLi / XSS inspection so this is reading already-
    // hot memory.
    let body = req.body.peek(8 * 1024);
    if body.is_empty() {
        return None;
    }

    // JSON: `"username":"…"` or `"user":"…"`. Cheap substring
    // search; no full JSON parse since attackers don't pretty-
    // print and the body may be malformed.
    if let Ok(text) = std::str::from_utf8(body) {
        for key in &["\"username\"", "\"user\""] {
            if let Some(idx) = text.find(key) {
                let tail = &text[idx + key.len()..];
                // Skip `:` + whitespace + `"`.
                let tail = tail.trim_start_matches(|c: char| {
                    c.is_whitespace() || c == ':' || c == '"'
                });
                if let Some(end) = tail.find('"') {
                    let user = &tail[..end];
                    if !user.is_empty() && user.len() < 256 {
                        return Some(user.to_string());
                    }
                }
            }
        }
        // Form-urlencoded: `username=…&…`.
        for pair in text.split('&') {
            if let Some(val) = pair
                .strip_prefix("username=")
                .or_else(|| pair.strip_prefix("user="))
            {
                if !val.is_empty() {
                    return Some(val.to_string());
                }
            }
        }
    }

    None
}

fn is_auth_path(path: &str) -> bool {
    // Common login routes across the openapi.public.yaml target
    // and the broader hackathon corpus. Trailing slash + case-
    // insensitive match. Order picked for early-out (most
    // common first).
    let p = path.trim_end_matches('/').to_ascii_lowercase();
    matches!(
        p.as_str(),
        "/login"
            | "/api/login"
            | "/signin"
            | "/sign-in"
            | "/api/signin"
            | "/auth"
            | "/auth/login"
            | "/api/auth"
            | "/api/auth/login"
            | "/api/v1/login"
            | "/api/v2/login"
            | "/account/login"
            | "/user/login"
            | "/users/login"
            | "/session"
            | "/sessions"
    )
}

/// BF-OTP-P1 (2026-07-06) — OTP / second-factor verify routes across the
/// hackathon corpus. Exact-path match (trailing-slash trimmed, lowercased) —
/// NOT substring, so `/verify-email` never trips `/verify`. Substring matching
/// on an additive-score gate would risk false positives on business routes.
fn is_otp_path(path: &str) -> bool {
    let p = path.trim_end_matches('/').to_ascii_lowercase();
    matches!(
        p.as_str(),
        "/otp"
            | "/api/otp"
            | "/verify-otp"
            | "/otp/verify"
            | "/2fa"
            | "/2fa/verify"
            | "/api/2fa/verify"
            | "/mfa"
            | "/mfa/verify"
            | "/verify"
            | "/challenge/verify"
            | "/api/auth/verify"
            | "/totp"
            | "/api/totp"
    )
}

/// BF-OTP-P1 — extract the pre-auth IDENTITY an OTP submission belongs to, in
/// order: body `login_token` (JSON or form) → `sid`/`session` cookie →
/// `Authorization: Bearer <token>`. This is the tracking key for both OTP axes.
/// Returns `None` when nothing identifies the session (then only per-IP applies).
/// NEVER returns the `otp_code` — the guess must not become the identity.
fn extract_otp_identity(req: &RequestView<'_>) -> Option<String> {
    // 1. Body `login_token` (the openapi target's field).
    let body = req.body.peek(8 * 1024);
    if let Ok(text) = std::str::from_utf8(body) {
        if let Some(v) = json_str_field(text, "\"login_token\"") {
            return Some(v);
        }
        for pair in text.split('&') {
            if let Some(val) = pair.strip_prefix("login_token=") {
                if !val.is_empty() {
                    return Some(val.to_string());
                }
            }
        }
    }
    // 2. Session cookie (`sid` is what /otp sets on success; `session` fallback).
    if let Some(cookie) = req
        .headers
        .get(http::header::COOKIE)
        .and_then(|v| v.to_str().ok())
    {
        for part in cookie.split(';') {
            let part = part.trim();
            for k in &["sid=", "session="] {
                if let Some(val) = part.strip_prefix(k) {
                    if !val.is_empty() {
                        return Some(val.to_string());
                    }
                }
            }
        }
    }
    // 3. Bearer token.
    if let Some(auth) = req
        .headers
        .get(http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
    {
        if let Some(tok) = auth
            .strip_prefix("Bearer ")
            .or_else(|| auth.strip_prefix("bearer "))
        {
            let tok = tok.trim();
            if !tok.is_empty() {
                return Some(tok.to_string());
            }
        }
    }
    None
}

/// BF-OTP-P1 — extract the OTP GUESS (`otp_code` / `code` / `otp`) from the
/// body. Deliberately does NOT read `token` (that collides with `login_token`).
/// Returns the raw wire string; the caller hashes it before use.
fn extract_otp_code(req: &RequestView<'_>) -> Option<String> {
    let body = req.body.peek(8 * 1024);
    if body.is_empty() {
        return None;
    }
    let text = std::str::from_utf8(body).ok()?;
    for key in &["\"otp_code\"", "\"code\"", "\"otp\""] {
        if let Some(v) = json_str_field(text, key) {
            return Some(v);
        }
    }
    for pair in text.split('&') {
        for k in &["otp_code=", "code=", "otp="] {
            if let Some(val) = pair.strip_prefix(k) {
                if !val.is_empty() {
                    return Some(val.to_string());
                }
            }
        }
    }
    None
}

/// Pull a JSON string value for `quoted_key` (e.g. `"\"otp_code\""`) with a
/// cheap substring scan — no full parse, since attacker bodies may be malformed.
fn json_str_field(text: &str, quoted_key: &str) -> Option<String> {
    let idx = text.find(quoted_key)?;
    let tail = &text[idx + quoted_key.len()..];
    let tail = tail.trim_start_matches(|c: char| c.is_whitespace() || c == ':' || c == '"');
    let end = tail.find('"')?;
    let v = &tail[..end];
    if !v.is_empty() && v.len() < 256 {
        Some(v.to_string())
    } else {
        None
    }
}

/// Shared body for both OTP axes: in a windowed distinct-member map, record
/// `member` under `key`, prune the window, and return whether the distinct-
/// member count crosses `threshold`. Deduping `member` gives distinct-count
/// (not raw-attempt) semantics, which is what kills the retry/typo false
/// positives. Bounded per key at `threshold * 2` like the other axes.
///
/// Returns `(fired, newly_distinct)`: `fired` when the local distinct count
/// crosses `threshold`; `newly_distinct` when this is the first time this node
/// saw `member` under `key` in the window (the event the fleet channel
/// contributes upstream, mirroring the per-user/per-device axes).
fn record_distinct_windowed(
    map: &Mutex<HashMap<String, Vec<(String, Instant)>>>,
    window: Duration,
    key: &str,
    member: &str,
    threshold: u32,
) -> (bool, bool) {
    let now = Instant::now();
    let cutoff = now.checked_sub(window).unwrap_or(now);
    let mut state = map.lock().expect("otp distinct-map poisoned");
    let entry = state.entry(key.to_string()).or_default();
    entry.retain(|(_, t)| *t >= cutoff);
    let newly_distinct = !entry.iter().any(|(m, _)| m == member);
    if newly_distinct {
        entry.push((member.to_string(), now));
    }
    let cap = (threshold * 2).max(20) as usize;
    if entry.len() > cap {
        let drop_n = entry.len() - cap;
        entry.drain(0..drop_n);
    }
    let distinct: HashSet<&str> = entry.iter().map(|(m, _)| m.as_str()).collect();
    (distinct.len() as u32 > threshold, newly_distinct)
}

/// Stable non-cryptographic short hash. Used to key the OTP maps and to fill
/// audit fields without retaining the plaintext `otp_code` / `login_token`.
fn short_hash(s: &str) -> String {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    s.hash(&mut h);
    format!("{:016x}", h.finish())
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_core::pipeline::BodyPeek;

    fn make_req(method: http::Method, path: &str) -> (http::Method, http::Uri, http::HeaderMap, BodyPeek) {
        (method, path.parse().unwrap(), http::HeaderMap::new(), BodyPeek::empty())
    }
    fn view<'a>(
        m: &'a http::Method,
        u: &'a http::Uri,
        h: &'a http::HeaderMap,
        b: &'a BodyPeek,
        peer: &str,
    ) -> RequestView<'a> {
        RequestView {
            method: m,
            uri: u,
            version: http::Version::HTTP_11,
            headers: h,
            peer: peer.parse().unwrap(),
            tls: None,
            body: b,
        }
    }

    #[test]
    fn fires_after_threshold_in_window() {
        let d = BruteForceDetector::new(3, Duration::from_secs(60), 40);
        let (m, u, h, b) = make_req(http::Method::POST, "/login");
        // 3 requests still within threshold (≤ threshold).
        for _ in 0..3 {
            assert!(d.inspect(&view(&m, &u, &h, &b, "1.1.1.1:443")).is_empty());
        }
        // 4th tips over → fire.
        let signals = d.inspect(&view(&m, &u, &h, &b, "1.1.1.1:443"));
        assert!(signals.iter().any(|s| s.tag == "brute_force"));
    }

    #[test]
    fn does_not_fire_for_get() {
        let d = BruteForceDetector::new(2, Duration::from_secs(60), 40);
        let (m, u, h, b) = make_req(http::Method::GET, "/login");
        for _ in 0..10 {
            assert!(d.inspect(&view(&m, &u, &h, &b, "2.2.2.2:443")).is_empty());
        }
    }

    #[test]
    fn does_not_fire_for_non_auth_path() {
        let d = BruteForceDetector::new(2, Duration::from_secs(60), 40);
        let (m, u, h, b) = make_req(http::Method::POST, "/api/profile");
        for _ in 0..10 {
            assert!(d.inspect(&view(&m, &u, &h, &b, "3.3.3.3:443")).is_empty());
        }
    }

    #[test]
    fn separate_ips_track_independently() {
        let d = BruteForceDetector::new(2, Duration::from_secs(60), 40);
        let (m, u, h, b) = make_req(http::Method::POST, "/login");
        for _ in 0..2 {
            d.inspect(&view(&m, &u, &h, &b, "5.5.5.5:443"));
        }
        // Different IP — fresh counter.
        for _ in 0..2 {
            assert!(d.inspect(&view(&m, &u, &h, &b, "6.6.6.6:443")).is_empty());
        }
    }

    #[test]
    fn auth_path_aliases_match() {
        let d = BruteForceDetector::new(1, Duration::from_secs(60), 40);
        for path in [
            "/login", "/api/login", "/signin", "/sign-in", "/auth",
            "/auth/login", "/api/auth", "/api/auth/login",
            "/api/v1/login", "/api/v2/login", "/account/login",
            "/user/login", "/users/login", "/session", "/sessions",
        ] {
            // Each path uses a unique IP so the counter doesn't
            // bleed across iterations.
            let ip = format!("9.0.0.{}:443", path.len() % 250);
            let (m, u, h, b) = make_req(http::Method::POST, path);
            d.inspect(&view(&m, &u, &h, &b, &ip));
            let signals = d.inspect(&view(&m, &u, &h, &b, &ip));
            assert!(
                signals.iter().any(|s| s.tag == "brute_force"),
                "path {path} should be a brute-force trigger"
            );
        }
    }

    #[test]
    fn auth_path_negative() {
        let d = BruteForceDetector::new(1, Duration::from_secs(60), 40);
        for path in [
            "/api/profile", "/api/transactions", "/health", "/static/app.js",
            "/sitemap.xml", "/about", "/api/feedback", "/game/list",
        ] {
            let ip = format!("8.0.0.{}:443", path.len() % 250);
            let (m, u, h, b) = make_req(http::Method::POST, path);
            d.inspect(&view(&m, &u, &h, &b, &ip));
            let signals = d.inspect(&view(&m, &u, &h, &b, &ip));
            assert!(
                signals.is_empty(),
                "path {path} should NOT be a brute-force trigger"
            );
        }
    }

    #[test]
    fn old_entries_pruned() {
        // Window of 1ms — anything older than 1ms is pruned.
        let d = BruteForceDetector::new(2, Duration::from_millis(1), 40);
        let (m, u, h, b) = make_req(http::Method::POST, "/login");
        for _ in 0..3 {
            d.inspect(&view(&m, &u, &h, &b, "7.7.7.7:443"));
        }
        // Sleep longer than window — old timestamps prune away.
        std::thread::sleep(Duration::from_millis(5));
        // Fresh request → counter should reset.
        let signals = d.inspect(&view(&m, &u, &h, &b, "7.7.7.7:443"));
        assert!(signals.is_empty());
    }

    // ---- 2026-05-18 QC Sprint 2.3 — F-CRITICAL-014 ----

    fn view_with_body<'a>(
        m: &'a http::Method,
        u: &'a http::Uri,
        h: &'a http::HeaderMap,
        b: &'a BodyPeek,
        peer: &str,
    ) -> RequestView<'a> {
        RequestView {
            method: m,
            uri: u,
            version: http::Version::HTTP_11,
            headers: h,
            peer: peer.parse().unwrap(),
            tls: None,
            body: b,
        }
    }

    /// GET with `Authorization: Basic …` to an auth path now
    /// counts toward the per-IP axis (default `hydra` shape).
    /// Pre-fix only POST counted; this is the §5.3 OWASP fix.
    #[test]
    fn basic_auth_get_counts_per_ip() {
        let d = BruteForceDetector::new(2, Duration::from_secs(60), 40);
        let (m, u, _, b) = make_req(http::Method::GET, "/login");
        let mut h = http::HeaderMap::new();
        // base64("alice:wrong") = YWxpY2U6d3Jvbmc=
        h.insert(
            http::header::AUTHORIZATION,
            "Basic YWxpY2U6d3Jvbmc=".parse().unwrap(),
        );
        for _ in 0..2 {
            assert!(d.inspect(&view(&m, &u, &h, &b, "11.0.0.1:443")).is_empty());
        }
        // Third request fires the per-IP axis.
        let signals = d.inspect(&view(&m, &u, &h, &b, "11.0.0.1:443"));
        assert!(signals.iter().any(|s| s.tag == "brute_force"));
    }

    /// PUT to a password-change auth path counts (POST/PUT/PATCH
    /// allowlist).
    #[test]
    fn put_to_auth_path_counts() {
        let d = BruteForceDetector::new(2, Duration::from_secs(60), 40);
        let (m, u, h, b) = make_req(http::Method::PUT, "/login");
        for _ in 0..2 {
            assert!(d.inspect(&view(&m, &u, &h, &b, "12.0.0.1:443")).is_empty());
        }
        let signals = d.inspect(&view(&m, &u, &h, &b, "12.0.0.1:443"));
        assert!(signals.iter().any(|s| s.tag == "brute_force"));
    }

    /// Per-user axis: 6 distinct IPs auth-attempt for the same
    /// username → fires `brute_force_user`. The classic
    /// password-spraying shape — one user, rotating IP.
    #[test]
    fn password_spraying_fires_per_user_axis() {
        let mut d = BruteForceDetector::new(100, Duration::from_secs(60), 40);
        d.user_threshold = 3; // tighter for the test
        let body = BodyPeek::new(
            br#"{"username":"alice","password":"x"}"#.to_vec(),
            None,
            false,
        );
        let (m, u, h, _) = make_req(http::Method::POST, "/login");

        // Three distinct IPs — under threshold.
        for octet in 1..=3 {
            let ip = format!("13.0.0.{octet}:443");
            d.inspect(&view_with_body(&m, &u, &h, &body, &ip));
        }
        // 4th distinct IP for same user → fires.
        let signals =
            d.inspect(&view_with_body(&m, &u, &h, &body, "13.0.0.4:443"));
        assert!(
            signals.iter().any(|s| s.tag == "brute_force_user"),
            "expected brute_force_user signal, got {signals:?}",
        );
    }

    /// Per-user axis ignores duplicate IPs — the SAME IP retrying
    /// the same username doesn't inflate the distinct-IP count.
    #[test]
    fn per_user_axis_dedupes_repeated_ip() {
        let mut d = BruteForceDetector::new(100, Duration::from_secs(60), 40);
        d.user_threshold = 2;
        let body = BodyPeek::new(
            b"username=carol&password=x".to_vec(),
            None,
            false,
        );
        let (m, u, h, _) = make_req(http::Method::POST, "/login");
        // 10 attempts from the same IP — distinct-IP count is 1.
        for _ in 0..10 {
            let s =
                d.inspect(&view_with_body(&m, &u, &h, &body, "14.0.0.1:443"));
            assert!(
                !s.iter().any(|sig| sig.tag == "brute_force_user"),
                "single-IP retry must not trip user axis",
            );
        }
    }

    /// AC-P1-c (2026-07-03) — spray-evasion fix. The per-user axis
    /// keyed on the raw wire string, so `Alice` / `alice` / `ALICE`
    /// counted as three separate users and a case-rotating sprayer
    /// never crossed the distinct-IP threshold. The KEY is now
    /// canonicalized (trim + ASCII-lowercase); the audit field keeps
    /// the raw submitted string (see the companion test below).
    #[test]
    fn spray_with_case_and_whitespace_variants_counts_as_one_user() {
        let mut d = BruteForceDetector::new(100, Duration::from_secs(60), 40);
        d.user_threshold = 3;
        let (m, u, h, _) = make_req(http::Method::POST, "/login");

        // Three case variants from three distinct IPs — same user,
        // still under threshold (3 not > 3).
        for (octet, name) in [(1, "Alice"), (2, "alice"), (3, "ALICE")] {
            let body = BodyPeek::new(
                format!(r#"{{"username":"{name}","password":"x"}}"#).into_bytes(),
                None,
                false,
            );
            let s = d.inspect(&view_with_body(&m, &u, &h, &body, &format!("16.0.0.{octet}:443")));
            assert!(
                !s.iter().any(|sig| sig.tag == "brute_force_user"),
                "under threshold at {octet} distinct IPs: {s:?}",
            );
        }
        // 4th distinct IP submits a whitespace variant via a form
        // body (form extraction preserves the padding) → 4 distinct
        // IPs for the canonical user → fires.
        let body = BodyPeek::new(b"username=alice &password=x".to_vec(), None, false);
        let signals =
            d.inspect(&view_with_body(&m, &u, &h, &body, "16.0.0.4:443"));
        assert!(
            signals.iter().any(|s| s.tag == "brute_force_user"),
            "case/whitespace variants must aggregate as ONE user: {signals:?}",
        );
    }

    /// AC-P1-c — canonicalize the KEY only: the audit signal still
    /// reports the raw submitted username so ops see what was sent
    /// on the wire (and the naive fix — canonicalizing inside
    /// `extract_username` — stays caught).
    #[test]
    fn signal_field_reports_raw_submitted_username() {
        let mut d = BruteForceDetector::new(100, Duration::from_secs(60), 40);
        d.user_threshold = 1;
        let (m, u, h, _) = make_req(http::Method::POST, "/login");
        let body_lower = BodyPeek::new(
            br#"{"username":"alice","password":"x"}"#.to_vec(),
            None,
            false,
        );
        let _ = d.inspect(&view_with_body(&m, &u, &h, &body_lower, "17.0.0.1:443"));
        // Second distinct IP crosses threshold (2 > 1) with the
        // MiXeD-case variant — the field must echo that raw form.
        let body_mixed = BodyPeek::new(
            br#"{"username":"AliCe","password":"x"}"#.to_vec(),
            None,
            false,
        );
        let signals =
            d.inspect(&view_with_body(&m, &u, &h, &body_mixed, "17.0.0.2:443"));
        let field = signals
            .iter()
            .find(|s| s.tag == "brute_force_user")
            .map(|s| s.field.clone());
        assert_eq!(
            field.as_deref(),
            Some("user:AliCe"),
            "audit field must keep the raw wire username",
        );
    }

    /// AC-P1-c — canonicalization must NOT merge genuinely distinct
    /// users: bob's attempts don't inherit alice's distinct-IP count.
    #[test]
    fn distinct_users_still_track_independently() {
        let mut d = BruteForceDetector::new(100, Duration::from_secs(60), 40);
        d.user_threshold = 2;
        let (m, u, h, _) = make_req(http::Method::POST, "/login");
        for octet in 1..=3 {
            let body = BodyPeek::new(
                br#"{"username":"alice","password":"x"}"#.to_vec(),
                None,
                false,
            );
            let _ = d.inspect(&view_with_body(&m, &u, &h, &body, &format!("18.0.0.{octet}:443")));
        }
        // bob from ONE fresh IP — nowhere near his own threshold.
        let body = BodyPeek::new(
            br#"{"username":"bob","password":"x"}"#.to_vec(),
            None,
            false,
        );
        let signals =
            d.inspect(&view_with_body(&m, &u, &h, &body, "18.0.0.9:443"));
        assert!(
            !signals.iter().any(|s| s.tag == "brute_force_user"),
            "bob must not inherit alice's distinct-IP count: {signals:?}",
        );
    }

    /// Per-user axis pulls username from JSON body.
    #[test]
    fn extract_username_from_json_body() {
        let body = BodyPeek::new(
            br#"{"username":"bob","password":"hunter2"}"#.to_vec(),
            None,
            false,
        );
        let (m, u, h, _) = make_req(http::Method::POST, "/login");
        let view = view_with_body(&m, &u, &h, &body, "15.0.0.1:443");
        assert_eq!(extract_username(&view).as_deref(), Some("bob"));
    }

    /// Per-user axis pulls username from form-urlencoded body.
    #[test]
    fn extract_username_from_form_body() {
        let body = BodyPeek::new(
            b"username=charlie&password=hunter2".to_vec(),
            None,
            false,
        );
        let (m, u, h, _) = make_req(http::Method::POST, "/login");
        let view = view_with_body(&m, &u, &h, &body, "15.0.0.2:443");
        assert_eq!(extract_username(&view).as_deref(), Some("charlie"));
    }

    /// Per-user axis pulls username from Basic-auth header. The
    /// header path wins over body if both present.
    #[test]
    fn extract_username_from_basic_auth() {
        let mut h = http::HeaderMap::new();
        // base64("dave:wrong") = ZGF2ZTp3cm9uZw==
        h.insert(
            http::header::AUTHORIZATION,
            "Basic ZGF2ZTp3cm9uZw==".parse().unwrap(),
        );
        let body = BodyPeek::empty();
        let (m, u, _, _) = make_req(http::Method::GET, "/login");
        let view = view_with_body(&m, &u, &h, &body, "15.0.0.3:443");
        assert_eq!(extract_username(&view).as_deref(), Some("dave"));
    }

    /// `extract_username` returns None when no recognisable
    /// username appears anywhere.
    #[test]
    fn extract_username_returns_none_when_absent() {
        let body = BodyPeek::new(b"nothing-useful-here".to_vec(), None, false);
        let (m, u, h, _) = make_req(http::Method::POST, "/login");
        let view = view_with_body(&m, &u, &h, &body, "15.0.0.4:443");
        assert_eq!(extract_username(&view), None);
    }

    // ---- AC-P2-b (2026-07-04) — fleet-aggregate axes ----

    use std::sync::atomic::AtomicU64;

    /// Minimal shared-counter backend: a real `incrby`/`get_counter`
    /// store so two detectors sharing it aggregate like two nodes on
    /// one Redis. Counts backend calls (per-node scope must make NONE)
    /// and can be flipped to error (fail-safe-to-local test).
    struct FleetMock {
        counters: Mutex<HashMap<String, u64>>,
        fail: bool,
        calls: AtomicU64,
    }

    impl FleetMock {
        fn new() -> Self {
            Self {
                counters: Mutex::new(HashMap::new()),
                fail: false,
                calls: AtomicU64::new(0),
            }
        }
        fn new_failing() -> Self {
            Self { fail: true, ..Self::new() }
        }
        fn total(&self) -> u64 {
            self.counters.lock().unwrap().values().sum()
        }
    }

    #[async_trait::async_trait]
    impl StateBackend for FleetMock {
        async fn get(&self, _: &str) -> aegis_core::Result<Option<Vec<u8>>> { Ok(None) }
        async fn set(&self, _: &str, _: &[u8], _: Duration) -> aegis_core::Result<()> { Ok(()) }
        async fn del(&self, _: &str) -> aegis_core::Result<()> { Ok(()) }
        async fn incr_window(&self, _: &str, w: Duration, _: u64) -> aegis_core::Result<aegis_core::SlidingWindowResult> {
            Ok(aegis_core::SlidingWindowResult { count: 1, allowed: true, retry_after: Some(w) })
        }
        async fn token_bucket(&self, _: &str, _: u32, _: u32) -> aegis_core::Result<bool> { Ok(true) }
        async fn get_risk(&self, _: &aegis_core::RiskKey) -> aegis_core::Result<u32> { Ok(0) }
        async fn add_risk(&self, _: &aegis_core::RiskKey, _: i32, _: u32) -> aegis_core::Result<u32> { Ok(0) }
        async fn auto_block(&self, _: IpAddr, _: Duration) -> aegis_core::Result<()> { Ok(()) }
        async fn is_auto_blocked(&self, _: IpAddr) -> aegis_core::Result<bool> { Ok(false) }
        async fn put_nonce(&self, _: &str, _: Duration) -> aegis_core::Result<bool> { Ok(true) }
        async fn consume_nonce(&self, _: &str) -> aegis_core::Result<bool> { Ok(true) }
        async fn incrby(&self, key: &str, delta: u64) -> aegis_core::Result<u64> {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            if self.fail {
                return Err(aegis_core::WafError::State("incrby failed (test)".into()));
            }
            let mut m = self.counters.lock().unwrap();
            let v = m.entry(key.to_string()).or_insert(0);
            *v += delta;
            Ok(*v)
        }
        async fn get_counter(&self, key: &str) -> aegis_core::Result<u64> {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            if self.fail {
                return Err(aegis_core::WafError::State("get_counter failed (test)".into()));
            }
            Ok(*self.counters.lock().unwrap().get(key).unwrap_or(&0))
        }
    }

    fn fleet_detector(backend: &Arc<FleetMock>) -> BruteForceDetector {
        let mut d = BruteForceDetector::new(100, Duration::from_secs(60), 40);
        d.user_threshold = 5;
        d.set_count_scope(BruteForceCountScope::Fleet);
        d.install_fleet_backend(backend.clone());
        d
    }

    /// Poll (yielding to the current-thread runtime so fire-and-forget
    /// tasks run) until `cond` holds — deterministic wait, panics with
    /// `what` on timeout.
    async fn wait_until(what: &str, mut cond: impl FnMut() -> bool) {
        for _ in 0..500 {
            if cond() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        panic!("timed out waiting for: {what}");
    }

    /// The load-balanced-campaign shape: 3 IPs hit node1, 3 hit node2 —
    /// each node's local distinct-IP count (3) stays under threshold (5),
    /// but the shared fleet counter reaches 6 and the user axis fires.
    #[tokio::test]
    async fn fleet_scope_aggregates_user_axis_across_two_nodes() {
        let backend = Arc::new(FleetMock::new());
        let node1 = fleet_detector(&backend);
        let node2 = fleet_detector(&backend);
        let body = BodyPeek::new(b"username=alice&password=x".to_vec(), None, false);
        let (m, u, h, _) = make_req(http::Method::POST, "/login");

        // node1: 3 distinct IPs — local count 3 ≤ 5, silent.
        for octet in 1..=3 {
            let s = node1.inspect(&view_with_body(&m, &u, &h, &body, &format!("21.0.0.{octet}:443")));
            assert!(
                !s.iter().any(|sig| sig.tag == "brute_force_user"),
                "node1 local count must stay under threshold: {s:?}",
            );
        }
        wait_until("node1's 3 fleet contributions to land", || backend.total() == 3).await;

        // node2: 3 more distinct IPs — local count 3 ≤ 5, but the fleet
        // total reaches 6. (The cache is written by fire-and-forget tasks,
        // so the fire lands on the NEXT auth attempt, not mid-loop.)
        for octet in 4..=6 {
            let _ = node2.inspect(&view_with_body(&m, &u, &h, &body, &format!("21.0.0.{octet}:443")));
        }
        wait_until("node2's fleet cache to reach 6", || {
            node2.fleet_cached("user:alice").unwrap_or(0) >= 6
        })
        .await;

        // A repeat attempt (NOT a new distinct IP — no backend write) now
        // sees the cached fleet count 6 > 5 → fires, though node2's local
        // distinct count is still only 3.
        let s = node2.inspect(&view_with_body(&m, &u, &h, &body, "21.0.0.4:443"));
        assert!(
            s.iter().any(|sig| sig.tag == "brute_force_user"),
            "fleet count 6 must trip the user axis while local counts are 3+3: {s:?}",
        );
    }

    /// Backend errors must fail safe to the per-node count — no panic,
    /// no stall, and the local axis still fires at its own threshold.
    #[tokio::test]
    async fn fleet_backend_error_falls_back_to_per_node() {
        let backend = Arc::new(FleetMock::new_failing());
        let node = fleet_detector(&backend);
        let body = BodyPeek::new(b"username=bob&password=x".to_vec(), None, false);
        let (m, u, h, _) = make_req(http::Method::POST, "/login");

        // 5 distinct IPs — under local threshold, errors swallowed.
        for octet in 1..=5 {
            let s = node.inspect(&view_with_body(&m, &u, &h, &body, &format!("22.0.0.{octet}:443")));
            assert!(!s.iter().any(|sig| sig.tag == "brute_force_user"));
        }
        // Let the failing fire-and-forget tasks run — the cache must stay
        // empty (fail-safe: local count governs).
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(node.fleet_cached("user:bob"), None, "errored fleet reads must not populate the cache");

        // 6th distinct IP crosses the LOCAL threshold — detection intact.
        let s = node.inspect(&view_with_body(&m, &u, &h, &body, "22.0.0.6:443"));
        assert!(
            s.iter().any(|sig| sig.tag == "brute_force_user"),
            "local axis must still fire at its own threshold on backend failure: {s:?}",
        );
    }

    /// `per_node` (the default) must be byte-identical to today: the
    /// backend is installed but NEVER touched.
    #[tokio::test]
    async fn per_node_default_never_touches_backend() {
        let backend = Arc::new(FleetMock::new());
        let mut d = BruteForceDetector::new(100, Duration::from_secs(60), 40);
        d.user_threshold = 2;
        // Scope left at default (per_node); backend present but inert.
        d.install_fleet_backend(backend.clone());
        let body = BodyPeek::new(b"username=carol&password=x".to_vec(), None, false);
        let (m, u, h, _) = make_req(http::Method::POST, "/login");

        for octet in 1..=3 {
            let _ = d.inspect(&view_with_body(&m, &u, &h, &body, &format!("23.0.0.{octet}:443")));
        }
        // Local axis fires exactly as before (3 distinct > 2)…
        let s = d.inspect(&view_with_body(&m, &u, &h, &body, "23.0.0.3:443"));
        assert!(s.iter().any(|sig| sig.tag == "brute_force_user"));
        // …and the shared backend saw zero traffic.
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(
            backend.calls.load(std::sync::atomic::Ordering::Relaxed),
            0,
            "per_node scope must never touch the shared backend",
        );
    }

    /// `fleet` requested but no shared backend installed (single-node /
    /// non-cluster boot): logs once and runs per-node — never a silent
    /// half-fleet, never a panic.
    #[tokio::test]
    async fn fleet_scope_without_backend_runs_per_node() {
        let mut d = BruteForceDetector::new(100, Duration::from_secs(60), 40);
        d.user_threshold = 2;
        d.set_count_scope(BruteForceCountScope::Fleet);
        // No install_fleet_backend — the cluster gate said no.
        let body = BodyPeek::new(b"username=dave&password=x".to_vec(), None, false);
        let (m, u, h, _) = make_req(http::Method::POST, "/login");
        for octet in 1..=2 {
            let s = d.inspect(&view_with_body(&m, &u, &h, &body, &format!("24.0.0.{octet}:443")));
            assert!(!s.iter().any(|sig| sig.tag == "brute_force_user"));
        }
        let s = d.inspect(&view_with_body(&m, &u, &h, &body, "24.0.0.3:443"));
        assert!(
            s.iter().any(|sig| sig.tag == "brute_force_user"),
            "local counting must be intact when fleet has no backend: {s:?}",
        );
    }

    /// The per-device axis aggregates through the same fleet channel:
    /// one JA4 fingerprint across 3+3 IPs on two nodes trips at 6.
    #[tokio::test]
    async fn fleet_scope_aggregates_device_axis_across_two_nodes() {
        let backend = Arc::new(FleetMock::new());
        let mk = || {
            let mut d = BruteForceDetector::new(100, Duration::from_secs(60), 40);
            d.device_threshold = 5;
            d.set_count_scope(BruteForceCountScope::Fleet);
            d.install_fleet_backend(backend.clone());
            d
        };
        let node1 = mk();
        let node2 = mk();
        let fp = aegis_core::TlsFingerprint { ja3: String::new(), ja4: "t13d_stuffer_ja4".into() };
        let body = BodyPeek::empty();
        let (m, u, h, _) = make_req(http::Method::POST, "/login");
        let mk_view = |peer: &str| RequestView {
            method: &m,
            uri: &u,
            version: http::Version::HTTP_11,
            headers: &h,
            peer: peer.parse().unwrap(),
            tls: Some(&fp),
            body: &body,
        };

        for octet in 1..=3 {
            let s = node1.inspect(&mk_view(&format!("25.0.0.{octet}:443")));
            assert!(!s.iter().any(|sig| sig.tag == "brute_force_device"));
        }
        wait_until("node1's device contributions to land", || backend.total() == 3).await;
        for octet in 4..=6 {
            let _ = node2.inspect(&mk_view(&format!("25.0.0.{octet}:443")));
        }
        wait_until("node2's device fleet cache to reach 6", || {
            node2.fleet_cached("device:t13d_stuffer_ja4").unwrap_or(0) >= 6
        })
        .await;
        let s = node2.inspect(&mk_view("25.0.0.4:443"));
        assert!(
            s.iter().any(|sig| sig.tag == "brute_force_device"),
            "fleet device count 6 must trip while local counts are 3+3: {s:?}",
        );
    }

    // ---- BF-OTP-P1 (2026-07-06) — OTP / second-factor brute-force axes ----

    fn otp_body(login_token: &str, code: &str) -> BodyPeek {
        BodyPeek::new(
            format!(r#"{{"login_token":"{login_token}","otp_code":"{code}"}}"#).into_bytes(),
            None,
            false,
        )
    }

    // --- pure extractor tests ---

    #[test]
    fn extract_otp_identity_from_json_login_token() {
        let body = otp_body("tok-abc", "123456");
        let (m, u, h, _) = make_req(http::Method::POST, "/otp");
        let v = view_with_body(&m, &u, &h, &body, "30.0.0.1:443");
        assert_eq!(extract_otp_identity(&v).as_deref(), Some("tok-abc"));
    }

    #[test]
    fn extract_otp_identity_from_form_login_token() {
        let body = BodyPeek::new(b"login_token=tok-form&otp_code=123456".to_vec(), None, false);
        let (m, u, h, _) = make_req(http::Method::POST, "/otp");
        let v = view_with_body(&m, &u, &h, &body, "30.0.0.2:443");
        assert_eq!(extract_otp_identity(&v).as_deref(), Some("tok-form"));
    }

    #[test]
    fn extract_otp_identity_from_cookie_when_no_body_token() {
        let mut h = http::HeaderMap::new();
        h.insert(http::header::COOKIE, "sid=sess-xyz; other=1".parse().unwrap());
        let body = BodyPeek::new(br#"{"otp_code":"123456"}"#.to_vec(), None, false);
        let (m, u, _, _) = make_req(http::Method::POST, "/otp");
        let v = view_with_body(&m, &u, &h, &body, "30.0.0.3:443");
        assert_eq!(extract_otp_identity(&v).as_deref(), Some("sess-xyz"));
    }

    #[test]
    fn extract_otp_identity_from_bearer_when_no_body_or_cookie() {
        let mut h = http::HeaderMap::new();
        h.insert(http::header::AUTHORIZATION, "Bearer beartok".parse().unwrap());
        let body = BodyPeek::new(br#"{"otp_code":"123456"}"#.to_vec(), None, false);
        let (m, u, _, _) = make_req(http::Method::POST, "/otp");
        let v = view_with_body(&m, &u, &h, &body, "30.0.0.4:443");
        assert_eq!(extract_otp_identity(&v).as_deref(), Some("beartok"));
    }

    #[test]
    fn extract_otp_code_from_json_and_form() {
        let (m, u, h, _) = make_req(http::Method::POST, "/otp");
        let j = otp_body("t", "000090");
        assert_eq!(
            extract_otp_code(&view_with_body(&m, &u, &h, &j, "30.0.0.5:443")).as_deref(),
            Some("000090"),
        );
        let f = BodyPeek::new(b"login_token=t&otp_code=000091".to_vec(), None, false);
        assert_eq!(
            extract_otp_code(&view_with_body(&m, &u, &h, &f, "30.0.0.6:443")).as_deref(),
            Some("000091"),
        );
    }

    /// Load-bearing correctness property: identity (`login_token`) and code
    /// (`otp_code`) are SEPARATE extractions. Keying the per-session axis on the
    /// code would make the detector count every guess as a new "identity" and
    /// never fire the spray. They must never be equal for a real submission.
    #[test]
    fn never_keys_identity_on_otp_code() {
        let body = otp_body("the-token", "000090");
        let (m, u, h, _) = make_req(http::Method::POST, "/otp");
        let v = view_with_body(&m, &u, &h, &body, "30.0.0.7:443");
        assert_eq!(extract_otp_identity(&v).as_deref(), Some("the-token"));
        assert_eq!(extract_otp_code(&v).as_deref(), Some("000090"));
        assert_ne!(extract_otp_identity(&v), extract_otp_code(&v));
    }

    #[test]
    fn otp_path_aliases_match_and_negatives_dont() {
        for p in [
            "/otp", "/api/otp", "/verify-otp", "/2fa", "/2fa/verify", "/mfa", "/verify",
            "/challenge/verify", "/totp", "/api/totp",
        ] {
            assert!(is_otp_path(p), "{p} should be an OTP path");
        }
        for p in ["/verify-email", "/api/profile", "/login", "/otpx", "/verifyotp"] {
            assert!(!is_otp_path(p), "{p} should NOT be an OTP path");
        }
    }

    // --- Axis B: spray (distinct tokens, same code) ---

    #[test]
    fn otp_spray_fires_above_threshold() {
        let d = BruteForceDetector::default();
        let (m, u, h, _) = make_req(http::Method::POST, "/otp");
        // 20 distinct tokens, same code — at threshold, silent.
        for i in 0..20 {
            let body = otp_body(&format!("tok{i}"), "000090");
            let s = d.inspect(&view_with_body(&m, &u, &h, &body, "31.0.0.1:443"));
            assert!(
                !s.iter().any(|x| x.tag == "brute_force_otp_spray"),
                "under spray threshold at {i} tokens",
            );
        }
        // 21st distinct token → > 20 → fires.
        let body = otp_body("tok20", "000090");
        let s = d.inspect(&view_with_body(&m, &u, &h, &body, "31.0.0.1:443"));
        assert!(
            s.iter().any(|x| x.tag == "brute_force_otp_spray"),
            "21 distinct tokens on one code must fire spray: {s:?}",
        );
    }

    #[test]
    fn otp_spray_is_ip_independent() {
        let d = BruteForceDetector::default();
        let (m, u, h, _) = make_req(http::Method::POST, "/otp");
        let mut fired = false;
        // 21 distinct tokens, same code, each from a DIFFERENT IP.
        for i in 0..21 {
            let body = otp_body(&format!("rtok{i}"), "555555");
            let ip = format!("32.0.{}.{}:443", i / 250, i % 250);
            let s = d.inspect(&view_with_body(&m, &u, &h, &body, &ip));
            if s.iter().any(|x| x.tag == "brute_force_otp_spray") {
                fired = true;
            }
        }
        assert!(fired, "spray must fire on distinct-token/same-code across rotating IPs");
    }

    #[test]
    fn otp_spray_dedupes_repeated_identity() {
        let d = BruteForceDetector::default();
        let (m, u, h, _) = make_req(http::Method::POST, "/otp");
        // ONE token retries the same code 50× — distinct-identity count = 1.
        let body = otp_body("solo", "000090");
        for _ in 0..50 {
            let s = d.inspect(&view_with_body(&m, &u, &h, &body, "33.0.0.1:443"));
            assert!(
                !s.iter().any(|x| x.tag == "brute_force_otp_spray"),
                "a single token must never trip the spray axis",
            );
        }
    }

    // --- Axis A: grind (distinct codes, same token) ---

    #[test]
    fn otp_grind_fires_above_threshold() {
        let d = BruteForceDetector::default();
        let (m, u, h, _) = make_req(http::Method::POST, "/otp");
        // one token, 10 distinct codes — at threshold, silent.
        for i in 0..10 {
            let body = otp_body("grindtok", &format!("{i:06}"));
            let s = d.inspect(&view_with_body(&m, &u, &h, &body, "34.0.0.1:443"));
            assert!(
                !s.iter().any(|x| x.tag == "brute_force_otp"),
                "under grind threshold at {i} codes",
            );
        }
        // 11th distinct code → > 10 → fires.
        let body = otp_body("grindtok", "000099");
        let s = d.inspect(&view_with_body(&m, &u, &h, &body, "34.0.0.1:443"));
        assert!(
            s.iter().any(|x| x.tag == "brute_force_otp"),
            "11 distinct codes on one token must fire grind: {s:?}",
        );
    }

    #[test]
    fn otp_grind_dedupes_repeated_code() {
        let d = BruteForceDetector::default();
        let (m, u, h, _) = make_req(http::Method::POST, "/otp");
        // one token submits the SAME code 30× — distinct-code count = 1.
        let body = otp_body("typotok", "123456");
        for _ in 0..30 {
            let s = d.inspect(&view_with_body(&m, &u, &h, &body, "35.0.0.1:443"));
            assert!(
                !s.iter().any(|x| x.tag == "brute_force_otp"),
                "repeated identical code must not trip the grind axis",
            );
        }
    }

    // --- false-positive guards (the owner directive) ---

    #[test]
    fn distinct_codes_across_many_tokens_no_spray() {
        let d = BruteForceDetector::default();
        let (m, u, h, _) = make_req(http::Method::POST, "/otp");
        // 50 distinct tokens each with a DISTINCT code — the legit shape.
        for i in 0..50 {
            let body = otp_body(&format!("legit{i}"), &format!("{:06}", 100000 + i));
            let s = d.inspect(&view_with_body(&m, &u, &h, &body, "36.0.0.1:443"));
            assert!(
                s.iter().all(|x| x.tag != "brute_force_otp_spray"),
                "distinct codes must never cluster into a spray",
            );
        }
    }

    #[test]
    fn non_otp_path_emits_no_otp_signal() {
        let d = BruteForceDetector::default();
        let (m, u, h, _) = make_req(http::Method::POST, "/api/profile");
        for i in 0..30 {
            let body = otp_body(&format!("t{i}"), "000090");
            let s = d.inspect(&view_with_body(&m, &u, &h, &body, "37.0.0.1:443"));
            assert!(
                s.iter().all(|x| !x.tag.starts_with("brute_force_otp")),
                "no OTP signals off OTP paths",
            );
        }
    }

    #[test]
    fn per_ip_axis_fires_on_otp_path() {
        // default per-IP threshold 10 — 11+ from one IP fires classic brute_force.
        let d = BruteForceDetector::default();
        let (m, u, h, _) = make_req(http::Method::POST, "/otp");
        let mut fired = false;
        for i in 0..12 {
            let body = otp_body(&format!("iptok{i}"), &format!("{i:06}"));
            let s = d.inspect(&view_with_body(&m, &u, &h, &body, "38.0.0.1:443"));
            if s.iter().any(|x| x.tag == "brute_force") {
                fired = true;
            }
        }
        assert!(fired, "per-IP axis must fire on /otp once the path is recognized");
    }

    #[test]
    fn otp_spray_signal_field_has_no_plaintext_code() {
        let d = BruteForceDetector::default();
        let (m, u, h, _) = make_req(http::Method::POST, "/otp");
        let mut field = None;
        for i in 0..22 {
            let body = otp_body(&format!("htok{i}"), "000090");
            let s = d.inspect(&view_with_body(&m, &u, &h, &body, "39.0.0.1:443"));
            if let Some(sig) = s.iter().find(|x| x.tag == "brute_force_otp_spray") {
                field = Some(sig.field.clone());
            }
        }
        let field = field.expect("spray must have fired within 22 tokens");
        assert!(
            !field.contains("000090"),
            "audit field must not leak the plaintext OTP: {field}",
        );
    }

    // ---- BF-OTP-P2 — fleet aggregation of the OTP spray axis ----

    fn otp_fleet_detector(backend: &Arc<FleetMock>) -> BruteForceDetector {
        let d = BruteForceDetector::default(); // spray threshold 20
        d.set_count_scope(BruteForceCountScope::Fleet);
        d.install_fleet_backend(backend.clone());
        d
    }

    /// IP-rotating spray load-balanced across nodes: 11 tokens hit node1, 10 hit
    /// node2 (each node local ≤ 20, silent), but the shared fleet counter reaches
    /// 21 and the spray axis fires — the exact threat the S-Tester report warned
    /// about (rotate IPs / spread across the fleet to dilute per-node counts).
    #[tokio::test]
    async fn otp_spray_fleet_aggregates_across_two_nodes() {
        let backend = Arc::new(FleetMock::new());
        let node1 = otp_fleet_detector(&backend);
        let node2 = otp_fleet_detector(&backend);
        let (m, u, h, _) = make_req(http::Method::POST, "/otp");
        let cache_key = format!("otp_spray:{}", short_hash("000090"));

        // node1: 11 distinct tokens, same code — local 11 ≤ 20, silent.
        for i in 0..11 {
            let body = otp_body(&format!("ftok{i}"), "000090");
            let s = node1.inspect(&view_with_body(&m, &u, &h, &body, "41.0.0.1:443"));
            assert!(
                !s.iter().any(|x| x.tag == "brute_force_otp_spray"),
                "node1 local must stay under threshold at {i}",
            );
        }
        // Wait on the spray-specific counter (the grind axis also writes its own
        // per-identity keys, so `backend.total()` isn't spray-only here).
        wait_until("node1's 11 spray contributions to land", || {
            node1.fleet_cached(&cache_key).unwrap_or(0) >= 11
        })
        .await;

        // node2: 10 more distinct tokens — local 10 ≤ 20, fleet total reaches 21.
        for i in 11..21 {
            let body = otp_body(&format!("ftok{i}"), "000090");
            let _ = node2.inspect(&view_with_body(&m, &u, &h, &body, "41.0.0.2:443"));
        }
        wait_until("node2's fleet cache to reach 21", || {
            node2.fleet_cached(&cache_key).unwrap_or(0) >= 21
        })
        .await;

        // A repeat token (NOT newly distinct — no backend write) now sees the
        // cached fleet count 21 > 20 → fires, though node2's local count is 10.
        let body = otp_body("ftok11", "000090");
        let s = node2.inspect(&view_with_body(&m, &u, &h, &body, "41.0.0.2:443"));
        assert!(
            s.iter().any(|x| x.tag == "brute_force_otp_spray"),
            "fleet count 21 must trip the spray axis while local counts are 11+10: {s:?}",
        );
    }

    /// Backend errors fail safe to the per-node count — no panic, no stall, and
    /// the local spray axis still fires at its own threshold.
    #[tokio::test]
    async fn otp_spray_fleet_backend_error_falls_back_to_per_node() {
        let backend = Arc::new(FleetMock::new_failing());
        let node = otp_fleet_detector(&backend);
        let (m, u, h, _) = make_req(http::Method::POST, "/otp");
        // 20 distinct tokens — under local threshold, errors swallowed.
        for i in 0..20 {
            let body = otp_body(&format!("etok{i}"), "000090");
            let s = node.inspect(&view_with_body(&m, &u, &h, &body, "42.0.0.1:443"));
            assert!(!s.iter().any(|x| x.tag == "brute_force_otp_spray"));
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
        // 21st distinct token crosses the LOCAL threshold — detection intact.
        let body = otp_body("etok20", "000090");
        let s = node.inspect(&view_with_body(&m, &u, &h, &body, "42.0.0.1:443"));
        assert!(
            s.iter().any(|x| x.tag == "brute_force_otp_spray"),
            "local axis must still fire on backend failure: {s:?}",
        );
    }
}
