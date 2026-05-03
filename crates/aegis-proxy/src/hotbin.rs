//! Hot binary reload via SIGUSR2.
//!
//! On SIGUSR2: `fork+exec` a new binary with listening socket FDs passed via
//! environment variables. The old process enters the drain path. If the new
//! process fails its readiness probe, the old process resumes accepting.

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

/// State of the hot-reload process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReloadState {
    /// Normal operation.
    Idle,
    /// New binary spawned, waiting for readiness.
    Pending,
    /// Reload succeeded, old process draining.
    Draining,
    /// Reload failed, old process resumed.
    RolledBack,
}

/// Manages the hot binary reload lifecycle.
pub struct HotReloader {
    state: std::sync::Mutex<ReloadState>,
    signal_received: AtomicBool,
    readiness_timeout: Duration,
}

impl HotReloader {
    pub fn new(readiness_timeout: Duration) -> Self {
        Self {
            state: std::sync::Mutex::new(ReloadState::Idle),
            signal_received: AtomicBool::new(false),
            readiness_timeout,
        }
    }

    /// Mark that SIGUSR2 was received.
    pub fn signal(&self) {
        self.signal_received.store(true, Ordering::Release);
    }

    /// Check if a signal was received and reset the flag.
    pub fn take_signal(&self) -> bool {
        self.signal_received.swap(false, Ordering::AcqRel)
    }

    /// Transition to a new state.
    pub fn transition(&self, new_state: ReloadState) {
        let mut state = self.state.lock().unwrap();
        *state = new_state;
    }

    /// Current state.
    pub fn state(&self) -> ReloadState {
        *self.state.lock().unwrap()
    }

    pub fn readiness_timeout(&self) -> Duration {
        self.readiness_timeout
    }
}

/// Describes how FDs are passed to the new binary.
#[derive(Debug, Clone)]
pub struct FdPassConfig {
    /// Environment variable name for passing the number of listener FDs.
    pub env_fd_count: String,
    /// Base FD number (usually 3, after stdin/stdout/stderr).
    pub base_fd: i32,
}

impl Default for FdPassConfig {
    fn default() -> Self {
        Self {
            env_fd_count: "AEGIS_LISTEN_FDS".into(),
            base_fd: 3,
        }
    }
}

/// Parse the FD count from the environment (used by the new binary on startup).
pub fn inherited_fd_count() -> Option<usize> {
    std::env::var("AEGIS_LISTEN_FDS")
        .ok()
        .and_then(|v| v.parse().ok())
}

/// FDP-T1 — outcome of an `adopt_inherited_listeners` call.
/// Distinguishes "no inheritance configured" (caller should
/// fresh-bind every listener — first-boot path) from explicit
/// errors (caller should fail fast — half-handover is worse
/// than fresh-bind).
#[derive(Debug)]
pub enum AdoptOutcome {
    /// Either `AEGIS_LISTEN_FDS` was unset or it parsed to 0.
    /// Caller fresh-binds.
    NoInheritance,
    /// Inheritance was requested but the env was inconsistent
    /// (FD count vs. name list mismatch, malformed names, etc).
    /// Caller MUST fail fast — silently fresh-binding would
    /// race the parent's still-alive listener.
    Misconfigured(String),
    /// Inheritance succeeded. The map is keyed by the names
    /// from `AEGIS_LISTEN_FD_NAMES`, in the same order they
    /// appeared. Each listener has been put into non-blocking
    /// mode so it's ready to hand to `tokio::net::TcpListener::from_std`.
    Inherited(std::collections::HashMap<String, std::net::TcpListener>),
}

/// FDP-T1 — adopt listeners passed by an exec'ing parent.
///
/// Contract:
///
/// - Reads `AEGIS_LISTEN_FDS` (count) + `AEGIS_LISTEN_FD_NAMES`
///   (comma-separated names, same order as FD slots starting at
///   [`FdPassConfig::base_fd`]).
/// - Returns [`AdoptOutcome::NoInheritance`] when the count env
///   is unset or zero.
/// - Returns [`AdoptOutcome::Misconfigured`] with a one-line
///   reason when:
///     * `AEGIS_LISTEN_FD_NAMES` is unset but the count is > 0,
///     * the comma-split name count doesn't match the FD count,
///     * a name is empty or duplicated.
/// - Returns [`AdoptOutcome::Inherited`] with `count` listeners
///   keyed by name when everything checked out.
///
/// SAFETY: this calls `from_raw_fd` on FDs `base_fd..base_fd+N`
/// claiming sole ownership. The contract is that the parent
/// process placed exactly those FDs in those slots via
/// `exec` inheritance; mis-calling this in any other context
/// will hand over arbitrary FDs (typically nonexistent →
/// later `set_nonblocking` returns Err and we surface
/// `Misconfigured`).
pub fn adopt_inherited_listeners() -> AdoptOutcome {
    adopt_inherited_listeners_with_cfg(&FdPassConfig::default())
}

/// Test-friendly variant — accepts a custom [`FdPassConfig`]
/// so unit tests can use a non-stdio base FD.
pub fn adopt_inherited_listeners_with_cfg(cfg: &FdPassConfig) -> AdoptOutcome {
    let count = match std::env::var(&cfg.env_fd_count) {
        Err(_) => return AdoptOutcome::NoInheritance,
        Ok(s) => match s.parse::<usize>() {
            Ok(n) => n,
            Err(_) => {
                return AdoptOutcome::Misconfigured(format!(
                    "{} is not a valid usize: {s:?}",
                    cfg.env_fd_count,
                ));
            }
        },
    };
    if count == 0 {
        return AdoptOutcome::NoInheritance;
    }

    let names_raw = match std::env::var("AEGIS_LISTEN_FD_NAMES") {
        Ok(s) => s,
        Err(_) => {
            return AdoptOutcome::Misconfigured(format!(
                "{} is set but AEGIS_LISTEN_FD_NAMES is missing",
                cfg.env_fd_count,
            ));
        }
    };
    let names: Vec<&str> = names_raw.split(',').collect();
    if names.len() != count {
        return AdoptOutcome::Misconfigured(format!(
            "AEGIS_LISTEN_FD_NAMES count {} != {} {}",
            names.len(),
            cfg.env_fd_count,
            count,
        ));
    }
    if names.iter().any(|n| n.is_empty()) {
        return AdoptOutcome::Misconfigured(
            "AEGIS_LISTEN_FD_NAMES contains an empty name".into(),
        );
    }
    let mut seen = std::collections::HashSet::new();
    for n in &names {
        if !seen.insert(*n) {
            return AdoptOutcome::Misconfigured(format!(
                "AEGIS_LISTEN_FD_NAMES contains duplicate name '{n}'",
            ));
        }
    }

    adopt_listeners_from_fds(&names, cfg.base_fd)
}

/// FDP-T2 — adopt the listener for `name` from `inherited` if
/// present, else fresh-bind to `addr`. The boot path's
/// drop-in replacement for `tokio::net::TcpListener::bind`.
///
/// Errors propagate: a misconfigured inherited FD that can't be
/// promoted to a tokio listener fails fast rather than
/// silently fresh-binding (which would race the parent's
/// still-alive FD on the same port).
pub async fn adopt_or_bind(
    inherited: &mut std::collections::HashMap<String, std::net::TcpListener>,
    name: &str,
    addr: std::net::SocketAddr,
) -> std::io::Result<tokio::net::TcpListener> {
    if let Some(std_l) = inherited.remove(name) {
        tracing::info!(name = %name, fd_addr = %std_l.local_addr().ok().map(|a| a.to_string()).unwrap_or_else(|| "?".into()), "listener: adopted inherited FD");
        return tokio::net::TcpListener::from_std(std_l);
    }
    tracing::info!(name = %name, addr = %addr, "listener: fresh bind");
    tokio::net::TcpListener::bind(addr).await
}

/// FDP-T3 — plan for spawning a successor process via
/// `Command::new(binary_path)` with the listener FDs pre-placed
/// into slots `3..3+listeners.len()` so the child's
/// `adopt_inherited_listeners()` finds them.
#[cfg(unix)]
#[derive(Debug, Clone)]
pub struct SuccessorPlan {
    /// Path to the binary to exec. Typically the parent's own
    /// `current_exe()` for hot-restart, but separable so tests
    /// can spawn `/bin/sh` for verification.
    pub binary_path: std::path::PathBuf,
    /// Live listener FDs to pass to the child. The order
    /// determines slot assignment: `listeners[0]` lands at
    /// FD 3, `listeners[1]` at FD 4, etc. Names also drive
    /// `AEGIS_LISTEN_FD_NAMES`.
    pub listeners: Vec<(String, std::os::fd::RawFd)>,
    /// Additional env-var pairs to set on the child. Use for
    /// boot config (`--config`, `RUST_LOG`, etc) without
    /// needing an extra arg-vector field.
    pub extra_env: Vec<(String, String)>,
    /// Args to pass after the binary path. Forwarded verbatim
    /// to the child process.
    pub args: Vec<String>,
}

/// FDP-T3 — build a `std::process::Command` that, when spawned,
/// fork+execs a successor with listener FDs pre-placed into
/// slots `3..3+N`. Caller can set stdio (`Stdio::piped()`,
/// `Stdio::inherit()`, etc) before calling `.spawn()`.
///
/// Default stdio is `Stdio::inherit()` — the production
/// hot-restart path wants the child's logs to flow wherever
/// the parent's were going (typically a journal / file). Tests
/// override with piped stdio for output capture.
///
/// CLOEXEC: we clear `FD_CLOEXEC` on each pre-placed slot
/// inside the post-fork pre-exec closure so the FD survives
/// the exec. The original FDs in the parent process keep
/// their CLOEXEC state — this is a child-only mutation.
#[cfg(unix)]
pub fn build_successor_command(plan: SuccessorPlan) -> std::process::Command {
    use std::os::unix::process::CommandExt;

    let mut cmd = std::process::Command::new(&plan.binary_path);
    cmd.args(&plan.args);

    let n = plan.listeners.len();
    cmd.env("AEGIS_LISTEN_FDS", n.to_string());
    let names = plan
        .listeners
        .iter()
        .map(|(name, _)| name.as_str())
        .collect::<Vec<_>>()
        .join(",");
    cmd.env("AEGIS_LISTEN_FD_NAMES", names);
    for (k, v) in &plan.extra_env {
        cmd.env(k, v);
    }

    // Capture the FD list for the post-fork closure. The
    // closure runs in the forked child between fork() and
    // exec() — only async-signal-safe operations are valid
    // here. dup2 + fcntl are both AS-safe.
    let fds: Vec<std::os::fd::RawFd> =
        plan.listeners.iter().map(|(_, fd)| *fd).collect();

    // SAFETY: pre_exec runs post-fork in the child; calls in
    // the closure must be async-signal-safe. dup2 + fcntl with
    // F_GETFD / F_SETFD are AS-safe per POSIX. We don't
    // allocate, take locks, or call into Rust runtime here —
    // the only work is FD slot juggling.
    unsafe {
        cmd.pre_exec(move || {
            for (i, &src_fd) in fds.iter().enumerate() {
                let target_fd: std::os::fd::RawFd = 3 + i as std::os::fd::RawFd;
                if libc_dup2(src_fd, target_fd) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                // Clear FD_CLOEXEC on the target slot so the
                // FD survives exec. We could also pass
                // O_CLOEXEC=false to dup2 (Linux-specific
                // dup3) but the F_SETFD path is portable.
                let flags = libc_fcntl_getfd(target_fd);
                if flags < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc_fcntl_setfd(target_fd, flags & !FD_CLOEXEC_VALUE) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }

    cmd
}

/// FDP-T3 — sugar wrapper that builds the command + spawns it
/// with default (inherited) stdio. Returns the
/// [`std::process::Child`] handle so the caller (FDP-T4 drain
/// protocol) can poll readiness + wait for exit code.
#[cfg(unix)]
pub fn spawn_successor(plan: SuccessorPlan) -> std::io::Result<std::process::Child> {
    build_successor_command(plan).spawn()
}

/// `FD_CLOEXEC` constant. Defined inline to avoid a libc dep;
/// the value is `1` on every Unix platform that defines it.
#[cfg(unix)]
const FD_CLOEXEC_VALUE: i32 = 1;

/// `F_GETFD` and `F_SETFD` are 1 and 2 respectively on every
/// modern Unix (Linux + macOS + BSDs). Defined inline.
#[cfg(unix)]
const F_GETFD_VALUE: i32 = 1;
#[cfg(unix)]
const F_SETFD_VALUE: i32 = 2;

#[cfg(unix)]
extern "C" {
    fn dup2(oldfd: i32, newfd: i32) -> i32;
    fn fcntl(fd: i32, cmd: i32, ...) -> i32;
}

#[cfg(unix)]
fn libc_dup2(oldfd: std::os::fd::RawFd, newfd: std::os::fd::RawFd) -> std::os::fd::RawFd {
    // SAFETY: dup2 with valid FDs is always safe; -1 + errno on failure.
    unsafe { dup2(oldfd, newfd) }
}

#[cfg(unix)]
fn libc_fcntl_getfd(fd: std::os::fd::RawFd) -> i32 {
    // SAFETY: F_GETFD is the no-arg variant; passing the
    // varargs as 0 is the convention.
    unsafe { fcntl(fd, F_GETFD_VALUE) }
}

#[cfg(unix)]
fn libc_fcntl_setfd(fd: std::os::fd::RawFd, flags: i32) -> i32 {
    // SAFETY: F_SETFD takes one int via varargs.
    unsafe { fcntl(fd, F_SETFD_VALUE, flags) }
}

/// Lower-level: take ownership of FDs `base..base+names.len()`,
/// promote each into a non-blocking `std::net::TcpListener`,
/// and return them keyed by `names[i]`.
///
/// Pulled out so the unit tests can drive the adoption with
/// FDs they `dup()`'d themselves rather than relying on
/// exec-inheritance ordering.
fn adopt_listeners_from_fds(
    names: &[&str],
    base_fd: i32,
) -> AdoptOutcome {
    use std::os::fd::FromRawFd;
    let mut out = std::collections::HashMap::with_capacity(names.len());
    for (i, name) in names.iter().enumerate() {
        let fd = base_fd + i as i32;
        // SAFETY: caller's contract — see `adopt_inherited_listeners`
        // doc-comment. We assume sole ownership from here forward.
        let std_listener = unsafe { std::net::TcpListener::from_raw_fd(fd) };
        if let Err(e) = std_listener.set_nonblocking(true) {
            return AdoptOutcome::Misconfigured(format!(
                "fd {fd} ('{name}') failed set_nonblocking: {e}",
            ));
        }
        out.insert((*name).to_string(), std_listener);
    }
    AdoptOutcome::Inherited(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::{AsRawFd, IntoRawFd};
    use std::sync::Mutex;

    /// Serialise tests that mutate process-wide env. `std::env::set_var`
    /// is `unsafe` on Rust 2024 because concurrent reads from another
    /// thread are UB; the mutex makes ordering explicit.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn env_set(key: &str, val: &str) {
        // SAFETY: serialised by ENV_LOCK in every call site.
        unsafe { std::env::set_var(key, val) };
    }
    fn env_unset(key: &str) {
        // SAFETY: serialised by ENV_LOCK in every call site.
        unsafe { std::env::remove_var(key) };
    }

    #[test]
    fn initial_state_is_idle() {
        let r = HotReloader::new(Duration::from_secs(10));
        assert_eq!(r.state(), ReloadState::Idle);
    }

    #[test]
    fn signal_and_take() {
        let r = HotReloader::new(Duration::from_secs(10));
        assert!(!r.take_signal());
        r.signal();
        assert!(r.take_signal());
        assert!(!r.take_signal()); // consumed
    }

    #[test]
    fn state_transitions() {
        let r = HotReloader::new(Duration::from_secs(10));
        r.transition(ReloadState::Pending);
        assert_eq!(r.state(), ReloadState::Pending);
        r.transition(ReloadState::Draining);
        assert_eq!(r.state(), ReloadState::Draining);
    }

    #[test]
    fn rollback_on_failure() {
        let r = HotReloader::new(Duration::from_secs(10));
        r.transition(ReloadState::Pending);
        // Simulate readiness failure → rollback.
        r.transition(ReloadState::RolledBack);
        assert_eq!(r.state(), ReloadState::RolledBack);
    }

    #[test]
    fn fd_pass_config_default() {
        let cfg = FdPassConfig::default();
        assert_eq!(cfg.env_fd_count, "AEGIS_LISTEN_FDS");
        assert_eq!(cfg.base_fd, 3);
    }

    #[test]
    fn inherited_fd_count_missing() {
        // In test environment, this env var should not be set.
        let _g = ENV_LOCK.lock().unwrap();
        env_unset("AEGIS_LISTEN_FDS");
        assert!(inherited_fd_count().is_none());
    }

    // -----------------------------------------------------------
    // FDP-T1 — adopt_inherited_listeners
    // -----------------------------------------------------------

    #[test]
    fn adopt_no_inheritance_when_env_unset() {
        let _g = ENV_LOCK.lock().unwrap();
        env_unset("AEGIS_LISTEN_FDS");
        env_unset("AEGIS_LISTEN_FD_NAMES");
        match adopt_inherited_listeners() {
            AdoptOutcome::NoInheritance => {}
            other => panic!("expected NoInheritance, got {other:?}"),
        }
    }

    #[test]
    fn adopt_no_inheritance_when_count_is_zero() {
        let _g = ENV_LOCK.lock().unwrap();
        env_set("AEGIS_LISTEN_FDS", "0");
        env_unset("AEGIS_LISTEN_FD_NAMES");
        match adopt_inherited_listeners() {
            AdoptOutcome::NoInheritance => {}
            other => panic!("expected NoInheritance, got {other:?}"),
        }
        env_unset("AEGIS_LISTEN_FDS");
    }

    #[test]
    fn adopt_misconfigured_when_names_missing() {
        let _g = ENV_LOCK.lock().unwrap();
        env_set("AEGIS_LISTEN_FDS", "2");
        env_unset("AEGIS_LISTEN_FD_NAMES");
        match adopt_inherited_listeners() {
            AdoptOutcome::Misconfigured(msg) => {
                assert!(
                    msg.contains("AEGIS_LISTEN_FD_NAMES is missing"),
                    "got: {msg}",
                );
            }
            other => panic!("expected Misconfigured, got {other:?}"),
        }
        env_unset("AEGIS_LISTEN_FDS");
    }

    #[test]
    fn adopt_misconfigured_when_count_unparseable() {
        let _g = ENV_LOCK.lock().unwrap();
        env_set("AEGIS_LISTEN_FDS", "not-a-number");
        match adopt_inherited_listeners() {
            AdoptOutcome::Misconfigured(msg) => {
                assert!(msg.contains("not a valid usize"), "got: {msg}");
            }
            other => panic!("expected Misconfigured, got {other:?}"),
        }
        env_unset("AEGIS_LISTEN_FDS");
    }

    #[test]
    fn adopt_misconfigured_when_name_count_mismatches_fd_count() {
        let _g = ENV_LOCK.lock().unwrap();
        env_set("AEGIS_LISTEN_FDS", "3");
        env_set("AEGIS_LISTEN_FD_NAMES", "admin,data");
        match adopt_inherited_listeners() {
            AdoptOutcome::Misconfigured(msg) => {
                assert!(
                    msg.contains("count 2 != AEGIS_LISTEN_FDS 3"),
                    "got: {msg}",
                );
            }
            other => panic!("expected Misconfigured, got {other:?}"),
        }
        env_unset("AEGIS_LISTEN_FDS");
        env_unset("AEGIS_LISTEN_FD_NAMES");
    }

    #[test]
    fn adopt_misconfigured_when_name_is_empty() {
        let _g = ENV_LOCK.lock().unwrap();
        env_set("AEGIS_LISTEN_FDS", "2");
        env_set("AEGIS_LISTEN_FD_NAMES", "admin,");
        match adopt_inherited_listeners() {
            AdoptOutcome::Misconfigured(msg) => {
                assert!(msg.contains("empty name"), "got: {msg}");
            }
            other => panic!("expected Misconfigured, got {other:?}"),
        }
        env_unset("AEGIS_LISTEN_FDS");
        env_unset("AEGIS_LISTEN_FD_NAMES");
    }

    #[test]
    fn adopt_misconfigured_when_names_have_duplicates() {
        let _g = ENV_LOCK.lock().unwrap();
        env_set("AEGIS_LISTEN_FDS", "2");
        env_set("AEGIS_LISTEN_FD_NAMES", "admin,admin");
        match adopt_inherited_listeners() {
            AdoptOutcome::Misconfigured(msg) => {
                assert!(msg.contains("duplicate name 'admin'"), "got: {msg}");
            }
            other => panic!("expected Misconfigured, got {other:?}"),
        }
        env_unset("AEGIS_LISTEN_FDS");
        env_unset("AEGIS_LISTEN_FD_NAMES");
    }

    /// End-to-end FD-adopt: bind a real listener, hand its FD
    /// to `adopt_listeners_from_fds`, prove the returned
    /// `std::net::TcpListener` accepts a connection on the same
    /// port. Validates that the unsafe `from_raw_fd` step
    /// actually round-trips a working socket.
    #[test]
    fn adopt_real_listener_round_trips_an_accept() {
        let bound = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = bound.local_addr().unwrap();
        // Hand ownership of the FD to the adopt path. Using
        // `into_raw_fd()` releases `bound`'s Drop so we don't
        // double-close.
        let raw = bound.into_raw_fd();

        let outcome = adopt_listeners_from_fds(&["admin"], raw);
        let mut map = match outcome {
            AdoptOutcome::Inherited(m) => m,
            other => panic!("expected Inherited, got {other:?}"),
        };
        let adopted = map.remove("admin").expect("name keyed");

        // Adopted listener must be on the same address (same
        // kernel socket) and must accept a real connection.
        assert_eq!(adopted.local_addr().unwrap(), addr);

        // Drive a connection to prove the FD is live. Spawn
        // accept on a background thread because the listener
        // is non-blocking after adopt — easier to use
        // `set_nonblocking(false)` than write a poll loop.
        adopted.set_nonblocking(false).unwrap();
        let h = std::thread::spawn(move || {
            let (_sock, _peer) = adopted.accept().unwrap();
            // Drop closes — we only care that accept fired.
        });
        // Connect from the same thread.
        let _client = std::net::TcpStream::connect(addr).unwrap();
        h.join().unwrap();
    }

    #[test]
    fn adopt_with_cfg_uses_custom_base_fd() {
        // Same as above but verifies that the env-driven path
        // honours a custom `base_fd`. We manually set the env
        // and place a real listener at the requested slot.
        let bound = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let original_fd = bound.as_raw_fd();
        // dup to a large slot so we don't collide with stdio.
        // SAFETY: dup is always safe.
        let target_fd: i32 = 200;
        let dup_fd = unsafe { libc_dup2(original_fd, target_fd) };
        assert!(
            dup_fd >= 0,
            "dup2 to fd {target_fd} failed (errno={})",
            std::io::Error::last_os_error(),
        );
        // Drop the original — only `dup_fd` keeps the socket alive.
        drop(bound);

        let _g = ENV_LOCK.lock().unwrap();
        env_set("AEGIS_LISTEN_FDS", "1");
        env_set("AEGIS_LISTEN_FD_NAMES", "admin");
        let cfg = FdPassConfig {
            env_fd_count: "AEGIS_LISTEN_FDS".into(),
            base_fd: target_fd,
        };
        let outcome = adopt_inherited_listeners_with_cfg(&cfg);
        env_unset("AEGIS_LISTEN_FDS");
        env_unset("AEGIS_LISTEN_FD_NAMES");

        match outcome {
            AdoptOutcome::Inherited(m) => {
                assert!(m.contains_key("admin"));
            }
            other => panic!("expected Inherited, got {other:?}"),
        }
    }

    // libc_dup2 lives at module level (FDP-T3 helpers); use it
    // directly instead of redeclaring.

    // -----------------------------------------------------------
    // FDP-T2 — adopt_or_bind
    // -----------------------------------------------------------

    #[tokio::test]
    async fn adopt_or_bind_falls_through_to_fresh_bind_when_name_absent() {
        let mut inherited = std::collections::HashMap::new();
        let addr: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
        let tcp = adopt_or_bind(&mut inherited, "admin", addr).await.unwrap();
        // Fresh bind succeeded; map is unchanged.
        assert!(tcp.local_addr().is_ok());
        assert!(inherited.is_empty());
    }

    #[tokio::test]
    async fn adopt_or_bind_consumes_inherited_entry_when_name_matches() {
        let bound = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        bound.set_nonblocking(true).unwrap();
        let original_addr = bound.local_addr().unwrap();
        let mut inherited = std::collections::HashMap::new();
        inherited.insert("admin".to_string(), bound);

        let tcp = adopt_or_bind(&mut inherited, "admin", "127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        assert_eq!(tcp.local_addr().unwrap(), original_addr);
        // Adopted entry was removed from the map.
        assert!(!inherited.contains_key("admin"));
    }

    // -----------------------------------------------------------
    // FDP-T3 — spawn_successor
    // -----------------------------------------------------------

    /// Spawn a /bin/sh under the FDP-T3 plan, capturing stdout
    /// for assertion. Pulled out so each test stays focused on
    /// what it's asserting.
    fn run_sh_and_capture(plan: SuccessorPlan) -> (std::process::ExitStatus, String) {
        let mut cmd = build_successor_command(plan);
        cmd.stdout(std::process::Stdio::piped());
        cmd.stderr(std::process::Stdio::piped());
        let child = cmd.spawn().expect("spawn");
        let output = child.wait_with_output().expect("wait");
        let stdout = String::from_utf8(output.stdout).unwrap();
        (output.status, stdout)
    }

    #[test]
    fn spawn_successor_env_carries_listen_fd_count_and_names() {
        // Spawn /bin/sh to print the env vars we set, capture
        // stdout, assert the contract. We plumb one real
        // listener so the FD-placement path is exercised too.
        let bound = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        bound.set_nonblocking(true).unwrap();
        let raw_fd = bound.as_raw_fd();

        let plan = SuccessorPlan {
            binary_path: std::path::PathBuf::from("/bin/sh"),
            listeners: vec![("admin".to_string(), raw_fd)],
            extra_env: vec![],
            args: vec![
                "-c".to_string(),
                "printf '%s\\n%s\\n' \"$AEGIS_LISTEN_FDS\" \"$AEGIS_LISTEN_FD_NAMES\"".to_string(),
            ],
        };
        let (status, stdout) = run_sh_and_capture(plan);
        assert!(status.success(), "sh exited non-zero");
        let lines: Vec<&str> = stdout.trim_end().split('\n').collect();
        assert_eq!(lines.len(), 2, "expected 2 lines, got: {stdout:?}");
        assert_eq!(lines[0], "1", "AEGIS_LISTEN_FDS should be 1");
        assert_eq!(lines[1], "admin", "AEGIS_LISTEN_FD_NAMES should be 'admin'");

        drop(bound);
    }

    #[test]
    fn spawn_successor_with_two_listeners_sets_comma_separated_names() {
        let l1 = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let l2 = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l1.set_nonblocking(true).unwrap();
        l2.set_nonblocking(true).unwrap();

        let plan = SuccessorPlan {
            binary_path: std::path::PathBuf::from("/bin/sh"),
            listeners: vec![
                ("admin".to_string(), l1.as_raw_fd()),
                ("data-0".to_string(), l2.as_raw_fd()),
            ],
            extra_env: vec![],
            args: vec![
                "-c".to_string(),
                "echo \"$AEGIS_LISTEN_FDS|$AEGIS_LISTEN_FD_NAMES\"".to_string(),
            ],
        };
        let (status, stdout) = run_sh_and_capture(plan);
        assert!(status.success());
        assert_eq!(
            stdout.trim_end(),
            "2|admin,data-0",
            "got: {stdout:?}",
        );

        drop(l1);
        drop(l2);
    }

    #[test]
    fn spawn_successor_passes_extra_env_through() {
        let plan = SuccessorPlan {
            binary_path: std::path::PathBuf::from("/bin/sh"),
            listeners: vec![],
            extra_env: vec![("AEGIS_TEST_KEY".into(), "test-value-42".into())],
            args: vec!["-c".into(), "echo \"$AEGIS_TEST_KEY\"".into()],
        };
        let (status, stdout) = run_sh_and_capture(plan);
        assert!(status.success());
        assert_eq!(stdout.trim_end(), "test-value-42");
    }

    #[test]
    fn spawn_successor_places_fd_at_slot_3() {
        // Bind a listener, spawn /bin/sh, have it inspect
        // /dev/fd/3 to prove the FD landed at slot 3. Verifies:
        // dup2(src_fd, 3) ran in the post-fork closure, AND
        // FD_CLOEXEC was cleared so the FD survived exec.
        // Without the CLOEXEC clear the slot would be empty.
        let bound = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        bound.set_nonblocking(true).unwrap();

        let plan = SuccessorPlan {
            binary_path: std::path::PathBuf::from("/bin/sh"),
            listeners: vec![("admin".into(), bound.as_raw_fd())],
            extra_env: vec![],
            args: vec![
                "-c".into(),
                "if [ -e /dev/fd/3 ]; then echo HAVE_FD3; else echo NO_FD3; fi".into(),
            ],
        };
        let (status, stdout) = run_sh_and_capture(plan);
        assert!(status.success(), "shell exited non-zero");
        assert!(
            stdout.contains("HAVE_FD3"),
            "expected /dev/fd/3 to exist in child, got: {stdout:?}",
        );

        drop(bound);
    }

    #[tokio::test]
    async fn adopt_or_bind_leaves_unrelated_entries_alone() {
        let bound1 = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let bound2 = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        bound1.set_nonblocking(true).unwrap();
        bound2.set_nonblocking(true).unwrap();
        let bound2_addr = bound2.local_addr().unwrap();

        let mut inherited = std::collections::HashMap::new();
        inherited.insert("admin".into(), bound1);
        inherited.insert("data-0".into(), bound2);

        let _ = adopt_or_bind(&mut inherited, "admin", "127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        // data-0 still present.
        assert!(inherited.contains_key("data-0"));
        let data = adopt_or_bind(&mut inherited, "data-0", "127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        assert_eq!(data.local_addr().unwrap(), bound2_addr);
    }
}
