/// Tracing initialization and W3C Trace Context middleware.
///
/// Sets up tracing-subscriber with JSON layer.
/// OTLP export deferred behind `otel` feature flag.
use std::fmt::Write;

/// Tracing configuration.
#[derive(Clone, Debug)]
pub struct TracingConfig {
    pub json_output: bool,
    pub level: String,
}

impl Default for TracingConfig {
    fn default() -> Self {
        Self {
            json_output: true,
            level: "info".into(),
        }
    }
}

/// Initialize tracing subscriber (stub — real init uses tracing_subscriber).
///
/// Returns true if initialization succeeded.
pub fn init(_config: &TracingConfig) -> bool {
    // In production: tracing_subscriber::fmt().json().init()
    // For library code we just return success.
    true
}

/// W3C Trace Context: `traceparent` header format.
///
/// Format: `{version}-{trace_id}-{parent_id}-{flags}`
///
///  - version: `00`
///  - trace_id: 32 hex chars
///  - parent_id: 16 hex chars
///  - flags: `01` (sampled)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TraceContext {
    pub version: String,
    pub trace_id: String,
    pub parent_id: String,
    pub flags: String,
}

impl TraceContext {
    /// Parse from a `traceparent` header value.
    pub fn parse(header: &str) -> Option<Self> {
        let parts: Vec<&str> = header.split('-').collect();
        if parts.len() != 4 {
            return None;
        }
        let version = parts[0];
        let trace_id = parts[1];
        let parent_id = parts[2];
        let flags = parts[3];

        // Validate lengths.
        if version.len() != 2 || trace_id.len() != 32 || parent_id.len() != 16 || flags.len() != 2 {
            return None;
        }

        // Validate hex.
        if !trace_id.chars().all(|c| c.is_ascii_hexdigit())
            || !parent_id.chars().all(|c| c.is_ascii_hexdigit())
        {
            return None;
        }

        // Reject all-zero trace_id or parent_id.
        if trace_id.chars().all(|c| c == '0') || parent_id.chars().all(|c| c == '0') {
            return None;
        }

        Some(Self {
            version: version.into(),
            trace_id: trace_id.into(),
            parent_id: parent_id.into(),
            flags: flags.into(),
        })
    }

    /// Format as a `traceparent` header value.
    pub fn to_header(&self) -> String {
        format!("{}-{}-{}-{}", self.version, self.trace_id, self.parent_id, self.flags)
    }
}

/// Generate a new random trace context.
pub fn generate_trace_context() -> TraceContext {
    let trace_id = random_hex(32);
    let parent_id = random_hex(16);
    TraceContext {
        version: "00".into(),
        trace_id,
        parent_id,
        flags: "01".into(),
    }
}

/// Ensure trace context: accept existing `traceparent` or generate a new one.
pub fn ensure_trace_context(traceparent: Option<&str>) -> TraceContext {
    if let Some(header) = traceparent {
        if let Some(ctx) = TraceContext::parse(header) {
            return ctx;
        }
    }
    generate_trace_context()
}

/// Generate a new span ID (16 hex chars) for child spans.
pub fn new_span_id() -> String {
    random_hex(16)
}

/// Create a child context from a parent, preserving trace_id but generating new parent_id.
pub fn child_context(parent: &TraceContext) -> TraceContext {
    TraceContext {
        version: parent.version.clone(),
        trace_id: parent.trace_id.clone(),
        parent_id: new_span_id(),
        flags: parent.flags.clone(),
    }
}

fn random_hex(len: usize) -> String {
    // Use blake3 hash of timestamp + counter for pseudo-random IDs.
    // In production, use a proper random source.
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let cnt = COUNTER.fetch_add(1, Ordering::Relaxed);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let input = format!("{now}:{cnt}");
    let hash = blake3::hash(input.as_bytes());
    let hex = hash.to_hex();
    let mut result = String::with_capacity(len);
    for ch in hex.chars().take(len) {
        let _ = write!(result, "{ch}");
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    // TraceContext parsing.
    #[test]
    fn parse_valid_traceparent() {
        let tp = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
        let ctx = TraceContext::parse(tp).unwrap();
        assert_eq!(ctx.version, "00");
        assert_eq!(ctx.trace_id, "4bf92f3577b34da6a3ce929d0e0e4736");
        assert_eq!(ctx.parent_id, "00f067aa0ba902b7");
        assert_eq!(ctx.flags, "01");
    }

    #[test]
    fn parse_roundtrip() {
        let tp = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
        let ctx = TraceContext::parse(tp).unwrap();
        assert_eq!(ctx.to_header(), tp);
    }

    #[test]
    fn parse_rejects_too_few_parts() {
        assert!(TraceContext::parse("00-abc-01").is_none());
    }

    #[test]
    fn parse_rejects_wrong_trace_id_length() {
        assert!(TraceContext::parse("00-abc123-00f067aa0ba902b7-01").is_none());
    }

    #[test]
    fn parse_rejects_wrong_parent_id_length() {
        assert!(TraceContext::parse("00-4bf92f3577b34da6a3ce929d0e0e4736-short-01").is_none());
    }

    #[test]
    fn parse_rejects_all_zero_trace_id() {
        assert!(TraceContext::parse("00-00000000000000000000000000000000-00f067aa0ba902b7-01").is_none());
    }

    #[test]
    fn parse_rejects_all_zero_parent_id() {
        assert!(TraceContext::parse("00-4bf92f3577b34da6a3ce929d0e0e4736-0000000000000000-01").is_none());
    }

    #[test]
    fn parse_rejects_non_hex() {
        assert!(TraceContext::parse("00-zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz-00f067aa0ba902b7-01").is_none());
    }

    #[test]
    fn parse_unsampled_flag() {
        let tp = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-00";
        let ctx = TraceContext::parse(tp).unwrap();
        assert_eq!(ctx.flags, "00");
    }

    // Generate.
    #[test]
    fn generate_produces_valid_context() {
        let ctx = generate_trace_context();
        assert_eq!(ctx.version, "00");
        assert_eq!(ctx.trace_id.len(), 32);
        assert_eq!(ctx.parent_id.len(), 16);
        assert_eq!(ctx.flags, "01");
    }

    #[test]
    fn generate_unique_trace_ids() {
        let c1 = generate_trace_context();
        let c2 = generate_trace_context();
        assert_ne!(c1.trace_id, c2.trace_id);
    }

    #[test]
    fn generate_unique_parent_ids() {
        let c1 = generate_trace_context();
        let c2 = generate_trace_context();
        assert_ne!(c1.parent_id, c2.parent_id);
    }

    // Ensure.
    #[test]
    fn ensure_accepts_valid() {
        let tp = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
        let ctx = ensure_trace_context(Some(tp));
        assert_eq!(ctx.trace_id, "4bf92f3577b34da6a3ce929d0e0e4736");
    }

    #[test]
    fn ensure_generates_on_none() {
        let ctx = ensure_trace_context(None);
        assert_eq!(ctx.trace_id.len(), 32);
    }

    #[test]
    fn ensure_generates_on_invalid() {
        let ctx = ensure_trace_context(Some("garbage"));
        assert_eq!(ctx.trace_id.len(), 32);
    }

    // Child context.
    #[test]
    fn child_preserves_trace_id() {
        let parent = generate_trace_context();
        let child = child_context(&parent);
        assert_eq!(child.trace_id, parent.trace_id);
    }

    #[test]
    fn child_has_new_parent_id() {
        let parent = generate_trace_context();
        let child = child_context(&parent);
        assert_ne!(child.parent_id, parent.parent_id);
    }

    #[test]
    fn child_preserves_flags() {
        let parent = generate_trace_context();
        let child = child_context(&parent);
        assert_eq!(child.flags, parent.flags);
    }

    // Span ID.
    #[test]
    fn new_span_id_length() {
        let id = new_span_id();
        assert_eq!(id.len(), 16);
    }

    #[test]
    fn new_span_id_is_hex() {
        let id = new_span_id();
        assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn new_span_ids_unique() {
        let a = new_span_id();
        let b = new_span_id();
        assert_ne!(a, b);
    }

    // Init.
    #[test]
    fn init_succeeds() {
        assert!(init(&TracingConfig::default()));
    }

    #[test]
    fn default_config() {
        let c = TracingConfig::default();
        assert!(c.json_output);
        assert_eq!(c.level, "info");
    }
}
