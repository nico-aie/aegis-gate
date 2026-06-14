//! Response-mode classification for the data plane (SSE plan, decisions
//! 2 + 2a).
//!
//! A response is classified **exactly once**, in `forward()`, the moment
//! the upstream response headers arrive: its media type is matched
//! against a config allowlist to decide [`ResponseMode::Streaming`] vs
//! [`ResponseMode::Buffered`]. The result then rides the `DecisionTag` to
//! every later consumer (filter/cache bypass, audit, metrics) — those
//! sites read the carried mode and never re-parse `Content-Type`, which
//! is what prevents the classification from drifting between phases.
//!
//! Media-type matching is a proper parse, not a `starts_with`: SSE is
//! sent as both `text/event-stream` and `text/event-stream;
//! charset=utf-8`, so we compare only the `type/subtype` essence
//! (parameters and surrounding whitespace stripped, ASCII-lowercased).

/// Whether a response is buffered (today's behaviour: size-capped,
/// body-inspected) or streamed through incrementally.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseMode {
    /// Buffered to a size cap, response body inspected (the default).
    Buffered,
    /// Streamed through frame-by-frame; response body is **not** buffered
    /// or body-inspected (header-inspected only — see plan decision 3).
    Streaming,
}

impl ResponseMode {
    pub fn is_streaming(self) -> bool {
        matches!(self, ResponseMode::Streaming)
    }
}

/// Extract the `type/subtype` essence of a `Content-Type` value:
/// everything before the first `;`, trimmed and ASCII-lowercased.
/// `None` when the value carries no media type.
fn media_type_essence(content_type: &str) -> Option<String> {
    let essence = content_type.split(';').next()?.trim();
    if essence.is_empty() {
        return None;
    }
    Some(essence.to_ascii_lowercase())
}

/// Classify a response from its `Content-Type` against the streaming
/// allowlist. Returns [`ResponseMode::Streaming`] only when the media-type
/// essence matches an allowlist entry (case-insensitively); everything
/// else — including a missing `Content-Type` or an empty allowlist —
/// buffers. This is the single source of the streaming decision
/// (plan decision 2a); call it exactly once, in `forward()`.
pub fn classify_response_mode(content_type: Option<&str>, allowlist: &[String]) -> ResponseMode {
    let Some(essence) = content_type.and_then(media_type_essence) else {
        return ResponseMode::Buffered;
    };
    if allowlist.iter().any(|a| a.trim().eq_ignore_ascii_case(&essence)) {
        ResponseMode::Streaming
    } else {
        ResponseMode::Buffered
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn allow() -> Vec<String> {
        vec!["text/event-stream".to_string()]
    }

    #[test]
    fn bare_event_stream_streams() {
        assert_eq!(
            classify_response_mode(Some("text/event-stream"), &allow()),
            ResponseMode::Streaming,
        );
    }

    #[test]
    fn event_stream_with_charset_param_streams() {
        assert_eq!(
            classify_response_mode(Some("text/event-stream; charset=utf-8"), &allow()),
            ResponseMode::Streaming,
        );
        // No space after the semicolon either.
        assert_eq!(
            classify_response_mode(Some("text/event-stream;charset=utf-8"), &allow()),
            ResponseMode::Streaming,
        );
    }

    #[test]
    fn matching_is_case_insensitive_and_trims() {
        assert_eq!(
            classify_response_mode(Some("Text/Event-Stream"), &allow()),
            ResponseMode::Streaming,
        );
        assert_eq!(
            classify_response_mode(Some("  text/event-stream  "), &allow()),
            ResponseMode::Streaming,
        );
    }

    #[test]
    fn non_allowlisted_types_buffer() {
        assert_eq!(
            classify_response_mode(Some("text/html"), &allow()),
            ResponseMode::Buffered,
        );
        assert_eq!(
            classify_response_mode(Some("application/json"), &allow()),
            ResponseMode::Buffered,
        );
        // `text/event-streamx` must NOT match (essence compare, not prefix).
        assert_eq!(
            classify_response_mode(Some("text/event-streamx"), &allow()),
            ResponseMode::Buffered,
        );
    }

    #[test]
    fn missing_content_type_buffers() {
        assert_eq!(
            classify_response_mode(None, &allow()),
            ResponseMode::Buffered,
        );
    }

    #[test]
    fn empty_allowlist_never_streams() {
        let empty: Vec<String> = Vec::new();
        assert_eq!(
            classify_response_mode(Some("text/event-stream"), &empty),
            ResponseMode::Buffered,
        );
    }
}
