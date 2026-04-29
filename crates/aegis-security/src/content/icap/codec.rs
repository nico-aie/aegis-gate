//! RFC 3507 ICAP wire-format helpers.
//!
//! Every helper here is pure — string in, string out — so the
//! TCP client in [`super::tcp`] is reduced to a thin I/O
//! wrapper and every framing edge case can be unit-tested
//! without sockets.

use super::IcapMode;

/// Embedded HTTP request used inside `REQMOD` requests.
///
/// We send a single canonical "GET / HTTP/1.1" with the
/// configured upstream Host so the scanner has the metadata
/// it expects. Most production AV/DLP servers don't actually
/// inspect this — they care about the body — but RFC 3507
/// requires *something* coherent in the encapsulated
/// req-hdr section.
pub fn embedded_request_for_reqmod(host: &str) -> String {
    format!("GET / HTTP/1.1\r\nHost: {host}\r\n\r\n")
}

/// Embedded HTTP response used inside `RESPMOD` requests.
///
/// We use a minimal `200 OK` because the scanner cares about
/// `Content-Type` and the body — not the request that
/// produced the response.
pub fn embedded_response_for_respmod(content_type: &str) -> String {
    format!(
        "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\n\r\n"
    )
}

/// Compose the full wire request, returning the bytes ready
/// to write to the socket.
///
/// `service_path` is the scanner's service URI segment — for
/// c-icap that's `avscan` (REQMOD) or `respmod` (RESPMOD);
/// for Symantec it's `SYMCScanResp-AV` (RESPMOD) etc.
pub fn build_request(
    mode: &IcapMode,
    host: &str,
    port: u16,
    service_path: &str,
    upstream_host: &str,
    body: &[u8],
) -> Vec<u8> {
    let method = match mode {
        IcapMode::Reqmod => "REQMOD",
        IcapMode::Respmod => "RESPMOD",
    };
    let embedded = match mode {
        IcapMode::Reqmod => embedded_request_for_reqmod(upstream_host),
        IcapMode::Respmod => embedded_response_for_respmod("application/octet-stream"),
    };
    let embedded_bytes = embedded.as_bytes();
    let hdr_offset = 0;
    let body_offset = embedded_bytes.len();
    // RFC 3507 names the offsets "req-hdr" / "req-body" for
    // REQMOD and "res-hdr" / "res-body" for RESPMOD.
    let (hdr_label, body_label) = match mode {
        IcapMode::Reqmod => ("req-hdr", "req-body"),
        IcapMode::Respmod => ("res-hdr", "res-body"),
    };
    let path = trim_leading_slash(service_path);
    let request_line = format!(
        "{method} icap://{host}:{port}/{path} ICAP/1.0\r\n"
    );
    let host_header = format!("Host: {host}:{port}\r\n");
    let allow_header = "Allow: 204\r\n";
    let encapsulated = format!(
        "Encapsulated: {hdr_label}={hdr_offset}, {body_label}={body_offset}\r\n"
    );
    let mut out = Vec::with_capacity(
        request_line.len()
            + host_header.len()
            + allow_header.len()
            + encapsulated.len()
            + 2
            + embedded_bytes.len()
            + body.len()
            + 16,
    );
    out.extend_from_slice(request_line.as_bytes());
    out.extend_from_slice(host_header.as_bytes());
    out.extend_from_slice(allow_header.as_bytes());
    out.extend_from_slice(encapsulated.as_bytes());
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(embedded_bytes);
    // Encode the body as a single chunk + zero terminator.
    if !body.is_empty() {
        out.extend_from_slice(format!("{:x}\r\n", body.len()).as_bytes());
        out.extend_from_slice(body);
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"0\r\n\r\n");
    out
}

fn trim_leading_slash(s: &str) -> &str {
    s.trim_start_matches('/')
}

/// Decoded ICAP response head — status line + headers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IcapResponseHead {
    pub status: u16,
    pub reason: String,
    pub headers: Vec<(String, String)>,
}

impl IcapResponseHead {
    /// Find a header by case-insensitive name.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// Errors when decoding an ICAP response head.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    /// Could not find `\r\n\r\n` end-of-headers within the
    /// allowed buffer.
    HeadIncomplete,
    /// Status line malformed.
    BadStatusLine(String),
    /// Header line missing `:` separator.
    BadHeader(String),
    /// Status line had no recognisable code.
    BadStatusCode(String),
    /// Status line was not ICAP.
    NotIcap(String),
}

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DecodeError::HeadIncomplete => write!(f, "icap response head incomplete"),
            DecodeError::BadStatusLine(s) => write!(f, "bad status line: {s:?}"),
            DecodeError::BadHeader(s) => write!(f, "bad header line: {s:?}"),
            DecodeError::BadStatusCode(s) => write!(f, "bad status code: {s:?}"),
            DecodeError::NotIcap(s) => write!(f, "not an ICAP response: {s:?}"),
        }
    }
}

impl std::error::Error for DecodeError {}

/// Try to decode the head from a buffer. Returns the decoded
/// head and the offset where the body section begins (always
/// just past `\r\n\r\n`). The caller may have already read
/// more bytes — we don't touch them.
pub fn decode_head(buf: &[u8]) -> Result<(IcapResponseHead, usize), DecodeError> {
    let end = find_double_crlf(buf).ok_or(DecodeError::HeadIncomplete)?;
    let head_str = std::str::from_utf8(&buf[..end])
        .map_err(|e| DecodeError::BadStatusLine(format!("not UTF-8: {e}")))?;
    let mut lines = head_str.split("\r\n");
    let status_line = lines
        .next()
        .ok_or_else(|| DecodeError::BadStatusLine("empty".into()))?;
    let (status, reason) = parse_status_line(status_line)?;
    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| DecodeError::BadHeader(line.to_string()))?;
        headers.push((name.trim().to_string(), value.trim().to_string()));
    }
    Ok((
        IcapResponseHead {
            status,
            reason,
            headers,
        },
        end + 4,
    ))
}

fn find_double_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

fn parse_status_line(line: &str) -> Result<(u16, String), DecodeError> {
    let mut parts = line.splitn(3, ' ');
    let proto = parts
        .next()
        .ok_or_else(|| DecodeError::BadStatusLine(line.to_string()))?;
    if !proto.starts_with("ICAP/") {
        return Err(DecodeError::NotIcap(proto.to_string()));
    }
    let code_str = parts
        .next()
        .ok_or_else(|| DecodeError::BadStatusLine(line.to_string()))?;
    let status: u16 = code_str
        .parse()
        .map_err(|_| DecodeError::BadStatusCode(code_str.to_string()))?;
    let reason = parts.next().unwrap_or("").to_string();
    Ok((status, reason))
}

/// Verdict returned by [`classify_response`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Clean,
    Infected { threat_name: String },
    UnexpectedStatus { status: u16 },
}

/// Map a decoded ICAP head to a high-level verdict.
///
/// Decision table (de-facto across c-icap / Symantec /
/// Sophos / McAfee — they all converge on `X-Infection-Found`
/// or `X-Virus-ID`):
///
/// - **204 No Content** → Clean (no modification needed)
/// - **200 OK** + `X-Infection-Found` or `X-Virus-ID`
///   → Infected (with the threat name from the header)
/// - **200 OK** without infection header → Clean
///   (scanner returned a possibly-modified body but didn't
///   flag a threat — the reasonable default is to treat as
///   clean; operators wanting strict mode can post-filter)
/// - **403 Forbidden** → Infected (Sophos returns this on
///   block; threat name is "blocked" if no header)
/// - anything else → UnexpectedStatus
pub fn classify_response(head: &IcapResponseHead) -> Verdict {
    if head.status == 204 {
        return Verdict::Clean;
    }
    if let Some(name) = infection_header(head) {
        return Verdict::Infected {
            threat_name: name.to_string(),
        };
    }
    if head.status == 200 {
        return Verdict::Clean;
    }
    if head.status == 403 {
        return Verdict::Infected {
            threat_name: "blocked".to_string(),
        };
    }
    Verdict::UnexpectedStatus {
        status: head.status,
    }
}

fn infection_header(head: &IcapResponseHead) -> Option<&str> {
    // RFC has no standard header for this; vendors converge
    // on these three. Try them in popularity order.
    head.header("X-Infection-Found")
        .or_else(|| head.header("X-Virus-ID"))
        .or_else(|| head.header("X-Violations-Found"))
        .map(extract_threat_name)
}

/// `X-Infection-Found` looks like
/// `Type=0; Resolution=2; Threat=EICAR-Test-File;` —
/// extract the `Threat=` value, falling back to the raw
/// value if unstructured.
fn extract_threat_name(raw: &str) -> &str {
    for part in raw.split(';') {
        let part = part.trim();
        if let Some(rest) = part.strip_prefix("Threat=") {
            return rest.trim();
        }
    }
    raw.trim()
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- Embedded HTTP framing ----

    #[test]
    fn embedded_reqmod_includes_host() {
        let s = embedded_request_for_reqmod("api.example.com");
        assert!(s.starts_with("GET / HTTP/1.1\r\n"));
        assert!(s.contains("Host: api.example.com\r\n"));
        assert!(s.ends_with("\r\n\r\n"));
    }

    #[test]
    fn embedded_respmod_includes_content_type() {
        let s = embedded_response_for_respmod("application/pdf");
        assert!(s.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(s.contains("Content-Type: application/pdf\r\n"));
    }

    // ---- build_request ----

    #[test]
    fn build_reqmod_request_has_correct_request_line() {
        let req = build_request(
            &IcapMode::Reqmod,
            "scanner",
            1344,
            "/avscan",
            "api.example.com",
            b"hello",
        );
        let s = std::str::from_utf8(&req).unwrap();
        assert!(s.starts_with("REQMOD icap://scanner:1344/avscan ICAP/1.0\r\n"));
    }

    #[test]
    fn build_respmod_request_uses_respmod_method() {
        let req = build_request(
            &IcapMode::Respmod,
            "scanner",
            1344,
            "/respmod",
            "api.example.com",
            b"hello",
        );
        let s = std::str::from_utf8(&req).unwrap();
        assert!(s.starts_with("RESPMOD "));
        assert!(s.contains("res-hdr=0"));
        assert!(s.contains("res-body="));
    }

    #[test]
    fn build_request_includes_host_and_allow_headers() {
        let req = build_request(
            &IcapMode::Reqmod,
            "scanner",
            1344,
            "/avscan",
            "api.example.com",
            b"hello",
        );
        let s = std::str::from_utf8(&req).unwrap();
        assert!(s.contains("Host: scanner:1344\r\n"));
        assert!(s.contains("Allow: 204\r\n"));
    }

    #[test]
    fn build_request_uses_chunked_body_terminator() {
        let req = build_request(
            &IcapMode::Reqmod,
            "scanner",
            1344,
            "/avscan",
            "api.example.com",
            b"hi",
        );
        let s = std::str::from_utf8(&req).unwrap();
        // Chunk size 2 = "2\r\nhi\r\n", then the zero terminator.
        assert!(s.ends_with("2\r\nhi\r\n0\r\n\r\n"));
    }

    #[test]
    fn build_request_with_empty_body_uses_zero_terminator_only() {
        let req = build_request(
            &IcapMode::Reqmod,
            "scanner",
            1344,
            "/avscan",
            "api.example.com",
            b"",
        );
        let s = std::str::from_utf8(&req).unwrap();
        assert!(s.ends_with("0\r\n\r\n"));
        // No chunk-size hex line precedes the terminator.
        assert!(!s.contains("0\r\nhi"));
    }

    #[test]
    fn build_request_strips_leading_slash_from_service_path() {
        let req = build_request(
            &IcapMode::Reqmod,
            "scanner",
            1344,
            "/avscan",
            "x",
            b"",
        );
        let s = std::str::from_utf8(&req).unwrap();
        assert!(s.starts_with("REQMOD icap://scanner:1344/avscan"));
    }

    #[test]
    fn build_request_handles_no_leading_slash() {
        let req = build_request(
            &IcapMode::Reqmod,
            "scanner",
            1344,
            "avscan",
            "x",
            b"",
        );
        let s = std::str::from_utf8(&req).unwrap();
        assert!(s.starts_with("REQMOD icap://scanner:1344/avscan"));
    }

    #[test]
    fn build_request_encapsulated_offsets_match_embedded_size() {
        let req = build_request(
            &IcapMode::Reqmod,
            "scanner",
            1344,
            "/avscan",
            "h",
            b"x",
        );
        let s = std::str::from_utf8(&req).unwrap();
        // Embedded `GET / HTTP/1.1\r\nHost: h\r\n\r\n` is 27
        // bytes, so req-body offset must equal 27.
        let embedded = embedded_request_for_reqmod("h");
        let expected = format!("req-body={}", embedded.len());
        assert!(
            s.contains(&expected),
            "expected {expected:?} in {s:?}"
        );
    }

    // ---- decode_head ----

    #[test]
    fn decode_204_no_content() {
        let raw = b"ICAP/1.0 204 No Content\r\nISTag: \"abc\"\r\n\r\n";
        let (head, body_off) = decode_head(raw).unwrap();
        assert_eq!(head.status, 204);
        assert_eq!(head.reason, "No Content");
        assert_eq!(body_off, raw.len());
        assert_eq!(head.header("ISTag"), Some("\"abc\""));
    }

    #[test]
    fn decode_200_with_infection_header() {
        let raw = b"ICAP/1.0 200 OK\r\nX-Infection-Found: Type=0; Resolution=2; Threat=EICAR-Test-File;\r\n\r\n";
        let (head, _) = decode_head(raw).unwrap();
        assert_eq!(head.status, 200);
        assert_eq!(
            head.header("x-infection-found"),
            Some("Type=0; Resolution=2; Threat=EICAR-Test-File;")
        );
    }

    #[test]
    fn decode_incomplete_head_errors() {
        let err = decode_head(b"ICAP/1.0 200 OK\r\nFoo: bar\r\n").unwrap_err();
        assert_eq!(err, DecodeError::HeadIncomplete);
    }

    #[test]
    fn decode_non_icap_protocol_errors() {
        let err = decode_head(b"HTTP/1.1 200 OK\r\n\r\n").unwrap_err();
        assert!(matches!(err, DecodeError::NotIcap(_)));
    }

    #[test]
    fn decode_bad_status_code_errors() {
        let err = decode_head(b"ICAP/1.0 NOTANUM Bad\r\n\r\n").unwrap_err();
        assert!(matches!(err, DecodeError::BadStatusCode(_)));
    }

    #[test]
    fn decode_bad_header_errors() {
        let err = decode_head(b"ICAP/1.0 200 OK\r\nNoColonHere\r\n\r\n").unwrap_err();
        assert!(matches!(err, DecodeError::BadHeader(_)));
    }

    #[test]
    fn decode_header_lookup_is_case_insensitive() {
        let raw = b"ICAP/1.0 200 OK\r\nX-Virus-ID: NastyOne\r\n\r\n";
        let (head, _) = decode_head(raw).unwrap();
        assert_eq!(head.header("x-virus-id"), Some("NastyOne"));
        assert_eq!(head.header("X-VIRUS-ID"), Some("NastyOne"));
    }

    // ---- classify_response ----

    fn head(status: u16, headers: &[(&str, &str)]) -> IcapResponseHead {
        IcapResponseHead {
            status,
            reason: "".into(),
            headers: headers
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        }
    }

    #[test]
    fn classify_204_is_clean() {
        assert_eq!(classify_response(&head(204, &[])), Verdict::Clean);
    }

    #[test]
    fn classify_200_without_infection_header_is_clean() {
        assert_eq!(classify_response(&head(200, &[])), Verdict::Clean);
    }

    #[test]
    fn classify_200_with_x_infection_found_threat_extracted() {
        let v = classify_response(&head(
            200,
            &[("X-Infection-Found", "Type=0; Resolution=2; Threat=EICAR-Test-File;")],
        ));
        assert_eq!(
            v,
            Verdict::Infected {
                threat_name: "EICAR-Test-File".into()
            }
        );
    }

    #[test]
    fn classify_200_with_x_virus_id_uses_raw_value() {
        // X-Virus-ID is unstructured — fall through to raw.
        let v = classify_response(&head(200, &[("X-Virus-ID", "Win.Trojan.Foo")]));
        assert_eq!(
            v,
            Verdict::Infected {
                threat_name: "Win.Trojan.Foo".into()
            }
        );
    }

    #[test]
    fn classify_200_with_violations_found_uses_raw_value() {
        let v = classify_response(&head(200, &[("X-Violations-Found", "1")]));
        assert_eq!(
            v,
            Verdict::Infected {
                threat_name: "1".into()
            }
        );
    }

    #[test]
    fn classify_403_is_blocked() {
        assert_eq!(
            classify_response(&head(403, &[])),
            Verdict::Infected {
                threat_name: "blocked".into()
            }
        );
    }

    #[test]
    fn classify_500_is_unexpected() {
        assert_eq!(
            classify_response(&head(500, &[])),
            Verdict::UnexpectedStatus { status: 500 }
        );
    }

    #[test]
    fn classify_204_wins_over_infection_header() {
        // Defensive: a 204 means the scanner is saying "no
        // change needed", which we treat as Clean even if a
        // header is present (servers don't actually send
        // both, but the contract should be unambiguous).
        let v = classify_response(&head(204, &[("X-Infection-Found", "x")]));
        assert_eq!(v, Verdict::Clean);
    }
}
