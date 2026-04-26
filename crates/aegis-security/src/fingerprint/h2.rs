/// HTTP/2 fingerprint from SETTINGS frame and pseudo-header order.
///
/// The fingerprint is a stable string derived from:
///   - SETTINGS frame parameters (HEADER_TABLE_SIZE, MAX_CONCURRENT_STREAMS, etc.)
///   - Pseudo-header order (:method, :authority, :scheme, :path)
///   - WINDOW_UPDATE initial value
///
/// HTTP/2 SETTINGS parameters.
#[derive(Clone, Debug, Default)]
pub struct H2Settings {
    pub header_table_size: Option<u32>,
    pub enable_push: Option<u32>,
    pub max_concurrent_streams: Option<u32>,
    pub initial_window_size: Option<u32>,
    pub max_frame_size: Option<u32>,
    pub max_header_list_size: Option<u32>,
    pub window_update: Option<u32>,
}

/// Compute H2 fingerprint string.
pub fn compute(settings: &H2Settings, pseudo_header_order: &[&str]) -> String {
    let mut parts = Vec::new();

    // Encode SETTINGS in a deterministic order.
    if let Some(v) = settings.header_table_size {
        parts.push(format!("1:{v}"));
    }
    if let Some(v) = settings.enable_push {
        parts.push(format!("2:{v}"));
    }
    if let Some(v) = settings.max_concurrent_streams {
        parts.push(format!("3:{v}"));
    }
    if let Some(v) = settings.initial_window_size {
        parts.push(format!("4:{v}"));
    }
    if let Some(v) = settings.max_frame_size {
        parts.push(format!("5:{v}"));
    }
    if let Some(v) = settings.max_header_list_size {
        parts.push(format!("6:{v}"));
    }

    let settings_str = parts.join(";");

    // Pseudo-header order as a joined string.
    let pho = pseudo_header_order.join(",");

    // Window update.
    let wu = settings.window_update.map_or("0".to_string(), |v| v.to_string());

    format!("{settings_str}|{pho}|{wu}")
}

/// Compute a hashed H2 fingerprint.
pub fn compute_hash(settings: &H2Settings, pseudo_header_order: &[&str]) -> String {
    let raw = compute(settings, pseudo_header_order);
    blake3::hash(raw.as_bytes()).to_hex()[..16].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chrome_settings() -> H2Settings {
        H2Settings {
            header_table_size: Some(65536),
            enable_push: Some(0),
            max_concurrent_streams: Some(1000),
            initial_window_size: Some(6291456),
            max_frame_size: Some(16384),
            max_header_list_size: None,
            window_update: Some(15663105),
        }
    }

    fn chrome_pho() -> Vec<&'static str> {
        vec![":method", ":authority", ":scheme", ":path"]
    }

    fn tonic_settings() -> H2Settings {
        H2Settings {
            header_table_size: Some(4096),
            enable_push: Some(0),
            max_concurrent_streams: None,
            initial_window_size: Some(65535),
            max_frame_size: Some(16384),
            max_header_list_size: None,
            window_update: Some(65535),
        }
    }

    fn tonic_pho() -> Vec<&'static str> {
        vec![":method", ":scheme", ":path", ":authority"]
    }

    fn firefox_settings() -> H2Settings {
        H2Settings {
            header_table_size: Some(65536),
            enable_push: Some(0),
            max_concurrent_streams: Some(100),
            initial_window_size: Some(131072),
            max_frame_size: Some(16384),
            max_header_list_size: Some(65536),
            window_update: Some(12517377),
        }
    }

    fn firefox_pho() -> Vec<&'static str> {
        vec![":method", ":path", ":authority", ":scheme"]
    }

    #[test]
    fn h2_deterministic() {
        let s = chrome_settings();
        let pho = chrome_pho();
        let a = compute(&s, &pho);
        let b = compute(&s, &pho);
        assert_eq!(a, b);
    }

    #[test]
    fn h2_chrome_vs_tonic_differ() {
        let a = compute(&chrome_settings(), &chrome_pho());
        let b = compute(&tonic_settings(), &tonic_pho());
        assert_ne!(a, b);
    }

    #[test]
    fn h2_chrome_vs_firefox_differ() {
        let a = compute(&chrome_settings(), &chrome_pho());
        let b = compute(&firefox_settings(), &firefox_pho());
        assert_ne!(a, b);
    }

    #[test]
    fn h2_hash_length() {
        let h = compute_hash(&chrome_settings(), &chrome_pho());
        assert_eq!(h.len(), 16);
    }

    #[test]
    fn h2_pseudo_header_order_matters() {
        let s = chrome_settings();
        let a = compute(&s, &[":method", ":authority", ":scheme", ":path"]);
        let b = compute(&s, &[":method", ":scheme", ":path", ":authority"]);
        assert_ne!(a, b);
    }

    #[test]
    fn h2_window_update_matters() {
        let mut s1 = chrome_settings();
        let mut s2 = chrome_settings();
        s1.window_update = Some(100);
        s2.window_update = Some(200);
        let pho = chrome_pho();
        assert_ne!(compute(&s1, &pho), compute(&s2, &pho));
    }
}
