use std::collections::HashMap;

/// JWT validation configuration.
#[derive(Clone, Debug)]
pub struct JwtConfig {
    pub issuer: Option<String>,
    pub audience: Option<String>,
    pub leeway_s: u64,
}

/// JWT validation result.
#[derive(Clone, Debug)]
pub struct JwtClaims {
    pub sub: Option<String>,
    pub iss: Option<String>,
    pub aud: Option<String>,
    pub exp: Option<u64>,
    pub iat: Option<u64>,
    pub custom: HashMap<String, String>,
}

/// JWT validation error.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum JwtError {
    Malformed,
    Expired,
    WrongIssuer,
    WrongAudience,
    InvalidSignature,
    MissingClaim(String),
}

/// Decode and validate a JWT token (stub).
///
/// In production, use `jsonwebtoken` crate with JWKS.
/// This stub parses the base64 payload for testing.
pub fn validate(token: &str, config: &JwtConfig, now: u64) -> Result<JwtClaims, JwtError> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(JwtError::Malformed);
    }

    // Decode payload (part 1).
    let payload = base64_decode(parts[1]).map_err(|_| JwtError::Malformed)?;
    let claims: serde_json::Value = serde_json::from_slice(&payload).map_err(|_| JwtError::Malformed)?;

    let sub = claims.get("sub").and_then(|v| v.as_str()).map(String::from);
    let iss = claims.get("iss").and_then(|v| v.as_str()).map(String::from);
    let aud = claims.get("aud").and_then(|v| v.as_str()).map(String::from);
    let exp = claims.get("exp").and_then(|v| v.as_u64());
    let iat = claims.get("iat").and_then(|v| v.as_u64());

    // Validate issuer.
    if let Some(expected_iss) = &config.issuer {
        match &iss {
            Some(i) if i == expected_iss => {}
            _ => return Err(JwtError::WrongIssuer),
        }
    }

    // Validate audience.
    if let Some(expected_aud) = &config.audience {
        match &aud {
            Some(a) if a == expected_aud => {}
            _ => return Err(JwtError::WrongAudience),
        }
    }

    // Validate expiration.
    if let Some(exp_time) = exp {
        if now > exp_time + config.leeway_s {
            return Err(JwtError::Expired);
        }
    }

    // Collect custom claims.
    let mut custom = HashMap::new();
    if let Some(obj) = claims.as_object() {
        for (k, v) in obj {
            if !["sub", "iss", "aud", "exp", "iat", "nbf", "jti"].contains(&k.as_str()) {
                if let Some(s) = v.as_str() {
                    custom.insert(k.clone(), s.to_string());
                }
            }
        }
    }

    Ok(JwtClaims { sub, iss, aud, exp, iat, custom })
}

fn base64_decode(input: &str) -> Result<Vec<u8>, ()> {
    // Simple base64url decoder.
    let padded = match input.len() % 4 {
        2 => format!("{input}=="),
        3 => format!("{input}="),
        _ => input.to_string(),
    };
    let standard = padded.replace('-', "+").replace('_', "/");

    // Manual base64 decode.
    let mut result = Vec::new();
    let chars: Vec<u8> = standard.bytes().collect();
    let mut i = 0;
    while i < chars.len() {
        let a = b64_val(chars[i]).ok_or(())?;
        let b = b64_val(chars[i + 1]).ok_or(())?;
        result.push((a << 2) | (b >> 4));
        if chars.get(i + 2) != Some(&b'=') {
            let c = b64_val(chars[i + 2]).ok_or(())?;
            result.push(((b & 0xF) << 4) | (c >> 2));
            if chars.get(i + 3) != Some(&b'=') {
                let d = b64_val(chars[i + 3]).ok_or(())?;
                result.push(((c & 0x3) << 6) | d);
            }
        }
        i += 4;
    }
    Ok(result)
}

fn b64_val(c: u8) -> Option<u8> {
    match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a' + 26),
        b'0'..=b'9' => Some(c - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_token(payload_json: &str) -> String {
        let header = base64_encode(b"{\"alg\":\"HS256\"}");
        let payload = base64_encode(payload_json.as_bytes());
        format!("{header}.{payload}.fake_signature")
    }

    fn base64_encode(data: &[u8]) -> String {
        const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let mut result = String::new();
        for chunk in data.chunks(3) {
            let b0 = chunk[0] as u32;
            let b1 = chunk.get(1).copied().unwrap_or(0) as u32;
            let b2 = chunk.get(2).copied().unwrap_or(0) as u32;
            let triple = (b0 << 16) | (b1 << 8) | b2;
            result.push(CHARS[((triple >> 18) & 0x3F) as usize] as char);
            result.push(CHARS[((triple >> 12) & 0x3F) as usize] as char);
            if chunk.len() > 1 {
                result.push(CHARS[((triple >> 6) & 0x3F) as usize] as char);
            }
            if chunk.len() > 2 {
                result.push(CHARS[(triple & 0x3F) as usize] as char);
            }
        }
        result
    }

    fn default_config() -> JwtConfig {
        JwtConfig {
            issuer: Some("https://auth.example.com".into()),
            audience: Some("my-app".into()),
            leeway_s: 30,
        }
    }

    #[test]
    fn valid_token() {
        let token = make_token(r#"{"sub":"user-1","iss":"https://auth.example.com","aud":"my-app","exp":2000000000,"iat":1700000000,"role":"admin"}"#);
        let result = validate(&token, &default_config(), 1700000100);
        assert!(result.is_ok());
        let claims = result.unwrap();
        assert_eq!(claims.sub.as_deref(), Some("user-1"));
        assert_eq!(claims.custom.get("role").map(|s| s.as_str()), Some("admin"));
    }

    #[test]
    fn expired_token() {
        let token = make_token(r#"{"sub":"user-1","iss":"https://auth.example.com","aud":"my-app","exp":1600000000}"#);
        let result = validate(&token, &default_config(), 1700000000);
        assert_eq!(result.unwrap_err(), JwtError::Expired);
    }

    #[test]
    fn wrong_issuer() {
        let token = make_token(r#"{"sub":"user-1","iss":"https://evil.com","aud":"my-app","exp":2000000000}"#);
        let result = validate(&token, &default_config(), 1700000000);
        assert_eq!(result.unwrap_err(), JwtError::WrongIssuer);
    }

    #[test]
    fn wrong_audience() {
        let token = make_token(r#"{"sub":"user-1","iss":"https://auth.example.com","aud":"other-app","exp":2000000000}"#);
        let result = validate(&token, &default_config(), 1700000000);
        assert_eq!(result.unwrap_err(), JwtError::WrongAudience);
    }

    #[test]
    fn malformed_token() {
        let result = validate("not.a.valid.token", &default_config(), 1700000000);
        assert!(result.is_err());
    }

    #[test]
    fn missing_parts() {
        let result = validate("only_one_part", &default_config(), 1700000000);
        assert_eq!(result.unwrap_err(), JwtError::Malformed);
    }

    #[test]
    fn leeway_allows_slightly_expired() {
        let token = make_token(r#"{"sub":"user-1","iss":"https://auth.example.com","aud":"my-app","exp":1700000000}"#);
        // 20 seconds past expiry but within 30s leeway.
        let result = validate(&token, &default_config(), 1700000020);
        assert!(result.is_ok());
    }

    #[test]
    fn no_issuer_check_when_none() {
        let config = JwtConfig { issuer: None, audience: None, leeway_s: 0 };
        let token = make_token(r#"{"sub":"user-1","exp":2000000000}"#);
        let result = validate(&token, &config, 1700000000);
        assert!(result.is_ok());
    }
}
