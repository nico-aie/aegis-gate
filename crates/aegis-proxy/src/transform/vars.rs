use hyper::header::HeaderMap;
use std::collections::HashMap;

/// Context available for variable expansion.
pub struct VarContext<'a> {
    pub host: &'a str,
    pub client_ip: &'a str,
    pub request_id: &'a str,
    pub headers: &'a HeaderMap,
    pub jwt_claims: Option<&'a HashMap<String, String>>,
    pub cookies: Option<&'a HashMap<String, String>>,
}

/// Expand `$host`, `$client_ip`, `$request_id`, `$jwt.<claim>`,
/// `$cookie.<name>`, `$header.<name>` in the given template string.
pub fn expand_variables(template: &str, ctx: &VarContext<'_>) -> String {
    let mut result = String::with_capacity(template.len());
    let mut chars = template.chars().peekable();

    while let Some(ch) = chars.next() {
        if ch == '$' {
            let mut var_name = String::new();
            while let Some(&c) = chars.peek() {
                if c.is_alphanumeric() || c == '_' || c == '.' || c == '-' {
                    var_name.push(c);
                    chars.next();
                } else {
                    break;
                }
            }
            result.push_str(&resolve_var(&var_name, ctx));
        } else {
            result.push(ch);
        }
    }

    result
}

fn resolve_var(name: &str, ctx: &VarContext<'_>) -> String {
    match name {
        "host" => ctx.host.to_string(),
        "client_ip" => ctx.client_ip.to_string(),
        "request_id" => ctx.request_id.to_string(),
        _ if name.starts_with("jwt.") => {
            let claim = &name[4..];
            ctx.jwt_claims
                .and_then(|m| m.get(claim))
                .cloned()
                .unwrap_or_default()
        }
        _ if name.starts_with("cookie.") => {
            let cookie_name = &name[7..];
            ctx.cookies
                .and_then(|m| m.get(cookie_name))
                .cloned()
                .unwrap_or_default()
        }
        _ if name.starts_with("header.") => {
            let header_name = &name[7..];
            ctx.headers
                .get(header_name)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_string()
        }
        _ => format!("${name}"), // Unknown variable — pass through.
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::header::{HeaderMap, HeaderValue};

    fn base_ctx() -> (HeaderMap, HashMap<String, String>, HashMap<String, String>) {
        let mut headers = HeaderMap::new();
        headers.insert("x-custom", HeaderValue::from_static("custom-val"));

        let mut jwt = HashMap::new();
        jwt.insert("sub".into(), "user-123".into());
        jwt.insert("role".into(), "admin".into());

        let mut cookies = HashMap::new();
        cookies.insert("session".into(), "abc".into());

        (headers, jwt, cookies)
    }

    #[test]
    fn expand_host() {
        let (headers, jwt, cookies) = base_ctx();
        let ctx = VarContext {
            host: "example.com",
            client_ip: "1.2.3.4",
            request_id: "req-1",
            headers: &headers,
            jwt_claims: Some(&jwt),
            cookies: Some(&cookies),
        };
        assert_eq!(expand_variables("Host: $host", &ctx), "Host: example.com");
    }

    #[test]
    fn expand_client_ip() {
        let (headers, _, _) = base_ctx();
        let ctx = VarContext {
            host: "h",
            client_ip: "10.0.0.1",
            request_id: "r",
            headers: &headers,
            jwt_claims: None,
            cookies: None,
        };
        assert_eq!(expand_variables("ip=$client_ip", &ctx), "ip=10.0.0.1");
    }

    #[test]
    fn expand_jwt_claim() {
        let (headers, jwt, _) = base_ctx();
        let ctx = VarContext {
            host: "h",
            client_ip: "ip",
            request_id: "r",
            headers: &headers,
            jwt_claims: Some(&jwt),
            cookies: None,
        };
        assert_eq!(expand_variables("sub=$jwt.sub", &ctx), "sub=user-123");
    }

    #[test]
    fn expand_cookie() {
        let (headers, _, cookies) = base_ctx();
        let ctx = VarContext {
            host: "h",
            client_ip: "ip",
            request_id: "r",
            headers: &headers,
            jwt_claims: None,
            cookies: Some(&cookies),
        };
        assert_eq!(
            expand_variables("sid=$cookie.session", &ctx),
            "sid=abc"
        );
    }

    #[test]
    fn expand_header() {
        let (headers, _, _) = base_ctx();
        let ctx = VarContext {
            host: "h",
            client_ip: "ip",
            request_id: "r",
            headers: &headers,
            jwt_claims: None,
            cookies: None,
        };
        assert_eq!(
            expand_variables("val=$header.x-custom", &ctx),
            "val=custom-val"
        );
    }

    #[test]
    fn unknown_variable_passed_through() {
        let (headers, _, _) = base_ctx();
        let ctx = VarContext {
            host: "h",
            client_ip: "ip",
            request_id: "r",
            headers: &headers,
            jwt_claims: None,
            cookies: None,
        };
        assert_eq!(expand_variables("$unknown_var", &ctx), "$unknown_var");
    }

    #[test]
    fn multiple_variables() {
        let (headers, jwt, cookies) = base_ctx();
        let ctx = VarContext {
            host: "api.example.com",
            client_ip: "192.168.1.1",
            request_id: "req-42",
            headers: &headers,
            jwt_claims: Some(&jwt),
            cookies: Some(&cookies),
        };
        let tpl = "$host - $client_ip - $request_id - $jwt.sub - $cookie.session";
        assert_eq!(
            expand_variables(tpl, &ctx),
            "api.example.com - 192.168.1.1 - req-42 - user-123 - abc"
        );
    }

    #[test]
    fn no_variables() {
        let (headers, _, _) = base_ctx();
        let ctx = VarContext {
            host: "h",
            client_ip: "ip",
            request_id: "r",
            headers: &headers,
            jwt_claims: None,
            cookies: None,
        };
        assert_eq!(expand_variables("no vars here", &ctx), "no vars here");
    }
}
