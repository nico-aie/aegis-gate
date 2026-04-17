pub struct CacheKey {
    pub method: String,
    pub host: String,
    pub path: String,
    pub vary_headers: Vec<(String, String)>,
}

pub struct CachedResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: bytes::Bytes,
}

#[async_trait::async_trait]
pub trait CacheProvider: Send + Sync + 'static {
    async fn get(&self, key: &CacheKey) -> Option<CachedResponse>;
    async fn put(
        &self,
        key: CacheKey,
        resp: CachedResponse,
        ttl: std::time::Duration,
    );
    async fn invalidate(&self, key: &CacheKey);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cache_key_fields() {
        let k = CacheKey {
            method: "GET".into(),
            host: "example.com".into(),
            path: "/api/users".into(),
            vary_headers: vec![("accept".into(), "application/json".into())],
        };
        assert_eq!(k.method, "GET");
        assert_eq!(k.vary_headers.len(), 1);
    }

    #[test]
    fn cached_response_fields() {
        let r = CachedResponse {
            status: 200,
            headers: vec![("content-type".into(), "text/html".into())],
            body: bytes::Bytes::from_static(b"hello"),
        };
        assert_eq!(r.status, 200);
        assert_eq!(r.body, &b"hello"[..]);
    }
}
