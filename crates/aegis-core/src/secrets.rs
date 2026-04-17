use crate::error::Result;

#[derive(Clone)]
pub struct Secret(pub zeroize::Zeroizing<Vec<u8>>);

impl Secret {
    pub fn new(data: Vec<u8>) -> Self {
        Self(zeroize::Zeroizing::new(data))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secret([REDACTED])")
    }
}

#[async_trait::async_trait]
pub trait SecretProvider: Send + Sync + 'static {
    async fn resolve(&self, reference: &str) -> Result<Secret>;
    fn watch(
        &self,
        reference: &str,
    ) -> futures::stream::BoxStream<'static, Secret>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_new_and_access() {
        let s = Secret::new(b"my-password".to_vec());
        assert_eq!(s.as_bytes(), b"my-password");
    }

    #[test]
    fn secret_debug_redacted() {
        let s = Secret::new(b"sensitive".to_vec());
        let debug = format!("{:?}", s);
        assert_eq!(debug, "Secret([REDACTED])");
        assert!(!debug.contains("sensitive"));
    }

    #[test]
    fn secret_clone() {
        let s1 = Secret::new(b"key".to_vec());
        let s2 = s1.clone();
        assert_eq!(s1.as_bytes(), s2.as_bytes());
    }
}
