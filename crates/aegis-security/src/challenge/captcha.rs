use std::net::IpAddr;

/// CAPTCHA provider trait.
#[async_trait::async_trait]
pub trait CaptchaProvider: Send + Sync {
    fn id(&self) -> &'static str;
    async fn verify(&self, client_token: &str, ip: IpAddr) -> aegis_core::Result<bool>;
}

/// Cloudflare Turnstile provider.
pub struct Turnstile {
    pub secret_key: String,
    pub site_url: String,
}

#[async_trait::async_trait]
impl CaptchaProvider for Turnstile {
    fn id(&self) -> &'static str {
        "turnstile"
    }

    async fn verify(&self, client_token: &str, ip: IpAddr) -> aegis_core::Result<bool> {
        // In production: POST to https://challenges.cloudflare.com/turnstile/v0/siteverify
        // Body: secret={secret}&response={client_token}&remoteip={ip}
        let _ = (&self.secret_key, &self.site_url, client_token, ip);
        tracing::debug!(provider = "turnstile", "verifying CAPTCHA token");
        // Stub: always returns Ok(true) until HTTP client is wired.
        Ok(true)
    }
}

/// hCaptcha provider.
pub struct HCaptcha {
    pub secret_key: String,
}

#[async_trait::async_trait]
impl CaptchaProvider for HCaptcha {
    fn id(&self) -> &'static str {
        "hcaptcha"
    }

    async fn verify(&self, client_token: &str, ip: IpAddr) -> aegis_core::Result<bool> {
        // In production: POST to https://hcaptcha.com/siteverify
        let _ = (&self.secret_key, client_token, ip);
        tracing::debug!(provider = "hcaptcha", "verifying CAPTCHA token");
        Ok(true)
    }
}

/// Google reCAPTCHA v3 provider.
pub struct ReCaptchaV3 {
    pub secret_key: String,
    pub min_score: f64,
}

#[async_trait::async_trait]
impl CaptchaProvider for ReCaptchaV3 {
    fn id(&self) -> &'static str {
        "recaptcha_v3"
    }

    async fn verify(&self, client_token: &str, ip: IpAddr) -> aegis_core::Result<bool> {
        // In production: POST to https://www.google.com/recaptcha/api/siteverify
        let _ = (&self.secret_key, &self.min_score, client_token, ip);
        tracing::debug!(provider = "recaptcha_v3", "verifying CAPTCHA token");
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn turnstile_stub_verifies() {
        let p = Turnstile {
            secret_key: "test-secret".into(),
            site_url: "https://example.com".into(),
        };
        let result = p.verify("token-abc", "1.2.3.4".parse().unwrap()).await.unwrap();
        assert!(result);
        assert_eq!(p.id(), "turnstile");
    }

    #[tokio::test]
    async fn hcaptcha_stub_verifies() {
        let p = HCaptcha {
            secret_key: "test-secret".into(),
        };
        let result = p.verify("token-abc", "1.2.3.4".parse().unwrap()).await.unwrap();
        assert!(result);
        assert_eq!(p.id(), "hcaptcha");
    }

    #[tokio::test]
    async fn recaptcha_stub_verifies() {
        let p = ReCaptchaV3 {
            secret_key: "test-secret".into(),
            min_score: 0.5,
        };
        let result = p.verify("token-abc", "1.2.3.4".parse().unwrap()).await.unwrap();
        assert!(result);
        assert_eq!(p.id(), "recaptcha_v3");
    }

    #[test]
    fn providers_are_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Turnstile>();
        assert_send_sync::<HCaptcha>();
        assert_send_sync::<ReCaptchaV3>();
    }
}
