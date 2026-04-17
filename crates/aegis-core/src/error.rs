#[derive(Debug, thiserror::Error)]
pub enum WafError {
    #[error("config: {0}")]
    Config(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("state backend: {0}")]
    State(String),
    #[error("rule: {0}")]
    Rule(String),
    #[error("other: {0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, WafError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_error_displays_message() {
        let e = WafError::Config("invalid route".into());
        assert_eq!(e.to_string(), "config: invalid route");
    }

    #[test]
    fn io_error_converts_from_std() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file missing");
        let waf_err: WafError = io_err.into();
        assert!(waf_err.to_string().contains("file missing"));
    }

    #[test]
    fn state_error_displays_message() {
        let e = WafError::State("redis timeout".into());
        assert_eq!(e.to_string(), "state backend: redis timeout");
    }

    #[test]
    fn rule_error_displays_message() {
        let e = WafError::Rule("invalid regex".into());
        assert_eq!(e.to_string(), "rule: invalid regex");
    }

    #[test]
    fn result_type_alias_works() {
        let ok: Result<i32> = Ok(42);
        assert_eq!(ok.unwrap(), 42);

        let err: Result<i32> = Err(WafError::Other("boom".into()));
        assert!(err.is_err());
    }
}
