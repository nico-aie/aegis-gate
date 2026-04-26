pub mod graphql;
pub mod hmac_sign;
pub mod api_keys;

use std::collections::HashMap;

/// OpenAPI enforcement mode.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EnforcementMode {
    Enforce,
    Monitor,
    Learn,
}

/// A simplified OpenAPI operation.
#[derive(Clone, Debug)]
pub struct ApiOperation {
    pub path: String,
    pub method: String,
    pub parameters: Vec<ApiParam>,
    pub required_headers: Vec<String>,
    pub allowed_body_fields: Option<Vec<String>>,
}

/// API parameter definition.
#[derive(Clone, Debug)]
pub struct ApiParam {
    pub name: String,
    pub location: ParamLocation,
    pub required: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ParamLocation {
    Query,
    Header,
    Path,
}

/// OpenAPI schema validator.
pub struct SchemaValidator {
    pub mode: EnforcementMode,
    operations: HashMap<String, ApiOperation>,
}

/// Validation error.
#[derive(Clone, Debug)]
pub struct ValidationError {
    pub path: String,
    pub message: String,
}

impl SchemaValidator {
    pub fn new(mode: EnforcementMode) -> Self {
        Self {
            mode,
            operations: HashMap::new(),
        }
    }

    /// Register an operation.
    pub fn add_operation(&mut self, op: ApiOperation) {
        let key = format!("{}:{}", op.method.to_uppercase(), op.path);
        self.operations.insert(key, op);
    }

    /// Validate a request against the schema.
    pub fn validate(
        &self,
        method: &str,
        path: &str,
        query_params: &HashMap<String, String>,
        headers: &HashMap<String, String>,
        body_fields: Option<&[String]>,
    ) -> Vec<ValidationError> {
        let key = format!("{}:{}", method.to_uppercase(), path);

        let op = match self.operations.get(&key) {
            Some(op) => op,
            None => {
                if self.mode == EnforcementMode::Learn {
                    return vec![];
                }
                return vec![ValidationError {
                    path: path.into(),
                    message: format!("unknown endpoint: {method} {path}"),
                }];
            }
        };

        let mut errors = Vec::new();

        // Check required parameters.
        for param in &op.parameters {
            if param.required {
                let present = match param.location {
                    ParamLocation::Query => query_params.contains_key(&param.name),
                    ParamLocation::Header => headers.contains_key(&param.name.to_lowercase()),
                    ParamLocation::Path => true, // Assume path params are always present if route matched.
                };
                if !present {
                    errors.push(ValidationError {
                        path: format!("/{}", param.name),
                        message: format!("missing required parameter: {}", param.name),
                    });
                }
            }
        }

        // Check required headers.
        for h in &op.required_headers {
            if !headers.contains_key(&h.to_lowercase()) {
                errors.push(ValidationError {
                    path: format!("/headers/{h}"),
                    message: format!("missing required header: {h}"),
                });
            }
        }

        // Check body fields (mass-assignment protection).
        if let (Some(allowed), Some(actual)) = (&op.allowed_body_fields, body_fields) {
            for field in actual {
                if !allowed.contains(field) {
                    errors.push(ValidationError {
                        path: format!("/body/{field}"),
                        message: format!("unknown body field: {field}"),
                    });
                }
            }
        }

        errors
    }

    pub fn operation_count(&self) -> usize {
        self.operations.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup_validator() -> SchemaValidator {
        let mut v = SchemaValidator::new(EnforcementMode::Enforce);
        v.add_operation(ApiOperation {
            path: "/api/users".into(),
            method: "POST".into(),
            parameters: vec![
                ApiParam { name: "content-type".into(), location: ParamLocation::Header, required: true },
            ],
            required_headers: vec!["content-type".into()],
            allowed_body_fields: Some(vec!["name".into(), "email".into()]),
        });
        v.add_operation(ApiOperation {
            path: "/api/users".into(),
            method: "GET".into(),
            parameters: vec![
                ApiParam { name: "page".into(), location: ParamLocation::Query, required: false },
            ],
            required_headers: vec![],
            allowed_body_fields: None,
        });
        v
    }

    #[test]
    fn valid_post_accepted() {
        let v = setup_validator();
        let headers: HashMap<String, String> = [("content-type".into(), "application/json".into())].into();
        let errors = v.validate("POST", "/api/users", &HashMap::new(), &headers, Some(&["name".into(), "email".into()]));
        assert!(errors.is_empty());
    }

    #[test]
    fn unknown_body_field_rejected() {
        let v = setup_validator();
        let headers: HashMap<String, String> = [("content-type".into(), "application/json".into())].into();
        let errors = v.validate("POST", "/api/users", &HashMap::new(), &headers, Some(&["name".into(), "is_admin".into()]));
        assert!(!errors.is_empty());
        assert!(errors.iter().any(|e| e.message.contains("is_admin")));
    }

    #[test]
    fn missing_required_header() {
        let v = setup_validator();
        let errors = v.validate("POST", "/api/users", &HashMap::new(), &HashMap::new(), Some(&["name".into()]));
        assert!(errors.iter().any(|e| e.message.contains("content-type")));
    }

    #[test]
    fn unknown_endpoint_rejected() {
        let v = setup_validator();
        let errors = v.validate("DELETE", "/api/admin", &HashMap::new(), &HashMap::new(), None);
        assert!(errors.iter().any(|e| e.message.contains("unknown endpoint")));
    }

    #[test]
    fn learn_mode_allows_unknown() {
        let v = SchemaValidator::new(EnforcementMode::Learn);
        let errors = v.validate("DELETE", "/api/admin", &HashMap::new(), &HashMap::new(), None);
        assert!(errors.is_empty());
    }

    #[test]
    fn valid_get_accepted() {
        let v = setup_validator();
        let query: HashMap<String, String> = [("page".into(), "1".into())].into();
        let errors = v.validate("GET", "/api/users", &query, &HashMap::new(), None);
        assert!(errors.is_empty());
    }

    #[test]
    fn operation_count() {
        let v = setup_validator();
        assert_eq!(v.operation_count(), 2);
    }
}
