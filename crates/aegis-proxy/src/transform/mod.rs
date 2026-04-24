pub mod vars;
pub mod cors;

pub use cors::{CorsConfig, handle_preflight, apply_cors_headers};
pub use vars::expand_variables;
