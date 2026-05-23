//! Build script — compiles the `aegis-infer` gRPC proto into a tonic
//! CLIENT, but ONLY when the `ai-remote` feature is enabled. For every
//! other build (the default WAF build) this is a no-op, so the extra
//! `tonic`/`prost` codegen cost is paid only by `ai-remote` builds.

fn main() {
    // Cargo exports `CARGO_FEATURE_<NAME>` for each enabled feature.
    if std::env::var_os("CARGO_FEATURE_AI_REMOTE").is_none() {
        return;
    }

    // Vendored protoc — the build needs no system protobuf-compiler
    // (macOS dev + Linux staging out of the box). Mirrors the serving
    // server's build.rs so both sides compile the same way.
    std::env::set_var(
        "PROTOC",
        protoc_bin_vendored::protoc_bin_path().expect("vendored protoc binary"),
    );

    println!("cargo:rerun-if-changed=proto/aegis_infer.proto");
    tonic_build::configure()
        .build_server(false) // WAF is a client only
        .build_client(true)
        .compile_protos(&["proto/aegis_infer.proto"], &["proto"])
        .expect("failed to compile proto/aegis_infer.proto");
}
