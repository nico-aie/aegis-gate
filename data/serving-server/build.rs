fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Compile proto → tonic generated code into OUT_DIR.
    // 2026-05-23 (staging-local) — use the vendored protoc (the
    // `protoc-bin-vendored` build-dep already declared in Cargo.toml)
    // so the build needs no system protobuf-compiler, matching the WAF's
    // crates/aegis-security/build.rs. Without this the build errored
    // "Could not find `protoc`" on this host.
    std::env::set_var(
        "PROTOC",
        protoc_bin_vendored::protoc_bin_path().expect("vendored protoc binary"),
    );
    tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .compile_protos(&["proto/aegis_infer.proto"], &["proto"])?;
    Ok(())
}
