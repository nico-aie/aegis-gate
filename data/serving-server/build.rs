fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Compile proto → tonic generated code into OUT_DIR.
    // Requires `protoc` (protobuf compiler) to be on PATH.
    // macOS: brew install protobuf
    // Ubuntu: apt install -y protobuf-compiler
    tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .compile_protos(&["proto/aegis_infer.proto"], &["proto"])?;
    Ok(())
}
