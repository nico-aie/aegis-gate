# Tích hợp `aegis-infer` vào Aegis-Gate WAF

## Tổng quan

`aegis-infer` là một **gRPC batch inference server** tách biệt khỏi WAF process.
Thay vì WAF tự load ONNX model và chạy inference đồng bộ mỗi request (~700µs/req,
serialised qua `Mutex<Session>`), WAF gửi feature vector 27-float đến serving server
qua gRPC, server gom batch trong ≤2ms rồi chạy `[N×27]` tensor một lần.

```
Trước (in-process, serialised):
  Request → extract_features → Mutex<OrtSession>.run([1,27]) → Signal
                                       ↑ bottleneck tại 2k RPS

Sau (external batch server):
  Request → extract_features → gRPC send → BatchAccumulator → OrtSession.run([N,27])
                                                                         ↑ 10k+ RPS
```

---

## Điểm tích hợp trong codebase hiện tại

### Luồng hiện tại

```
aegis-proxy / data_plane.rs
  └─ detectors::run_all_filtered_timed(detectors, mask, req, record)
       ├─ sqli, xss, path_traversal, … (sync, ~10–50µs each)
       └─ AiDetector::inspect(req)          ← chỉ chạy khi không có Base detector fire
            └─ features::extract_features(request_str)
            └─ Model::predict(&feats)        ← Mutex lock → OrtSession::run([1,27])
```

`Detector` trait hiện là **sync**:
```rust
// crates/aegis-security/src/detectors/mod.rs
pub trait Detector: Send + Sync {
    fn id(&self) -> &'static str;
    fn inspect(&self, req: &RequestView<'_>) -> Vec<Signal>;   // ← sync
}
```

### Chiến lược tích hợp

Có 2 cách, tuỳ mức độ thay đổi bạn muốn:

| | Option A — Drop-in replacement | Option B — Async pre-classify |
|---|---|---|
| Thay đổi | Chỉ `aegis-security` | `aegis-security` + `aegis-proxy/data_plane` |
| Breaking change | Không | Có (trait thay đổi) |
| Latency | +gRPC RTT (blocked) | Không tăng (parallel) |
| Khuyến nghị | **Bắt đầu với cái này** | Sau khi đã ổn định |

---

## Option A — Drop-in `RemoteAiDetector` (khuyến nghị bắt đầu)

Tạo `RemoteAiDetector` implement cùng `Detector` trait, dùng
`tokio::task::block_in_place` để gọi async gRPC từ sync context.

### 1. Thêm dependency vào `crates/aegis-security/Cargo.toml`

```toml
[features]
# Hiện có:
ai = ["dep:ort", "dep:ndarray"]

# Thêm:
ai-remote = ["dep:tonic", "dep:prost"]

[dependencies]
# Thêm (optional, chỉ khi ai-remote feature):
tonic = { workspace = true, optional = true }
prost = { workspace = true, optional = true }
```

Thêm vào `Cargo.toml` workspace root:
```toml
tonic = { version = "0.12", features = ["transport"] }
prost = "0.13"
```

### 2. Tạo proto client wrapper

Tạo file `crates/aegis-security/src/detectors/ai/remote.rs`:

```rust
//! gRPC client wrapper cho aegis-infer serving server.

use std::sync::Arc;
use std::time::Duration;

use tonic::transport::Channel;

// Proto generated code — copy proto/aegis_infer.proto vào
// crates/aegis-security/proto/ và khai báo trong build.rs
mod proto {
    tonic::include_proto!("aegis.infer.v1");
}
use proto::{aegis_infer_client::AegisInferClient, ClassifyRequest};

use super::{features::extract_features, Detector, Signal};
use aegis_core::pipeline::RequestView;

/// Aegis-infer remote detector.
///
/// Implements the same `Detector` trait as `AiDetector` (in-process).
/// Drop-in replacement — swap in `default_detectors_with()` builder.
///
/// ## Failure mode
/// Inference errors → no signal (fail-open), identical to in-process.
pub struct RemoteAiDetector {
    /// Thread-safe tonic channel — cheap to clone, multiplexed H2.
    client: Arc<tokio::sync::Mutex<AegisInferClient<Channel>>>,
    threshold: f32,
    score: u32,
}

impl RemoteAiDetector {
    /// Connect to serving server via TCP (host:port).
    pub async fn connect_tcp(addr: &str, threshold: f32) -> Result<Self, tonic::transport::Error> {
        let endpoint = tonic::transport::Endpoint::from_shared(
            format!("http://{addr}")
        )?
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_millis(50)); // WAF latency budget

        let channel = endpoint.connect().await?;
        Ok(Self::from_channel(channel, threshold))
    }

    /// Connect via Unix Domain Socket (same-host, lower latency).
    pub async fn connect_uds(path: &str, threshold: f32) -> Result<Self, tonic::transport::Error> {
        use hyper_util::rt::TokioIo;
        use tokio::net::UnixStream;
        use tower::service_fn;

        let path = path.to_string();
        let channel = tonic::transport::Endpoint::from_static("http://[::]:0")
            .connect_with_connector(service_fn(move |_| {
                let p = path.clone();
                async move {
                    Ok::<_, std::io::Error>(TokioIo::new(UnixStream::connect(p).await?))
                }
            }))
            .await?;

        Ok(Self::from_channel(channel, threshold))
    }

    fn from_channel(channel: Channel, threshold: f32) -> Self {
        Self {
            client: Arc::new(tokio::sync::Mutex::new(
                AegisInferClient::new(channel)
            )),
            threshold,
            score: crate::detectors::scores::ai::AI, // reuse same score weight
        }
    }
}

impl Detector for RemoteAiDetector {
    fn id(&self) -> &'static str { "ai" }

    fn inspect(&self, req: &RequestView<'_>) -> Vec<Signal> {
        // Extract features locally (same as in-process AiDetector).
        // Cost: ~0.1ms — identical to before, no network cost here.
        let request_str = build_request_string(req);
        let features = extract_features(&request_str);

        // gRPC call: block the current OS thread via block_in_place
        // so Tokio scheduler can run other tasks on other threads.
        // Latency: gRPC RTT (~0.05ms UDS / ~0.3ms TCP) + queue wait
        // (≤delay_ms=2ms) + inference time.
        let client = Arc::clone(&self.client);
        let threshold = self.threshold;
        let score = self.score;

        tokio::task::block_in_place(|| {
            let handle = tokio::runtime::Handle::current();
            handle.block_on(async move {
                let req = ClassifyRequest {
                    request_id: String::new(),
                    features: features.to_vec(),
                    raw_request: String::new(),
                };

                let mut c = client.lock().await;
                match c.classify(req).await {
                    Ok(resp) => {
                        let r = resp.into_inner();
                        if r.prob_attack >= threshold {
                            vec![Signal {
                                score,
                                tag: "ai".into(),
                                field: "request".into(),
                            }]
                        } else {
                            vec![]
                        }
                    }
                    Err(e) => {
                        // Fail-open: log and continue.
                        tracing::trace!(
                            error = %e,
                            "remote ai inference error — fail-open"
                        );
                        vec![]
                    }
                }
            })
        })
    }
}

/// Same as `AiDetector::build_request_string` — must stay in sync
/// with the format the model was trained on.
fn build_request_string(req: &RequestView<'_>) -> String {
    let pq = req.uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");
    let body = req.body.peek(4096);

    let mut out = String::with_capacity(64 + body.len());
    out.push_str(req.method.as_str());
    out.push(' ');
    out.push_str(pq);
    if !body.is_empty() {
        out.push(' ');
        out.push_str(&String::from_utf8_lossy(body));
    }
    for hdr in ["user-agent", "cookie", "referer"] {
        if let Some(v) = req.headers.get(hdr).and_then(|v| v.to_str().ok()) {
            out.push('\n');
            let canonical = match hdr {
                "user-agent" => "User-Agent",
                "cookie"     => "Cookie",
                _            => "Referer",
            };
            out.push_str(canonical);
            out.push_str(": ");
            out.push_str(v);
        }
    }
    out
}
```

### 3. Thêm `RemoteAiDetector` vào `default_detectors_with_canary`

Sửa `crates/aegis-security/src/detectors/mod.rs`:

```rust
/// Config mở rộng cho remote AI inference.
pub struct RemoteAiConfig {
    /// "tcp://127.0.0.1:50051" hoặc "unix:///tmp/aegis-infer.sock"
    pub endpoint: String,
    pub threshold: f32,
}

pub async fn build_remote_ai_detector(
    cfg: &RemoteAiConfig,
) -> Result<Box<dyn Detector>, Box<dyn std::error::Error>> {
    let detector = if cfg.endpoint.starts_with("unix://") {
        let path = cfg.endpoint.trim_start_matches("unix://");
        ai::remote::RemoteAiDetector::connect_uds(path, cfg.threshold).await?
    } else {
        let addr = cfg.endpoint.trim_start_matches("tcp://");
        ai::remote::RemoteAiDetector::connect_tcp(addr, cfg.threshold).await?
    };
    Ok(Box::new(detector))
}
```

### 4. Wire vào `aegis-proxy/src/run.rs`

Tìm đoạn khởi tạo `AiDetector` (khoảng `cfg.ai.enabled`) và thay bằng:

```rust
// Trước:
#[cfg(feature = "ai")]
if cfg.ai.enabled {
    let model = AiDetector::load(&cfg.ai.model_path, ...)?;
    detectors.push(Box::new(model));
}

// Sau:
if let Some(ref remote_cfg) = cfg.ai.remote_endpoint {
    // Dùng serving server nếu được config
    let detector = aegis_security::detectors::build_remote_ai_detector(
        &RemoteAiConfig {
            endpoint: remote_cfg.clone(),
            threshold: cfg.ai.threshold,
        }
    ).await?;
    detectors.push(detector);
} else {
    // Fallback: in-process ONNX (hiện tại)
    #[cfg(feature = "ai")]
    if cfg.ai.enabled {
        let model = AiDetector::load(&cfg.ai.model_path, ...)?;
        detectors.push(Box::new(model));
    }
}
```

### 5. Thêm config vào `aegis-core/src/config.rs`

```rust
#[derive(Debug, Clone, Deserialize, Default)]
pub struct AiConfig {
    pub enabled: bool,
    pub model_path: String,
    pub threshold: f32,

    /// Nếu set, dùng remote serving server thay vì in-process ONNX.
    /// Format: "tcp://host:port" hoặc "unix:///path/to/socket"
    /// Ví dụ: "unix:///tmp/aegis-infer.sock"
    #[serde(default)]
    pub remote_endpoint: Option<String>,
}
```

Trong `config/dev.yaml`:
```yaml
ai:
  enabled: true
  threshold: 0.5
  # Uncomment để dùng serving server:
  # remote_endpoint: "unix:///tmp/aegis-infer.sock"
  # remote_endpoint: "tcp://127.0.0.1:50051"
```

---

## Option B — Async pre-classify (higher throughput, lower latency)

> Thực hiện sau Option A khi đã ổn định. Yêu cầu thay đổi `Detector` trait.

Ý tưởng: chạy gRPC call **song song** với regex detector chain thay vì blocking.

```rust
// data_plane.rs — pseudo-code
async fn handle_request(req: RequestView<'_>, ...) {
    // Kick off AI classify concurrently (không await ngay)
    let ai_future = remote_ai_client.classify_raw(&request_str);

    // Chạy regex detector chain (sync, ~100µs)
    let (signals, fired) = run_all_filtered_timed(&detectors, mask, &req, ...);

    // Chỉ await AI result nếu regex chain không fire gì
    // (giữ đúng logic hiện tại: AI chỉ chạy khi Base detector miss)
    if fired.is_empty() {
        if let Ok(result) = ai_future.await {
            if result.is_attack {
                signals.push(Signal { tag: "ai", score: AI_SCORE, ... });
            }
        }
    }
}
```

**Lợi ích**: AI latency được che khuất bởi regex chain → tổng latency không tăng.

---

## Triển khai production

### Topology khuyến nghị (same-host)

```
┌─────────────────────────────────────────┐
│  EC2 / bare-metal node                  │
│                                         │
│  ┌──────────────┐    UDS     ┌────────┐ │
│  │  aegis-gate  │◄──────────►│ infer  │ │
│  │  (WAF proxy) │            │ server │ │
│  └──────────────┘            └────────┘ │
│        ↑                         ↑      │
│     HTTPS                   ONNX model  │
│     5-10k RPS               4 workers   │
└─────────────────────────────────────────┘
```

UDS cho same-host vì latency thấp hơn TCP ~0.2ms và không cần TLS.

### systemd service cho serving server

```ini
# /etc/systemd/system/aegis-infer.service
[Unit]
Description=Aegis WAF AI Inference Server
After=network.target
Requires=network.target

[Service]
Type=simple
User=aegis
ExecStart=/usr/local/bin/aegis-infer \
    --model-path /etc/aegis/ai_model/waf_model.onnx \
    --workers 4 \
    --max-batch 256 \
    --delay-ms 2 \
    --bind-uds /run/aegis/infer.sock \
    --bind-tcp 127.0.0.1:50051 \
    --log-level info
Restart=always
RestartSec=2
RuntimeDirectory=aegis
RuntimeDirectoryMode=0750

[Install]
WantedBy=multi-user.target
```

### Tuning theo workload

| Workload | `--workers` | `--max-batch` | `--delay-ms` | Expected RPS |
|---|---|---|---|---|
| Low (< 1k RPS) | 1 | 64 | 5 | 1k |
| Medium (1–5k) | 2 | 128 | 2 | 5k |
| High (5–10k) | 4 | 256 | 2 | 10k |
| Very high (>10k) | 8 | 512 | 1 | 20k+ |

`--workers` = số ONNX sessions = số CPU core dành cho inference (không nên > physical cores).

---

## Failure handling

Serving server **luôn fail-open**: nếu gRPC call timeout hoặc connection reset,
WAF tiếp tục xử lý request mà không có AI verdict — hành vi giống hệt với
in-process `AiDetector` khi `inference error`.

```
RemoteAiDetector::inspect()
    │
    ├─ gRPC OK → prob_attack >= threshold → Signal { tag: "ai" }
    ├─ gRPC OK → prob_attack < threshold  → []  (no signal)
    └─ gRPC error (timeout/reset/crash)   → []  (fail-open, log trace)
```

Khi serving server down hoàn toàn, WAF tiếp tục hoạt động bình thường với
chỉ regex detectors — không có outage.

---

## Các bước thực hiện (theo thứ tự)

1. **[ ] Chạy serving server** với model thật, verify với `infer-bench`
2. **[ ] Copy `proto/aegis_infer.proto`** vào `crates/aegis-security/proto/`
3. **[ ] Thêm `tonic`, `prost` vào workspace** `Cargo.toml`
4. **[ ] Tạo `crates/aegis-security/src/detectors/ai/remote.rs`** (code ở trên)
5. **[ ] Thêm `ai.remote_endpoint`** vào `AiConfig` struct
6. **[ ] Wire `RemoteAiDetector`** vào `run.rs` với fallback về in-process
7. **[ ] Test end-to-end**: WAF → infer server → `x-waf-rule-id: ai` trong response header
8. **[ ] Benchmark**: so sánh throughput trước/sau với `eval_waf_legitimate_dataset.py`

---

## Tham khảo

| File | Vai trò |
|---|---|
| `crates/aegis-security/src/detectors/ai/mod.rs` | In-process `AiDetector` (reference) |
| `crates/aegis-security/src/detectors/ai/features.rs` | Feature extractor 27-dim |
| `crates/aegis-security/src/detectors/mod.rs` | `run_all_filtered_timed` — AI deferred logic |
| `crates/aegis-proxy/src/data_plane.rs` | Call site: WAF hot path |
| `crates/aegis-core/src/config.rs` | `AiConfig` struct |
| `data/serving-server/proto/aegis_infer.proto` | gRPC contract |
| `data/serving-server/src/features.rs` | Feature extractor (mirror, must stay in sync) |
