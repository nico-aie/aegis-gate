# WAF Interop Contract v2.3

> **Đối tượng**: Ứng viên WAF Hackathon

> **Phạm vi**: Mô tả các decision (quyết định) và control-plane interface (giao diện điều khiển) mà WAF của bạn phải expose để Ban Tổ Chức (BTC) có thể đánh giá một cách deterministic (Nếu BTC thực hiện cùng một thao tác (input) trong cùng một điều kiện, BTC phải luôn nhận được kết quả output y hệt nhau, không có sự sai khác ngẫu nhiên).

---

## 1. Mục đích

Để phục vụ automated judging (quá trình chấm điểm tự động), WAF PHẢI cung cấp các tín hiệu phản hồi (observable outputs) rõ ràng để Benchmarking tool (tool chấm điểm) của Ban Tổ Chức (BTC) có thể phân loại hành vi ngay lập tức. BTC sẽ không can thiệp vào mã nguồn hoặc logic nội bộ trừ trường hợp cần kiểm tra sự bất thường (discrepancy)

Là ứng viên, WAF của bạn BẮT BUỘC gắn các observability headers được quy định ở §5 vào mọi HTTP response. Dù Audit log (§6) vẫn là yêu cầu bắt buộc để correlation (đối chiếu) và post-run inspection (kiểm tra sau khi chạy), các response headers này là yếu tố quan trọng cho real-time classification và không thể được thay thế bằng audit log.

Ngoài response observability, WAF BẮT BUỘC expose một local control plane nhỏ để BTC có thể:

1. Truy vấn cấu hình: Cung cấp thông tin tổng quan về các khả năng, tính năng và chính sách hiện tại của WAF
2. Khởi tạo trạng thái: Cho phép xóa sạch toàn bộ dữ liệu tạm thời giữa các bài kiểm tra.
3. Điều chỉnh cơ chế hoạt động: Chuyển đổi linh hoạt giữa chế độ Chặn (Enforcement) và Chỉ ghi log (Log-only) đối với một hoặc toàn bộ các chính sách.
4. Quản lý bộ nhớ đệm: Hỗ trợ xóa bộ nhớ đệm (Flush cache) khi tính năng này đang kích hoạt.
5. Đối chiếu kết quả: Xác định mối liên hệ giữa các quyết định phản hồi của WAF với chính sách tương ứng đang áp dụng.

---

## 2. WAF Control Interface

### 2.1 Required Control Endpoints

Recommended prefix:

```text
/__waf_control
```

| Method | Path | Requirement | Purpose |
|--------|------|-------------|---------|
| `GET` | `/__waf_control/capabilities` | **BẮT BUỘC** | Cho phép BTC discover các WAF features, policies, và toggle controls được hỗ trợ. |
| `POST` | `/__waf_control/reset_state` | **BẮT BUỘC** | Xóa temporary WAF runtime state giữa các test runs. |
| `POST` | `/__waf_control/set_profile` | **BẮT BUỘC** | Toggle mode `enforce` / `log_only` cho toàn bộ, một, hoặc một tập features/policies được chọn. |
| `POST` | `/__waf_control/flush_cache` | **BẮT BUỘC nếu caching tồn tại** | Xóa WAF cache khi cache được implement. |

Tất cả control endpoints BẮT BUỘC là local/admin-only và KHÔNG ĐƯỢC proxy tới upstream.

### 2.2 Authentication

Control endpoints BẮT BUỘC yêu cầu benchmark secret header:

```http
X-Benchmark-Secret: waf-hackathon-2026-ctrl
```

Secret bị thiếu/không hợp lệ BẮT BUỘC trả về `403 Forbidden`.

### 2.3 WAF Capabilities

Endpoint:

```http
GET /__waf_control/capabilities
```

Response BẮT BUỘC cho phép BTC hiểu toàn bộ minimal controllable surface (bề mặt có thể điều khiển tối thiểu) mà WAF implementation expose.

Teams CÓ THỂ expose thêm implementation-specific features hoặc policies, nhưng không bắt buộc. BTC có thể dùng extra capabilities cho bonus evaluation, diagnostics, hoặc manual review.

Các baseline capability names bên dưới được cố ý đặt generic. Một WAF tối thiểu có thể chỉ expose một access-control ruleset nhỏ, trong khi các WAF nâng cao hơn CÓ THỂ expose thêm generic rule groups.

Minimal success response:

```json
{
  "ok": true,
  "features": {
    //SKELETON
    "rules_name": {
      "supported": true,
      "toggleable": true,
      "policies": ["policy_A", "policy_B"]
    },
    //EXAMPLE
    "access_control": {
      "supported": true,
      "toggleable": true,
      "policies": ["blacklist", "whitelist"]
    }
  },
  "active": {
    "default_mode": "enforce",
    "overrides": {}
  }
}
```

Feature và policy names là implementation-defined, nhưng BẮT BUỘC ổn định trong một benchmark run. Candidate-facing documentation NÊN giữ names ở dạng generic. BTC có thể dùng response này để quyết định features/policies nào CÓ THỂ toggle thông qua `POST /__waf_control/set_profile`.

### 2.4 Runtime Reset

Endpoint:

```http
POST /__waf_control/reset_state
```

`reset_state` BẮT BUỘC xóa temporary runtime state, tối thiểu bao gồm:

- risk state,
- rate-limit counters,
- cache state,
- challenge/session state,
- temporary client/session metadata,
- temporary enforcement state.

Nó NÊN giữ lại long-term static config trừ khi có yêu cầu rõ ràng khác.

`reset_state` KHÔNG ĐƯỢC delete, truncate, rotate, rewrite, hoặc modify `./waf_audit.log` hay audit-log file đã cấu hình. Audit log là evidence (bằng chứng) cho BTC-side correlation, backup verification, và post-run inspection, nên nó BẮT BUỘC giữ append-only qua các WAF state resets. Implementations CÓ THỂ append một structured audit event để ghi nhận rằng `reset_state` đã được gọi, nhưng KHÔNG ĐƯỢC xóa các log entries trước đó.

`reset_state` BẮT BUỘC synchronous và atomic từ góc nhìn của benchmarker. Success response KHÔNG ĐƯỢC trả về cho đến khi toàn bộ temporary runtime state liệt kê phía trên đã được xóa hoàn toàn. Trong quá trình reset, implementations CÓ THỂ tạm thời reject hoặc queue các in-flight non-control requests, nhưng KHÔNG ĐƯỢC expose partially reset state sau khi đã trả success.

Nếu implementation trả successful `reset_state` response trước khi temporary runtime state thực sự được xóa hết, run đó NÊN KHÔNG bị coi là automatic failure chỉ vì lý do này. Tuy nhiên, BTC CÓ THỂ áp dụng scoring penalty vì premature success responses có thể làm nhiễm các test sau, làm benchmark results flaky, hoặc yêu cầu thêm manual verification.

Minimal success response:

```json
{
  "ok": true,
  "action": "reset_state",
  "audit_log_preserved": true,
  "ts_ms": 1777363200123
}
```

### 2.5 WAF Feature / Policy Mode Control

Endpoint:

```http
POST /__waf_control/set_profile
```

WAF BẮT BUỘC hỗ trợ controlled switching của feature/policy behavior để BTC có thể evaluate WAF một cách deterministic mà không tiết lộ hidden test logic.

Endpoint này KHÔNG phải benchmark-specific bypass hoặc scoring shortcut. Teams KHÔNG ĐƯỢC hard-code behavior cho benchmark, hidden tests, organizer traffic, hoặc specific payloads. Enabling evaluation compatibility nghĩa là expose deterministic control và observability semantics; nó KHÔNG ĐƯỢC relax, boost, hoặc special-case detection logic cho các benchmark cases chưa được tiết lộ.

BTC có thể toggle:

1. toàn bộ supported features/policies cùng lúc;
2. một feature/policy;
3. một list các features/policies được chọn.

#### Enforcement semantics

Mỗi feature/policy mode BẮT BUỘC dùng một trong các giá trị sau:

- `enforce`: policy đang active và `X-WAF-Action` của nó được áp dụng lên traffic. Ví dụ, nếu WAF quyết định `block`, request sẽ thực sự bị block trước upstream.
- `log_only`: policy vẫn được evaluate bình thường và BẮT BUỘC report intended `X-WAF-Action`, `X-WAF-Rule-Id`, và audit-log evidence như trong `enforce` mode, nhưng enforcement effect KHÔNG ĐƯỢC áp dụng. Trong `log_only`, policy nào nếu ở `enforce` mode sẽ tạo ra `block`, `challenge`, `rate_limit`, `timeout`, hoặc `circuit_breaker` thì BẮT BUỘC report intended action đó qua `X-WAF-Action` và BẮT BUỘC report `X-WAF-Mode: log_only`, trong khi request NÊN tiếp tục tới upstream trừ khi bị chặn bởi non-WAF transport failures hoặc upstream availability issues. Điều này cho phép BTC verify detector hoạt động mà không buộc mọi test request phải bị deny hoặc interrupt.

Minimal request body schema:

```json
{
  "scope": "all | features | policies",
  "mode": "enforce | log_only"
}
```

Allowed values:

- `scope`: `all`, `features`, hoặc `policies`
- `mode`: `enforce` hoặc `log_only`

Update semantics:

- `scope: "all"` thay đổi default mode cho toàn bộ supported features/policies.
- `scope: "features"` chỉ thay đổi các features được liệt kê. Tất cả omitted features BẮT BUỘC giữ nguyên current mode.
- `scope: "policies"` chỉ thay đổi các policies được liệt kê. Tất cả omitted policies trong cùng feature, và tất cả unrelated features, BẮT BUỘC giữ nguyên current mode.

Examples:

```json
{
  "scope": "all",
  "mode": "enforce"
}
```

Trong ví dụ này, toàn bộ supported features và policies được chuyển sang `enforce`. Mọi feature-level hoặc policy-level `log_only` overrides trước đó NÊN clear trừ khi WAF explicitly report khác trong response `active.overrides`.

```json
{
  "scope": "features",
  "mode": "log_only",
  "features": ["access_control"]
}
```

Trong ví dụ này, chỉ `access_control` được chuyển sang `log_only`. Các features khác như `rules_name` BẮT BUỘC giữ nguyên.

```json
{
  "scope": "policies",
  "mode": "log_only",
  "feature": "access_control",
  "policies": ["blacklist"]
}
```

Trong ví dụ này, chỉ policy `blacklist` trong `access_control` được chuyển sang `log_only`. Policy `whitelist` và tất cả features/policies khác BẮT BUỘC giữ nguyên.

Minimal success response for disabling one feature:

```json
{
  "ok": true,
  "action": "set_profile",
  "applied": {
    "scope": "features",
    "mode": "log_only",
    "features": ["access_control"]
  },
  "active": {
    "default_mode": "enforce",
    "overrides": {
      "access_control": "log_only"
    }
  },
  "unsupported": [],
  "ts_ms": 1777363201123
}
```

Minimal success response for disabling one policy:

```json
{
  "ok": true,
  "action": "set_profile",
  "applied": {
    "scope": "policies",
    "mode": "log_only",
    "feature": "access_control",
    "policies": ["blacklist"]
  },
  "active": {
    "default_mode": "enforce",
    "overrides": {
      "access_control.blacklist": "log_only"
    }
  },
  "unsupported": [],
  "ts_ms": 1777363201123
}
```

Nếu requested feature hoặc policy không được hỗ trợ, WAF KHÔNG ĐƯỢC silently ignore nó. Response BẮT BUỘC chọn một trong hai cách:

1. trả về `400 Bad Request` hoặc `422 Unprocessable Entity` kèm machine-readable `unsupported` list; hoặc
2. chỉ trả success cho các items được hỗ trợ và đưa các unsupported items vào `unsupported` list.

Behavior đã chọn BẮT BUỘC nhất quán trong toàn bộ benchmark run.

### 2.6 Cache Flush

Endpoint:

```http
POST /__waf_control/flush_cache
```

Nếu WAF caching được implement, endpoint này BẮT BUỘC hỗ trợ để benchmark runs không bị ảnh hưởng bởi stale cached decisions.

Nếu caching không được implement, WAF CÓ THỂ trả về clear not-supported response.

### 2.7 Response Headers for Control-Mode Correlation

Với mọi proxied response:

- `X-WAF-Mode`: **BẮT BUỘC** (`enforce` hoặc `log_only`) để BTC có thể verify active policy đang enforcing hay chỉ logging.

Khi một request match nhiều policies với active modes khác nhau, `X-WAF-Mode` NÊN phản ánh mode của policy tạo ra final reported `X-WAF-Action`.

Khi `X-WAF-Mode: log_only`, các decisions `block`, `challenge`, `rate_limit`, `timeout`, và `circuit_breaker` BẮT BUỘC report qua `X-WAF-Action` như intended decisions only; enforcement effect KHÔNG ĐƯỢC áp dụng.

---

## 3. WAF Decision Classes

Mỗi request đi qua WAF tạo ra đúng một decision:

| Decision | Meaning |
|----------|---------|
| `allow` | Request được proxy tới upstream; upstream response được trả về client |
| `block` | Request bị deny trước khi tới upstream |
| `challenge` | Request bị giữ lại; client phải giải JS challenge hoặc proof-of-work (PoW) trước khi tiếp tục |
| `rate_limit` | Request bị deny vì vượt quá rate threshold |
| `timeout` | WAF đã proxy request, nhưng upstream không phản hồi đúng hạn |
| `circuit_breaker` | WAF từ chối proxy vì upstream được đánh dấu unhealthy |

### 3.1 Threat Category to Action Semantics

Bảng sau định nghĩa semantic mapping kỳ vọng giữa threat categories và WAF actions. Benchmark sẽ đánh giá action mà WAF chọn có nằm trong tập "acceptable" cho từng threat category hay không. Một category có thể có nhiều acceptable actions; teams có thể lựa chọn dựa trên detection confidence của mình.

| Threat Category | Acceptable Actions | Unacceptable Actions | Notes |
|-----------------|--------------------|----------------------|-------|
| High-confidence injection (SQLi, XSS, command injection, SSRF) | `block`, `challenge` | `rate_limit`, `timeout`, `allow` | `challenge` chấp nhận được khi confidence thấp hơn ngưỡng do team tự định nghĩa |
| Low-confidence injection (heuristic match only) | `block`, `challenge`, `log_only` | — | Team tự quyết định dựa trên detection model |
| Authentication abuse (credential stuffing, brute force) | `rate_limit`, `challenge`, `block` | `timeout`, `circuit_breaker` | `block` chấp nhận được với known-bad IP/fingerprint |
| Volumetric abuse from single source | `rate_limit`, `block` | `circuit_breaker` | `circuit_breaker` dùng để bảo vệ upstream, không dùng để quản lý rate theo source |
| Slow-loris / connection exhaustion | `timeout`, `block` | `rate_limit` | Đây là vấn đề connection-level, không phải request-level |
| Upstream degradation detected by WAF | `circuit_breaker` | `block`, `rate_limit` | Action nhằm bảo vệ upstream, không nhắm vào client |
| Reconnaissance / scanning patterns | `block`, `rate_limit`, `challenge` | — | Team tự quyết định |
| Known malicious IP (blacklist) | `block` | — | — |

**Quan trọng:** Bảng này định nghĩa semantic expectations của contract. Đây không phải danh sách đầy đủ các threat scenarios sẽ được test. Teams nên tổng quát hóa các nguyên tắc này (ví dụ: "actions should target the actor responsible for the threat") để xử lý các scenarios không được liệt kê.

---

## 4. Detection via HTTP Response (Primary)

Benchmarker chủ yếu classify WAF decisions bằng các required observability headers trong §5. HTTP status và response body được dùng như compatibility signals và để validate user-facing behavior.

Recommended response behavior:

| `X-WAF-Action` | Recommended HTTP behavior |
|----------------|---------------------------|
| `allow` | Proxy request tới upstream và trả upstream response. |
| `block` | Trả một denial response rõ ràng, thường là `403`. |
| `challenge` | Trả challenge response, thường là `429`, với đủ thông tin để automated challenge solving. |
| `rate_limit` | Trả rate-limit response, thường là `429`. |
| `timeout` | Trả timeout response, thường là `504`. |
| `circuit_breaker` | Trả temporary-unavailable response, thường là `503`. |

**Design intent**: Teams có thể dùng bất kỳ response body format nào — HTML page, JSON object, hoặc plain text — miễn là required headers vẫn chính xác và HTTP behavior nhất quán với reported action.

### Challenge Response Format

Khi WAF trả về `challenge` (status `429` + body chứa `challenge`), response body BẮT BUỘC có đủ thông tin để benchmarker giải challenge programmatically. Hai formats được hỗ trợ:

**Format A — JSON challenge:**
```json
{
  "challenge": true,
  "challenge_type": "proof_of_work",
  "challenge_token": "abc123...",
  "difficulty": 4,
  "submit_url": "/challenge/verify",
  "submit_method": "POST"
}
```

**Format B — HTML challenge:**
```html
<!-- Body BẮT BUỘC contain "challenge" (case-insensitive) for detection -->
<form action="/challenge/verify" method="POST">
  <input type="hidden" name="challenge_token" value="abc123..." />
  <!-- JS computes nonce -->
</form>
```

**Challenge solution submission**: Benchmarker submit `POST <submit_url>` với body `{"challenge_token":"...","nonce":"..."}`. Khi thành công, WAF nên trả `200` kèm session cookie hoặc token cho phép original request tiếp tục.

Nếu WAF dùng challenge format mà benchmarker không parse được, challenge sẽ được ghi nhận là `challenge_unsolvable` — WAF vẫn được credit vì đã phát challenge, nhưng không được credit cho lifecycle test "challenge success lowers score".

### Minimum response requirements

WAF của bạn BẮT BUỘC include `X-WAF-Request-Id` trên mọi response để benchmarker có thể correlate request-level evidence giữa response headers và audit log.

Nếu `X-WAF-Request-Id` bị thiếu, malformed, hoặc không nhất quán với audit log `request_id`, benchmarker ghi nhận observability contract failure cho request đó.

---

## 5. Mandatory Observability Headers

WAF của bạn BẮT BUỘC expose required observability headers bên dưới trên mọi HTTP response được trả qua WAF, bao gồm các decisions `allow`, `block`, `challenge`, `rate_limit`, `timeout`, và `circuit_breaker`.

Benchmarker dùng các headers này như primary machine-readable decision interface cho risk lifecycle checks, rule attribution, caching verification, control-mode correlation, và candidate dashboard evidence. HTTP status/body classification trong §4 vẫn là compatibility fallback, nhưng missing required observability headers được xem là contract failure.

### 5.1 Required headers

| Header | Type | Description | Exact format |
|--------|------|-------------|-------------|
| `X-WAF-Request-Id` | UUID | Canonical request ID cho request/response pair này | UUID v4 string, ví dụ `550e8400-e29b-41d4-a716-446655440000` |
| `X-WAF-Risk-Score` | integer 0–100 | Current accumulated risk score cho {IP + device + session} tại decision time | Plain integer, không có whitespace. Ví dụ: `42` |
| `X-WAF-Action` | string | Final reported WAF decision. Trong `log_only`, đây BẮT BUỘC là intended action lẽ ra sẽ được enforce trong khi request vẫn được allowed tới upstream. | Một trong: `allow`, `block`, `challenge`, `rate_limit`, `timeout`, `circuit_breaker`; lowercase, exact match |
| `X-WAF-Rule-Id` | string hoặc `none` | ID của rule, model, policy, hoặc detector trực tiếp nhất gây ra decision | Alphanumeric + hyphens, ví dụ `rule-001`, `policy-default`, hoặc `none` |
| `X-WAF-Cache` | `HIT` / `MISS` / `BYPASS` | Response có được serve từ WAF cache hay không | Uppercase, exact match. Dùng `BYPASS` cho non-cacheable routes hoặc khi caching disabled. |
| `X-WAF-Mode` | `enforce` / `log_only` | Policy tạo ra final reported action đang enforcing hay chỉ logging | Lowercase, exact match: `enforce` hoặc `log_only` |


### 5.2 Additional observability headers (scored under Dashboard criterion)
Headers được liệt kê trong §5.1 là minimum required response headers cho benchmark compatibility. Teams CÓ THỂ thêm các extra `X-WAF-*` response headers để hỗ trợ tracing, investigation, dashboards, forensics, hoặc operational debugging.

Additional headers BẮT BUỘC tuân theo các rules sau:
- chúng BẮT BUỘC dùng prefix `X-WAF-`;
- chúng KHÔNG ĐƯỢC thay thế hoặc làm yếu bất kỳ required header nào trong §5.1;
- chúng KHÔNG ĐƯỢC chứa secrets, raw credentials, session tokens, stack traces, hoặc sensitive user data;
- chúng NÊN stable và machine-readable khi có thể.

BTC có thể xem xét useful extra observability như một phần của dashboard, intelligence, hoặc operational-quality evaluation, nhưng tài liệu này cố ý không quy định specific optional header names.

### 5.3 Header consistency rules

- `X-WAF-Action` BẮT BUỘC khớp với actual behavior của response khi `X-WAF-Mode: enforce`.
- Khi `X-WAF-Mode: log_only`, WAF BẮT BUỘC evaluate policies bình thường và BẮT BUỘC report intended `X-WAF-Action` lẽ ra sẽ được enforce, trong khi block/challenge/rate-limit/timeout/circuit_breaker enforcement KHÔNG ĐƯỢC áp dụng.
- Trong `log_only`, request NÊN tiếp tục tới upstream trừ khi bị chặn bởi non-WAF transport failures hoặc upstream availability issues.
- `X-WAF-Mode` BẮT BUỘC phản ánh mode của policy tạo ra final reported `X-WAF-Action`.
- `X-WAF-Risk-Score` BẮT BUỘC phản ánh score sau khi evaluate current request.
- `X-WAF-Rule-Id` BẮT BUỘC là `none` khi không có rule, model, hoặc policy cụ thể nào gây ra decision.
- `X-WAF-Cache` BẮT BUỘC là `BYPASS` trên authenticated, dynamic, sensitive, high-risk, hoặc otherwise non-cacheable routes.
- `X-WAF-Request-Id` BẮT BUỘC khớp với audit log `request_id` cho cùng request.
- Required headers BẮT BUỘC xuất hiện trên allowed responses cũng như block/challenge/rate-limit/timeout/circuit_breaker responses. Benchmarker dùng allowed-response risk scores để verify risk accumulation và decay (§8 của benchmark spec).

---

## 6. Audit Log (Secondary)

WAF của bạn ghi structured JSON logs vào `./waf_audit.log` (configurable path). Append-only, mỗi dòng là một JSON object (JSONL), SIEM-ingestible.

### Minimal required fields per entry

```json
{
  "request_id": "uuid",
  "ts_ms": 1714000000000,
  "ip": "1.2.3.4",
  "method": "POST",
  "path": "/login",
  "action": "block",
  "risk_score": 75,
  "mode": "enforce"
}
```

| Field | Type | Constraints |
|-------|------|------------|
| `request_id` | string (UUID v4) | BẮT BUỘC match `X-WAF-Request-Id` header nếu cả hai cùng tồn tại |
| `ts_ms` | integer | Unix epoch milliseconds |
| `ip` | string | TCP peer address (NOT XFF). IPv4 dotted decimal. |
| `method` | string | Uppercase HTTP method |
| `path` | string | Request path bao gồm query string |
| `action` | string | Một trong 6 decision classes từ §3 |
| `risk_score` | integer 0–100 | Score tại thời điểm decision |
| `mode` | string | `enforce` hoặc `log_only`; phải khớp với `X-WAF-Mode` khi có |

### Additional audit-log fields (scored under Dashboard criterion)

Các fields được liệt kê trong §6 là minimum required audit-log fields cho correlation và benchmark compatibility. Teams CÓ THỂ thêm extra JSON fields vào mỗi audit-log entry để hỗ trợ tracing, investigation, dashboards, forensics, operational debugging, hoặc richer security analytics.

Additional audit-log fields BẮT BUỘC tuân theo các rules sau:

- chúng KHÔNG ĐƯỢC thay thế hoặc làm yếu bất kỳ required field nào trong §6;
- chúng KHÔNG ĐƯỢC chứa secrets, raw credentials, session tokens, stack traces, hoặc sensitive user data;
- chúng NÊN stable và machine-readable khi có thể;
- chúng NÊN giữ JSONL compatibility: mỗi dòng là một valid JSON object.

BTC có thể xem xét useful extra audit-log fields như một phần của dashboard, intelligence, hoặc operational-quality evaluation, nhưng tài liệu này cố ý không quy định specific optional field names.

Benchmarker đọc file này sau mỗi run để correlation, diagnostics, và score validation. Audit log không thay thế mandatory response headers trong §5.

### Audit Log IP Field Semantics

Field `ip` BẮT BUỘC là TCP peer address (`peer_addr` / `remote_addr` từ socket), KHÔNG phải value parse từ `X-Forwarded-For` hoặc bất kỳ header nào khác. Điều này quan trọng vì:
1. Benchmarker mô phỏng các source IP khác nhau qua loopback aliases.
2. XFF có thể bị spoof — WAF có thể trust hoặc không trust nó.
3. Benchmarker correlate audit log entries bằng TCP source IP.

---

## 7. Decision Normalization Matrix

Borderline scenarios phải được classify nhất quán. Benchmarker chủ yếu dùng required observability headers trong §5.1, sau đó dùng HTTP status/body và BTC-side validation evidence làm supporting signals.

| Required signal | How it is used during normalization |
|-----------------|--------------------------------------|
| `X-WAF-Request-Id` | Correlate response headers với matching audit-log entry. Missing hoặc mismatched IDs có thể bị xem là observability contract issue. |
| `X-WAF-Risk-Score` | Hỗ trợ risk lifecycle checks, risk accumulation/decay validation, và false-positive analysis. |
| `X-WAF-Action` | Primary reported WAF decision. Expected values là `allow`, `block`, `challenge`, `rate_limit`, `timeout`, hoặc `circuit_breaker`. |
| `X-WAF-Rule-Id` | Xác định rule/model/policy/detector chịu trách nhiệm cho reported action, hoặc `none` khi không có detector cụ thể nào áp dụng. |
| `X-WAF-Cache` | Phân biệt cache behavior với real upstream/WAF decisions. Expected values là `HIT`, `MISS`, hoặc `BYPASS`. |
| `X-WAF-Mode` | Phân biệt enforced decisions với detection-only `log_only` decisions. |

Classification matrix bên dưới BẮT BUỘC hiểu cùng với các required headers phía trên:

| Scenario | Required header expectation | Classification | Rationale |
|----------|-----------------------------|---------------|-----------|
| WAF blocks một malicious request | `X-WAF-Action: block`, `X-WAF-Mode: enforce` | `prevented` | Explicit enforced block trước khi exploit thành công |
| WAF rate-limits hoặc challenges một malicious request | `X-WAF-Action: rate_limit` hoặc `challenge`, `X-WAF-Mode: enforce` | `prevented` | Request bị deny hoặc giữ lại trước khi tới vulnerable path |
| WAF times out hoặc trips circuit breaker cho malicious request | `X-WAF-Action: timeout` hoặc `circuit_breaker`, `X-WAF-Mode: enforce` | `prevented` | Request không hoàn tất thành công against upstream |
| WAF allows một malicious request và BTC-side validation xác nhận unsafe effect | `X-WAF-Action: allow`, `X-WAF-Mode: enforce` | `passed` | Unsafe effect không bị prevent |
| WAF rewrites/sanitizes payload và BTC-side validation xác nhận unsafe effect không xảy ra | `X-WAF-Action` NÊN phản ánh final decision, thường là `allow` hoặc `block`; `X-WAF-Rule-Id` NÊN identify responsible detector | `prevented_sanitized` | Attack đã được neutralize dù request có thể đã tới upstream |
| WAF reports một malicious request là detected nhưng chạy ở log-only mode | `X-WAF-Action: block`, `challenge`, hoặc `rate_limit`; `X-WAF-Mode: log_only` | `log_only_detected` | Detector phát hiện vấn đề, nhưng enforcement intentionally disabled bởi control mode |
| Legitimate request bị blocked, challenged, hoặc rate-limited ngoài expected stress conditions | `X-WAF-Action: block`, `challenge`, hoặc `rate_limit`; `X-WAF-Mode: enforce` | `false_positive` | Good traffic bị ảnh hưởng tiêu cực bởi enforcement |
| Legitimate request nhận challenge rồi thành công sau solver completion | `X-WAF-Action: challenge` followed by một successful allowed request với correlated `X-WAF-Request-Id` / audit evidence | `allowed_after_challenge` | Challenge đã được vượt qua và không nên tự động tính là false positive |
| Legitimate request trong DDoS/stress nhận rate limit | `X-WAF-Action: rate_limit`, `X-WAF-Mode: enforce` | `collateral` | Được tính riêng khỏi false positives; expected dưới extreme load |
| Response được serve từ WAF cache | `X-WAF-Cache: HIT` | Classified theo `X-WAF-Action`, với cache behavior được verify riêng | Tránh nhầm stale cache với fresh upstream/WAF decisions |

**Enforce rule**: Trong `enforce` mode, malicious request được xem là `prevented` khi `X-WAF-Action` report một enforced denial/control action (`block`, `challenge`, `rate_limit`, `timeout`, hoặc `circuit_breaker`) và BTC-side validation xác nhận unsafe effect không xảy ra.

**Log-only rule**: Trong `log_only` mode, benchmarker verify detector behavior từ `X-WAF-Action`, `X-WAF-Rule-Id`, audit log evidence, và BTC-side validation evidence. Requests trong `log_only` NÊN tiếp tục tới upstream trừ khi bị chặn bởi non-WAF transport failures hoặc upstream availability issues, do đó unsafe effect vẫn có thể xảy ra ngay cả khi WAF report đúng intended `block`, `challenge`, hoặc `rate_limit` action.



---

## 8. WAF Startup & Binary Contract

Từ competition rules — lặp lại ở đây để benchmark/judgement alignment:

```text
Binary:   ./waf
Start:    ./waf run
Config:   ./waf.yaml (or ./waf.toml) — BẮT BUỘC exist in working directory
Logs:     ./waf_audit.log (default, configurable in config file)
```

Benchmarker/judging panel expects:
1. WAF binary tồn tại tại `./waf`
2. `./waf run` start WAF và bắt đầu listening trước khi startup timeout hết hạn
3. WAF đọc upstream target từ config file
4. WAF listen trên port được chỉ định trong config
5. `./waf_audit.log` được tạo sau khi request đầu tiên được xử lý

### Health Check

Sau khi start `./waf run`, benchmarker poll configured health endpoint cho đến khi startup timeout hết hạn. Response `200` đầu tiên = WAF đã ready.

Nếu WAF không respond trước khi startup timeout hết hạn, benchmarker ghi nhận `startup_failed`.

---

## 9. Caching Observability

Nếu WAF implements caching, benchmarker verify cache behavior có safe và observable hay không bằng `X-WAF-Cache` headers và supporting response behavior.

General expectations:

| Route type | Expected cache behavior |
|------------|------------------------|
| Sensitive, authenticated, dynamic, hoặc high-risk routes | NÊN KHÔNG được cached. Trả `BYPASS` khi caching bị skip. |
| Static hoặc explicitly cacheable routes | CÓ THỂ cached. Trả `MISS` cho cacheable response đầu tiên và `HIT` cho response sau được serve từ cache. |
| Unknown/default routes | NÊN KHÔNG được cached trừ khi WAF có thể chứng minh chúng safe to cache. |

`X-WAF-Cache` là mandatory trên mọi responses. Với non-cacheable routes, trả `BYPASS`.

Nếu caching được implement, `POST /__waf_control/flush_cache` BẮT BUỘC clear stale cache entries trước khi trả success.

---

## 10. Source IP Trust Model

Section này làm rõ WAF nên xử lý source IPs và proxy headers như thế nào trong competition:

| Signal | Source of truth | WAF NÊN... |
|--------|----------------|---------------|
| TCP peer address (`peer_addr`) | Socket layer | Luôn log giá trị này trong audit log field `ip`. Dùng làm primary IP cho rate limiting và risk scoring. |
| `X-Forwarded-For` | Request header (spoofable) | Chỉ xem là supplementary context. So sánh với `peer_addr` khi hữu ích, nhưng KHÔNG ĐƯỢC dùng làm sole IP identity. |
| `X-Real-IP` | Request header (spoofable) | Giống XFF — supplementary signal, không phải identity. |
| `Host` | Request header | Validate với expected hostname. Reject hoặc sanitize unexpected values. |

**In the sandbox**: Toàn bộ traffic đến từ các địa chỉ loopback `127.0.0.x`. WAF BẮT BUỘC xem các địa chỉ `127.0.0.x` khác nhau là distinct clients (khác IP cho rate limiting, risk scoring, v.v.).

---

## 11. Non-Disclosure Principle

Teams được yêu cầu implement observability headers, audit log, startup contract, và WAF control interface phía trên.

BTC không tiết lộ detailed benchmark scenarios, hidden payloads, rule mappings, hoặc scoring logic trong tài liệu này.

---

## 12. Version 2.3 Delta Summary

So với `v2.2`, version này bổ sung:

1. Minimal WAF control plane cho deterministic benchmark orchestration:
   - `GET /__waf_control/capabilities`
   - `POST /__waf_control/reset_state`
   - `POST /__waf_control/set_profile`
   - `POST /__waf_control/flush_cache` (nếu cache được implement)
2. Strict secret-based protection model cho control endpoints (`X-Benchmark-Secret`).
3. Explicit synchronous/atomic runtime state reset semantics để giảm cross-phase contamination trong khi vẫn preserve append-only WAF audit log.
4. Capability-driven feature/policy mode control (`enforce` / `log_only`) cho toàn bộ, một, hoặc selected features/policies.
5. Response-level mode correlation (`X-WAF-Mode`) và hỗ trợ additional implementation-defined `X-WAF-*` observability headers.
6. Updated observability và audit-log consistency rules cho `log_only` mode.



