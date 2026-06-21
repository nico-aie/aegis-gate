# Aegis-Gate WAF — Load Shedder đặt sai vị trí trong pipeline (overload → throughput collapse)

> **Mục đích:** Gửi chuyên gia phân tích & fix. Báo cáo chỉ ra **vị trí đặt cổng load-shed** trong data-plane khiến WAF **không giữ được goodput plateau** khi quá tải, kèm dẫn chứng `file:line` và hướng giải quyết theo chuẩn ngành.
>
> - **Service:** `aegis-gate` (Rust WAF reverse proxy)
> - **Ngày:** 2026-06-20
> - **Severity:** 🟠 High (overload resilience — ảnh hưởng availability dưới tải/DoS)
> - **Phạm vi:** thứ tự stage trong `data_plane.rs` quanh cổng `LoadShedder::should_admit`

---

## 0. Triệu chứng (từ load test)

| Tải đưa vào | Kết quả |
|---|---|
| ~11,000 rps | Ổn định, CPU > 95% (sát bão hoà) |
| ~14,000 rps (+3k) | **Sụp đột ngột còn ~2,000–3,000 rps** |

Đây là **congestion collapse / metastable failure**: vượt "đầu gối" thì throughput không đi ngang (plateau) mà **rơi xuống dưới cả mức đỉnh**. Hệ thống tốt phải **giữ ~11k dù bị bắn 14k/50k/100k** (AWS gọi là *goodput plateau*). WAF **đã có** `LoadShedder` (Gradient2 — `shed.rs`) đúng hướng, nhưng **đặt sai chỗ** nên không chặn được collapse.

> **Lưu ý phạm vi:** Việc **Critical tier được miễn shed là CHỦ ĐÍCH của vận hành** — *không* coi là lỗi. Báo cáo này chỉ xử lý **vị trí đặt cổng shed**, và đề xuất cách giữ nguyên hành vi "Critical không bao giờ bị shed" một cách an toàn (xem §5.4).

---

## 1. Thứ tự pipeline thực tế (đã verify trong code)

Trình tự một request đi qua `handle_data_request_inner` ([data_plane.rs:228](../aegis-gate/crates/aegis-proxy/src/data_plane.rs#L228)):

| # | Stage | File:line | Chi phí |
|---|---|---|---|
| 1 | `request_start = Instant::now()` | [data_plane.rs:291](../aegis-gate/crates/aegis-proxy/src/data_plane.rs#L291) | — |
| 2 | Route resolve / blacklist / whitelist | 424 / 458 / 490 | rẻ |
| 3 | DDoS check (in-process) | [data_plane.rs:571-579](../aegis-gate/crates/aegis-proxy/src/data_plane.rs#L571) | rẻ |
| 4 | Rate-limit (in-process) | [data_plane.rs:734](../aegis-gate/crates/aegis-proxy/src/data_plane.rs#L734) | rẻ |
| 5 | `req.into_parts()` | [data_plane.rs:840](../aegis-gate/crates/aegis-proxy/src/data_plane.rs#L840) | rẻ |
| 6 | **🔴 BODY BUFFERING** — `Limited::new(body, cap).collect().await` đọc **toàn bộ body vào RAM** | [data_plane.rs:866](../aegis-gate/crates/aegis-proxy/src/data_plane.rs#L866) | **đắt** (network read + heap alloc + memcpy) |
| 7 | `tier = route_tier` (tier cuối, đã áp `tier_override`) | [data_plane.rs:935](../aegis-gate/crates/aegis-proxy/src/data_plane.rs#L935) | rẻ |
| 8 | **🚩 CỔNG SHED** — `should_admit(&tier)` + `admit_guard()` | [data_plane.rs:950-967](../aegis-gate/crates/aegis-proxy/src/data_plane.rs#L950) | quyết định 503 |
| 9 | **🔴 DETECTOR PIPELINE** — `run_all_filtered_timed` (regex + AI/ONNX) | [data_plane.rs:985-991](../aegis-gate/crates/aegis-proxy/src/data_plane.rs#L985) | **rất đắt** (CPU) |
| 10 | Forward upstream | sau đó | — |
| 11 | `record_rtt(request_start.elapsed())` — tín hiệu điều khiển shedder | [data_plane.rs:1733](../aegis-gate/crates/aegis-proxy/src/data_plane.rs#L1733) | — |

**Điểm mấu chốt:** cổng shed (8) nằm **SAU body buffering (6)** và **TRƯỚC detector pipeline (9)**.

✅ Đặt shed *trước* detector pipeline là **đúng** — giữ nguyên.
🔴 Nhưng nó **quá muộn ở 3 khía cạnh khác**, phân tích bên dưới.

---

## 2. Nguyên tắc ngành mà thiết kế hiện tại vi phạm

Các hệ thống lớn (Google SRE, AWS Builders' Library, WeChat DAGOR, Netflix) đều quy về một nguyên tắc:

> **Admission control: từ chối ở CỬA, nhanh và rẻ, TRƯỚC khi tốn tài nguyên đắt.**
> *"Reject excess as early and as cheaply as possible"* — request bị shed thì **không được tiêu** network/RAM/CPU đáng kể.

Và mục tiêu đo lường:

> *"The ideal load test result is for goodput to **plateau** when fully utilized and **remain flat even when more throughput is applied**."* — AWS Builders' Library

Thiết kế hiện tại shed **sau khi đã ăn** network read + full-body allocation, và **dùng tín hiệu sai** (RTT thay vì CPU), nên không đạt plateau.

---

## 3. CHỖ SAI — phân tích chi tiết

### 3.1 [Critical] Shed SAU khi đã đọc + cấp phát toàn bộ body

**Bằng chứng:** body được `collect().await` vào RAM tại [data_plane.rs:866](../aegis-gate/crates/aegis-proxy/src/data_plane.rs#L866); cổng shed mới chạy ở [data_plane.rs:950](../aegis-gate/crates/aegis-proxy/src/data_plane.rs#L950).

→ Với một request **rốt cuộc bị shed**, WAF đã trả giá: nhận hết body trên socket + cấp phát + memcpy **toàn bộ payload**. Dưới một **POST flood** (mix tải thực tế nặng POST), đây là **áp lực allocator + băng thông bộ nhớ khổng lồ đổ vào đúng lúc CPU đang 95%** — chính là nhiên liệu cho death spiral. Request bị từ chối lẽ ra **không nên tốn một byte RAM nào** cho body.

> *Lưu ý:* commit PROXY-01 ([data_plane.rs:841-848](../aegis-gate/crates/aegis-proxy/src/data_plane.rs#L841)) đã chặn được body **quá cỡ** (OOM) bằng `Limited`, nhưng **không** giải quyết vấn đề này: một flood các body **đúng cỡ** vẫn bị đọc + cấp phát đầy đủ trước khi shed.

### 3.2 [High] Không có admission ở tầng accept/TLS — "cửa trước" bỏ ngỏ

**Bằng chứng:** cổng shed nằm **sâu trong handler L7 per-request**. Tầng `accept.rs` **không có** `should_admit`/giới hạn concurrency nào trước khi bắt tay TLS (grep `should_admit|admit_guard|load_shedder|Semaphore` trong `accept.rs` → rỗng).

→ Dưới **connection flood**, mọi **bắt tay TLS** (crypto đắt) đều hoàn tất **trước khi** có bất kỳ quyết định shed nào. Shedder chỉ bảo vệ phần *sau* khi request đã vào sâu — không bảo vệ được chính tài nguyên (CPU crypto, fd, accept queue) bị flood ở cửa.

### 3.3 [High] Tín hiệu shed (RTT-gradient) trễ pha so với ràng buộc thật (CPU)

**Bằng chứng:** `LoadShedder` Gradient2 quyết định bằng `gradient = rtt_min / rtt_now` ([shed.rs:85-106](../aegis-gate/crates/aegis-proxy/src/shed.rs#L85)); tín hiệu được nạp bằng `record_rtt(request_start.elapsed())` tại **cuối** quá trình inspection ([data_plane.rs:1733](../aegis-gate/crates/aegis-proxy/src/data_plane.rs#L1733)).

Hai hệ quả:

1. **Sai biến điều khiển.** Ở 11k, ràng buộc cứng là **CPU > 95%**, nhưng shedder lại nhìn **RTT**. RTT chỉ tăng *sau khi* hàng đợi đã dồn → shedder phản ứng **sau khi collapse đã bắt đầu**, không phòng ngừa. Google SRE khuyến nghị shed **trực tiếp theo CPU utilization**.
2. **Trễ một-request trong vòng phản hồi.** Tín hiệu điều khiển việc admit request N+1 lại là **độ trễ của request N** (đo ở cuối pipeline). Khi tải dốc lên, vòng phản hồi này luôn đuổi theo sau.

### 3.4 [By design — giữ nguyên] Critical miễn shed, nhưng có 1 hệ quả về vị trí

`should_admit(Tier::Critical)` trả `true` vô điều kiện ([shed.rs:121](../aegis-gate/crates/aegis-proxy/src/shed.rs#L121)) — **đúng ý vận hành, không sửa**. Chỉ nêu một tương tác liên quan tới vị trí: request Critical **vẫn gọi `admit_guard()`** (đếm inflight) và **vẫn nạp RTT** vào estimator. Nên một Critical-flood **tự làm bão hoà** WAF và **siết limit của tier thấp hơn**, trong khi bản thân Critical không có van. Cách xử lý đúng (không vi phạm "Critical không bị shed") là **dành riêng capacity/floor cho Critical** thay vì shed — xem §5.4.

---

## 4. Vì sao điều này gây collapse (nối với triệu chứng §0)

```
Vượt đầu gối (CPU>95%)
   │  shed dùng RTT (trễ) → chưa kịp từ chối
   ▼
Body của MỌI request (kể cả sắp-bị-shed) đã được đọc + alloc vào RAM (3.1)
   │  → allocator + memory-bandwidth pressure ↑ khi CPU đã cạn
   ▼
TLS handshake ở cửa không bị chặn (3.2) → CPU crypto ↑
   ▼
Chi phí mỗi request TĂNG (contention) → năng lực thực < 11k
   ▼
RTT mới bắt đầu tăng → shedder mới shed → nhưng đã muộn
   ▼
Goodput rơi về 2-3k thay vì plateau ở ~11k   = CLIFF
```

Việc shed đặt sai chỗ biến nó thành **van xả mở muộn**: tới lúc nó mở thì hệ đã trượt vào vùng work-amplification.

---

## 5. Hướng giải quyết đề xuất (theo chuẩn ngành)

Nguyên tắc: **đẩy quyết định shed lên SỚM NHẤT và RẺ NHẤT có thể**, dùng **CPU/concurrency** làm tín hiệu chính, giữ RTT-gradient làm phụ.

### 5.1 [P1 — ROI cao nhất] Di chuyển cổng shed lên TRƯỚC body buffering
- Chạy `should_admit(&tier)` **ngay sau khi có headers + tier**, **trước** `collect().await` ở [data_plane.rs:866](../aegis-gate/crates/aegis-proxy/src/data_plane.rs#L866).
- Request bị shed trả `503 + Retry-After` **mà không đọc/alloc body** → loại bỏ áp lực RAM ở §3.1.
- Tier classification cần tier sớm: dùng `early_tier` (path-based) đã có sẵn ở [data_plane.rs:578](../aegis-gate/crates/aegis-proxy/src/data_plane.rs#L578) cho quyết định shed cửa-trước; tier cuối (`route_tier`) vẫn dùng cho detector mask như cũ.

### 5.2 [P1] Thêm tín hiệu admission theo CPU / in-flight concurrency
- Bổ sung một gate **fast-reject theo CPU utilization** (vd > 85% → bắt đầu shed tier thấp) hoặc theo **in-flight concurrency cap** (semaphore) làm **tín hiệu chính**, RTT-gradient làm phụ.
- Đây là cách Google SRE ("shed khi CPU vượt ngưỡng") và AWS (concurrency/queue-depth) làm. Phản ứng *trước* khi RTT kịp tăng.

### 5.3 [P2] Admission ở tầng accept/TLS
- Thêm một **concurrency cap ở `accept.rs`** trước bắt tay TLS: khi vượt ngưỡng kết nối đang xử lý, từ chối/đóng sớm (hoặc không accept) để CPU crypto không bị flood.
- Cân nhắc backlog tường minh + `somaxconn`/`ulimit -n` (đã nêu ở các report perf khác).

### 5.4 [P2] Giữ "Critical không bị shed" một cách an toàn (KHÔNG đổi hành vi)
- **Giữ nguyên** `should_admit(Critical) = true`.
- Để Critical-flood không tự bão hoà cả node: **dành riêng một phần capacity/floor cho Critical** (reservation) tách khỏi limit của tier thấp, thay vì để Critical ăn chung inflight rồi siết tier khác. Critical vẫn luôn được nhận, nhưng không còn "kéo sập" phần còn lại.

### 5.5 [P3] Reject phải thật sự rẻ
- Đảm bảo nhánh 503 không kèm việc đắt (dựng audit event nặng, JSON lớn, blake3…). Reject phải < ~100µs để bản thân việc shed không trở thành tải.

---

## 6. Tiêu chí nghiệm thu (acceptance)

1. **Goodput plateau:** bắn 11k → 14k → 30k → 100k, goodput **giữ ngang ≈ mức đỉnh** (không rơi về 2-3k). Đây là phép thử quyết định.
2. **Không alloc body cho request bị shed:** xác nhận bằng profiler — request 503 không đi qua `collect()` ở line 866.
3. **p99 latency bị chặn** dưới tải vượt ngưỡng (không nổ vô hạn).
4. **Critical vẫn 100% được nhận** dưới mọi mức tải (hành vi giữ nguyên), trong khi tier thấp bị shed có kiểm soát.
5. **Recovery:** sau khi spike rút, goodput **tự hồi** về đỉnh (không kẹt ở trạng thái metastable).

---

## 7. File/line map (đã verify 2026-06-20)

| Thing | File:line |
|---|---|
| Entry handler + `request_start` | [data_plane.rs:228, 291](../aegis-gate/crates/aegis-proxy/src/data_plane.rs#L228) |
| DDoS check (early_tier) | [data_plane.rs:571-579](../aegis-gate/crates/aegis-proxy/src/data_plane.rs#L571) |
| Rate-limit | [data_plane.rs:734](../aegis-gate/crates/aegis-proxy/src/data_plane.rs#L734) |
| **Body buffering (collect)** | [data_plane.rs:866](../aegis-gate/crates/aegis-proxy/src/data_plane.rs#L866) |
| `tier = route_tier` | [data_plane.rs:935](../aegis-gate/crates/aegis-proxy/src/data_plane.rs#L935) |
| **Cổng shed** `should_admit`/`admit_guard` | [data_plane.rs:950-967](../aegis-gate/crates/aegis-proxy/src/data_plane.rs#L950) |
| **Detector pipeline** (regex + AI) | [data_plane.rs:985-991](../aegis-gate/crates/aegis-proxy/src/data_plane.rs#L985) |
| `record_rtt` (tín hiệu shedder, đo ở cuối) | [data_plane.rs:1733](../aegis-gate/crates/aegis-proxy/src/data_plane.rs#L1733) |
| Gradient2 logic | [shed.rs:85-142](../aegis-gate/crates/aegis-proxy/src/shed.rs#L85) |
| Critical miễn shed (by design) | [shed.rs:120-121](../aegis-gate/crates/aegis-proxy/src/shed.rs#L120) |
| accept layer (không có admission gate) | [accept.rs](../aegis-gate/crates/aegis-proxy/src/accept.rs) |

---

## 8. Tham chiếu chuẩn ngành

- Google SRE — *Handling Overload* (shed theo CPU, client-side throttling): https://sre.google/sre-book/handling-overload/
- Google SRE — *Addressing Cascading Failures* (positive feedback, retry storm): https://sre.google/sre-book/addressing-cascading-failures/
- AWS Builders' Library — *Using load shedding to avoid overload* (goodput plateau, reject-before-work): https://aws.amazon.com/builders-library/using-load-shedding-to-avoid-overload/
- Netflix — *concurrency-limits* (Gradient2 adaptive, fast-reject 429): https://github.com/Netflix/concurrency-limits
- WeChat — *DAGOR: Overload Control for Scaling Microservices* (cheapest-check-first): https://arxiv.org/pdf/1806.04075
- *Metastable Failures in the Wild* — USENIX OSDI 2022: https://www.usenix.org/system/files/osdi22-huang-lexiang.pdf

---

*Tóm tắt: cổng load-shed đặt đúng (trước detector) nhưng vẫn quá muộn — nó chạy SAU khi đã đọc + cấp phát toàn bộ body, KHÔNG có admission ở tầng accept/TLS, và dùng RTT (trễ) thay vì CPU làm tín hiệu. Đẩy quyết định shed lên trước body-buffering + thêm tín hiệu CPU/concurrency + admission ở cửa, đồng thời giữ nguyên "Critical không bị shed" bằng capacity reservation. Mục tiêu: goodput plateau ở ~11k dù bị bắn phá bao nhiêu.*
