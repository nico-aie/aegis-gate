# Aegis-Gate WAF — Redis Throughput Bottleneck Report

> **Mục đích:** Gửi chuyên gia phân tích/đánh giá & fix. Báo cáo mô tả hiện tượng sụp throughput dưới tải cao, chỉ ra các điểm lỗi trong thiết kế Redis của data-plane, kèm bằng chứng (file:line) và hướng giải quyết đề xuất.
>
> - **Service:** `aegis-gate` (Rust WAF reverse proxy)
> - **Target test:** `https://aiagent.waf-exams.info`
> - **Ngày:** 2026-06-20
> - **Phạm vi review:** đường đi của Redis trong `aegis-proxy` (rate-limit / ddos / state backend)

---

## 1. Tóm tắt điều hành (TL;DR)

WAF chạy ổn ở ~8,000 rps (CPU ~90%, RAM bình thường), nhưng khi nâng tải lên ~11,000 rps thì throughput **sụp xuống chỉ còn ~3,000 rps** (hiện tượng *performance cliff*, không phải xuống dốc tuyến tính). Khi profiling, **Redis là thành phần chậm bất thường**.

Nguyên nhân gốc là một **antipattern kinh điển**: rate-limit kiểu *sliding-window-log* lưu **mỗi request thành một member trong Redis ZSET**. Cộng thêm 4 yếu tố khuếch đại (pool quá nhỏ, 1 round-trip/op không pipelining, mutex toàn cục trên hot path, timeout 5s không fail-fast). Khi tải dồn vào **ít source IP** (đặc biệt là test từ 1 máy = 1 IP), toàn bộ áp lực đổ vào **một hot key duy nhất** mà Redis (single-threaded) phải xử lý tuần tự với độ phức tạp O(log N) trên cấu trúc ngày càng phình to → tạo vòng lặp dương → cliff.

**Lưu ý quan trọng (đọc kỹ §6):** trong các config hiện tại, đội đã refactor rate-limit/ddos về *in-process*, nên Redis có thể **không còn nằm trên hot path đồng bộ** ở mọi cấu hình. Do đó cần **xác nhận bằng đo đạc (§7)** xem Redis có thật sự trên critical path của config đang chạy hay không, **trước khi** tối ưu. Một phần con số "3000 rps" còn là **artifact của cách test bằng 1 source IP** (§6.b).

---

## 2. Hiện tượng quan sát được

| Tải bắn vào | Kết quả WAF | Tài nguyên |
|---|---|---|
| ~8,000 rps | Chạy ổn định, xử lý hết | CPU ~90%, RAM bình thường |
| ~11,000 rps | **Throughput tụt còn ~3,000 rps** | Redis chậm bất thường |

Đặc trưng: **cliff** (sụp đột ngột khi vượt một ngưỡng), không phải suy giảm dần. Đây là dấu hiệu kinh điển của **bão hoà tài nguyên có hàng đợi** (pool cạn / hot key serialize), không phải thiếu CPU thuần tuý.

---

## 3. Kiến trúc Redis hiện tại (tóm tắt)

- Client: `deadpool-redis 0.18` + `redis 0.27` (`tokio-comp`, `script`).
- Backend: `RedisBackend` tại [`crates/aegis-proxy/src/state/redis.rs`](../aegis-gate/crates/aegis-proxy/src/state/redis.rs).
- Pool tạo ở `connect()` với `.max_size(config.pool_size)` + `Runtime::Tokio1` — [redis.rs:275-280](../aegis-gate/crates/aegis-proxy/src/state/redis.rs#L275).
- Mỗi op = `conn()` lấy 1 connection từ pool → chạy **1 lệnh** → trả về. Không pipelining — [redis.rs:299](../aegis-gate/crates/aegis-proxy/src/state/redis.rs#L299).
- Rate-limit ở config dùng `algo: sliding_window`, `window: "1m"` — [config/dev.yaml:330](../aegis-gate/config/dev.yaml#L330).
- `pool_size`: `8` (cluster-a/b), `16` (dev/default), `32` (prod).

---

## 4. CHỖ LỖI — phân tích chi tiết

### 4.1 [GỐC — Critical] Sliding-window-log: lưu mỗi request thành 1 ZSET member

**Vị trí:** `SLIDING_WINDOW_LUA` — [redis.rs:69-85](../aegis-gate/crates/aegis-proxy/src/state/redis.rs#L69), gọi trong `incr_window()` — [redis.rs:475](../aegis-gate/crates/aegis-proxy/src/state/redis.rs#L475).

```lua
-- SLIDING_WINDOW_LUA
redis.call('ZREMRANGEBYSCORE', key, 0, now_ms - window_ms)  -- O(log N + M)
redis.call('ZADD', key, now_ms, member)                     -- O(log N), 1 member / request
redis.call('PEXPIRE', key, window_ms)
return redis.call('ZCARD', key)
```

`member` là duy nhất mỗi lần gọi (`"{now}:{uuid}"` — [redis.rs:485](../aegis-gate/crates/aegis-proxy/src/state/redis.rs#L485)), nghĩa là **mỗi request được lưu vĩnh viễn vào ZSET cho đến khi rơi ra khỏi cửa sổ**.

**Tại sao đây là lỗi:**

1. **Bộ nhớ & độ phức tạp tỉ lệ với lưu lượng:** với `window = 1m` và 11,000 rps dồn vào **một** key, ZSET đó giữ tới `11,000 × 60 ≈ 660,000` member. ZADD/ZREMRANGEBYSCORE trở thành O(log N) trên cấu trúc khổng lồ; ZREMRANGEBYSCORE còn O(M) theo số phần tử bị xoá mỗi nhịp.
2. **Redis là single-threaded:** mọi op trên **cùng một hot key** bị **serialize tuyệt đối** trên một core. Không thể scale bằng cách cấp thêm CPU cho Redis.
3. **Vòng lặp dương → cliff:** tải cao hơn → ZSET to hơn → mỗi op chậm hơn → pool giữ connection lâu hơn → hàng đợi dài hơn → latency tăng → … → sụp. Ngưỡng 8k chưa qua "đầu gối"; 11k vượt qua nên gãy.

**Nghịch lý:** code **đã có sẵn** `TOKEN_BUCKET_LUA` (O(1), chỉ lưu 2 field tokens/last_refill) — [redis.rs:89](../aegis-gate/crates/aegis-proxy/src/state/redis.rs#L89) — nhưng config lại chọn `sliding_window`. Sliding-window-log gần như **không bao giờ nên dùng** ở data-plane WAF; chuẩn công nghiệp là **fixed-window counter (INCR + EXPIRE, O(1))** hoặc **token-bucket / sliding-window-counter** (2 counter, O(1)).

---

### 4.2 [Khuếch đại — High] Connection pool quá nhỏ → trần throughput cứng

**Vị trí:** default `pool_size = 16` — [redis.rs:56](../aegis-gate/crates/aegis-proxy/src/state/redis.rs#L56); config thực tế `8` (cluster) / `32` (prod) — [config/cluster-a.yaml:90](../aegis-gate/config/cluster-a.yaml#L90).

Vì **mỗi op = đúng 1 round-trip** ([redis.rs:299](../aegis-gate/crates/aegis-proxy/src/state/redis.rs#L299), không pipelining), trần throughput của backend là:

```
max_throughput ≈ pool_size / latency_mỗi_op
```

Khi hot-key (§4.1) đẩy latency mỗi op lên ~2–3 ms:

```
8 connections / 3 ms ≈ 2,600 ops/s     → khớp với "tụt còn ~3,000 rps"
```

Khi offered load vượt trần này, `pool.get()` xếp hàng → in-flight phình → latency tăng tiếp → **cliff**. Đây là lý do trực tiếp con số dừng ở ~3,000.

---

### 4.3 [Khuếch đại — Medium] Mutex toàn cục trên mỗi op (latency ring)

**Vị trí:** [redis.rs:319](../aegis-gate/crates/aegis-proxy/src/state/redis.rs#L319) trong `with_timeout()`.

```rust
if let Ok(mut buf) = self.latency.lock() {   // Mutex chung, mọi op thành công đều lock
    buf.push(elapsed.as_micros() ...);
}
```

Ở 11k rps, **mọi worker thread tranh nhau một `Mutex`** chỉ để ghi histogram latency → contention cross-core ngay trên hot path. Telemetry không nên nằm trên đường nóng dưới dạng mutex chung.

---

### 4.4 [Khuếch đại — High] Timeout 5s, không fail-fast / không circuit breaker

**Vị trí:** default `timeout = 5s` — [redis.rs:57](../aegis-gate/crates/aegis-proxy/src/state/redis.rs#L57); áp dụng ở [redis.rs:315](../aegis-gate/crates/aegis-proxy/src/state/redis.rs#L315).

Khi Redis chậm, mỗi request **chờ tới 5 giây** thay vì bỏ nhanh. Hệ quả: in-flight requests và RAM bùng nổ, biến tình trạng "chậm" thành "sập" (cascading failure). Data-plane WAF cần **fast-fail (~50–100 ms) + circuit breaker + fail-open** để không kéo sập toàn hệ thống vì một dependency chậm.

---

### 4.5 [Khuếch đại — Medium] Nhiều round-trip tuần tự mỗi request (ở biến thể Redis của ddos)

**Vị trí:** biến thể `check_with_tier(state, ip, tier)` — [ddos.rs:549](../aegis-gate/crates/aegis-security/src/ddos.rs#L549).

```
state.is_auto_blocked(ip).await?      // RTT #1
state.incr_window(...).await?         // RTT #2  (chính là ZSET-log ở §4.1)
state.auto_block(...).await?          // RTT #3  (khi breach)
```

Tối đa 3 round-trip **nối tiếp** mỗi request. Cần gộp thành **1 Lua script atomic** (check-block + incr + maybe-block trong một lần EVALSHA) để giảm xuống 1 RTT.

---

## 5. Cơ chế sụp đổ (vì sao 8k ổn nhưng 11k gãy)

```
Tải tăng  ──►  Hot ZSET (1 key/1 source IP) phình to
            ──►  ZADD/ZREMRANGEBYSCORE chậm dần (O(log N), single-thread Redis)
            ──►  Mỗi op giữ connection lâu hơn
            ──►  Pool (8–32) cạn  ──►  pool.get() xếp hàng
            ──►  In-flight phình + timeout 5s giữ request lâu
            ──►  Latency tăng  ──►  ZSET càng to  ──►  (quay lại đầu)  ⟲  CLIFF
```

Throughput của một hot key bị chặn cứng bởi `1 / op_latency` của Redis trên key đó. 8k rps nằm dưới "đầu gối" của đường cong; 11k vượt qua → rơi tự do về ~3,000.

---

## 6. ⚠️ Bối cảnh quan trọng — phải đọc trước khi fix

### 6.a Rate-limit/ddos đã được refactor về in-process

Đội đã chuyển quyết định per-request của ddos/rate-limit **về in-process**, bỏ round-trip Redis khỏi hot path:

- Perf-note: *"the per-request decision is now fully in-process: NO `StateBackend` round-trip on the hot path (was 2 — `is_auto_blocked` + `incr_window`)"* — [ddos.rs:289](../aegis-gate/crates/aegis-security/src/ddos.rs#L289).
- Data-plane gọi bản in-process `check_with_tier(peer_ip, tier)`; Redis chỉ bị đụng **fire-and-forget** khi có IP **mới** bị block (`tokio::spawn`) — [ddos.rs:327](../aegis-gate/crates/aegis-security/src/ddos.rs#L327).
- Rate-limit per-request là **in-process** `IpRateLimiter` — [data_plane.rs:734](../aegis-gate/crates/aegis-proxy/src/data_plane.rs#L734).

→ Trong config dev/cluster, **Redis có thể không nằm trên critical path đồng bộ** của rate-limit nữa. Nếu vẫn thấy Redis bão hoà, cần xác định op nào (có thể là L2 cache, metrics flush, auto_block propagation, hoặc một config bật biến thể Redis của ddos ở §4.5).

### 6.b Cách test bằng 1 source IP đang phóng đại vấn đề

Bắn tải từ 1 máy = **1 source IP**. Cả hai đường đều dồn 100% tải vào **đúng 1 key / 1 shard**:

- **Bản Redis:** một hot ZSET duy nhất (§4.1).
- **Bản in-process:** một entry `DashMap<key, VecDeque<Instant>>` — một shard, một `VecDeque` khổng lồ, lock mỗi request — [ddos.rs:452](../aegis-gate/crates/aegis-security/src/ddos.rs#L452).

Production với hàng nghìn IP thật sẽ **trải đều** ra nhiều key/shard và **không gãy như thế này**. Vì vậy một phần "3000 rps" là **artifact của phương pháp test**, một phần là **design thật sự cần sửa** (ZSET-log + pool nhỏ).

**Khuyến nghị test lại:** dùng nhiều source IP (hoặc X-Forwarded-For xoay vòng, nếu được tin cậy) để tách *artifact đo đạc* khỏi *lỗi thiết kế*.

---

## 7. Cách xác nhận thủ phạm (chạy khi đang load)

```bash
redis-cli SLOWLOG RESET            # trước khi bắn tải
# ... bắn tải ...
redis-cli SLOWLOG GET 20           # op nào chậm nhất
redis-cli INFO commandstats        # ZADD / ZREMRANGEBYSCORE / EVALSHA chiếm % nào
redis-cli --bigkeys                # tìm hot key g:rl:sw:* khổng lồ
redis-cli ZCARD g:rl:sw:ddos:ip:none:<your_ip>   # 1 key có bao nhiêu member
redis-cli INFO clients             # blocked_clients, connected_clients vs pool_size
redis-cli --latency                # latency nền của chính Redis
redis-cli INFO cpu                 # used_cpu_sys/user — Redis có nghẽn 1 core không
```

**Tín hiệu xác nhận §4.1:** `commandstats` cho thấy ZADD/ZREMRANGEBYSCORE thống trị, và `--bigkeys` ra một ZSET vài trăm nghìn member.

---

## 8. Hướng giải quyết đề xuất (ưu tiên)

| # | Hạng mục | Việc cần làm | Mức độ |
|---|---|---|---|
| 1 | **Fix gốc (§4.1)** | Đổi rate-limit Redis từ *sliding-window-log* → **fixed-window (INCR+EXPIRE, O(1))** hoặc **sliding-window-counter (2 counter)**; hoặc dùng `TOKEN_BUCKET_LUA` đã có | Critical |
| 2 | **Pool (§4.2)** | Nâng `pool_size` lên **64–128**; cân nhắc `MultiplexedConnection` + **pipelining** để mỗi connection phục vụ nhiều inflight | High |
| 3 | **Fail-fast (§4.4)** | Hạ per-op timeout xuống **~50–100 ms** + thêm **circuit breaker**, **fail-open** trên data-plane | High |
| 4 | **Round-trip (§4.5)** | Gộp check-block + incr + maybe-block thành **1 Lua atomic** (1 RTT thay vì 3) | Medium |
| 5 | **Mutex (§4.3)** | Bỏ `Mutex` latency-ring khỏi hot path → atomic histogram / sharded counters | Medium |
| 6 | **Phương pháp test (§6.b)** | Re-test với **nhiều source IP** để đo đúng hành vi production | High |
| 7 | **Xác minh (§6.a, §7)** | Trước khi tối ưu, **xác nhận** Redis có thật sự trên hot path của config đang chạy không | Bắt buộc |

---

## 9. Phụ lục — Bản đồ file/line tham chiếu

| Vấn đề | File:line |
|---|---|
| `RedisConfig` default (pool_size=16, timeout=5s) | [redis.rs:43-58](../aegis-gate/crates/aegis-proxy/src/state/redis.rs#L43) |
| `SLIDING_WINDOW_LUA` (ZSET-log) | [redis.rs:69-85](../aegis-gate/crates/aegis-proxy/src/state/redis.rs#L69) |
| `TOKEN_BUCKET_LUA` (O(1), đã có sẵn) | [redis.rs:89](../aegis-gate/crates/aegis-proxy/src/state/redis.rs#L89) |
| Pool tạo `.max_size().runtime()` | [redis.rs:275-280](../aegis-gate/crates/aegis-proxy/src/state/redis.rs#L275) |
| `conn()` — 1 RTT/op, không pipelining | [redis.rs:299](../aegis-gate/crates/aegis-proxy/src/state/redis.rs#L299) |
| `with_timeout()` + Mutex latency + timeout 5s | [redis.rs:310-340](../aegis-gate/crates/aegis-proxy/src/state/redis.rs#L310) |
| `incr_window()` (gọi ZSET-log) | [redis.rs:475](../aegis-gate/crates/aegis-proxy/src/state/redis.rs#L475) |
| ddos in-process (perf note) | [ddos.rs:289-298](../aegis-gate/crates/aegis-security/src/ddos.rs#L289) |
| ddos in-process DashMap VecDeque | [ddos.rs:452](../aegis-gate/crates/aegis-security/src/ddos.rs#L452) |
| ddos biến thể Redis (3 RTT tuần tự) | [ddos.rs:549-588](../aegis-gate/crates/aegis-security/src/ddos.rs#L549) |
| Rate-limit in-process trên hot path | [data_plane.rs:734](../aegis-gate/crates/aegis-proxy/src/data_plane.rs#L734) |
| Config rate-limit `algo: sliding_window` | [config/dev.yaml:330](../aegis-gate/config/dev.yaml#L330) |
| `pool_size` theo môi trường (8/16/32) | [cluster-a.yaml:90](../aegis-gate/config/cluster-a.yaml#L90), [prod.yaml:124](../aegis-gate/config/prod.yaml#L124) |

---

*Báo cáo tạo để gửi chuyên gia đánh giá & fix. Mọi nhận định đều kèm tham chiếu file:line trong repo `aegis-gate` để kiểm chứng trực tiếp.*
