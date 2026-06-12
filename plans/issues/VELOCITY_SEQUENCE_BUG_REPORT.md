# Bug Report — VelocitySequenceDetector Không Tắt Được Qua Dashboard/Mask

**File:** `crates/aegis-security/src/detectors/velocity_sequence.rs`  
**Severity:** High — gây block sai (False Positive) ngay cả khi operator đã tắt toàn bộ detectors  
**Symptom:** WAF vẫn block `POST /deposit` và `POST /withdrawal` với rules `velocity_login_to_deposit`, `velocity_otp_to_deposit`, `velocity_login_to_withdrawal`, `velocity_otp_to_withdrawal` dù đã tắt hết detectors trên dashboard  
**Root cause:** ID mismatch giữa `VelocitySequenceDetector::id()` và `DetectorClass::Velocity::as_str()`

---

## 1. Triệu chứng

Trong dashboard (Live Feed), các request bị block bởi velocity rules dù operator đã tắt toàn bộ detectors:

```
POST /deposit    → BLOCK  rules: velocity_login_to_deposit, velocity_otp_to_deposit
POST /withdrawal → BLOCK  rules: velocity_login_to_withdrawal, velocity_otp_to_withdrawal
POST /withdrawal → BLOCK  rules: velocity_login_to_withdrawal, velocity_otp_to_withdrawal
```

Score breakdown từ rules:

| Rule | Score | Threshold để block |
|------|-------|--------------------|
| `velocity_login_to_deposit` | 60 | ≥60 → BLOCK |
| `velocity_login_to_withdrawal` | 70 | ≥60 → BLOCK |
| `velocity_otp_to_deposit` | 50 | ≥60 → không block một mình |
| `velocity_otp_to_withdrawal` | 60 | ≥60 → BLOCK |

Khi `login + otp` đều hit trước `deposit`: score = 60 + 50 = 110 → BLOCK chắc chắn.

---

## 2. Root Cause — ID Mismatch

### 2.1 Detector trả về ID sai

**File:** `velocity_sequence.rs:228`

```rust
impl Detector for VelocitySequenceDetector {
    fn id(&self) -> &'static str {
        "velocity_sequence"   // ← trả về "velocity_sequence"
    }
    // ...
}
```

### 2.2 DetectorClass đăng ký string khác

**File:** `mask.rs:124`

```rust
DetectorClass::Velocity => "velocity",   // ← class string là "velocity"
```

### 2.3 Mask lookup fallback về `true` khi không match

**File:** `mask.rs:251-257`

```rust
pub fn is_enabled_id(self, id: &str) -> bool {
    match DetectorClass::from_id(id) {
        Some(c) => self.is_enabled(c),
        // Unknown detectors run unconditionally.  ← đây là vấn đề
        None => true,
    }
}
```

### 2.4 Chuỗi lỗi đầy đủ

```
run_all_filtered_timed() gọi:
  mask.is_enabled_id("velocity_sequence")
    → DetectorClass::from_id("velocity_sequence")
    → tìm trong ALL classes: không có class nào có as_str() == "velocity_sequence"
       (Velocity class có as_str() == "velocity", không phải "velocity_sequence")
    → trả về None
    → is_enabled_id trả về true   ← detector LUÔN chạy, bỏ qua mask hoàn toàn
```

**Kết quả:** Dù operator toggle off "velocity" trên dashboard hay tắt toàn bộ detectors, `VelocitySequenceDetector` vẫn chạy và emit signals vì nó được hệ thống xem là "unknown detector" → run unconditionally.

---

## 3. Tại Sao Lại Có Mismatch?

`VelocitySequenceDetector` có tên internal là `velocity_sequence` (mô tả đúng chức năng: sequence-based velocity detection). Nhưng `DetectorClass` đặt tên đơn giản hơn là `velocity`.

Hai tên này chưa bao giờ được sync lại — detector được thêm vào sau khi `DetectorClass::Velocity` đã tồn tại, và không có compile-time check nào đảm bảo `Detector::id()` phải match `DetectorClass::as_str()`.

---

## 4. Fix

### 4.1 Fix ngắn gọn — đổi ID của detector

**File:** `crates/aegis-security/src/detectors/velocity_sequence.rs`, dòng 228

```rust
// TRƯỚC (bị lỗi):
fn id(&self) -> &'static str {
    "velocity_sequence"
}

// SAU (đúng):
fn id(&self) -> &'static str {
    "velocity"
}
```

Sau fix này, `is_enabled_id("velocity")` → `from_id("velocity")` → `Some(DetectorClass::Velocity)` → `self.is_enabled(Velocity)` → tôn trọng trạng thái mask đúng cách.

### 4.2 Cập nhật unit test bị ảnh hưởng

**File:** `velocity_sequence.rs:425`

```rust
// TRƯỚC:
fn id_is_velocity_sequence() {
    assert_eq!(VelocitySequenceDetector::new().id(), "velocity_sequence");
}

// SAU:
fn id_is_velocity_sequence() {
    assert_eq!(VelocitySequenceDetector::new().id(), "velocity");
}
```

### 4.3 Cập nhật signal tag nếu cần

Hiện tại signal tags (`velocity_login_to_deposit`, `velocity_login_to_withdrawal`, v.v.) được tạo từ `EndpointTag::as_str()`, không phụ thuộc vào `Detector::id()`:

```rust
signals.push(Signal {
    score: rule.score,
    tag: format!("velocity_{}_to_{}", rule.prev.as_str(), rule.next.as_str()),
    // ...
});
```

**Các tags này KHÔNG thay đổi** khi fix `id()` — dashboard rules vẫn hiển thị đúng tên `velocity_login_to_deposit`, v.v.

---

## 5. Vấn Đề Thứ Cấp — Không Có Compile-time Enforcement

Không có cơ chế nào đảm bảo `Detector::id()` match với `DetectorClass::as_str()`. Có thể xảy ra lại với detectors khác trong tương lai.

**Khuyến nghị** (optional, cho sprint sau):

Thêm một integration test trong `mask.rs` hoặc `mod.rs`:

```rust
#[test]
fn all_registered_detectors_have_known_class_ids() {
    use crate::detectors::{default_detectors_with_canary, DetectorClass};
    use aegis_core::config::DetectorsConfig;
    use crate::detectors::canary::CanaryPaths;

    let cfg = DetectorsConfig::default();
    let canary = CanaryPaths::default();
    let detectors = default_detectors_with_canary(&cfg, &canary);

    for d in &detectors {
        assert!(
            DetectorClass::from_id(d.id()).is_some(),
            "Detector '{}' has no matching DetectorClass — mask gating will not work",
            d.id()
        );
    }
}
```

Test này sẽ fail ngay khi ai thêm detector mới với ID không match class, thay vì silently bypass mask.

---

## 6. Tóm Tắt

| | Trước fix | Sau fix |
|---|---|---|
| `VelocitySequenceDetector::id()` | `"velocity_sequence"` | `"velocity"` |
| `DetectorClass::from_id("velocity_sequence")` | `None` | — |
| `DetectorClass::from_id("velocity")` | `Some(Velocity)` | `Some(Velocity)` |
| Mask toggle "velocity" có hiệu lực? | **Không** | **Có** |
| Disable toàn bộ detectors có tắt được? | **Không** | **Có** |
| Signal tags thay đổi? | — | Không (tags độc lập với id) |

---

**Files cần sửa:**

1. [`crates/aegis-security/src/detectors/velocity_sequence.rs:228`](../aegis-gate/crates/aegis-security/src/detectors/velocity_sequence.rs) — đổi `"velocity_sequence"` → `"velocity"` trong `fn id()`
2. [`crates/aegis-security/src/detectors/velocity_sequence.rs:425`](../aegis-gate/crates/aegis-security/src/detectors/velocity_sequence.rs) — cập nhật assert trong `test id_is_velocity_sequence`
