# WAF Hackathon 2026 — Candidate Briefing

> Tài liệu này là bản tóm tắt dành cho các đội tham gia. Nội dung chi tiết và ràng buộc kỹ thuật nằm trong [`final_docs/VN_waf_interop_contract_v2.3.md`](final_docs/VN_waf_interop_contract_v2.3.md) và API public nằm trong [`final_docs/openapi.public.yaml`](final_docs/openapi.public.yaml).

---

## 1. Mục tiêu cuộc thi

Các đội sẽ xây dựng một WAF chạy phía trước target application. WAF cần bảo vệ upstream khỏi traffic không an toàn nhưng vẫn cho phép traffic hợp lệ hoạt động bình thường.

Một WAF tốt cần cân bằng 3 mục tiêu:

1. **Security efficacy**: nhận diện và xử lý request có rủi ro.
2. **Low false positive**: không làm gián đoạn user hợp lệ hoặc business flow hợp lệ.
3. **Operational quality**: có observability rõ ràng, log đầy đủ, chạy ổn định và dễ vận hành.

Nói ngắn gọn: **WAF phải bảo vệ được hệ thống, nhưng không được trở thành nguyên nhân làm hệ thống chậm, sai hoặc sập.**

---

## 2. Tổng quan 3 vòng thi

Cuộc thi được chia thành 3 vòng. Phần bên dưới chỉ mô tả mục tiêu và tiêu chí ở mức tổng quan để teams định hướng thiết kế WAF; chi tiết cách chạy, dữ liệu kiểm thử và logic đánh giá nội bộ không được công bố.

| Vòng | Tên vòng | Nội dung chính | Tiêu chí chấm ở mức tổng quan |
|------|----------|----------------|--------------------------------|
| 1 | **Kiểm định chức năng WAF-PROXY (Rust) & WAF-FE (Dashboard)** | Kiểm tra WAF có chạy được bình thường không, core viết bằng Rust, có Dashboard quản trị cơ bản và đáp ứng các tiêu chí tối thiểu của một WAF. | Khởi chạy thành công; reverse proxy hoạt động; chặn được tấn công cơ bản; quản lý rule qua UI; hot-reload hoạt động; có log/monitor. Vòng này là vòng loại trực tiếp (Pass/Fail). |
| 2 | **Automated benchmark & đối kháng** | Benchmark tool chạy qua WAF để kiểm tra khả năng xử lý traffic rủi ro và traffic hợp lệ trên API public. | Required headers/audit log/control plane đúng contract; action/risk/rule/mode nhất quán; xử lý request rủi ro phù hợp; false positive thấp; behavior trong `enforce` và `log_only` đúng semantics. |
| 3 | **Hiệu năng, khả năng chịu tải & điểm cộng nâng cao** | Sau khi WAF pass vòng benchmark chức năng, kiểm tra hiệu suất thực tế, khả năng chịu áp lực, mức độ sẵn sàng enterprise và các tính năng mở rộng/sáng tạo. | Hiệu năng tổng thể; khả năng chịu tải; khả năng scale/mở rộng; chất lượng vận hành; tính ổn định trong điều kiện áp lực; điểm cộng theo Tier A/B/C cho các tính năng nâng cao. |

### 2.1 Cơ cấu tính điểm (Scoring Model)
Điểm chung cuộc của các đội sẽ được tính dựa trên trọng số của các vòng thi như sau:
- **Vòng 1 (Kiểm định chức năng):** Đây là vòng **loại trực tiếp (Pass/Fail)**. Tất cả các đội bắt buộc phải Pass vòng này để được đi tiếp.
- **Vòng 2 (Automated Benchmark):** Chiếm **65%** tổng số điểm. Vòng này đóng vai trò như một "cửa ải" (gate). WAF phải đạt tối thiểu **70%** điểm tuân thủ contract ở Vòng 2 mới đủ điều kiện bước vào Vòng 3.
- **Vòng 3 (Hiệu năng & Chịu tải):** Chiếm **35%** tổng số điểm. Điểm cộng (Bonus) từ các tính năng nâng cao sẽ được xét ở Vòng 3 và cộng trực tiếp vào điểm tổng. Nếu một đội không đạt đủ 70% ở Vòng 2, đội đó sẽ không được tham gia chấm điểm Vòng 3. Khi đó, điểm chung cuộc của đội chỉ bao gồm số điểm tương ứng với các test case đã pass ở Vòng 2.

### 2.2 Vòng 1 — Kiểm định chức năng WAF-PROXY (Rust) & WAF-FE (Dashboard)

Vòng 1 là vòng **loại trực tiếp (Pass/Fail)**. Nếu hệ thống không đạt các tiêu chí cơ bản dưới đây, đội thi sẽ bị loại khỏi cuộc thi. Mục tiêu của vòng này là đảm bảo WAF có thể chạy được bình thường, hoạt động đúng vai trò của một Reverse Proxy và có công cụ quản trị (Dashboard) vận hành thực tế.

**Các tiêu chí chấm điểm cụ thể (Bắt buộc phải đạt để qua vòng 1):**

**1. WAF-PROXY (Core System)**
- **Công nghệ bắt buộc:** Core proxy phải được viết hoàn toàn bằng **Rust**.
  - *Đánh giá:* BTC sẽ review source code và quy trình build để xác nhận tính tuân thủ.
- **Khởi chạy & Vận hành:** Build thành single binary, khởi chạy thành công và duy trì trạng thái hoạt động ổn định.
  - *Đánh giá:* Hệ thống phải khởi động thành công qua command line và không bị crash/panic khi xử lý một lượng traffic hợp lệ liên tục.
- **Reverse Proxy:** Đảm bảo luồng traffic cơ bản hoạt động xuyên suốt:
  - **REQUEST:** Client -> WAF-PROXY -> UPSTREAM
  - **RESPONSE:** UPSTREAM -> WAF-PROXY -> CLIENT
  - *Đánh giá:* WAF phải forward chính xác các HTTP methods, headers và body tới upstream, đồng thời trả về nguyên vẹn response từ upstream mà không làm biến dạng dữ liệu hợp lệ.
- **Bảo mật cơ bản:** Có khả năng phát hiện và ngăn chặn các nhóm tấn công cơ bản nhất (OWASP Top 5) và kiểm soát truy cập (Blacklist, Rate Limit).
  - *Đánh giá:* BTC sẽ sử dụng một tập hợp các payload tấn công phổ biến. WAF phải nhận diện đúng và thực thi action ngăn chặn (ví dụ: trả về HTTP 403) thay vì để lọt tới upstream.

**2. WAF-FE (Dashboard & Quản trị)**
- **Tính năng bắt buộc (Functional completeness):**
  - **Real-time monitor:** Log/Event phải xuất hiện trên Dashboard trong vòng **≤ 5 giây** kể từ khi WAF xử lý request.
  - **Quản lý Rule/Config:** Hỗ trợ đầy đủ các thao tác Thêm/Sửa/Xóa/Bật/Tắt rule qua UI.
  - **Audit Log Viewer:** Có khả năng tìm kiếm và filter log (theo thời gian, IP, Rule ID, Request ID).
  - **Health/Status View:** Hiển thị được trạng thái cơ bản của WAF (Uptime, Mode hiện tại, Số lượng rule đang active).
- **Hiệu quả vận hành (Operational efficiency):**
  - **Hot-reload:** Thời gian từ lúc bấm "Save" rule trên UI đến khi rule có hiệu lực thực tế dưới WAF-PROXY phải **≤ 10 giây** (không cần restart service). Có dấu hiệu nhận biết trên UI là config đã được apply thành công.
  - **Usability:** Thao tác tạo rule mới nhanh chóng (mục tiêu ≤ 5 clicks). Tìm kiếm một event cụ thể trong Audit Log dễ dàng (mục tiêu ≤ 30 giây).
- **Tính hiệu lực của Features/Rules/Policies:** Tất cả feature/policy được trình bày trong UI/UX hoặc mô tả trong tài liệu submit phải có tác động thực tế tới behavior của WAF-PROXY. UI đẹp, workflow đầy đủ hoặc tài liệu mô tả chi tiết sẽ không được tính là hợp lệ nếu feature đó chỉ là demo/mock hoặc không điều khiển được WAF-PROXY thật.
  - *Đánh giá:* BTC sẽ đối chiếu trạng thái cấu hình trên UI, workflow được mô tả trong tài liệu submit và behavior thực tế của WAF-PROXY thông qua việc gửi traffic kiểm chứng. Nếu UI báo thao tác thành công hoặc tài liệu mô tả feature đã hỗ trợ, nhưng traffic thực tế không bị ảnh hưởng đúng như expected behavior (ví dụ: bật chặn IP trên UI nhưng IP đó vẫn truy cập được), thì feature đó bị đánh giá là không đạt.
  - *Các trường hợp có thể bị trừ điểm hoặc không được tính điểm cộng:* UI hiển thị feature/policy nhưng thao tác bật/tắt/cấu hình không làm thay đổi behavior thực tế của WAF-PROXY; tài liệu submit mô tả một feature đang được hỗ trợ nhưng BTC không kiểm chứng được bằng traffic thực tế; Dashboard dùng mock data, state cục bộ hoặc response giả lập khiến trạng thái UI không khớp với trạng thái thật của WAF-PROXY; feature chỉ hoạt động ở tầng hiển thị nhưng không enforce/detect/log đúng như expected behavior đã mô tả.

*(Lưu ý: Tài liệu này cố tình không liệt kê các tiêu chí bảo mật nâng cao, cơ chế chống abuse phức tạp hay các yêu cầu về hiệu năng của WAF-PROXY. Những yếu tố này sẽ là trọng tâm chấm điểm phân hạng ở Vòng 2 và Vòng 3. Các đội cần tự nghiên cứu và thiết kế kiến trúc phù hợp để giành điểm cao ở các vòng sau).*

### 2.3 Vòng 2 — Automated benchmark & đối kháng

Vòng này là nơi benchmark tool chạy qua WAF để đánh giá behavior theo contract. Teams không cần biết workflow nội bộ của tool; chỉ cần đảm bảo WAF tuân thủ interop contract và hoạt động tổng quát trên API surface public. *(Lưu ý: File `openapi.public.yaml` chỉ cung cấp để các team hiểu tổng quan sơ bộ về target application. Trên thực tế, một WAF chuẩn phải có khả năng bảo vệ ứng dụng mà không cần phụ thuộc hay biết trước về source code hay các endpoint cụ thể của ứng dụng đó).* Để đảm bảo công bằng và minh bạch, sau vòng này mỗi team sẽ nhận được benchmark report để biết kết quả và điểm số của mình.

Tiêu chí tổng quan:

- **Tuân thủ Tuyệt đối Interop Contract:** WAF phải implement đầy đủ các control endpoints (`/__waf_control/capabilities`, `reset_state`, `set_profile`, `flush_cache`) và xác thực bằng `X-Benchmark-Secret`. Các endpoint này phải hoạt động đúng semantics (ví dụ: `reset_state` phải clear toàn bộ state nhưng giữ nguyên audit log). **Cảnh báo:** Benchmark tool của BTC được lập trình để chấm điểm tự động dựa trên Interop Contract. Nếu WAF không tuân thủ đúng định dạng (sai tên header, sai format JSON, thiếu trường bắt buộc), tool sẽ không nhận diện được và đánh giá là Fail. Các đội phải tự chịu trách nhiệm nếu mất điểm do lỗi không tuân thủ contract.
- **Observability Headers:** Mọi response trả về từ WAF (kể cả allow hay block) đều BẮT BUỘC phải có đầy đủ các headers tối thiểu: `X-WAF-Request-Id`, `X-WAF-Risk-Score`, `X-WAF-Action`, `X-WAF-Rule-Id`, `X-WAF-Cache`, `X-WAF-Mode`. Thiếu hoặc sai format sẽ bị tính là lỗi contract. *(Lưu ý: Đây là minimum requirements. Teams được khuyến khích thêm các custom `X-WAF-*` headers để hỗ trợ tracing, debug hoặc hiển thị trên Dashboard. Việc có thêm các headers hữu ích sẽ là một điểm cộng lớn).*
- **Audit Log:** Phải ghi log ra file `./waf_audit.log` theo chuẩn JSONL với đầy đủ các trường bắt buộc tối thiểu (`request_id`, `ts_ms`, `ip`, `method`, `path`, `action`, `risk_score`, `mode`). *(Tương tự như headers, teams có thể thêm các trường JSON khác vào log để làm giàu dữ liệu cho SIEM/Dashboard, và điều này sẽ được tính là điểm cộng).*
- **Xử lý rủi ro (Enforce mode):** Request rủi ro phải được xử lý bằng action phù hợp (`block`, `challenge`, `rate_limit`, `timeout`, `circuit_breaker`) và thực sự ngăn chặn được payload chạm tới upstream.
- **Chế độ Log Only:** Khi được set qua `set_profile` thành `log_only`, WAF vẫn phải detect và ghi nhận action dự kiến vào header/log, nhưng KHÔNG ĐƯỢC chặn request (phải cho qua upstream).
- **False Positive:** Request hợp lệ trên các API public không được phép bị chặn nhầm.

**Lưu ý quan trọng (Disclaimer):** Các tiêu chí trên là **nguyên tắc đánh giá cốt lõi**. Benchmark tool của BTC sẽ sử dụng hàng ngàn test case động (dynamic payloads, mutated requests, edge cases, evasion techniques) dựa trên các nguyên tắc này. Việc WAF chỉ chặn được một vài payload cơ bản (hardcode) nhưng thất bại trước các biến thể (mutations) hoặc các kịch bản tấn công phức hợp (chained attacks) sẽ bị trừ điểm nặng hoặc đánh giá không đạt. BTC bảo lưu quyền sử dụng các test case ẩn (hidden scenarios) không được công bố trước để đánh giá năng lực phòng thủ thực sự của WAF.

Tài liệu này không liệt kê payload, route ưu tiên, rule mapping hoặc hidden scenario. Teams nên build WAF tổng quát, observable và ổn định trên toàn bộ API surface trong OpenAPI public.

### 2.4 Vòng 3 — Hiệu năng & khả năng chịu tải

Vòng này dành cho các WAF đã pass vòng 2 ở mức benchmark chức năng. Mục tiêu là chấm điểm hiệu suất và mức độ sẵn sàng enterprise: WAF có chạy nhanh, ổn định, chịu tải tốt, scale được và vận hành được trong môi trường thực tế hay không.

**Tính chất đối kháng trực tiếp:** Ở vòng này, các WAF vượt qua Vòng 2 sẽ được đưa lên bàn cân để **so đọ trực tiếp với nhau**. Đội chiến thắng sẽ là đội có WAF sở hữu bộ tính năng (features) hoàn thiện hơn, tốc độ xử lý request nhanh hơn, overhead thấp hơn và duy trì performance tốt nhất dưới cùng một áp lực tải.

Bài kiểm tra có thể bao gồm stress test từ localhost và traffic áp lực/DDoS từ bên ngoài để quan sát hiệu năng thực tế. BTC cũng có thể xem xét khả năng mở rộng, kiến trúc vận hành, khả năng scale theo tài nguyên/hạ tầng, và cách WAF giữ chất lượng dịch vụ khi traffic thay đổi mạnh.

Tiêu chí ở vòng này được giữ ở mức tổng quan:

- Hiệu suất xử lý và độ trễ khi đi qua WAF (Latency overhead).
- Khả năng chịu tải, ổn định và phục hồi khi có áp lực lớn (Throughput & Resilience).
- Khả năng scale/mở rộng theo hướng enterprise.
- Chất lượng vận hành khi hệ thống hoặc upstream gặp điều kiện bất lợi (Graceful degradation).
- Khả năng duy trì observability và behavior nhất quán trong điều kiện tải cao.

**Điểm cộng (Bonus Features - Phân loại theo Tier)**
Các tính năng mở rộng và sáng tạo của WAF-FE sẽ được cộng điểm theo mức độ ưu tiên từ cao xuống thấp (Tier A > Tier B > Tier C). Việc triển khai nhiều tính năng trong cùng một Tier sẽ mang lại điểm cộng giảm dần (diminishing returns).
- **Tier A (Bảo mật & Phát hiện):** Các tính năng giúp tăng cường khả năng nhận diện rủi ro, làm giàu dữ liệu bảo mật (enrichment), trực quan hóa các mẫu tấn công phức tạp, hoặc cung cấp môi trường giả lập/kiểm thử rule an toàn.
- **Tier B (Vận hành nâng cao):** Các tính năng giúp tối ưu hóa trải nghiệm quản trị viên, quản lý vòng đời cấu hình (versioning, rollback), hoặc hỗ trợ triển khai cấu hình quy mô lớn.
- **Tier C (Tích hợp hệ thống):** Các tính năng giúp WAF giao tiếp với hệ sinh thái bên ngoài như đẩy log tập trung, cảnh báo tự động, hoặc xuất metrics cho hệ thống giám sát.

Tài liệu này không công bố ngưỡng tải, pattern traffic, kiến trúc kỳ vọng hoặc cách tính điểm chi tiết. Teams nên tối ưu WAF theo hướng sản phẩm thật: nhanh, ổn định, mở rộng được, observable và an toàn khi chịu áp lực.

---

## 3. Yêu cầu tài liệu khi submit WAF

Khi submit WAF, teams cần nộp thêm một file hướng dẫn đi kèm. File này nên liệt kê workflow của các features chính để BTC hiểu dụng ý thiết kế, cách vận hành và ý đồ bảo vệ của WAF.

Mỗi feature/policy nên mô tả ngắn gọn theo format tương tự:

```md
+ Policy/Feature: Blacklist
+ Description: Cung cấp cơ chế bảo vệ website bằng cách chặn truy cập dựa trên các thuộc tính của client. Feature này giúp phòng thủ trước các nguồn truy cập độc hại đã biết, scanners hoặc visitors đáng nghi bằng cách từ chối truy cập dựa trên IP address.
+ How it works:
1. WAF kiểm tra incoming requests theo các tiêu chí blacklist được cấu hình, ví dụ IP address.
2. Blacklist có thể được khai báo trực tiếp trong configuration hoặc load từ config file.
3. Nếu visitor match bất kỳ blacklist rule nào, access sẽ bị deny.
```

File hướng dẫn không cần tiết lộ source code nội bộ, nhưng phải đủ rõ để BTC hiểu feature hoạt động như thế nào, cấu hình ở đâu, workflow vận hành ra sao và expected behavior khi feature được bật/tắt.

---

## 4. Tài liệu các đội cần dùng

| File | Mục đích |
|------|----------|
| [`final_docs/VN_waf_interop_contract_v2.3.md`](final_docs/VN_waf_interop_contract_v2.3.md) | Quy định WAF phải expose control endpoints, headers, audit log, decision classes và startup contract như thế nào. |
| [`final_docs/openapi.public.yaml`](final_docs/openapi.public.yaml) | Public API contract của upstream target application. Có thể import vào Postman/Swagger/Insomnia để hiểu endpoint, method, auth, parameters và response schema. |

Các đội không cần biết source code upstream. Upstream được xem như một black-box service có domain và OpenAPI public.

