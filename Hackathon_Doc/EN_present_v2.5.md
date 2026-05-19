# WAF Hackathon 2026 — Candidate Briefing

> This document is a summary for participating teams. Detailed technical requirements and constraints are defined in [`EN_waf_interop_contract_v2.5.md`](EN_waf_interop_contract_v2.5.md), and the public API specification is available in [`openapi.public.yaml`](openapi.public.yaml).

---

## 1. Competition Objective

Teams will build a WAF that runs in front of the target application. The WAF must protect the upstream service from unsafe traffic while still allowing legitimate traffic to work normally.

A good WAF must balance three goals:

1. **Security efficacy**: identify and handle risky requests.
2. **Low false positives**: avoid disrupting legitimate users or valid business flows.
3. **Operational quality**: provide clear observability, complete logs, stable operation, and ease of use.

In short: **the WAF must protect the system, but it must not become the reason the system becomes slow, incorrect, or unavailable.**

---

## 2. Overview of the 3 Competition Rounds

The competition is divided into 3 rounds. The information below only describes the goals and judging criteria at a high level so teams can orient their WAF design; detailed execution steps, test data, and internal evaluation logic are not disclosed.

| Round | Name | Main focus | High-level judging criteria |
|-------|------|------------|-----------------------------|
| 1 | **Functionality Review: WAF-PROXY (Rust) & WAF-FE (Dashboard)** | Check whether the WAF can run normally, the core is written in Rust, it has a basic administration Dashboard, and meets the minimum criteria of a WAF. | Starts successfully; reverse proxy works; blocks basic attacks; rule management via UI; hot-reload works; has logs/monitoring. This is an elimination round (Pass/Fail). |
| 2 | **Automated Benchmark & Adversarial Evaluation** | The benchmark tool runs through the WAF to evaluate how it handles risky traffic and legitimate traffic on the public API. | Required headers/audit log/control plane follow the contract; action/risk/rule/mode values are consistent; risky requests are handled appropriately; false positives are low; behavior in `enforce` and `log_only` follows the required semantics. |
| 3 | **Performance & Load Resilience** | After the WAF passes the functional benchmark round, evaluate real-world performance, ability to handle pressure, and enterprise readiness. | Overall performance; load resilience; scalability/expandability; operational quality and stability under pressure. |

### 2.1 Scoring Model Across Rounds
The final score of the teams will be calculated based on the weight of the rounds as follows:
- **Round 1 (Functionality Review):** This is an **elimination round (Pass/Fail)**. All teams must pass this round to proceed. Bonus points from advanced features in Round 1 will be added directly to the total score.
- **Round 2 (Automated Benchmark):** Accounts for **65%** of the total score. This round acts as a "gate". The WAF must achieve a minimum contract compliance score of **70%** in Round 2 to be eligible for Round 3 evaluation.
- **Round 3 (Performance & Load Resilience):** Accounts for **35%** of the total score. If a team fails to reach 70% in Round 2, they will not be evaluated in Round 3. In that case, the team's final score will only include the Bonus points (Round 1) and the points corresponding to the passed test cases in Round 2.

### 2.2 Round 1 — Functionality Review: WAF-PROXY (Rust) & WAF-FE (Dashboard)

Round 1 is an **elimination round (Pass/Fail)**. If the system does not meet the basic criteria below, the team will be eliminated from the competition. The goal of this round is to ensure the WAF can run normally, act correctly as a Reverse Proxy, and have a practical administration tool (Dashboard).

**Specific Scoring Criteria (Must pass to proceed):**

**1. WAF-PROXY (Core System)**
- **Mandatory Technology:** The core proxy must be written entirely in **Rust**.
  - *Evaluation:* The Organizing Committee (OC) will review the source code and build process to confirm compliance.
- **Startup & Operation:** Build as a single binary, start successfully, and maintain stable operation.
  - *Evaluation:* The system must start successfully via the command line and not crash/panic when handling a continuous stream of legitimate traffic.
- **Reverse Proxy:** Ensure the basic traffic flow works seamlessly:
  - **REQUEST:** Client -> WAF-PROXY -> UPSTREAM
  - **RESPONSE:** UPSTREAM -> WAF-PROXY -> CLIENT
  - *Evaluation:* The WAF must accurately forward HTTP methods, headers, and body to the upstream, and return the response from the upstream intact without distorting valid data.
- **Basic Security:** Capable of detecting and preventing the most basic attack groups (OWASP Top 5) and basic access control (Blacklist, Rate Limit).
  - *Evaluation:* The OC will use a set of common attack payloads. The WAF must correctly identify and execute a blocking action (e.g., return HTTP 403) instead of letting it reach the upstream.

**2. WAF-FE (Dashboard & Administration)**
- **Functional completeness (Mandatory):**
  - **Real-time monitor:** Logs/Events must appear on the Dashboard within **≤ 5 seconds** of the WAF processing the request.
  - **Rule/Config Management:** Fully supports Add/Edit/Delete/Enable/Disable operations via the UI.
  - **Audit Log Viewer:** Capable of searching and filtering logs (by time, IP, Rule ID, Request ID).
  - **Health/Status View:** Displays the basic status of the WAF (Uptime, Current Mode, Number of active rules).
- **Operational efficiency:**
  - **Hot-reload:** The time from clicking "Save" on a rule in the UI until the rule takes actual effect in the WAF-PROXY must be **≤ 10 seconds** (without restarting the service). There must be a visible indication on the UI that the config has been successfully applied.
  - **Usability:** Creating a new rule is fast (target ≤ 5 clicks). Finding a specific event in the Audit Log is easy (target ≤ 30 seconds).
- **Effectiveness of Features/Rules/Policies:** The features configured on the Dashboard must actually work under the WAF-PROXY.
  - *Evaluation:* The OC will cross-check the configuration status on the UI with the actual behavior of the WAF-PROXY by sending traffic. If the UI reports success but the actual traffic is unaffected (e.g., enabling IP block but that IP can still access), that feature is considered a fail.

**3. Bonus Features (Categorized by Tier)**
Extended and creative features of the WAF-FE will be awarded bonus points based on priority from high to low (Tier A > Tier B > Tier C). Implementing multiple features within the same Tier will yield diminishing returns.
- **Tier A (Security & Detection):** Features that enhance risk detection capabilities, enrich security data, visualize complex attack patterns, or provide a safe simulator/test environment for rules.
- **Tier B (Advanced Operations):** Features that optimize the administrator experience, manage configuration lifecycles (versioning, rollback), or support large-scale configuration deployment.
- **Tier C (System Integration):** Features that help the WAF communicate with the external ecosystem, such as centralized log forwarding, automated alerts, or exporting metrics to monitoring systems.

*(Note: This document intentionally omits advanced security criteria, complex anti-abuse mechanisms, or performance requirements for the WAF-PROXY. These factors will be the focus of the ranking evaluation in Round 2 and Round 3. Teams need to research and design appropriate architectures to score high in the subsequent rounds).*

### 2.3 Round 2 — Automated Benchmark & Adversarial Evaluation

This is the round where the benchmark tool runs through the WAF to evaluate behavior according to the contract. Teams do not need to know the tool's internal workflow; they only need to ensure the WAF complies with the interop contract and works generally across the public API surface. *(Note: The `openapi.public.yaml` file is provided only for teams to understand the target application at a high level. In reality, a standard WAF must be able to protect an application without depending on or knowing the source code or specific endpoints of that application in advance).* To ensure fairness and transparency, after this round each team will receive a benchmark report showing their results and score.

High-level criteria:

- **Strict Interop Contract Compliance:** The WAF must fully implement the control endpoints (`/__waf_control/capabilities`, `reset_state`, `set_profile`, `flush_cache`) and authenticate using `X-Benchmark-Secret`. These endpoints must operate with the correct semantics (e.g., `reset_state` must clear all state but preserve the audit log). **Warning:** The OC's benchmark tool is programmed to score automatically based on the Interop Contract. If the WAF does not comply with the exact format (wrong header name, wrong JSON format, missing mandatory fields), the tool will not recognize it and evaluate it as a Fail. Teams must bear full responsibility if they lose points due to non-compliance with the contract.
- **Observability Headers:** Every response returned from the WAF (whether allow or block) MUST include all minimum required headers: `X-WAF-Request-Id`, `X-WAF-Risk-Score`, `X-WAF-Action`, `X-WAF-Rule-Id`, `X-WAF-Cache`, `X-WAF-Mode`. Missing or incorrect formats will be considered a contract violation. *(Note: These are minimum requirements. Teams are encouraged to add custom `X-WAF-*` headers to support tracing, debugging, or displaying on the Dashboard. Having useful additional headers will be a significant bonus).*
- **Audit Log:** Must write logs to the `./waf_audit.log` file in JSONL format with all minimum mandatory fields (`request_id`, `ts_ms`, `ip`, `method`, `path`, `action`, `risk_score`, `mode`). *(Similar to headers, teams can add other JSON fields to the log to enrich data for SIEM/Dashboard, and this will be considered a bonus).*
- **Risk Handling (Enforce mode):** Risky requests must be handled with an appropriate action (`block`, `challenge`, `rate_limit`, `timeout`, `circuit_breaker`) and actually prevent the payload from reaching the upstream.
- **Log Only Mode:** When set via `set_profile` to `log_only`, the WAF must still detect and record the intended action in the header/log, but MUST NOT block the request (must let it pass to the upstream).
- **False Positives:** Legitimate requests on public APIs must not be incorrectly blocked.

**Important Disclaimer:** The criteria above are **core evaluation principles**. The OC's benchmark tool will use thousands of dynamic test cases (dynamic payloads, mutated requests, edge cases, evasion techniques) based on these principles. If a WAF only blocks a few basic payloads (hardcoded) but fails against variations (mutations) or complex attack scenarios (chained attacks), it will be heavily penalized or evaluated as failed. The OC reserves the right to use hidden scenarios not disclosed in advance to evaluate the true defensive capabilities of the WAF.

This document does not list payloads, prioritized routes, rule mappings, or hidden scenarios. Teams should build a general, observable, and stable WAF across the entire API surface in the public OpenAPI specification.

### 2.4 Round 3 — Performance & Load Resilience

This round is for WAFs that have passed Round 2 at the functional benchmark level. The goal is to evaluate performance and enterprise readiness: whether the WAF is fast, stable, resilient under load, scalable, and operationally suitable for real-world environments.

**Direct Head-to-Head Nature:** In this round, the WAFs that pass Round 2 will be put on the scale to **compete directly against each other**. The winning team will be the one whose WAF possesses a more complete feature set, faster request processing speed, lower overhead, and maintains the best performance under the same load pressure.

Tests may include localhost stress tests and external pressure/DDoS-like traffic to observe real-world performance. The event organizers may also consider expandability, operational architecture, the ability to scale with resources/infrastructure, and how the WAF maintains service quality when traffic changes sharply.

Criteria in this round are intentionally kept high-level:

- Processing performance and latency through the WAF (Latency overhead).
- Load resilience, stability, and recovery under significant pressure (Throughput & Resilience).
- Enterprise-oriented scalability/expandability.
- Operational quality when the system or upstream experiences unfavorable conditions (Graceful degradation).
- Ability to maintain observability and consistent behavior under high load.

This document does not disclose load thresholds, traffic patterns, expected architecture, or detailed scoring logic. Teams should optimize the WAF as a real product: fast, stable, scalable, observable, and safe under pressure.

---

## 3. Required Documentation When Submitting the WAF

When submitting the WAF, teams must also submit an accompanying guide file. This file should list the workflows of the main features so the event organizers can understand the WAF's design intent, operational model, and protection logic.

Each feature/policy should be described briefly using a similar format:

```md
+ Policy/Feature: Blacklist
+ Description: Provides protection for the website by blocking access based on client attributes. This feature helps defend against known malicious sources, scanners, or suspicious visitors by denying access based on IP address.
+ How it works:
1. The WAF checks incoming requests against configured blacklist criteria, such as IP address.
2. Blacklists can be declared directly in configuration or loaded from a config file.
3. If a visitor matches any blacklist rule, access is denied.
```

The guide file does not need to disclose internal source code, but it must be clear enough for the event organizers to understand how each feature works, where it is configured, how its operational workflow behaves, and what expected behavior should be observed when the feature is enabled or disabled.

---

## 4. Documents Teams Should Use

| File | Purpose |
|------|---------|
| `WAF_Hackathon_2026_Official_Rules ENG.docx.pdf` | The competition rulebook: objectives, eligibility, schedule, mission, technical requirements (Rust core, single binary, performance SLAs, mandatory features, dashboard, response filtering), scoring breakdown, Attack Battle procedure, prizes. **Read this first.** |
| [`EN_waf_interop_contract_v2.5.md`](EN_waf_interop_contract_v2.5.md) | Defines how the WAF must expose control endpoints, headers, audit logs, decision classes, and the startup contract. Binding spec for the automated benchmark. |
| [`openapi.public.yaml`](openapi.public.yaml) | Public API contract of the upstream target application. It can be imported into Postman/Swagger/Insomnia to understand endpoints, methods, authentication, parameters, and response schemas. The WAF MUST work generically across this surface — don't hard-code endpoint behaviour. |

Teams do not need to know the upstream source code. The upstream should be treated as a black-box service with a domain and a public OpenAPI specification.

---

## 5. Version 2.5 Delta Summary

Compared to v2.3, this revision aligns the candidate briefing with the latest interop contract and Official Rules:

1. **Architecture neutrality.** The interop contract no longer assumes a Cloudflare-shape WAF or any specific off-the-shelf engine. Teams may organise their data plane and control plane however they like — see [`EN_waf_interop_contract_v2.5.md`](EN_waf_interop_contract_v2.5.md) §2.6b.
2. **Behavioural-bot scoring (BC01/BC02) is decoupled from `X-WAF-Action: challenge`.** Any action is acceptable as long as session-state invariants hold (attack cookie invalidated within 5s, legitimate user recovers within 60s). `rate_limit` paired with cookie invalidation now passes; `rate_limit` alone scores zero.
3. **Minimum Viable WAF checklist.** The interop contract now ships a §13 single-page checklist of the bare-minimum surface a WAF must clear before any scoring criterion applies. Read it before submitting.
