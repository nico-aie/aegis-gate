# WAF Hackathon 2026 — Candidate Briefing

> This document is a summary for participating teams. Detailed technical requirements and constraints are defined in [`final_docs/EN_waf_interop_contract_v2.3.md`](final_docs/EN_waf_interop_contract_v2.3.md), and the public API specification is available in [`final_docs/openapi.public.yaml`](final_docs/openapi.public.yaml).

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
| 3 | **Performance, Load Resilience & Advanced Bonus Points** | After the WAF passes the functional benchmark round, evaluate real-world performance, ability to handle pressure, enterprise readiness, and extended/creative features. | Overall performance; load resilience; scalability/expandability; operational quality; stability under pressure; Tier A/B/C bonus points for advanced features. |

### 2.1 Scoring Model Across Rounds
The final score of the teams will be calculated based on the weight of the rounds as follows:
- **Round 1 (Functionality Review):** This is an **elimination round (Pass/Fail)**. All teams must pass this round to proceed.
- **Round 2 (Automated Benchmark):** Accounts for **65%** of the total score. This round acts as a "gate". The WAF must achieve a minimum contract compliance score of **70%** in Round 2 to be eligible for Round 3 evaluation.
- **Round 3 (Performance & Load Resilience):** Accounts for **35%** of the total score. Bonus points from advanced features will be evaluated in Round 3 and added directly to the total score. If a team fails to reach 70% in Round 2, they will not be evaluated in Round 3. In that case, the team's final score will only include the points corresponding to the passed test cases in Round 2.

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
- **Effectiveness of Features/Rules/Policies:** All features/policies presented in the UI/UX or described in the submission documentation must have a real effect on the behavior of the WAF-PROXY. A polished UI, complete workflow, or detailed documentation will not be considered valid if the feature is only a demo/mock or cannot control the actual WAF-PROXY.
  - *Evaluation:* The OC will cross-check the configuration status on the UI, the workflow described in the submission documentation, and the actual behavior of the WAF-PROXY by sending verification traffic. If the UI reports a successful operation or the documentation claims the feature is supported, but the actual traffic is not affected according to the expected behavior (e.g., enabling IP blocking in the UI but that IP can still access the service), that feature is considered a fail.
  - *Cases that may be penalized or not counted for bonus points:* The UI displays a feature/policy but enabling/disabling/configuring it does not change the actual behavior of the WAF-PROXY; the submission documentation describes a supported feature but the OC cannot verify it with real traffic; the Dashboard uses mock data, local state, or simulated responses that make the UI state inconsistent with the real WAF-PROXY state; the feature only works at the presentation layer but does not enforce/detect/log according to the described expected behavior.

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

**Bonus Features (Categorized by Tier)**
Extended and creative features of the WAF-FE will be awarded bonus points based on priority from high to low (Tier A > Tier B > Tier C). Implementing multiple features within the same Tier will yield diminishing returns.
- **Tier A (Security & Detection):** Features that enhance risk detection capabilities, enrich security data, visualize complex attack patterns, or provide a safe simulator/test environment for rules.
- **Tier B (Advanced Operations):** Features that optimize the administrator experience, manage configuration lifecycles (versioning, rollback), or support large-scale configuration deployment.
- **Tier C (System Integration):** Features that help the WAF communicate with the external ecosystem, such as centralized log forwarding, automated alerts, or exporting metrics to monitoring systems.

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
| [`final_docs/EN_waf_interop_contract_v2.3.md`](final_docs/EN_waf_interop_contract_v2.3.md) | Defines how the WAF must expose control endpoints, headers, audit logs, decision classes, and the startup contract. |
| [`final_docs/openapi.public.yaml`](final_docs/openapi.public.yaml) | Public API contract of the upstream target application. It can be imported into Postman/Swagger/Insomnia to understand endpoints, methods, authentication, parameters, and response schemas. |

Teams do not need to know the upstream source code. The upstream should be treated as a black-box service with a domain and a public OpenAPI specification.

---

## 5. Version 2.3 Delta Summary

Compared to `v2.2`, this version adds:

1. **Scoring Model Update:** Clarified the weight of each round (Round 1: Pass/Fail, Round 2: 65% with a 70% gate, Round 3: 35% head-to-head + Bonus).
2. **Round 1 Details:** Added specific, measurable criteria for WAF-PROXY (Rust core, single binary, reverse proxy flow, basic security) and WAF-FE (real-time monitor ≤ 5s, hot-reload ≤ 10s, rule management, audit log viewer). Clarified that UI/UX features and documented workflows must work against the actual WAF-PROXY behavior; mock/demo-only features may be penalized or not counted for bonus points.
3. **Round 2 Strictness:** Emphasized **strict compliance** with the Interop Contract. Added a strong warning that the automated benchmark tool will fail WAFs with incorrect formats (headers, JSON). Clarified that `openapi.public.yaml` is for reference only and WAFs must be generic. Added a disclaimer about dynamic/hidden test cases to prevent hardcoding.
4. **Round 3 Head-to-Head:** Explicitly stated the direct competitive nature of Round 3, focusing on feature completeness, latency overhead, throughput, resilience, graceful degradation, and the Tier-based bonus system (Tier A, B, C) with diminishing returns.
