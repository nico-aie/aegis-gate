# WAF Hackathon 2026 — Candidate Briefing

> This document is a summary for participating teams. Detailed technical requirements and constraints are defined in [`EN_waf_interop_contract_v2.6.md`](EN_waf_interop_contract_v2.6.md), and the public API specification is available in [`openapi.public.yaml`](openapi.public.yaml).

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
| 2 | **Enterprise Functional & Benchmark Evaluation** | Two-phase evaluation: Phase 1 is the OC's automated benchmark tool exercising the WAF over the public API; Phase 2 is a manual check of enterprise features, UI/UX, and protection logic through the WAF-Admin Dashboard. | Phase 1: required headers/audit log/control plane follow the contract; action/risk/rule/mode values are consistent; risky requests are handled appropriately; false positives are low; behavior in `enforce` and `log_only` follows the required semantics. Phase 2: every Dashboard-surfaced feature, when toggled, actually drives the WAF's behaviour; the OC manually verifies protection logic and enterprise feature coverage through the Dashboard. |
| 3 | **DDoS / Red Team Attack Battle** | After the WAF passes the functional benchmark level, evaluate real-world resilience under DDoS-like load and live Red Team attacks. | Overall protection performance under load; load resilience; ability to keep blocking risky requests and protecting the upstream; operational quality and stability under pressure. |

### 2.1 Scoring Model Across Rounds
The final score of the teams will be calculated based on the weight of the rounds as follows:
- **Round 1 — Functionality Review (Pass/Fail):** Teams must pass to enter Round 2. **No points from Round 1 are carried into the final score**, because the OC gives teams extra time to improve their WAF. Instead, the Round 1 criteria are re-checked again in Round 2 Phase 2.
- **Round 2 — Enterprise Functional & Benchmark Evaluation (70%):**
  - **Phase 1 (automated benchmark):** The WAF must pass at least **70%** of the benchmark tool's test cases to advance to Phase 2.
  - **Phase 2 (manual Dashboard check):** The OC verifies core enterprise WAF features, plus re-checks the improved Round 1 criteria (functionality, Dashboard operability, hot-reload, rule management, etc.).
  - **Selection:** Only the **top 6 teams** with the strongest combined Phase 1 + Phase 2 results move to Round 3. Passing 70% in Phase 1 does **not** guarantee advancement. A team that lacks the core features expected of an enterprise WAF in Phase 2 can still be eliminated, even if Phase 1 was passed.
- **Round 3 — DDoS / Red Team Attack Battle (30%):** The top 6 teams from Round 2 compete under DDoS-like load and live Red Team attacks. The **top 3 teams** are selected based on performance, resilience, and autonomous defense.

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

### 2.3 Round 2 — Enterprise Functional & Benchmark Evaluation

Round 2 evaluates the WAF's behaviour, feature set, and protection logic against the Interop Contract and the requirements of a production-grade WAF. It is run in two complementary phases that use different mechanisms but share the same evaluation surface:

- **Phase 1 — Automated Benchmark (tool-driven, runs first).** The OC's benchmark tool exercises the WAF over the public API surface, scoring adversarial detection, contract compliance, observability headers, audit-log integrity, false-positive behaviour, and enterprise feature coverage. The benchmark tool may be deployed to any team's WAF-server depending on the scenario (e.g., cross-team evaluation, isolation testing, or shared infrastructure). This ensures stable, reproducible results independent of network noise and allows the OC to control the execution environment per scenario.
- **Phase 2 — WAF-Admin Dashboard Verification (manual, runs second).** The OC operates the WAF through the WAF-Admin Dashboard and verifies that every surfaced feature, when configured or toggled through the Dashboard, actually drives the WAF's behaviour the way the feature is documented to behave. This phase checks the WAF's protection logic and confirms whether its feature set meets the bar expected of an enterprise-grade WAF, with concrete test traffic generated by the OC to validate that each claimed capability actually works as documented. Teams that ship a richer, more enterprise-oriented feature set — well-designed, well-implemented, and surfaced coherently through the WAF-Admin Dashboard — will score higher in this phase. It is a logic and configuration check performed entirely through the team's admin interface — the OC drives the WAF and observes its behaviour via the Dashboard, not via an automated external benchmark tool.

Teams do not need to know the benchmark tool's internal workflow; they only need to ensure the WAF complies with the Interop Contract and works generally across the public API surface. *(Note: The `openapi.public.yaml` file is provided only for teams to understand the target application at a high level. In reality, a standard WAF must be able to protect an application without depending on or knowing the source code or specific endpoints of that application in advance).* To ensure fairness and transparency, after this round each team will receive a benchmark report showing their results and score.

*Throughout this section, the term "client" refers to any peer that opens a connection to the WAF. The WAF's protection pipeline is expected to be uniform across all clients — no source may be implicitly trusted by the WAF's design simply because of where it connects from.*

**Phase 2 elimination warning.** Passing 70% of the automated benchmark in Phase 1 is required to enter Phase 2, but it does **not** guarantee advancement to Round 3. In Phase 2 the OC verifies that the WAF actually provides the core features expected of an enterprise-grade WAF (for example: reliable rule management, hot-reload, real-time event/metric display, audit-log accuracy, access control, detection coverage, mode toggling, and operational resilience). A team whose product is missing these core features, or whose Dashboard claims features that do not actually drive WAF behaviour, can be eliminated at this stage even if Phase 1 was passed.

**Submission readiness.** The OC evaluates the WAF exactly as submitted. The OC is not responsible for resetting, restarting, rebuilding, or otherwise preparing the WAF environment. The submitted WAF must be on-ready — if it does not start, does not run, or is misconfigured at submission time, it is the team's responsibility and will be scored accordingly.

---

### 2.4 Round 3 — DDoS / Red Team Attack Battle

This round is for the top 6 WAFs from Round 2. The goal is to evaluate real-world resilience under hostile traffic: whether the WAF can sustain high request throughput, hold latency overhead to a minimum, and continue protecting the upstream when the WAF itself is being targeted by load pressure, traffic floods, and live Red Team attacks.

**Direct Head-to-Head Nature:** In this round, the qualified WAFs will be put on the scale to **compete directly against each other**. The winning teams will be the ones whose WAFs deliver the best sustained performance, resilience, and autonomous defense under the same hostile load.

Tests may include localhost stress tests, external pressure, and DDoS-like traffic patterns (high RPS floods, slow-loris, large-body requests, connection exhaustion, etc.) to observe how the WAF behaves when it is itself the target of hostile load. The WAF's protection pipeline is expected to keep working correctly under this load — risky requests must still be identified and handled, decisions must still be observable, and the upstream must remain protected.

Criteria in this round are intentionally kept high-level:

- Processing performance and latency through the WAF (Latency overhead).
- Load resilience, stability, and recovery under significant pressure (Throughput & Resilience).
- Behaviour under DDoS-like hostile load: ability to keep identifying and handling risky requests, prevent upstream saturation, and avoid becoming the bottleneck that takes the upstream down.
- Ability to maintain observability and consistent decision-making under high load.
- WAF Dashboard operability under load: the Dashboard must keep running smoothly and display events, metrics, and WAF state that accurately reflect real traffic during the Attack Battle.

This document does not disclose load thresholds, traffic patterns, or detailed scoring logic. Teams should optimize the WAF for raw speed and load resilience, with the explicit assumption that the WAF itself will be a target of DDoS-like traffic during evaluation.

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
| [`EN_waf_interop_contract_v2.6.md`](EN_waf_interop_contract_v2.6.md) | Defines how the WAF must expose control endpoints, headers, audit logs, decision classes, and the startup contract. Binding spec for the automated benchmark. |
| [`openapi.public.yaml`](openapi.public.yaml) | Public API contract of the upstream target application. It can be imported into Postman/Swagger/Insomnia to understand endpoints, methods, authentication, parameters, and response schemas. The WAF MUST work generically across this surface — don't hard-code endpoint behaviour. |

Teams do not need to know the upstream source code. The upstream should be treated as a black-box service with a domain and a public OpenAPI specification.

---

## 5. Version 2.6 Delta Summary

Compared to v2.5:

1. **Round 2 re-structured into Phase 1 (automated benchmark) + Phase 2 (manual Dashboard check of enterprise features / UI/UX / protection logic).** Phase 1 gates Phase 2.
2. **Round 1 bonus points no longer carry forward.** Round 2 scoring starts fresh; Round 1 criteria are re-checked in Round 2 Phase 2.
3. **Round 2 / Round 3 weights updated to 70% / 30%.**
4. **Top 6 teams advance from Round 2 to Round 3; top 3 teams win.**
5. **Round 2 Phase 2 can eliminate teams lacking core enterprise WAF features, even if Phase 1 was passed.**
6. **Round 3 renamed DDoS / Red Team Attack Battle.** Added explicit Dashboard operability/accuracy requirement under load.
7. **Dashboard monitoring in Round 3 is mandatory:** OC MUST monitor the Dashboard to confirm displayed information reflects WAF state and real traffic, and that the Dashboard operates smoothly under load.
8. **Submission readiness.** The OC evaluates the WAF as submitted — no resets, restarts, or rebuilds by OC.
9. See [`EN_waf_interop_contract_v2.6.md`](EN_waf_interop_contract_v2.6.md) for detailed interop contract updates.
