# PLAN — SEC regression triage (2026-06-14) — SUPERSEDED

> **Superseded by [`PLAN-sec-regression-2026-06-16-newmodel.md`](./PLAN-sec-regression-2026-06-16-newmodel.md)** (2026-06-16).
>
> That plan re-evaluates the same gate-off / all-detectors-on baseline (`run-20260614-192320`)
> against the **new AI model** run (`run-20260616-201503`) and carries forward the still-open
> P2/P3 detector backlog (sqli mixed-case+hex, cmdi, xss, jwt routes, WS handshake controls,
> SSE request-side). See it for the current state of play.
>
> Key carry-over result: the prior P1 ship-blocker (systemic benign over-block, AI-driven —
> confirmed by the AI-off run `run-20260614-210530`, which dropped FP 42→8) got **worse** under
> the new model (benign FP 37→93). Do not ship the new model in enforce mode until that is fixed.
