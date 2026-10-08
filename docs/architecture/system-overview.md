# CSF — System Overview

## Purpose
An inline reverse-proxy security gateway that adjudicates HTTP requests through four cost-ordered stages, forwarding legitimate traffic and blocking injection attacks, while verifying API authentication tokens cryptographically at ingress.

## Design principle — cost-ordered adjudication
Expected added latency is `E[L] = Σ pᵢ·cᵢ`, where `cᵢ` is stage *i*'s cost and `pᵢ` the traffic fraction reaching it. The engineering goal is to drive `p₃` (transformer escalation) to a few percent without losing the recall the transformer provides, because S3 is 2–3 orders of magnitude more expensive than everything above it.

**The escalation policy, its calibration, and the measured residual rate are the engineering substance** — not the classifier's benchmark accuracy.

## Stages

| Stage | Responsibility | Cost (target) | Decisiveness (target) |
|---|---|---|---|
| **S0** Ingress | TLS, strict HTTP parse, bounded normalization, candidate extraction with provenance, JWT verification, rate state | ~10s µs + 50–200 µs JWT | terminates all invalid-token requests |
| **S1** Coraza + CRS v4 | Graded anomaly score, matched rules, split paranoia | 0.5–10 ms | 85–95% of traffic |
| **S2** Grammar-aware semantic | Parse candidates as SQL/JS/shell; attack *shape* via parse-tree divergence | 0.1–1 ms per candidate | 60–80% of S1 residual |
| **S3** Transformer | Multi-class classification on structured, provenance-tagged input | 5–20 ms p99 | the remainder |
| **Decision** | Calibrated combiner over all stage outputs + route risk + principal state + load | µs | — |

All targets are **targets**, not measurements. Nothing in this document is a claimed result.

## Components
- `gateway/` — Go. The proxy and S0–S2, decision engine, telemetry.
- `model/` — Python. Data pipeline, training, evaluation, calibration, ONNX export, serving.
- `vulnerable-app/` — controlled test target (never an external system).
- `traffic-generator/` — benign load for realistic FPR measurement.
- `adversarial/` — WAF-A-MoLE harness, generated-payload validation, JWT attack suite.
- `dashboard/` — operator UI.
- `benchmarks/` — reproducible latency/throughput/escalation harness.

## Operating modes
`shadow` (evaluate, never block) → `monitor` (evaluate + alert) → `enforce` (block per policy) → `emergency` (ML disabled, deterministic + semantic only). A kill switch is mandatory. **Shadow mode first, always** — the false-positive distribution of real traffic is never what the benchmark predicted.

## Non-goals
Second-order injection; fragment-only DOM XSS; business-logic flaws; traffic that bypasses the gateway; volumetric DDoS. See `docs/security/threat-model.md` §6.
