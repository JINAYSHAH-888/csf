# ADR-0018 — Production observability and deployment

**Status:** Accepted · **Date:** 2026-10-09

## Context

The backend was functionally complete and verified, but three things a WAF is
actually *operated* with were missing: scrapeable metrics (a code comment had
promised "Prometheus metrics arrive in Phase 9" and never delivered), Kubernetes
manifests (the `deployment/kubernetes` dir was empty), and an operations
runbook (`docs/runbooks` was empty). `/statusz`, `/healthz`, `/readyz` existed;
the gap was the metrics interface and the deploy/operate story around it.

## Decisions

### 1. A `/metrics` endpoint in Prometheus exposition format
`csf/metrics.py` is a small, **dependency-free** registry (Counter, Gauge,
Histogram). Dependency-free on purpose: the exposition format is simple text,
the gateway is single-process asyncio (metric updates happen on the event loop,
no locking needed), and the label sets are fixed and tiny (a few decisions and
stages, no cardinality risk). The data plane deliberately carries a minimal
dependency tree (the T4/supply-chain story), and a metrics library would be the
largest non-detection dependency added. Metric names and semantics match
`prometheus_client`, so swapping is mechanical if an operator prefers it.

Instrumentation is at `_audit`, the single chokepoint called exactly once per
proxied request on every terminal path (framing, auth, block, flag, allow) and
never for the admin endpoints — so request counters and the latency histogram
are correct by construction and `/healthz`/`/metrics` traffic cannot inflate
them (asserted in tests). Exposed: `csf_requests_total{decision}`,
`csf_request_duration_seconds` (buckets sized for the 10 ms budget),
`csf_stage_blocks_total{stage}`, and pull-mode gauges refreshed at scrape from
the decision/breaker/rate-limit snapshots (`csf_block_rate_ratio`,
`csf_circuit_breaker_tripped`, `csf_up`, `csf_build_info`). Verified live in the
container: 13 proxied requests counted, `/healthz` excluded, all under the 10 ms
latency bucket.

### 2. Kubernetes manifests mirroring the compose topology
Gateway and S1 sidecar as **two containers in one pod** sharing the socket over
an `emptyDir` — the same reasoning as ADR-0010 (S1 is internal, never a network
service). `fsGroup: 65532` makes the shared socket dir writable by both
containers, the k8s analogue of the compose socket-ownership fix. Liveness
(`/healthz`, process-only so a dependency outage can't cause restart loops) and
readiness (`/readyz`, fails closed on missing keys or a tripped breaker) probes,
resource limits, non-root + read-only-rootfs + dropped-caps security contexts,
tmpfs for Coraza's startup filesystem probe, Prometheus scrape annotations, and
config via ConfigMap. YAML validated.

### 3. An operations runbook
`docs/runbooks/operations.md`: the enforce cutover via calibration, block-rate-
over-budget response, breaker trips, sidecar outage, 401/JWKS spikes, signed-
config rotation, and rollback — each tied to a control that exists, with the
metrics to alert on.

## Consequences

- `/metrics` is a stable operational contract; `csf/metrics.py` and its tests
  pin the exposition format.
- The k8s manifests are a starting point: images reference `:dev` placeholder
  tags and must be published to a pullable registry. (Base images are now digest-pinned.)
- No new runtime dependency was added for any of this.

## Known limitations

- Metrics are per-pod; aggregate across replicas at the Prometheus/query layer
  (as usual). No exemplars or OpenTelemetry tracing — only metrics.
- The manifests are unapplied templates (no live cluster here); they are YAML-
  validated and topology-correct but not k8s-e2e-tested.
