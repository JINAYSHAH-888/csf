# ADR-0006 — Python backend; supersedes ADR-0001

**Status:** Accepted (Phase 1) · **Date:** 2026-10-01
**Supersedes:** ADR-0001 (Custom Go reverse proxy with in-process Coraza)

## Original proposal
ADR-0001 chose a custom Go reverse proxy with OWASP Coraza v3.8.0 embedded in-process, on the grounds that it removes an IPC hop from the fast path.

## Why it changed
Project direction: the backend is Python. This is a legitimate call and not merely a preference:

- **S3, the data pipeline, training, calibration, evaluation and ONNX export are all Python.** A Go gateway means the team maintains two toolchains, two CI lanes, and two implementations of the candidate-extraction and model-input serialisation logic. That duplication is a correctness risk precisely where it hurts most: if the gateway and the training pipeline serialise a candidate differently, the model is served inputs it was never trained on, and the failure is silent.
- **Ten-person student team.** One language lowers the cost of every review, every handover and every onboarding.
- **ASGI exposes raw headers.** `scope["headers"]` is a list of `(name, value)` byte pairs that preserves duplicates and original casing. Go's `net/http` destroys the CL+TE evidence before a handler runs — a defect measured and worked around in the Go prototype with a connection sniffer. ASGI needs no such workaround, so the Python port is *structurally better positioned* for threat-model T3. (To be verified empirically against the chosen server, not assumed.)

## Evidence
- Go prototype measurement (commit `a40279c`): with go1.27.1, a CL+TE request reaches the handler with `Header["Content-Length"] == []`, `r.ContentLength == -1`, `TransferEncoding == ["chunked"]`, response 200. Required a custom `net.Listener` wrapper to detect at all.
- ASGI specification: raw header list preserved, duplicates included.
- ASGI server performance (2026 benchmarks): Uvicorn, 4 workers, handles ~3,200 rps with p99 < 45 ms on a trivial route; Granian ~2× higher on synthetic hello-world but within 5–10% on real API routes. ⚠ These are third-party figures for trivial routes and are **not** a prediction of CSF's latency. Phase 10 measures ours.
- `pymodsecurity` (community-maintained bindings for libmodsecurity v3) exists. ModSecurity became an OWASP Production project in 2024; Python is listed among the supported bindings alongside Rust and Varnish, all community-maintained.

## New decision
**Python 3.14 backend.** ASGI application, Uvicorn for development, process-managed workers for production. Detection stages behind an abstract `Detector` protocol exactly as in the Go design.

**S1 strategy (the real cost of this change).** Coraza cannot be embedded. Three options, in preference order, to be settled by measurement in Phase 3:

1. **`pymodsecurity` bindings to libmodsecurity v3, in-process.** Preserves the no-IPC property. ⚠ Community-maintained; build complexity and maintenance risk must be assessed before committing.
2. **Coraza as a sidecar over a local socket.** Keeps the mature Go engine, costs an IPC hop. Falls back to the thing ADR-0001 rejected — but note it rejected it *unmeasured*, and Phase 3 will measure it.
3. **CRS evaluation via an nginx/ModSecurity front tier**, with CSF behind it handling S0/S2/S3.

No option is chosen here. Choosing one without measuring would repeat ADR-0001's error in the opposite direction.

## Trade-offs

**Lost:**
- In-process CRS evaluation. S1 now costs either an IPC hop or a native-bindings dependency.
- Go's tail-latency and concurrency headroom. The ≤10 ms p99 target is harder in Python and may not survive contact with measurement. **If it does not, that is a reportable result, not grounds for quietly relaxing the target.**
- A working, tested Go implementation of S0 (recoverable from commit `a40279c`).

**Gained:**
- One language across gateway, model, data pipeline and evaluation.
- Shared candidate-extraction and model-input code between serving and training, eliminating train/serve skew by construction.
- Raw header access via ASGI, removing the need for the connection-sniffer workaround.
- Direct in-process ONNX inference becomes possible for S3, removing *that* network hop — which may offset part of what S1 loses.

**Unchanged:** every security property, the threat model, the evaluation protocol, and ADRs 0002–0005. ADR-0002's rule is now enforced through PyJWT's mandatory `algorithms` parameter instead of `jwt.WithValidMethods`.

## Disposition of the Go prototype
Removed from the working tree rather than kept alongside. Two implementations of the same stage drift, and the spec forbids dead code. It remains in git history at `a40279c` and its measured findings are preserved in `docs/phases/P02-completion-report.md` and in `sniff.go`'s analysis, which is quoted in the threat model.

## Reversal strategy
If Phase 3 or Phase 10 shows Python cannot meet the latency budget, the fallback is a Go or Rust data plane with the Python stack retained for model, data and evaluation. The `Detector` protocol boundary is what makes that port tractable.
