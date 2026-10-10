# Phase P00 — Research Report

**Date:** 2026-10-01 · **Host:** Apple M5 (10 cores), macOS (Darwin 25.6.0)
**Status:** complete

## A. Current technology versions (verified 2026-10-01)

| Component | Version | Date | License | Notes |
|---|---|---|---|---|
| Go toolchain | **go1.27.1 darwin/arm64** | installed this phase | BSD-3 | Verified by `go version`. Was not present on host; installed via Homebrew. |
| OWASP Coraza | **v3.8.0** | 2026-09-30 | **Apache-2.0** | `github.com/corazawaf/coraza/v3`. ModSecurity SecLang compatible, 100% compatible with OWASP CRS v4. |
| OWASP CRS | v4.x (v4.28.0 LTS track noted) | 2026 | Apache-2.0 | Split `blocking_paranoia_level` / `detection_paranoia_level` available since v4. |
| golang-jwt/jwt | v5 (5.3.x) | 2026 | MIT | `WithValidMethods`, `WithExpirationRequired`, `WithIssuer`, `WithAudience`. |
| MicahParks/keyfunc | v3 | 2026 | MIT | JWKS (RFC 7517) as a `jwt.Keyfunc`. |
| vitess sqlparser | Apache-2.0 | 2026-06-24 | **Apache-2.0** | `vitess.io/vitess/go/vt/sqlparser`. MySQL-dialect AST. |
| Docker | 29.5.3 | — | — | **Daemon not currently running on host.** Container work is blocked until it is started. |
| Python | 3.14.6 | — | — | For the model workspace. |

⚠ **UNVERIFIED at time of writing:** exact pinned minor versions of keyfunc and vitess will be fixed by `go.mod` in Phase 1 and recorded in `docs/third-party.md`. The Docker daemon being down means no container build has been executed yet — nothing in this repo should be described as "container-verified" until it has.

## B. Academic literature

Carried forward from the project research paper (`RESEARCH-PAPER.md`, 39 refs). Phase-relevant findings:

- **Cascading is prior art.** arXiv:2312.13041 (cascaded NLP for SQLi, 99.86% acc, 20× faster than transformer-only) and ADL-WAF (arXiv:2511.12643). Our differentiation is composition + evaluation protocol, not the cascade. This constrains how we may describe the project (see §6 of the build spec).
- **Signature layer is weak against generated attacks.** GenSQLi (Future Internet 17(1):8, 2025): 514 GPT-4o payloads, 92.5% functional against MySQL, **89% bypassed ModSecurity** with current rules. This sets the S1 expectation: CRS is a *cheap filter and graded signal*, not a detector we can rely on.
- **Semantic parsing yields the best FPR.** SafeLine semantic engine reported at ~0.07% FPR vs ModSecurity PL1 ~17.6% (practitioner benchmark, ⚠ not peer-reviewed — to be reproduced in our own harness).
- **Latency evidence is thin but non-zero.** Seyyar et al. (IEEE Access 10:68633–68644, 2022) report 0.4 ms mean detection. No source reports p99 under concurrency with parsing included — that is the gap we measure.
- **Beware the 140× claim.** Musoke et al. (arXiv:2608.28889) report a stacked ensemble head ~140× faster than DistilBERT-SVM. That is the *classifier head only*; the DistilBERT forward pass is shared and dominates. Must report encoder and head latency separately.
- **INT8 is not automatically faster.** A published benchmark found ONNX INT8 **8% slower than FP32 on Apple Silicon**. Our dev host is an Apple M5. Directly actionable — see ADR-0005.

## C. Production implementations studied

| System | License | Lesson taken | Lesson rejected |
|---|---|---|---|
| open-appsec | Apache-2.0 | Contextual ML scoring; integrates via NGINX/Envoy/Kong/APISIX; signature-free operation is viable in production | Its "no signatures at all" stance — we keep CRS as a cheap graded prefilter |
| SafeLine | **GPL-3.0** (engine) | Grammar-aware semantic analysis is the right S2 mechanism | ⚠ **Architectural reference only. GPL-3.0 code must not be copied into our Apache-2.0 gateway.** We implement S2 independently against public grammar libraries. |
| Coraza | Apache-2.0 | In-process SecLang execution, no IPC hop | — |
| Envoy ext_proc | Apache-2.0 | Standard integration path for external processors | Default choice — adds an out-of-process hop we have not yet measured |
| WAF-A-MoLE | — | Mutational evasion fuzzer; adopt as red-team tool | — |
| ModSec-AdvLearn | — | CRS rule weights are learnable; default CRS config is suboptimal | — |
| ai-sqli-waf | — | proxy + inference-svc topology; **DistilBERT ~89× slower, ~477× larger than char-CNN** for comparable adversarial detection | Its seed corpus (~350 samples) is far too small |

## D. Research findings

**What the literature says:** transformer classifiers reach ~99.5% F1 on CSIC 2010 but are evaluated offline, single-corpus, without tail latency or auth integration. Cross-corpus degradation is largely unmeasured. Generated attacks defeat signature WAFs at high rates.

**What production systems do:** keep a cheap deterministic layer inline; run ML out-of-band or on a subset; integrate at the proxy via in-process modules or ext_proc; treat false positives as the binding operational constraint.

**What we adopt:** in-process Coraza for S1 as a graded signal; independent grammar-based S2; cascaded escalation with calibrated thresholds; strict RFC 8725 JWT verification at S0; cross-corpus + adversarial evaluation.

**What we avoid:** copying GPL-3.0 engine code; trusting published latency figures as our results; CRS as a binary blocker; auto-retraining on our own decisions; INT8 by default on Apple Silicon.

## E. New finding this phase — JWT CVE cluster, Q1 2026

Searching current advisories surfaced an active 2026 cluster of algorithm-confusion CVEs: **CVE-2026-22817** (Hono framework JWT middleware, auth bypass, fixed in 4.11.4 by requiring an explicit `alg` option), plus **CVE-2026-27804** and **CVE-2026-23552**. Root cause in every case: *the verification algorithm is selected from the attacker-controlled `alg` header.*

This is not historical trivia. It is the exact failure our S0 is designed to prevent, it is still shipping in current frameworks, and it makes the Phase 2 JWT suite a test of a live vulnerability class rather than a textbook exercise. It also sets a hard implementation rule, enforced in code review: **our verifier must never call a parse function without an explicit algorithm allowlist.** In `golang-jwt/jwt/v5` that means `jwt.WithValidMethods(...)` is mandatory on every parse path, and a unit test must fail the build if a parse call omits it.

⚠ Whether `golang-jwt/jwt/v5` itself is affected was **not** established by this search; the library documents `WithValidMethods` as the mitigation and the CVEs name other libraries. We treat the library as safe *only when used with the allowlist*, and we do not rely on its defaults.

---

## PHASE DECISION

**Chosen approach:** Custom Go reverse proxy with in-process Coraza v3.8.0 (Apache-2.0), strict RFC 8725 JWT verification at ingress using `golang-jwt/jwt/v5` with mandatory algorithm allowlisting, independently implemented grammar-aware S2, and a separately served ONNX transformer at S3 reached only via calibrated escalation.

**Rejected alternatives:**
- *Envoy + ext_proc as the primary path* — rejected for Phase 1–7 because it forces an out-of-process gRPC hop into the fast path before we have measured whether we can afford it. Retained as a Phase 10 benchmark comparison and a Phase 12 deployment option.
- *Forking SafeLine's semantic engine* — rejected on licensing (GPL-3.0 vs our Apache-2.0 intent), not on quality.
- *NGINX + Lua/njs* — rejected: splits the implementation across two languages and makes in-process Coraza awkward.
- *Python-only gateway* — rejected on tail-latency and concurrency grounds.

**Security implications:** In-process Coraza removes an IPC trust boundary. Mandatory algorithm allowlisting closes the CVE class above. A custom proxy means **we own the HTTP parser's correctness** — request smuggling and parser-differential testing become our responsibility and are mandatory phases (P8, P11), not optional.

**Performance implications:** No IPC hop for S1/S2. S3 remains out-of-process and is the only network hop, which is acceptable because it is reached by a small traffic fraction by design. Target: p99 added latency ≤ 10 ms on benign traffic, S3 escalation ≤ 5%.

**Maintenance implications:** Go + Python split means two toolchains and two CI lanes. Coraza tracks CRS upstream, so rule updates are low-cost. Owning the HTTP parser is the main long-term maintenance liability and is accepted deliberately.
