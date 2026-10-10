# CSF Threat Model

**Version:** 0.1 (Phase 0) · **Date:** 2026-10-01

## 1. System under consideration

CSF is an inline reverse-proxy security gateway. It terminates TLS, adjudicates each HTTP request through four cost-ordered stages (S0 ingress/JWT, S1 Coraza+CRS, S2 grammar-aware semantic analysis, S3 transformer), and forwards or rejects. It is **security-critical software on the request path**: its own compromise, crash, or latency is a security event.

## 2. Trust boundaries

```
  UNTRUSTED                    │  CSF TRUST DOMAIN              │  PROTECTED
  ─────────────────────────────┼────────────────────────────────┼──────────────
  Client / Internet            │  TLS term → HTTP parse         │
  ─ request line, headers      │  normalization                 │
  ─ body, cookies, JWT         │  candidate extraction          │
                               │  ────── boundary A ──────      │
                               │  S1 Coraza (in-process)        │
                               │  S2 grammar parsers            │
                               │  ────── boundary B ──────      │
                               │  S3 model service (network)    │
                               │  ────── boundary C ──────      │
                               │  policy / audit / metrics      │
                               │                                │  Backend API
                               │                                │  Database
```

- **Boundary A** — the HTTP/JSON parser. Everything past it is parsed structure; everything before it is bytes from an adversary. Most severe bug class lives here.
- **Boundary B** — the model service. Treated as *untrusted for availability and latency* (it may hang or die) but trusted for integrity (same deployment).
- **Boundary C** — the backend. CSF's parse of a request must agree with the backend's parse, or bypasses exist.

## 3. Assets

| Asset | Why it matters |
|---|---|
| Backend database contents | Primary exfiltration target |
| Session material / credentials | Enables account takeover |
| JWT signing keys and JWKS integrity | Forged admin token defeats every detection stage |
| Business logic via REST/GraphQL | Abuse target |
| CSF's own availability | A down or stalled gateway is an outage of everything behind it |
| CSF's audit log | Incident-response evidence; also a retraining input, so an attacker who shapes it poisons the model |
| CSF's policy configuration | Controls block/allow — a config write is equivalent to a bypass |

## 4. Adversaries

| ID | Adversary | Capability |
|---|---|---|
| A1 | Unauthenticated remote attacker | Arbitrary HTTP requests |
| A2 | Authenticated low-privilege user | Valid token + arbitrary requests |
| A3 | Black-box evasion adversary | Repeated queries, observes allow/block, mutates payloads (WAF-A-MoLE class) |
| A4 | Generative adversary | Mass-produces validated payloads (GenSQLi class: 89% ModSecurity bypass) |
| A5 | Data-poisoning adversary | Submits payloads designed to be logged and mislabelled into the retraining corpus |
| A6 | Resource-exhaustion adversary | Crafts cheap requests that force expensive work (normalization bombs, forced S3 escalation) |

## 5. Threats and mitigations

### T1 — Injection reaching the backend (A1, A2, A3, A4)
*SQLi, XSS, command injection, path traversal, including obfuscated and generated variants.*
**Mitigations:** layered S1/S2/S3 with different inductive biases; evasion must defeat regex, grammar parse, and a learned classifier simultaneously.
**Residual:** non-zero by assumption. Target ≤15% WAF-A-MoLE evasion, ≤20% generated-SQLi bypass. **We do not claim unevadability.**
**Phase 8 measured** (mutation / A3, sqlite execution oracle): cascade 0%, S2-alone 7.3% then 0% after closing an unterminated-`/*` parser differential (ADR-0012). S1-alone 0% on the same variants — the stages fail in opposite directions. Generative A4 (≤20%) not yet measured.
**Cross-corpus (ADR-0015):** S1's 66.86% ECML FPR was diagnosed to CRS PROTOCOL-ENFORCEMENT rules (which S0 owns, not S1). Scoring S1 on attack rules only takes the cascade from 67.14% → **4.71% FPR at 80% recall** on an unseen application, CSIC unchanged. The cascade is now deployable cross-application; a provably optimal universal threshold remains impossible from two corpora.
**cmdi weak class (ADR-0016):** S2 shell analyser extended (Windows commands, code-execution sinks, value-is-a-command) — cascade cmdi recall holdout 56.7% → **86.6%**, VAL 72.1% → 88.2%, at unchanged FPR. In-distribution only: ECML cmdi barely moved (already S1-caught at ~71%).

### T2 — Authentication bypass via JWT (A1)
*`alg:none`; RS256→HS256 confusion; `jku`/`x5u` injection; `kid` path traversal; `kid` SQL injection; weak HMAC secret; missing `exp`/`nbf`/`iss`/`aud`.*
Live CVE class: CVE-2026-22817, CVE-2026-27804, CVE-2026-23552 (Q1 2026).
**Mitigations:** algorithm is configuration, never input — `WithValidMethods` mandatory on every parse path; keys resolved only from pre-configured JWKS/pinned set; `jku`/`x5u` ignored entirely; `kid` is an opaque allowlist lookup with no filesystem or SQL interpolation; all of `exp`/`nbf`/`iss`/`aud` mandatory. Traceable clause-by-clause to RFC 8725.
**Gate:** 100% of the JWT attack suite blocked. No partial credit.

### T3 — Parser differential (A1)
*CSF parses a request one way, the backend another; the payload is invisible to CSF but live to the backend.* Vectors: request smuggling (conflicting `Content-Length`/`Transfer-Encoding`, ambiguous chunking), duplicate parameters, charset/Unicode normalization divergence, JSON duplicate keys, multipart edge cases.
**Mitigations:** strict HTTP parsing with rejection (not normalization) of ambiguous framing; **differential fuzzing between CSF and backend parsers is a required Phase 11 test, not optional**.
**Residual:** this is the most likely source of a real bypass. Treated as a first-class risk.

### T4 — Resource exhaustion via the defence itself (A6)
*Normalization CPU amplification (decode bombs, deep JSON); forced S3 escalation making every request cost a transformer inference; decompression bombs; oversized bodies/headers.*
**Mitigations:** hard caps on decode depth, body size, header size, nesting depth, and total normalization work, with cap-exceeded treated as a signal; per-principal escalation budgets; global escalation-rate circuit breaker degrading to S1+S2 with tightened thresholds; bounded queues; admission control.

### T5 — Model unavailability or stall (A6, operational)
**Mitigations:** per-request inference deadline; circuit breaker; explicit per-route fail-open/fail-closed configuration; degradation metric emitted. **The failure mode is a configuration choice, never an accident.**

### T6 — Retraining-corpus poisoning (A5)
**Mitigations:** no automatic training on our own block decisions — that laundERS current-model errors into ground truth; near-neighbour dedup, clustering, mandatory human labelling, evaluation gate with frozen-holdout no-regression check before promotion. Human-in-the-loop is a *security control*, not a convenience.

### T7 — Policy/configuration tampering
**Mitigations:** every config change audited with actor and diff; signed/validated config; safe-fail on corruption; rollback path.

### T8 — Sensitive data leakage through CSF's own telemetry
*Logs contain attacker payloads and, inevitably, legitimate user data.*
**Mitigations:** structured logs with redaction driven by learned/declared parameter types; **raw JWTs are never logged** (token hash only); passwords, secrets, credentials and PII redacted at the logging boundary, not downstream.

## 6. Explicitly out of scope

Stated so that no reader infers coverage we do not provide:

- **Second-order injection** — payload stored benignly, triggered by a later query. Invisible at the single-request boundary CSF occupies.
- **DOM-based XSS confined to the URL fragment** — the fragment is never transmitted to the server. Structurally undetectable at a gateway.
- **Business-logic flaws** — IDOR, broken access control, workflow abuse. Not pattern-detectable from request shape.
- **Channels bypassing the gateway** — direct DB access, internal service-to-service traffic, SSH.
- **Supply-chain compromise of CSF itself** — mitigated by SBOM, dependency and container scanning (Phase 11), but not by the runtime design.
- **Volumetric DDoS** — belongs upstream of this component.

## 7. Review cadence

Revised at the end of every phase that adds an attack surface (P2 JWT, P3 CRS, P5 parsers, P6 model, P8 adversarial lab, P11 hardening). Every vulnerability found becomes a permanent regression test.
