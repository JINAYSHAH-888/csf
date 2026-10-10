# CSF — Cascaded Semantic Firewall

An inline reverse-proxy security gateway that combines cryptographic JWT
verification, graded deterministic WAF rules (OWASP CRS via Coraza),
grammar-aware semantic analysis, and an optional learned stage, adjudicated by
a measured decision engine.

> **Status: backend complete through Phase 14, verified end-to-end in
> containers.** 656 tests, `ruff` + `mypy --strict` clean, pip-audit +
> govulncheck clean. Not independently security-audited; see the per-phase
> limitations in `docs/phases/` and the ADRs for what is and isn't claimed.
> The frontend/dashboard is a separate track and is not part of this backend.

## Design principle

Cost-ordered adjudication: `E[L] = Σ pᵢ·cᵢ`. Cheap deterministic stages resolve
the large majority of traffic; only the ambiguous residual reaches costlier
stages.

```
S0 Ingress+JWT  →  S1 CRS (graded)  →  S2 Grammar parse  →  S3 learned  →  S4 decision
```

**Cascading is not novel** (ADL-WAF, arXiv:2312.13041). What this project
contributes is the *composition* and a **deployment-realistic evaluation**:
every number is reported tuned on one corpus and tested on another, because a
WAF's only honest question is how it behaves on an application it was not tuned
on.

## What's implemented

| Stage | What it is | Status |
|---|---|---|
| S0 framing | strict HTTP admission; rejects smuggling/ambiguous framing | ✅ differential-fuzzed vs httptools/h11 (T3) |
| S0 auth | RFC 8725 JWT verification; JWKS rotation, fail-closed | ✅ full attack suite blocked |
| S1 rules | OWASP Coraza + CRS in a Go sidecar over a unix socket | ✅ scores on attack rules only (cross-corpus, ADR-0015) |
| S2 semantic | grammar-aware SQLi/XSS/shell/traversal analysis | ✅ parser-based, adversarially tested (ADR-0012) |
| S3 learned | char-n-gram classifier | ⚠ **trained, wired, OFF by default — does not generalise** (frozen-holdout AUC 0.66; learns benign value patterns, not attack structure). Advisory-only if enabled; per-deployment training is the only defensible use (ADR-0008) |
| S4 decision | disjunctive fusion, deferral, block-rate budget | ✅ ADR-0011 |
| S0 admission | per-principal rate limit, circuit breaker, cap-as-signal | ✅ ADR-0013 |
| Config integrity | fingerprint + Ed25519/HMAC signature, safe-fail | ✅ ADR-0014/0017 |
| Supply chain | CycloneDX SBOMs + pip-audit + govulncheck | ✅ 0 known vulns |
| Containers + CI | compose stack, GitHub Actions gate, `uv.lock` | ✅ |

## Headline measured results (see `docs/benchmarks/` and `docs/phases/`)

- **Frozen holdout (in-distribution, used once):** 94.3% claimed-class recall at
  0.00% FPR (sqli 96.3%, xss 95.5%, cmdi 86.6%).
- **Cross-application cascade (ECML, unseen app):** 80.0% recall at 4.71% FPR —
  deployable, after scoring S1 on attack rules only took it from an unusable
  67% FPR (ADR-0015).
- **Adversarial (mutation, sqlite oracle):** full cascade 0% evasion; a found
  S2 parser-differential bypass was fixed (ADR-0012).
- **No safe default threshold exists from two corpora** — operators calibrate
  to their own shadow traffic with `backend/scripts/calibrate.py` (ADR-0011/0017).

## Quick start

```bash
docker compose up -d --build     # gateway (S0–S4) + S1 Coraza/CRS sidecar
curl localhost:8080/statusz      # machine-readable operator status
```

Local development:

```bash
cd backend
uv sync --extra dev              # reproducible install from uv.lock
uv run pytest -q                 # 656 tests
uv run ruff check csf/ && uv run mypy --strict csf/
```

Defaults to **shadow mode** (evaluates and logs, forwards everything).
Enforcement is a deliberate config change, gated by readiness. See
`docs/running-with-docker.md`.

## Not included in this package

The evaluation corpora (CSIC 2010, ECML/PKDD 2007) and the frozen holdout are
licensed datasets, not redistributable — sources and SHA-256s are in
`docs/datasets/dataset-card.md`. The committed benchmark JSONs were produced
from them.

## Documentation

- `docs/security/threat-model.md` — trust boundaries, adversaries A1–A6, T1–T8, out-of-scope
- `docs/adr/` — 17 architecture decision records (every non-obvious choice, with its measurement)
- `docs/phases/` — completion reports, each with measured results **and** stated limitations
- `docs/third-party.md` + `docs/security/sbom*.json` — dependencies and licenses (SafeLine is GPL-3.0, reference-only)

## Honesty policy

Measured numbers state the corpus and operating point. Literature figures are
attributed, never presented as project results. Negative results (S3; the
absence of a universal safe default) are reported, not hidden. This policy is
enforced in the commit history and the ADRs.

## License

Apache-2.0. GPL-3.0 code must not be incorporated — see ADR-0003.
