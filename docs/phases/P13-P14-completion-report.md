# Phases 13–14 — Config Integrity & Final Verification — Report

**Date:** 2026-10-08 · **Threat:** T7 · **ADR:** ADR-0014 · plus the one-time
frozen-holdout evaluation that closes the backend.

## Phase 13 — config integrity (T7)

Config loading is now a trust decision, not just a parse (`csf/config_integrity.py`):
every load is fingerprinted (SHA-256, logged for the audit trail); with
`CSF_CONFIG_HMAC_KEY` set, a valid HMAC signature is mandatory; any doubt —
unreadable, bad JSON, failed validation, bad signature — is safe-fail, startup
stops. Wired through `main.py`; the audit record (hash, signed, actor) is logged
at startup. 10 tests, including a body tampered after signing failing to load.
Limitations (HMAC not asymmetric; no automated rollback; whole-file diff
granularity) are in ADR-0014, not papered over.

## Phase 14 — the frozen holdout, spent once

`test.jsonl` was sealed at Phase 4 with its SHA-256 in the manifest. Nothing —
no threshold, model, or analyser — was ever derived from it. Phase 14 verifies
the hash still matches (`32fa56f8…`; a changed holdout would invalidate the
result and the script aborts) and runs the deployed cascade over it **once**, at
the shipped operating point (S1 anomaly ≥ 8 OR S2 ≥ 4.0, disjunctive). No tuning.

### Result (in-distribution, used once)

| class | n | blocked | rate |
|---|---|---|---|
| **benign** | 1120 | 1 | **0.09% (FPR)** |
| sqli | 109 | 109 | **100.0%** |
| xss | 244 | 234 | **95.9%** |
| cmdi | 67 | 46 | **68.7%** |
| other (CSIC anomalous bucket) | 1198 | 275 | 23.0% |

**Claimed-class recall 92.6% at 0.09% FPR** (full-anomaly operating point).

**Superseded by ADR-0015:** the final system thresholds S1 on the attack score,
and the holdout re-run → 89.5% at 0.00% FPR; then the cmdi fix (ADR-0016)
raised it to **94.3% recall at 0.00% FPR** (sqli 96.3%, xss 95.5%, cmdi 56.7% →
**86.6%**). The ~3pp dip from the original full-anomaly 92.6% to attack-score
89.5% bought cross-application transfer (67% → 4.71% ECML FPR, ADR-0015); the
cmdi fix then more than recovered it in-distribution.

### What this is and is not

- **Is:** in-distribution generalisation. train/val/test are all CSIC-derived,
  split by template group so no row or endpoint leaks across them. "How does the
  shipped cascade do on held-out traffic from the world it was built in."
- **Is not:** cross-application transfer. That is ECML/PKDD, measured separately
  and far harder (S1 unusable cross-corpus at 66.86% FPR, S2 ~56% recall, the
  residual work of Phases 5/6/8). This holdout does not substitute for it and
  must not be quoted as if it did.
- **cmdi 68.7%** is the honest weak spot — command injection has been CSF's
  weakest class since Phase 4, and the holdout confirms it rather than hiding
  it.

## Final verification sweep

- **611 tests** pass; `ruff` and `mypy --strict` clean (29 source files).
- Supply chain: pip-audit 0 vulnerabilities (101 pkgs), govulncheck clean,
  0 release blockers.
- Frozen holdout verified against the manifest hash before use and spent once.

## Backend status at end of Phase 14

Phases 1–14 of the backend are complete: S0 framing/auth, S1 CRS sidecar, S2
grammar, S3 (built, negative result, off by default), S4 decision engine, S0
admission control + circuit breaker, adversarial lab, differential fuzzing,
SBOM + CVE scanning, config integrity, and this frozen-holdout evaluation.

Carried forward (honestly, not closed): no cross-application safe default
operating point (ADR-0011); S3 remains a negative result; no `uv.lock`/pinned
release manifest or CI gate wiring; per-subject rate limiting and asymmetric
config signing not built; the frontend/dashboard is a separate track not begun.
