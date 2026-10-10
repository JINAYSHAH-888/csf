# ADR-0004 — CRS is a graded signal and a cheap prefilter, not a binary blocker

**Status:** Accepted (Phase 0) · **Date:** 2026-10-01

## Context
ModSecurity/Coraza + OWASP CRS is the standard S1. The conventional deployment compares the CRS anomaly score against one threshold and blocks above it.

## Problem
That configuration has a cliff, not a curve. Published figures: PL1 ~70–82% detection at ~17–18% FPR; ~95% detection requires PL4 and ~52% FPR (⚠ practitioner benchmark, to be reproduced). Worse, GenSQLi found **89% of 514 validated GPT-4o SQLi payloads bypassed ModSecurity with current rules** — so against a generative adversary its effective recall is far below the benchmark figure.

## Decision
S1 emits a **graded signal**, not a verdict:
- `anomaly_score`, `matched_rule_ids`, `paranoia_level`, transformation results, request metadata.
- Two thresholds: block above `τ_hi`; forward below `τ_lo`; **escalate** the band `[τ_lo, τ_hi]` to S2.
- Run CRS with `detection_paranoia_level` **above** `blocking_paranoia_level` (a CRS v4 feature), so high-PL rules enrich the score without unilaterally blocking.
- `τ_lo`/`τ_hi` are **derived from a measured detection/FPR curve on our own traffic** (Phase 3), never hardcoded. The build spec forbids magic thresholds.

## Why
This converts CRS's weakness into a strength. We stop asking it to be accurate and start asking it to be *cheap and well-calibrated enough to triage*: resolve the easy majority, hand the ambiguous remainder to stages with different inductive biases. Its 89% bypass rate against generated payloads is then a tolerable property of a prefilter rather than a fatal one in a detector.

## Security impact
Requests CRS would have blocked at PL4 are no longer silently allowed — they escalate. Requests CRS false-positives on at PL1 are no longer blocked outright — they escalate and get a second opinion. **Risk:** if `τ_lo` is set too high, genuine attacks are forwarded without ever reaching S2/S3. Threshold selection is therefore a security decision and is gated on measurement.

## Performance impact
CRS full evaluation is ~0.5–10 ms depending on rule count and body size — the dominant deterministic cost. Rule subsetting (ModSec-AdvLearn found up to 50% of CRS rules discardable while *gaining* 30% detection) is a direct Phase 3 latency lever.

## Operational impact
Thresholds become tunable policy per route, versioned and audited. Operators need the matched rule IDs in the audit log to diagnose a decision.

## Reversal strategy
Setting `τ_lo == τ_hi` degenerates S1 to classic binary CRS. Available as an emergency mode.

## Sources
- OWASP CRS v4 paranoia-level docs (`blocking_paranoia_level` vs `detection_paranoia_level`)
- GenSQLi, Future Internet 17(1):8, 2025 (89% ModSecurity bypass)
- ModSec-AdvLearn, arXiv:2308.04964 (+30% detection, −50% rules)
- SafeLine/ModSecurity comparative FPR figures (⚠ practitioner benchmark)
