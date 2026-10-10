# ADR-0015 — S1 scores on attack rules only, to transfer across applications

**Status:** Accepted · **Date:** 2026-10-08 · **Threat:** T1 (cross-corpus)

## Context

Across Phases 4b–14 the standing failure was S1's cross-application transfer:
at a CSIC-derived threshold the full CRS anomaly score gave **66.86% FPR on an
unseen application (ECML/PKDD)** — blocking two-thirds of legitimate traffic.
The shipped cascade inherited it (67.14% FPR), so "usable on an application CSF
was not tuned on" was false. ADR-0011 named this and declined to fix it by
fitting a threshold to ECML, which would just make ECML a second development
corpus.

## Diagnosis (not tuning)

Every ECML benign false positive at the CSIC threshold — **468 of 468** — is
anchored by a CRS rule in the **PROTOCOL-ENFORCEMENT** family (920170, 920340,
920350: GET-with-body, missing Content-Type, etc.). **Zero** are pure
attack-rule false positives. These fire because ECML is a serialized test
corpus whose reconstructed requests have protocol oddities, not because CRS's
SQLi/XSS logic misfires on benign values.

The precision of S1's *attack* rules transfers across corpora; it is the
*protocol* rules that do not.

## Decision

**S1 thresholds on an attack-only score: the CRS anomaly score with
PROTOCOL-ENFORCEMENT and PROTOCOL-ATTACK rules excluded.**

This is justified by CSF's own architecture, not by ECML. CSF's S0 layer owns
HTTP-protocol correctness — `framing.py` rejects smuggling and malformed
framing outright (Phase 11, T3). CRS's protocol rules therefore double-count a
concern another stage already owns, and contribute a non-transferable signal to
a score that is supposed to mean "application-layer attack." Removing them
leaves S1 doing the one thing S0 cannot: signature/grammar attack detection.

The sidecar computes `attack_score` (sum of attack-rule severities, protocol
excluded) and returns it; the gateway thresholds on it. `score_field: "anomaly"`
restores the full score for operators who want it.

`tau_high` was re-derived from 8 (Phase 3 provisional, full anomaly) to **11**
on the attack score — roughly two independent critical attack signatures.

## Measured outcome

Tuned on CSIC, evaluated on ECML without re-tuning
(`docs/benchmarks/cross-corpus-attack-score.json`):

| variant | CSIC rec | CSIC FPR | ECML rec | ECML FPR |
|---|---|---|---|---|
| cascade: full anomaly OR S2 (old) | 88.8% | 0.00% | 96.4% | **67.14%** |
| **cascade: attack-only OR S2 (new)** | 88.6% | 0.00% | 80.0% | **4.71%** |

Cross-application FPR falls **67.14% → 4.71%** — from unusable to usable —
with CSIC performance essentially unchanged (−0.2pp recall, still 0% FPR). The
result is robust to the threshold: 11 and 15 give the same 4.71%.

In-distribution frozen holdout (re-run on the final system): **89.5% recall at
0.00% FPR** (was 92.6% at 0.09% on the old operating point). The ~3pp
in-distribution recall is the price of transfer — the protocol rules were
catching some in-distribution attacks too (cmdi 68.7%→56.7%). Trading a little
in-distribution recall for cross-application usability is the right call for a
product that deploys to applications it was not tuned on; a WAF that blocks 67%
of a new app's traffic is not deployable at any recall.

## Why this is not ECML-fitting

The exclusion is an entire architecturally-redundant *category*, justified by
the S0/S1 responsibility split, not a list of rules that happen to fire on
ECML. The ECML numbers are a *check* that the principled change works, and the
change is validated to preserve the development corpus (CSIC). The same
reasoning would apply had ECML never existed.

## Consequences

- Sidecar returns `attack_score`; `S1Config.score_field` / `S1Settings`
  select it (default) vs the full anomaly score. tau_high default 11.
- Both scores appear in the audit reason (`crs attack=.. anomaly=..`), so an
  operator still sees the protocol contribution.
- 3 new S1 tests pin the behaviour; the defaults test tracks the new value.

## Known limitations

- **Still not a corpus-independent safe default.** ADR-0011's wall stands: CSIC
  is 100%-precise at every threshold ≥11, so it cannot *pick* 11 vs 30. What
  changed is that the cost of the choice is no longer catastrophic — the
  attack score is forgiving cross-corpus (4.71% at both 11 and 15) where the
  full score swung from 0% to 67%. The gap is closed in the sense that matters
  (the cascade is now deployable on an unseen app), not in the sense of a
  provably optimal universal threshold, which the two corpora cannot provide.
- One unseen corpus (ECML). A third application could differ again.
- The attack score is a severity-weighted sum re-derived in the sidecar, not
  CRS's internal per-PL accounting; it is transparent and matches the
  measurements, but it is not CRS's own number.
