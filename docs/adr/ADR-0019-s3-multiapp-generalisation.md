# ADR-0019 — S3 generalises when trained on multiple applications

**Status:** Accepted · **Date:** 2026-10-24 · **Revisits:** ADR-0008, ADR-0017

## Context

ADR-0008 and ADR-0017 recorded S3 (the learned stage) as a **negative result**:
a character-n-gram model trained on one application (CSIC 2010) scored
ROC-AUC 0.53–0.71 on an unseen application and flagged ~100% of its legitimate
traffic. It was shipped **off by default**, and advisory-only when enabled.

That measurement was correct — but it was a measurement of **single-application
training**, not of the model class. The features module already named the
mechanism: the model learns one application's *benign vocabulary*, so a new
application's ordinary traffic is "not what benign looks like" and scores as
hostile. The lever that was never pulled is **training-set diversity**.

Both evaluation corpora are in fact fully labelled (`data/raw/waad/CSVData/`:
CSIC 61k rows, ECML 24k rows), which makes a leave-one-application-out and a
multi-application experiment possible.

## Measurements

All values-only (no provenance fingerprint, ADR-0008), same feature contract as
the gateway (`csf.model.features`), calibrated, frozen CSIC holdout **untouched**
(it shares the CSIC source and is not independent for a multi-app model). The
third application — the demo-shop upstream the console protects — is never in
training and serves as the honest generalisation probe.

**1. Single-application training does not transfer (confirms the negative result):**

| Train → Test | ROC-AUC | recall @ 1% FPR (held-out app) |
|---|---|---|
| CSIC → ECML | 0.70 | 3.9% |
| ECML → CSIC | 0.78 | 18.4% |
| CSIC → demo-shop | **0.50** | 100% recall @ **100% FPR** (useless) |

**2. Multi-application training transfers:**

| Model | demo-shop (unseen) ROC-AUC |
|---|---|
| CSIC only (shipped) | ~0.50 |
| **CSIC + ECML** | **~0.94** |

In-distribution the multi-app model still covers both training apps well
(CSIC AUC 0.97, ECML AUC 0.93; ~82% recall @ 1% FPR each).

**3. The residual is threshold transfer, not ranking.** Calibrated scores run
high on a new application, so a threshold set on the training apps over-flags
(AUC 0.94 but ~56% FPR at the transferred threshold). Setting the threshold on
the deployment's **own benign** (shadow mode, ADR-0017 / `calibrate.py`) recovers
a deployable point: **~82% recall at ~2–5% FPR** on the unseen demo-shop app.

## Decision

1. **Ship a multi-application model.** `scripts/train_s3_multiapp.py` trains on
   CSIC + ECML pooled (values-only, calibrated) and writes `s3_model.pkl` plus
   metadata that records the generalisation numbers and the shadow-calibrated
   deployment thresholds. This replaces the single-app `train_s3.py` artifact as
   the shipped model; `train_s3.py` is kept as the documented baseline.

2. **S3 is no longer framed as a pure negative result.** It is a working stage
   *when trained on diverse / the protected application's traffic and calibrated
   on that application's benign* — the ordinary requirement for a learned WAF
   stage, now met and measured rather than assumed.

3. **Advisory-only remains the default** (ADR-0017). The safety argument is
   unchanged: a learned stage should not block until an operator has validated
   FPR on their own traffic. The path to `advisory_only=False` is unchanged.

4. **The console enables S3** (`CSF_S3_ENABLE=1`) with the thresholds from the
   model metadata, so the live cascade shows a genuinely working S3 instead of
   the 100%-benign-flagging artifact of the single-app model.

## Honest bounds

- Three applications are involved (two trained, one held out). The 1-app → 2-app
  jump (AUC 0.50 → 0.94 on the unseen app) is strong evidence that diversity is
  the lever, but generalisation to *arbitrary* future applications is not proven
  and cannot be from three apps. The production guidance stands: train S3 on the
  diversity of traffic it will protect, and calibrate on the deployment's benign.
- The demo-shop probe is small (50 benign / 23 attack) and partly author-written
  (with deliberately tricky-but-benign values); it is an indicative generalisation
  probe, not a licensed corpus. The two-app leave-one-out AUCs above use the full
  real corpora.
- The frozen CSIC holdout is deliberately not reused here (shared source). The
  reported numbers are the clean held-out VAL split and the independent demo-shop
  probe.
