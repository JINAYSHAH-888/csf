# Phase 6 — S3 Learned Stage: Completion Report

**Date:** 2026-10-06 · **Status:** COMPLETE. **Quality bar NOT met.** The
negative result is the deliverable.

## Headline

A character n-gram classifier reaches **ROC-AUC 0.9993 on CSIC 2010** —
matching the ~99% figures the transformer-WAF literature reports — and
**0.5250 on an unseen application.** Random is 0.5.

**The near-perfect single-corpus number is almost entirely corpus
memorisation.**

| model | CSIC AUC | ECML AUC | ECML score spread |
|---|---|---|---|
| with provenance features | 0.9974 | **0.5250** | 5 distinct values, 0.996–1.000 |
| values only | 0.9993 | **0.7059** | 13 distinct, 0.734–1.000 |

## Finding 1 — provenance features are a corpus fingerprint

The research paper, following WADBERT, credits parameter-level provenance
(endpoint, location, parameter name) for its accuracy gains. We implemented
that and then ablated it.

`[ENDPOINT] /tienda1/publico/anadir.jsp [PARAM] nombre` identifies CSIC 2010
as surely as a watermark. A model trained with those tags separates corpora
without learning anything about payloads:

| | with provenance | values only |
|---|---|---|
| CSIC recall @ 0.1% FPR | 42.0% | **92.9%** |
| ECML FPR at the CSIC threshold | **99.57%** | 29.71% |
| ECML ROC-AUC | **0.5250** | 0.7059 |

Removing provenance **more than doubled in-corpus recall** (42% → 92.9%) and
cut cross-corpus FPR by 3.3×. Provenance was not merely useless here — it was
actively harmful, because the model spent its capacity on corpus identity
instead of payload structure.

This directly qualifies a published claim: provenance helps *within* a
corpus and sabotages transfer *across* one. Any paper reporting provenance
gains on a single corpus should report the cross-corpus ablation too.

## Finding 2 — a corpus-construction defect of our own, caught by the protocol

The first training run scored **100% recall at 0.18% FPR** on CSIC and
**100% FPR** on ECML. Investigating: `/api/search` was **100% attack** —
1,711 rows — because Phase 4 placed every payload-list attack at one
synthetic endpoint that never appears in benign traffic. A classifier
separates the classes perfectly from the endpoint alone.

Fixed by sampling request shapes from the benign distribution
(`benign_request_shapes`), so endpoint and parameter name carry no label
information. Endpoint separability fell 29.3% → 16.9%, and CSIC recall fell
from a suspicious 100% to a believable 42% (then 92.9% once provenance was
also removed).

**S1 and S2 results are unaffected** — neither uses the endpoint; they
analyse candidate values. Verified by re-running S2 on the rebuilt corpus:
−4.3pp at the operating threshold versus +2.2pp before, same conclusions.

## Finding 3 — the transferability ordering, which inverts the usual assumption

Across all three stages, measured under one protocol on the same corpora:

| stage | mechanism | in-corpus | unseen application |
|---|---|---|---|
| **S2** | grammar | 56.8% recall @ 0% FPR | 52.5% recall @ **3.43%** FPR |
| **S1** | regex signatures | 93.2% recall @ 0.18% FPR | 96.0% recall @ **66.86%** FPR |
| **S3** | learned n-grams | AUC 0.9993 | AUC **0.5250–0.7059**, FPR 29.7% |

**Grammar transfers best. Signatures transfer poorly. The learned model
transfers worst.** That inverts the implicit assumption behind the
transformer-WAF literature — that learned models generalise where rules do
not. On this evidence they generalise *least*, because what they learn most
readily is the corpus.

## ADR-0008 quality bar: NOT MET
- cross-corpus drop ≤ 15pp → **measured AUC 0.999 → 0.706**, recall usable
  only at 29.7% FPR. Failed.
- adds ≥ 10pp over S1+S2 on the deployment-realistic scenario → not
  achievable at a usable FPR. Failed.
- p99 ≤ 2 ms → not measured, because the quality bar failed first.

## What was shipped anyway, and why
S3 is implemented, tested and wired — but **disabled by default**, and the
config **refuses to enable it** without `trained_on_this_application: true`.
Startup logs the measured generalisation gap. The stage is defensible only
where the model was trained on traffic from the application it protects,
which is a real deployment mode and the one the numbers support.

## Consequence for the architecture
The residual Phase 5 identified — 59.2% of claimed attacks missed by S1 and
S2 on an unseen application — **is not closed by this model**. Honest options:

1. **Per-application training.** The in-corpus numbers (AUC 0.9993, 92.9%
   recall at 0.18% FPR) are genuinely strong. Shadow-mode deployment that
   trains on the protected application's own traffic is the mode the
   evidence supports.
2. **A transformer**, if the budget can be bought back (S1 rule subsetting,
   in-process CRS). But nothing here suggests a pretrained model would escape
   the domain-shift problem — LLM-WAF reports 96.8%, *below* compact
   encoders, and the failure we measured is about corpus identity, not model
   capacity.
3. **Accept the cascade as S0–S2** for cross-application deployment and treat
   S3 as a per-tenant add-on.

Option 1 is recommended and is what the config now enforces.

## Verification
```
405 tests pass · ruff clean · mypy --strict clean
15 S3 tests: feature contract (train/serve skew), determinism, bounds,
four degradation modes, threshold bands, and the generalisation guard
```
