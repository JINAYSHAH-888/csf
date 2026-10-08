# ADR-0008 — S3: character n-gram baseline first, transformer only if it earns it

**Status:** Accepted (Phase 6) · **Date:** 2026-10-06

## Context
S3 is the learned stage. The project's own research paper assumed a distilled
transformer (DistilBERT, with SecureBERT and CodeBERT as comparators). Phases
3–5 produced measurements that make that assumption testable rather than
inherited.

## The latency budget is now mostly spent

| stage | p99 measured | source |
|---|---|---|
| S0 ingress + JWT | 0.12 ms | Phase 2 |
| S1 CRS (incl. IPC) | 3.25 ms | Phase 3 |
| S2 semantic | 2.05 ms (cache-cleared worst case) | Phase 5 |
| **consumed** | **~5.4 ms** | |
| **remaining of 10 ms** | **~4.6 ms** | |

Published DistilBERT figures: ONNX INT8 p50 18.8 ms / p99 19.2 ms on one
benchmark; ~5.7 ms p50 for ONNX FP32 on short sequences on another. **The
optimistic published figure already exceeds the entire remaining budget**,
before tokenisation and before any CSF-specific input construction.

## Evidence against defaulting to a transformer
- `ai-sqli-waf` measured DistilBERT at **~89× slower and ~477× larger** than
  a character-level CNN for *comparable adversarial detection*. That is the
  closest available apples-to-apples comparison on this exact task.
- Musoke et al. (arXiv:2608.28889) reach 99.81% with DistilBERT embeddings
  feeding a cheap stacked classifier — and their ~140× speedup is in the
  *head*, not the encoder. The encoder cost is unavoidable and shared.
- LLM-WAF (IJWMT 16(4)) reports 96.8% accuracy, **below** the compact
  encoders. Bigger is not automatically better on this task.

## Decision
**Baseline first.** Build S3 as a character n-gram + linear classifier
(scikit-learn, ONNX-exportable), train it on the frozen splits, and measure
it against the same protocol as S1 and S2.

Escalate to a transformer **only if** the baseline fails a quality bar that a
transformer could plausibly clear, **and** the latency budget can absorb it —
which currently it cannot without displacing S2.

This is not a shortcut. It is the order the spec requires: *"If research
reveals that DistilBERT is too slow, benchmark a character CNN."* The
research revealed exactly that before we wrote any training code.

## What the baseline must beat
Phase 5's cascade ablation sized the job precisely: on ECML, **59.2% of
claimed attacks are missed by both S1 and S2**. S3's value is that residual,
not overall accuracy on a corpus S1 already handles.

Quality bar for the baseline, to be met on the validation split:
- cross-corpus recall drop ≤ 15pp at matched threshold (S2 achieved ±2.2pp;
  S1 was +50.8pp)
- adds ≥ 10pp recall over S1+S2 on the deployment-realistic ECML scenario
- p99 ≤ 2 ms, leaving headroom inside the remaining 4.6 ms

If the baseline misses the quality bar and a transformer could clear it, the
honest options are to buy latency back elsewhere (S1 rule subsetting, which
ModSec-AdvLearn showed can discard 50% of rules; or moving S1 in-process) or
to accept a higher total budget and say so. Those are reversals of earlier
decisions and would need their own ADRs.

## Trade-offs
**Lost:** the headline "transformer-based WAF" framing, and whatever
generalisation a pretrained language model brings that n-grams do not.
**Gained:** a model that fits the measured budget, trains in seconds,
exports to ONNX without a 2.5 GB dependency, and is honestly comparable
against S1 and S2 under one protocol.
**Risk:** n-grams may simply be too weak for the residual. That is a
measurable outcome and a reportable negative result, not a guess.

## Sources
- Phase 2/3/5 latency measurements in `docs/benchmarks/`
- `ai-sqli-waf` 3-model comparison (char-CNN vs DistilBERT)
- Static quantization with HF Optimum; inference-lab benchmarks
- ADR-0005 (benchmark quantisation per platform, never assume)
