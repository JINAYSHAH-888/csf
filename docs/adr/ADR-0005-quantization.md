# ADR-0005 — Do not assume INT8; benchmark on target hardware

**Status:** Accepted (Phase 0, binding on Phase 6) · **Date:** 2026-10-01

## Context
Standard advice is to export the S3 transformer to ONNX and quantize to INT8 for latency.

## Problem
Published INT8 speedups are architecture-dependent. One benchmark found ONNX **INT8 8% *slower* than FP32 on Apple Silicon** (6.14 ms vs 5.66 ms p50), while on x86 with AVX-512 VNNI INT8 gave ~4× (p50 18.8 ms → with 4.06× speedup, 256 MB → 65 MB). **Our development host is an Apple M5.**

## Decision
Phase 6 benchmarks the full matrix on each target platform before any deployment choice:

| | PyTorch eager | ONNX FP32 | ONNX INT8 |
|---|---|---|---|
| Apple Silicon (dev) | measure | measure | measure |
| x86-64 (prod target) | measure | measure | measure |

Deploy whichever wins **on the platform it will run on**. Record both. Dev and prod may legitimately differ.

## Why
The build spec is explicit: "If INT8 is slower on target hardware, do not deploy INT8 just because a paper says it is faster." This ADR exists so that instruction is binding rather than remembered.

## Security impact
Indirect: quantization can shift decision boundaries. Phase 6 must re-run the full evaluation (including calibration and adversarial) on the *exact* artefact that ships, not on the FP32 original.

## Performance impact
To be measured. No number is claimed here. Candidate heads also include a **character CNN** — the ai-sqli-waf comparison found DistilBERT ~89× slower and ~477× larger for comparable adversarial detection, so the CNN is a serious contender, not a strawman.

## Operational impact
Model registry records architecture, precision, target platform, and measured latency per artefact.

## Reversal strategy
Serving layer loads by artefact ID; swapping precision is a config change.

## Sources
- Static quantization with HF Optimum (DistilBERT SST-2 INT8: p50 18.8 ms, 4.06×, 256→65 MB)
- inference-lab benchmark (ONNX FP32 5.66 ms p50; INT8 8% slower on Apple Silicon)
- ai-sqli-waf model comparison (DistilBERT ~89× slower, ~477× larger than char-CNN)
