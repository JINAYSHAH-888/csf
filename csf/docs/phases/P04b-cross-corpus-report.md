# Cross-Corpus Evaluation — Report

**Date:** 2026-10-01 · **Stage evaluated:** S1 (Coraza + CRS v4.21.0) only
**Protocol:** tune on CSIC 2010, test on ECML/PKDD 2007
**Result: GATE FAILED.** Reported, not adjusted.

## The headline number

Recall on claimed classes (sqli, xss, cmdi, traversal) at **matched
false-positive rate**:

| target FPR | CSIC recall | @thr | ECML recall | @thr | drop |
|---|---|---|---|---|---|
| 5.0% | 95.9% | 1 | 72.3% | 24 | +23.6pp |
| 1.0% | 93.2% | 6 | 62.8% | 29 | +30.4pp |
| 0.5% | 93.2% | 6 | 54.9% | 34 | +38.3pp |
| **0.1%** | **88.9%** | **11** | **38.1%** | **44** | **+50.8pp** |

**Gate: drop at FPR=0.1% must be ≤10pp. Measured +50.8pp. FAIL.**

Comparing at a matched *threshold* would have been meaningless — the same
threshold sits at completely different operating points on the two corpora.
This is itself a finding: nearly all published same-corpus results are
reported at a threshold, not an FPR.

## Threshold transfer fails catastrophically

The τ_hi = 8 derived in Phase 4 on CSIC:

| | CSIC | ECML |
|---|---|---|
| FPR at τ=8 | 0.18% | **96.71%** |

To reach 0.1% FPR, CSIC needs threshold 11 and ECML needs **44** — a 4×
difference. A deployment that tuned on one application and shipped those
thresholds to another would block essentially all traffic.

## Both benchmark corpora are broken, in complementary ways

This is the most useful thing the experiment produced, and neither defect is
visible from a single-corpus evaluation.

**CSIC 2010: "anomalous" does not mean "injection attack."** Of 220 sampled
anomalies CRS scored below threshold, 188 were parameter tampering —
`remember=on%2F`, `pwdA=` instead of `pwd=`, `modo=entrar%252B`. Roughly 85%
of its attack class is not injection.

**ECML/PKDD 2007: "Valid" is not valid HTTP.** Measured on 80 sampled benign
requests:

| rule | hits | meaning |
|---|---|---|
| 920181 | **80/80** | Content-Length **and** Transfer-Encoding present |
| 920450 | 80/80 | restricted `Expect` header |
| 920170 | 66/80 | GET request with a body |
| 920171 | 66/80 | GET with Transfer-Encoding |
| 920340 | 66/80 | content present, no Content-Type |

Every sampled "Valid" request carries a request-smuggling primitive. **CSF's
own S0 framing check rejects 94.5% of the entire ECML corpus with HTTP 400
before S1 ever runs.**

So measuring FPR on raw ECML measures protocol conformance, not injection
detection. We added `protocol_normalize=True`, which drops the randomised
framing headers; S0 then accepts 100% of the corpus and the injection
question becomes askable. **Every number above uses the normalised form, and
which form was used must always be reported** — it changes the result
completely (ECML FPR at τ=8: 100% raw vs 96.71% normalised, and the shape of
the whole curve differs).

## What this means for the project

1. **The cascade is now justified by measurement, not assertion.** S1 alone
   loses ~51 points of recall when the application changes. That gap is
   precisely the space S2 and S3 have to earn. Before this experiment the
   argument for them was borrowed from the literature.

2. **Per-application tuning does not transfer, and tuning is mandatory.**
   Phase 4 showed CRS needs per-app exclusions to be usable at all (99.46% →
   0.18% FPR). This phase shows those exclusions and thresholds are
   app-specific. Both are true at once, and together they explain why
   signature WAFs are operationally expensive.

3. **Published single-corpus numbers should be read as upper bounds.** We
   reproduce high same-corpus performance (93.2% recall at 0.18% FPR on
   CSIC) and show it does not survive a corpus change.

## Caveats on this result

- **S1 only.** This is CRS, not CSF. The full cascade has not been measured
  cross-corpus because S2 and S3 do not exist yet.
- ECML's `other` class (Ldap/XPath/SSI) is excluded from recall, as is
  CSIC's `other`. Including them would flatter ECML (99.7% at τ=8) for
  attacks we never claimed to cover.
- CSIC has no traversal class, so that column has no cross-corpus pair.
- The CSIC exclusions remain applied in both runs. They were derived from
  CSIC and are not expected to help on ECML; removing them for the ECML run
  would be a different experiment and is not what "transfer" means.
- Latency on ECML is higher (engine p50 4.6 ms vs 2.2 ms) because its
  requests carry 42 headers. Request shape, not just rule count, drives S1
  cost.

## Reproduction
```bash
./s1-sidecar -crs vendor/crs -exclusions configs/crs/exclusions-csic.conf &
cd backend && python scripts/measure_cross_corpus.py normalized
ECML_PROTOCOL_NORMALIZE=0 python scripts/measure_cross_corpus.py raw
```
Raw results: `docs/benchmarks/cross-corpus-{normalized,tuned}.json`
