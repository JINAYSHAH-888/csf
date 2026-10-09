# Phase 4 — Data Engineering: Completion Report

**Date:** 2026-10-01 · **Status:** COMPLETE. Exit gate met; two gates deferred with reasons.

## Exit gate: a frozen evaluation set exists
`data/processed/{train,val,test}.jsonl` + `manifest.json` with SHA-256 per
split. Built deterministically. Leakage check passes. **The holdout has not
been evaluated against** — every threshold below came from `val`.

## Implemented
- `csf/data/corpus.py` — normalisation, dedup, two-regime grouping,
  stratified group splitting, leakage verification, unsplittable-class warnings.
- `csf/data/loaders.py` — CSIC 2010 and payload-list parsers.
- `scripts/build_corpus.py`, `scripts/measure_s1_real.py`
- `configs/crs/exclusions-csic.conf` — documented per-application exclusions.
- `docs/datasets/dataset-card.md`

## Finding 1 — 54% of the corpus was duplicates
17,876 of 32,808 rows collapsed under normalisation. A random row split would
scatter these across train and test. This is a concrete, measured mechanism
for the 99.5–99.7% F1 figures the literature reports on CSIC 2010, and it
cost nothing to find — it only required normalising before splitting.

## Finding 2 — the Phase 3 thresholds were catastrophically wrong
Phase 3 derived `tau_low=4, tau_high=8` from 40 hand-built benign samples and
labelled them provisional. Against real traffic they are a disaster:

| | hand-built corpus | real corpus (untuned) |
|---|---|---|
| benign p50 score | 0 | **10** |
| FPR at threshold 8 | 0% | **99.46%** |

Deploying the Phase 3 numbers would have blocked essentially all legitimate
traffic. The provisional labelling was correct and the re-derivation was not
optional.

## Finding 3 — two CRS rules produced ~100% FPR, and one is a perfect illustration
Diagnosed by reading match data on 60 benign requests:

- **920451** (60/60): *"HTTP header restricted by policy (/accept-charset/)"*.
  CRS v4 treats `Accept-Charset` as a scanner signal; every 2010-era CSIC
  request sends one. Corpus artifact. +5.
- **932236** (58/60): *"Unix Command Injection"* matching **`pwd` found within
  `ARGS_NAMES:pwd`**. The shop's **password field is named `pwd`**, and CRS
  reads it as the Unix `pwd` command. +5.

5 + 5 = the observed benign p50 of 10.

The second is a textbook signature-WAF false positive: a parameter *name*
colliding with a command name, with no payload involved anywhere.

Exclusions were written for both, scoped rather than blanket — 932236 is
excluded only for `ARGS_NAMES`, so a `pwd` command in a parameter *value* is
still caught. Removing the rule outright would have been the lazy fix and a
real blind spot. Effect:

| | before exclusions | after |
|---|---|---|
| benign p50 | 10 | **0** |
| benign p99 | 15 | **5** |
| FPR at threshold 8 | 99.46% | **0.18%** |

**This is now the second time a configuration error, not the rule set,
produced a catastrophic false-positive rate** (the first was JSON body
parsing in Phase 3). The hypothesis that much of CRS's FPR reputation is
configuration rather than rules is getting harder to dismiss, and is worth
testing properly as a paper contribution.

## Finding 4 — CSIC's "anomalous" label is not "injection attack"
Of 220 sampled CSIC anomalies scoring below threshold, 188 were parameter
tampering (`remember=on%2F`, `pwdA=` instead of `pwd=`, `modo=entrar%252B`,
empty values) — not injection.

**Therefore an aggregate detection rate over CSIC is a misleading metric.**
Per class, at 0.18% FPR (threshold 8), measured on `val`:

| class | recall |
|---|---|
| sqli | **97.1%** |
| xss | **96.4%** |
| cmdi | **77.6%** |
| other (CSIC mixed) | 14.7% |
| *aggregate* | *35.5%* |

The aggregate hides strong sqli/xss performance behind a class we never
claimed to cover. This vindicates the decision to make per-class recall a
first-class gate, and it is a substantive criticism of how CSIC is used in
the literature.

**cmdi remains the weakest claimed class at 77.6%** — the clearest target
for S2.

## Defects found and fixed in our own work
1. **Unstratified splitting** put zero cmdi in test and one sqli in val. Fixed
   with per-label stratification.
2. **Single-regime grouping** collapsed every payload list into one group,
   making whole classes unsplittable. Fixed with skeleton grouping for
   curated lists, keeping template grouping for generated traffic.
3. **Unsplittable classes were silent.** Added `split_warnings()`, which
   reports any class with fewer than 3 groups rather than letting it produce
   an empty split discovered later as a suspicious score.
4. **A test of mine used bad data** — `payload-variant-{i}` collapses under
   skeleton hashing. Replaced with genuinely distinct payloads.

## Verification
```
248 tests pass · ruff clean · mypy --strict clean
17 corpus tests incl. a guard-the-guard test asserting that the leakage
detector actually fails on a deliberately row-split corpus
```

## Gates not met, and why
- **Cross-corpus generalisation: NOT MEASURED.** ECML/PKDD 2007 is downloaded
  but unparsed. This is the headline gate of the whole evaluation protocol and
  remains outstanding.
- **FPR ≤ 0.1%: not established.** Measured 0.18% on 560 benign samples;
  that sample size cannot resolve 0.1%.
- **Captured real traffic: absent.** CSIC is one 2010 application.

## Next
Parse ECML/PKDD and run the cross-corpus comparison — train-on-one,
test-on-other — which is the number this project's evaluation protocol exists
to produce.
