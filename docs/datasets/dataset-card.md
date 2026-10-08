# CSF Evaluation Corpus — Dataset Card

**Built:** 2026-10-01 · **Builder:** `backend/scripts/build_corpus.py`
**Manifest:** `data/processed/manifest.json`

## Composition

| Source | License/Origin | Rows kept | Labels |
|---|---|---|---|
| HTTP CSIC 2010 | public research corpus (mirrored) | 12,483 | benign, other |
| libinjection-bypasses | foospidy/payloads | 474 | sqli |
| jbrofuzz sqli / xss | OWASP JBroFuzz | 268 | sqli, xss |
| sqlifuzzer | foospidy/payloads | 59 | sqli |
| xss-ismailtasdelen, xssdb, xss-packetstorm | foospidy/payloads | 1,199 | xss |
| cmdi-windows | foospidy/payloads | 446 | cmdi |

Input 32,808 → kept **14,929** across **3,212** groups.

## Processing

**Deduplication: 17,876 of 32,808 (54%) were exact duplicates** once
normalised. Normalisation percent-decodes, sorts parameters, and drops
volatile headers (`cookie`, `date`, `referer`, …). Without dropping cookies
nothing would deduplicate at all, because every CSIC request has a unique
`JSESSIONID`.

That 54% figure is the single most important number here. **A random row
split would scatter those duplicates across train and test**, so a model
would be scored on near-copies of its training data. This is the most likely
explanation for the 99.5–99.7% F1 figures the transformer-WAF literature
reports on CSIC 2010.

**Label conflicts: 3.** Identical normalised content appearing under two
labels. Dropped rather than resolved — we cannot know which is right.

**Splitting is by group, never by row**, with two regimes:
- *Generated traffic* (CSIC): group = template (endpoint + parameter names +
  parameter value **types**). Requests differing only in substituted values
  share a group.
- *Curated payload lists*: group = payload skeleton (lowercased, digits and
  whitespace stripped, truncated, hashed). Template grouping is wrong here —
  every payload in a list shares one synthetic endpoint, so the whole class
  collapses into one group. Measured: that put **zero command-injection
  samples in the test set**.

Splits are **stratified by label**, after a first implementation produced a
validation set containing one SQLi sample.

| Split | n | benign | cmdi | other | sqli | xss |
|---|---|---|---|---|---|---|
| train | 10,291 | 3,796 | 312 | 4,784 | 483 | 916 |
| val | 1,953 | 560 | 67 | 1,025 | 104 | 197 |
| **test (frozen)** | 2,685 | 1,120 | 67 | 1,198 | 104 | 196 |

Leakage check passes: no shared requests and no shared template groups across
any pair of splits. SHA-256 of each split is recorded in the manifest so
"nothing trained on the holdout" is checkable, not merely asserted.

## ⚠ Limitations that affect how results must be read

**1. CSIC's "anomalous" label does NOT mean "injection attack".** This is the
most consequential caveat. Inspecting 220 CSIC anomalies that CRS scored
below threshold, 188 were things like:

```
remember=on%2F        trailing slash on a parameter value
pwdA=cacoquimia       parameter NAME tampered
modo=entrar%252B      double-encoded suffix
pwd=+                 empty-ish value
```

These are parameter tampering and application-logic anomalies, not injection.
A signature WAF for injection should not be expected to flag them, and we
label them `other` rather than as an attack class we claim to cover.

**Consequence:** an aggregate detection rate over CSIC's anomalous set is a
misleading metric. Reported per class at 0.18% FPR, S1 achieves sqli 97.1%,
xss 96.4%, cmdi 77.6% — while `other` sits at 14.7% and drags the aggregate
to 35.5%. Papers quoting ~99% "accuracy" on CSIC binary classification are
substantially measuring the ability to spot parameter tampering in one 2010
Spanish e-commerce app. **We report per-class recall and never a single
headline accuracy.**

**2. Benign traffic is single-application and 15 years old.** CSIC is one
Tomcat shop, generated, Spanish-language, 2010-era browsers. It cannot
represent the diversity of real benign traffic. Captured traffic from our own
applications is still outstanding.

**3. Payload-list requests are synthetic.** The payloads are real; the
surrounding request is not. Every entry from one list shares an endpoint and
parameter name.

**4. No cross-corpus split yet.** ECML/PKDD 2007 is downloaded
(`data/raw/waad/OriginalDataSets/ecml_pkdd/`) but not yet parsed, so the
cross-corpus generalisation gate is **not yet measurable**.

**5. Class imbalance.** `other` is 47% of all attack-labelled rows; cmdi is
3%. Per-class metrics are mandatory.

## Reproduction
```bash
cd backend && python scripts/build_corpus.py   # deterministic, seed 20261001
```

## The frozen holdout
`data/processed/test.jsonl`. Training on it, or deriving thresholds from it,
invalidates every number in the evaluation. Its SHA-256 is in the manifest.

**Status:** the frozen holdout was spent ONCE in Phase 14 (`docs/phases/P13-P14-completion-report.md`, `benchmarks/frozen-holdout.json`): claimed-class recall 92.6% at 0.09% FPR, in-distribution. It must not be reused for tuning; any further threshold work goes back to val.
As of Phase 4 it has **not been evaluated against** — all tuning used `val`.
