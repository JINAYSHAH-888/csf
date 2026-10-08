# ADR-0017 — Closing the open backend gaps (operating point, S3, CI, signing)

**Status:** Accepted · **Date:** 2026-10-08

Four items stood open at the end of Phase 14. Each is addressed here as far as
it honestly can be; where an item cannot be "solved" (S3; a universal safe
default) this records the deliberate decision and its bound instead of faking a
result.

## 1. No cross-application safe default operating point → shadow calibration

There is no threshold derivable from the two corpora that is safe on a third
application; ADR-0011 proved the development corpus cannot even distinguish a
safe threshold from a dangerous one (it is 100%-precise at all of them). The
correct closure is the one ADR-0011 named: **set the operating point from the
target application's own traffic**, in shadow mode.

`scripts/calibrate.py` does this. Given a JSONL of the app's shadow-mode
requests (real traffic, overwhelmingly benign) it scores them through the real
S1 + S2, and recommends the lowest (highest-recall) thresholds whose block rate
— which on near-all-benign traffic ≈ the false-positive rate — stays within the
operator's budget. Demonstrated on ECML-as-an-unseen-app: it recommends
S1=20/S2=6.0 for a 0.29% block rate, i.e. it would have prevented the 67%-FPR
disaster the shipped default caused there.

It bounds FPR, not recall — shadow traffic is unlabeled — and says so. Recall
comes from the detectors' cross-corpus validation (ADR-0015). This closes the
*operational* gap (how does an operator get a safe point) without inventing a
universal constant that cannot exist.

## 2. S3 is a negative result → kept off, now also advisory-only if enabled

S3's cross-application AUC collapse (0.53–0.71 vs 0.999 in-corpus, Phase 6) is a
real measurement, not a bug to fix; forcing it to "work" would be fabrication.
The honest closure is a safe, explicit decision:

- **Off by default** (unchanged). Startup refuses to enable it without
  `trained_on_this_application` (unchanged).
- **Advisory-only by default when enabled (new).** `advisory_only=True` makes
  S3 able to FLAG but never BLOCK. Its failure mode is a cross-app FPR
  collapse; a learned stage that blocks on that is a block-storm. Advisory-only
  lets S3 contribute signal to the audit log and the decision engine while it
  structurally cannot cause a production incident.
- **Explicit re-enable-to-block criteria:** train on the protected
  application's own traffic, validate FPR on that application's shadow traffic
  (via `calibrate.py`), then — and only then — set `advisory_only=False`.

So S3 is closed as a decision with a bound and a path, not as a solved model.

## 3. No uv.lock / CI gate → both added

`backend/uv.lock` pins the full resolved dependency set (94 packages);
`uv sync --frozen` in CI gives reproducible installs. `.github/workflows/ci.yml`
gates every merge on: ruff, mypy --strict, the full pytest suite, pip-audit
(Python CVEs), the Go sidecar's gofmt/vet/build/govulncheck, and a build of
both container images. The corpus-dependent benchmarks are NOT CI gates — the
datasets are licensed and not in the repo — and that is stated in the workflow;
they are run by a maintainer with the data and their outputs are committed.

## 4. Config signing was HMAC-only → Ed25519 asymmetric added

`config_integrity.py` now prefers Ed25519. The config is signed OFFLINE with a
private key that never touches the server; the gateway holds only the public
key (`CSF_CONFIG_PUBKEY`) and can verify but not forge. HMAC remains as a
symmetric fallback for local use; when both are configured, asymmetric wins.
Tested, including that verification needs only the public key and that a body
tampered after signing fails. This defends against an attacker who can read the
gateway's filesystem — which the HMAC scheme, sharing one secret for sign and
verify, did not.

## What remains genuinely open

- **The frontend/dashboard** is a separate track, not a backend gap, and is not
  begun. It needs its own scoping (what an operator needs to see and do).
  `/statusz` already exposes the machine-readable state a dashboard would
  render.
- A universal safe default still does not exist and cannot from two corpora;
  calibration is the answer, and it requires the operator to run a shadow
  period. This is inherent to the problem, not a deferral.
