# Phases 11–12 — Differential Fuzzing & Supply Chain — Completion Report

**Date:** 2026-10-08 · **Threats:** T3 (parser differential), supply-chain
integrity · **Deliverables:** `scripts/fuzz_differential.py`,
`scripts/gen_sbom.py`, `docs/security/sbom.cdx.json`

## Phase 11 — parser-differential fuzzing (T3)

T3 is the bypass the threat model calls the most likely real one and marks a
*required* test: CSF frames a request one way, the backend another, and a
payload invisible to CSF is live to the backend.

**The property tested.** CSF sits behind the ASGI server's parser (httptools),
so it sees httptools's framing, not raw bytes. A backend may use a different
parser. If two independent parsers frame a request differently, CSF cannot know
which the backend follows, so it must **reject**. The fuzzer generates the
classic desync constructs, parses each with httptools and h11, and for every
request where the two disagree, asserts CSF rejects it.

**Result: 0 unrejected disagreements over 24 vectors.** The harness is not
vacuous — two vectors are genuine differentials (`TE: identity, chunked` and
duplicate `Host`: httptools accepts, h11 rejects) and CSF rejected both. A
clean control request both parsers accept passes framing. Four regression tests
pin this, including two that assert the differentials *remain* differentials, so
the test cannot lose its teeth silently.

**Honest limits.** A differential between these two parsers only. A construct
both httptools and h11 frame identically but a Go/nginx backend treats
differently is not found here. Random byte-fuzzing was rejected as low-signal —
it mostly yields garbage both parsers reject. The vector set is curated and
finite; it is a floor on CSF's framing strictness, not a proof of completeness.

## Phase 12 — supply chain / SBOM

**What it found first: the inventory was stale.** `docs/third-party.md`
described the abandoned Go-everything design (golang-jwt, keyfunc, vitess) —
dependencies the shipped code does not have. Phase 12 regenerated it from
`importlib.metadata` and `go.sum`, i.e. from what is installed, not remembered.

**Delivered.** `gen_sbom.py` drives **cyclonedx-py** (Python, CycloneDX 1.6, 101 environment components) and
**cyclonedx-gomod** (the Go sidecar, 19 components), then scans both with
**pip-audit** and **govulncheck**. (An earlier revision hand-rolled the SBOM to
avoid dependencies; that was corrected on review — a bespoke SBOM a reviewer
cannot trust, and one that cannot hit a vulnerability database, defeats the
purpose. The tools are a declared `security` extra.) The audit checks
three release-blocking conditions:
- unpinned direct Python deps (ranges are fine for a library; a release must
  lock them — there is no `uv.lock` in-tree yet, flagged);
- copyleft in the Python tree — **none**; the inventory is MIT/BSD/Apache/MPL/PSF;
- open "verify before use"/TBD rows in `third-party.md` — **none**, after the
  rewrite resolved the four stale ones.

The sidecar's **only** direct dependency is Coraza v3 (Apache-2.0); the other 32
Go modules are its transitive tree, enumerated in the SBOM. WAF-A-MoLE was
removed from the inventory: the adversarial lab is an in-tree re-implementation
(ADR-0012), so WAF-A-MoLE is neither vendored nor imported and is not a
distribution concern.

Licence claims in `third-party.md` were verified against the generated SBOM, not
asserted — including numpy's bundled `BSD-3-Clause AND 0BSD AND MIT AND Zlib AND
CC0-1.0` expression.

## Verification

- 596 tests (564 before; 32 added: 28 differential, 4 SBOM); `ruff` and
  `mypy --strict` clean.
- SBOM regenerated; audit clean (0 release blockers).

## Carried forward

- No `uv.lock` / pinned release manifest yet — ranges must be locked for a
  reproducible release build (also noted in ADR-0010 for base images).
- Differential fuzzing covers httptools vs h11 only; a third backend parser
  (Go `net/http`, nginx) is not in the comparison.
- CVE scanning IS wired (pip-audit for Python, govulncheck for Go), added in a
  Phase 12 follow-up after review; both reported clean (0 vulnerabilities). The
  SBOM generator was also replaced: it previously hand-rolled CycloneDX from
  importlib.metadata; it now drives cyclonedx-py and cyclonedx-gomod. What
  remains carried forward is the lock file (no `uv.lock`) and CI wiring of these
  scans as a merge gate.
