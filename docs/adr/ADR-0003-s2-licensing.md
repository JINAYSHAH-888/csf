# ADR-0003 — S2 semantic engine implemented independently; SafeLine is reference only

**Status:** Accepted (Phase 0) · **Date:** 2026-10-01

## Context
S2 is grammar-aware semantic analysis: parse a candidate value as SQL/JS/shell and decide whether the parse has attack *shape*. The best-known implementation is SafeLine's engine, reported at ~0.07% FPR against ModSecurity PL1's ~17.6%.

## Problem
SafeLine's semantic engine is **GPL-3.0**. CSF is intended to be permissively licensed (Apache-2.0).

## Decision
Study SafeLine's published architecture and behaviour as a **reference**. Do not read, copy, vendor, or translate its source into CSF. Implement S2 independently on permissively licensed grammar libraries:
- SQL: `vitess.io/vitess/go/vt/sqlparser` (Apache-2.0), MySQL dialect first.
- JS/HTML: Go ES parser or embedded engine, license verified at integration.
- Shell: purpose-written lexer.

## Why
GPL-3.0 is copyleft. Incorporating it into an Apache-2.0 distribution would force relicensing of the combined work. Architectural ideas are not copyrightable; source is.

## Security impact
Neutral. We lose SafeLine's battle-testing and must earn our own FPR number — which we must do anyway, since their figure is from practitioner benchmarks (⚠ not peer-reviewed) and must be reproduced in our harness before we cite it as fact.

## Performance impact
Target ~0.1–1 ms per candidate value. Dialect coverage gaps (PostgreSQL/MSSQL constructs under a MySQL grammar) must be measured and declared, not assumed away.

## Operational impact
`docs/third-party.md` records license, version, and usage mode (dependency vs reference-only) for every external project. Reviewed before each release.

## Reversal strategy
N/A — this constrains what we may not do.

## Sources
- SafeLine GPL-3.0 — github.com/chaitin/SafeLine
- vitess sqlparser, Apache-2.0, 2026-06-24
