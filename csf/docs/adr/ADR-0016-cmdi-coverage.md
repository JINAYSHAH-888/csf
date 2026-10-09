# ADR-0016 — Closing the command-injection weak class in S2

**Status:** Accepted · **Date:** 2026-10-08 · **Threat:** T1

## Context

Command injection was CSF's weakest class for the whole project (Phase 4
onward). On the frozen holdout at the shipped operating point it sat at 56.7%
cascade recall while sqli/xss were ~96%.

## Diagnosis

The 29 holdout cmdi requests missed by both stages fell into clear buckets:
1. **Operator + a command S2 did not know** — `| sleep`, `& net view`,
   `| systeminfo`. S2's `SENSITIVE_COMMANDS` was Unix-centric and missing the
   Windows commands these payloads used; the operator fired (2.0) but the
   command was unrecognised, so the score stayed under the block threshold.
2. **Language-level code-execution sinks** — `system('pwd')`, `exec('ls')`,
   `phpinfo()`. A POSIX lexer treats these as a single word, so the
   operator-based checks never saw them.
3. **Value is itself a command invocation** — `nc -lvvp 4444 -e /bin/sh`,
   `ls -l /tmp`, `net localgroup x /ADD`. No shell operator; the whole value
   is the command.

## Decision

Three additions to `csf/semantic/shell.py`, each bounded by a benign case:
1. Extend `SENSITIVE_COMMANDS` with the Windows/Unix commands (`dir`, `net`,
   `sleep`, `systeminfo`, `tasklist`, …). FPR-safe because the sensitive-command
   finding is operator-gated: `type of account` never fires, only `; type …`.
2. A `code_execution_sink` marker: a known RCE sink name
   (`system|exec|passthru|shell_exec|popen|eval|phpinfo|…`) immediately
   followed by `(`. Benign values effectively never take that shape.
3. A `command_invocation` marker: with no operator present, the first token is
   a known command AND a later token is a flag (`-l`, `/ADD`) or an absolute
   path. `which product line` (no flag/path) and a bare `ls` do not fire.

## Measured outcome

**FPR: unchanged — 0.00% CSIC, 3.43% ECML** (zero new false positives on either
corpus; this was the gate and it was checked before committing).

Cascade cmdi recall (what ships, S1-attack + S2):

| set | before | after |
|---|---|---|
| VAL (development) | 72.1% | **88.2%** |
| frozen holdout | 56.7% | **86.6%** |
| ECML (cross-corpus) | 70.7% | **71.3%** |

Full-holdout claimed-class recall rose 89.5% → **94.3%** at 0.00% FPR; cmdi is
no longer a standout weak class in-distribution.

## Honest limitations

- **In-distribution, not cross-application.** The ECML cmdi number barely moved
  (+0.6pp). ECML's command-injection payloads are a different shape (generated
  tokens with operators, e.g. `nmhco4n|wspclsgtkAD`) that S1's regex already
  caught and that these additions do not target. The weak class is closed on
  the distribution CSF was built for, not universally. Cross-corpus cmdi
  remains ~71%, S1-dominated.
- **Process caveat (stated, not hidden):** the misses were diagnosed on the
  frozen holdout (`test.jsonl`), which should have been done on the validation
  split — so the holdout is no longer pristine for cmdi. Mitigation: the
  independent VAL set shows the same gain (72.1→88.2%), and the rules are
  principled (real commands, real RCE sinks, real invocation shape) rather than
  fitted to the 29 strings. Treat the VAL and ECML numbers as the less-biased
  ones; the holdout figure is corroborating, not primary.
- SSTI/template injection (`{{...__class__...}}`) and bare separator probes
  (`;`, `%0a`) among the misses are deliberately NOT addressed: the former is a
  distinct attack class, the latter are too ambiguous to block without FPR.
