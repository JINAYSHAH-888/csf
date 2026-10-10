# Closing the S2 Coverage Residual — Report

**Date:** 2026-10-06 · **Stage changed:** S2 (grammar-aware semantic analysis)
**Question:** Phase 6 left 59.2% of claimed attacks missed by both S1 and S2 on
an unseen application. Is that domain shift, or missing detection?

**Answer: substantially missing detection.** Measured below. The headline
figure did not move, and §4 explains exactly why — the figure is defined at an
operating point no deployment can reach.

---

## 1. Method

The residual was characterised before anything was written. Every ECML/PKDD
request that S2 scored under `tau_block` was dumped with the per-candidate
scores that produced the miss, then bucketed by *why* it was missed. Four
shapes accounted for the bulk of the recoverable misses; each was reproduced as
a failing case, fixed, and paired with the false-positive case that bounds the
fix.

Two candidate fixes were **rejected on evidence**, which is recorded here
because rejecting them is part of the result:

- **A standalone-statement SQL context.** The idea was to parse a value as a
  statement rather than injecting it into a template, for payloads like
  `bulk insert od from 'pwdump.exe' with (codepage='RAW')`. Measured: ordinary
  prose parses as a complete statement — `select a size` → `Select`,
  `insert coin` → `Insert`, `update your profile` → `Update`. A completeness
  requirement (named target *and* a payload clause) removed all of those and
  produced 0 false positives across 1,260 benign requests from both corpora,
  but it **also failed to catch either target payload**: `BULK INSERT` and
  `EXEC xp_cmdshell` are T-SQL that sqlglot does not parse at all. A context
  that is safe and catches nothing is not worth its latency, so it was dropped.
  This is a parser-capability limit, not a design gap.
- **Remote-file-inclusion detection** (an absolute `http://` URL as a parameter
  value, 245 of the traversal misses). Not implemented: it cannot be separated
  from legitimate `returnUrl` / `redirect_uri` / `next` parameters without a
  per-endpoint schema of which parameters may carry a URL. That is positive
  security, and ECML cannot support building it — see §5.

## 2. What was fixed

| # | Analyser | Gap | Why the original marker missed it |
|---|---|---|---|
| 1 | `semantic/xss.py` | CSS `expression()`, `binding:`, `behavio(u)r:`, `-moz-binding`, `@import`, `url()` inside a `style` attribute or `<style>` element | The HTML tokeniser sees `style` as an ordinary attribute. The markup was parsed; the CSS inside it never was. An injected `<div style="...">` reached only the 2.0 `injected_markup` marker. |
| 2 | `semantic/xss.py` | URL-bearing attributes beyond the famous ones (`dynsrc`, `lowsrc`, `cite`, `longdesc`, …), and script schemes with a non-colon delimiter (`javascript#`) | `<input type="image" dynsrc="javascript:…">` scored 3.0: `dynsrc` was not in the URL-attribute set, so the scheme inside it was never read. |
| 3 | `semantic/sql.py` | Constant predicates in **any** comparison operator, not just `=` | `tautology` checked `exp.EQ` with two equal literals, i.e. `' OR '1'='1` and nothing else. `' OR 'ns' BETWEEN 'R' AND 'T'`, `' OR 'He' > 'S` and `' OR '99he' < 'X` are the same escape through a different operator. A predicate with no column reference is constant by definition; the operator is incidental. |
| 4 | `semantic/traversal.py` | Backslash-escaped separators (`\.\.\/\.\.\/etc\/passwd`), undecodable bytes standing in for a separator (`..\uFFFD\uFFFD..`), and dangerous schemes (`file:`, `php:`, `gopher:`, `dict:`, `expect:`) | Percent-decoding leaves `\.` untouched, so the dot segments stayed hidden from normalisation. One decoded view is not enough: each plausible reading is now normalised separately. |
| 5 | `semantic/shell.py` | Escaped line breaks — the literal two-character `\n` that a wrapper expands | `_LINE_BREAK` matched only real control characters, so `\n wget http://…/nftp.exe` produced no operator and the known command name was never corroborated. Scored 0. |

### A sixth defect, found while testing the above

`1 UNION SELECT password FROM users` scored **0** — and did so before any of
this work. The cheap pre-filter `_STRUCTURAL_CHARS` admits a value only if it
contains punctuation that could escape a leaf position. That payload contains
no quote, operator or separator, so the analyser **never ran at all**. A
numeric parameter needs no quote to escape: the keyword *is* the escape.

The pre-filter now also admits values containing a keyword that opens a query
or clause. The set-operation names are read off `exp.SetOperation.__subclasses__()`
rather than written out, and a test asserts every clause keyword is still one
sqlglot recognises, so an upstream rename fails the suite instead of silently
disabling the filter. `ORDER BY`/`GROUP BY` are matched as the full two-word
forms deliberately: admitting bare `order` or `group` would send "order
confirmation" and "group tour" to the parser for no possible finding.

This was the most serious of the six. It is recorded as found by accident,
because that is what happened.

## 3. Measured effect

Same corpora, same splits, same thresholds. Both runs executed in one session;
the "before" column is the analysers at commit `c5dd771` measured by the same
script, not a remembered number.

**At the configured blocking threshold (`S2Config.tau_block = 4.0`) — the
operating point the gateway ships with:**

| corpus | before | after | change | FPR (unchanged) |
|---|---|---|---|---|
| CSIC 2010 (development) | 53.0% | **57.7%** | **+4.7pp** | 0.00% |
| ECML/PKDD (unseen application) | 43.4% | **56.3%** | **+12.9pp** | 3.43% |

The cross-corpus recall gap at this threshold fell from **9.6pp to 1.4pp**.

**Per class on the unseen application** (threshold 0.5, CSIC's 0.1%-FPR point):

| class | before | after | change |
|---|---|---|---|
| xss | 64.7% | 77.4% | +12.7pp |
| cmdi | 46.7% | 53.3% | +6.6pp |
| traversal | 53.7% | 57.9% | +4.2pp |
| sqli | 44.9% | 44.9% | 0.0pp |
| **benign (FPR)** | **3.43%** | **3.43%** | **0.0pp** |

sqli is flat at this threshold because the constant-predicate payloads already
scored 3.0 and so already counted as detected here. The fix moved them from
3.0 to 7.0 — from *flagged* to *blocked* — which only the `tau_block` table
above can see. This is the same "recall at matched FPR is misleading" problem
the project documented in Phase 4b, in a new place.

**Cost:** S2 p99 latency 7,370µs → 7,420µs (+0.7%), from the widened
pre-filter sending more values to the parser. **False-positive cost: none
measurable on either corpus.**

**Missed requests**, counted directly: xss 336 → 158 (−53%), traversal 413 →
331, sqli 462 → 407, cmdi 373 → 327.

## 4. The 59.2% figure did not move. Why.

It is still 59.2%, and that is not a measurement error.

That figure is computed with each stage at the threshold that is **optimal on
the corpus being measured** — for ECML, S2 ≥ 8.5. Reaching it requires
labelled traffic from the application you have not deployed to yet, so no
deployment can choose it. Every gap closed here produces findings scoring
4.0–8.0, deliberately: those weights state "this is one confirmed escape", not
"three stacked". All of it is therefore invisible above 8.5.

`measure_cascade.py` now reports the residual at **both** operating points,
because the choice changes the number by a factor of three and only one of them
describes a deployment:

| operating point | ECML residual | combined FPR | usable? |
|---|---|---|---|
| per-corpus 0.1% FPR (S1≥44, S2≥8.5) | 59.2% | 0.00% | no — thresholds unobtainable |
| configured (S1≥11, S2≥4.0) | 3.6% | **67.14%** | no — S1 fires on two-thirds of benign traffic |
| **S2 alone, frozen from CSIC** | **43.7%** | **3.43%** | **yes** |

The last row is the only deployable configuration on an unseen application, and
it is the one that improved: **56.3% recall, up from 43.4%, at unchanged FPR.**
Neither of the first two rows describes something that could be shipped, so
neither should be quoted as *the* residual without its FPR beside it.

Both benchmark JSONs now persist the full table rather than a headline, because
a file holding one number cannot answer "did this change help?" — which is the
only question it exists for. Producing §3 required re-running the old code.

## 5. What remains, and what is not reachable

The remaining ECML misses were re-characterised after the fixes. Category D
("scored 3.0–4.0, just under blocking") is now small — sqli 21, traversal 36,
xss 0, cmdi 0 — so the easily-recoverable population is largely consumed. What
is left is two things:

**Genuine limits, named:**
- `exec xp_cmdshell '"x" >> script.vbs'` — T-SQL that sqlglot will not parse,
  and `exec` is not a shell command, so neither grammar applies (§1).
- `'select a '||'from b '||'where c='''||v||''''` — Oracle concatenation.
  **Tested and closed as a negative result (ADR-0009):** adding `oracle` to
  `DIALECTS` changed no score anywhere -- not on either corpus, not on ten
  hand-built Oracle-specific payloads -- while costing 23-28% p50 latency.
  This payload fails to parse in all four dialects including oracle; it is
  defeated by quote nesting, not by dialect coverage. The set stays at three.
- `qwer' or ooemxm9_v.Account='x@y.com` — a real escape scoring 3.0. It adds an
  OR with a *column*-to-literal predicate, so `constant_predicate` correctly
  does not fire. Raising `injected_or` to blocking strength is plausible but
  needs its own FPR measurement; it was not done here.

**Not reachable, and this is a corpus property:** a substantial share of ECML's
labelled attacks contain no attack structure in any candidate value. Observed
examples, each the highest-scoring candidate of a request labelled as an
attack: `'aa'` and `'iechoE'` (sqli), `'.'`, `'teii'` and `'Z-.'` (traversal),
`'psmFEqnetcatVE'` (cmdi), and requests whose only non-trivial value is a
generated User-Agent such as `Mozilla/0.9 (Windows; U; …) Gecko/23635036`. The
generator appears to have spliced attack keywords into random tokens. No
grammar-based analyser can recover these, and neither could a larger model —
there is nothing in the request to detect.

**This share is NOT quantified.** Separating "generator noise" from "a payload
CSF cannot see" needs a labelling judgement per request that has not been made,
so no number is given. The examples above are evidence that the population
exists and is non-trivial; they are not a measurement of its size.

## 6. Verification

- 462 tests pass (405 before; 57 added). Every fix has a detection test **and**
  the false-positive test that bounds it — notably that `C:\new\report.docx`
  and `C:\reports\new` stay at 0 despite containing `\n` and `\r`, which is the
  whole argument for requiring a command invocation after an escaped break.
- `ruff check` clean, `mypy --strict` clean (24 files).
- `scripts/measure_s2.py` and `scripts/measure_cascade.py` re-run; both
  benchmark JSONs regenerated.

## 7. Honest summary

Detection on an unseen application improved by **+12.9pp at the shipping
threshold with no false-positive cost**, and the cross-corpus gap narrowed from
9.6pp to 1.4pp. Five coverage gaps and one pre-filter defect that silently
disabled UNION detection were fixed.

The 59.2% residual as previously quoted is **unchanged**, and the reason is
that it was quoted at an operating point that cannot be deployed. The
deployable residual fell from 56.6% to 43.7%. Of what is left, some is named
parser limitation and some is corpus noise that nothing can detect; the split
between them has not been measured and is not claimed.

**S2 is still not a complete detector** — 43.7% of claimed attacks on an unseen
application go undetected at a usable FPR. The cascade's case still rests on
S1 and S2 failing differently, and S1 remains unusable cross-corpus at 66.86%
FPR. Nothing here changes that.
