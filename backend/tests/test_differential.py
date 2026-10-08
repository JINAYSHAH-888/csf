"""Phase 11 parser-differential regression (threat model T3).

The threat model makes differential fuzzing a *required* test. This pins its
result: CSF must reject every request on which two independent parsers
(httptools, h11) disagree about framing, because it cannot know which one the
backend follows.

The harness must also keep its teeth. Two of the generated cases are genuine
differentials — httptools accepts them, h11 rejects them — and the tests assert
BOTH that CSF rejects them (the security property) and that they really are
differentials (so a change that made them agree, hiding the test's power,
fails here too).
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

_SCRIPTS = str(Path(__file__).resolve().parent.parent / "scripts")
if _SCRIPTS not in sys.path:
    sys.path.insert(0, _SCRIPTS)

import fuzz_differential as fuzz  # noqa: E402

from csf.framing import Rejection, check_framing  # noqa: E402


def _views(raw: bytes):
    return fuzz.parse_httptools(raw), fuzz.parse_h11(raw)


def test_no_unrejected_parser_disagreements():
    """The headline property: zero requests where the two parsers disagree and
    CSF still accepts."""
    findings = []
    for name, raw in fuzz.generate():
        ht = fuzz.parse_httptools(raw)
        if not ht.accepted:
            continue  # never reaches CSF; uvicorn 400s it
        h = fuzz.parse_h11(raw)
        agree = h.accepted and h.body_len == ht.body_len
        if agree:
            continue
        csf = check_framing("GET", "/", ht.headers or [])
        if csf is Rejection.OK:
            findings.append(name)
    assert not findings, f"CSF accepted requests two parsers framed differently: {findings}"


def test_harness_has_teeth_identity_chunked():
    """httptools accepts `TE: identity, chunked`; h11 rejects it. A real
    differential, and CSF must reject it."""
    cases = dict(fuzz.generate())
    ht, h = _views(cases["te_identity_chunked"])
    assert ht.accepted and not h.accepted, "expected a real httptools/h11 split"
    assert check_framing("GET", "/", ht.headers or []) is not Rejection.OK


def test_harness_has_teeth_duplicate_host():
    cases = dict(fuzz.generate())
    ht, h = _views(cases["dup_host"])
    assert ht.accepted and not h.accepted
    assert check_framing("GET", "/", ht.headers or []) is Rejection.DUPLICATE_HOST


def test_clean_request_is_accepted():
    """A control: a clean request both parsers agree on must pass framing."""
    cases = dict(fuzz.generate())
    ht, _ = _views(cases["clean"])
    assert ht.accepted
    assert check_framing("GET", "/", ht.headers or []) is Rejection.OK


@pytest.mark.parametrize("name", [n for n, _ in fuzz.generate()])
def test_every_case_is_decided_without_error(name):
    """check_framing must never raise on any generated case, however malformed
    the httptools-parsed headers are."""
    cases = dict(fuzz.generate())
    ht = fuzz.parse_httptools(cases[name])
    if ht.accepted:
        check_framing("GET", "/", ht.headers or [])  # must not raise
