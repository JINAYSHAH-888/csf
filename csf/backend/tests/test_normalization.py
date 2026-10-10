"""Normalisation tests: decoding correctness, caps, and false-positive safety."""

from __future__ import annotations

import time

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from csf.normalization import Flag, Limits, normalize


@pytest.mark.parametrize(
    ("name", "value", "want_norm", "want_layers", "want_flags"),
    [
        ("plain", "hello world", "hello world", 0, []),
        ("single_url", "1%20OR%201%3D1", "1 OR 1=1", 1, []),
        ("plus_as_space", "a+b", "a b", 1, []),
        # %2527 -> %27 -> ' : two passes, therefore also multi-layer.
        ("double_url", "%2527%20OR%201%3D1", "' OR 1=1", 2, [Flag.MULTI_LAYER_ENCODING]),
        ("html_entity", "&lt;script&gt;", "<script>", 0, []),
        ("fullwidth", "ｓｅｌｅｃｔ", "select", 0, [Flag.UNICODE_CHANGED]),
    ],
)
def test_decoding(name, value, want_norm, want_layers, want_flags):
    got = normalize(value)
    assert got.normalized == want_norm
    assert got.decode_layers == want_layers
    for flag in want_flags:
        assert got.has_flag(flag), f"missing {flag}; got {got.flags}"
    assert got.original == value, "original must be preserved verbatim"


def test_depth_cap_is_enforced_and_flagged():
    # %25252527 needs 4 passes to reach "'".
    got = normalize("%25252527", Limits(max_decode_depth=2))
    assert got.decode_layers <= 2
    assert got.has_flag(Flag.DEPTH_CAP_HIT), f"flags={got.flags}"
    assert got.suspicious


def test_multi_layer_encoding_is_suspicious():
    got = normalize("%2531%2520OR%25201")
    assert got.has_flag(Flag.MULTI_LAYER_ENCODING)
    assert got.suspicious


def test_size_cap_truncates_and_flags():
    got = normalize("A" * 1000, Limits(max_value_bytes=100))
    assert len(got.original) == 100
    assert got.has_flag(Flag.SIZE_CAP_HIT)


def test_null_byte_is_stripped_and_flagged():
    got = normalize("admin%00.png")
    assert "\x00" not in got.normalized
    assert got.has_flag(Flag.NULL_BYTE)
    assert got.suspicious


@pytest.mark.parametrize(
    ("name", "value", "want", "want_flag"),
    [
        ("inline_block", "SEL/**/ECT", "SELECT", True),
        ("mysql_line", "1 OR 1=1 -- comment", "1 OR 1=1 ", True),
        ("hash_line", "1 OR 1=1 #c", "1 OR 1=1 ", True),
        ("html_comment", "a<!--x-->b", "ab", True),
        ("unterminated_block", "abc/*def", "abc", True),
        # "--" without trailing whitespace is NOT a MySQL comment. Stripping it
        # would corrupt legitimate values such as part numbers.
        ("double_dash_no_space", "part--123", "part--123", False),
        ("no_comment", "hello", "hello", False),
    ],
)
def test_comment_stripping(name, value, want, want_flag):
    got = normalize(value)
    assert got.comment_free == want
    assert got.has_flag(Flag.COMMENT_STRIPPED) is want_flag
    assert got.normalized, "primary view must not be emptied by comment handling"


@pytest.mark.parametrize(
    "value",
    [
        "hello world",
        "john.doe@example.com",
        "Product Name (Large, Blue)",
        "2026-10-01T12:00:00Z",
        "price>100&price<200",
        "SELECT desk lamp",
        "C++ programming",
        "50% off",
        "user's guide",
        "naïve café",
        "path/to/resource",
        "a--b",
        "1 + 1 = 2",
        '{"key":"value"}',
    ],
)
def test_benign_values_are_not_suspicious(value):
    """FPR is the binding constraint. A normaliser that flags everything is as
    useless as one that flags nothing."""
    got = normalize(value)
    assert not got.suspicious, f"benign {value!r} flagged: {got.flags}"


def test_normalisation_is_bounded_under_adversarial_input():
    """T4: normalisation must not be a CPU amplification vector."""
    bomb = "%25" * 20000 + "27"
    start = time.perf_counter()
    got = normalize(bomb, Limits(max_decode_depth=3, max_value_bytes=64 * 1024))
    elapsed = time.perf_counter() - start

    assert elapsed < 0.25, f"decode bomb took {elapsed:.3f}s; must stay bounded"
    assert got.decode_layers <= 3
    print(f"\ndecode bomb ({len(bomb)} bytes) in {elapsed * 1000:.2f}ms, "
          f"{got.decode_layers} layers, flags={got.flags}")


@given(st.text(max_size=2000))
@settings(max_examples=400, deadline=None)
def test_normalize_never_crashes_and_respects_caps(value):
    got = normalize(value, Limits(max_decode_depth=3, max_value_bytes=4096))
    assert len(got.original) <= 4096
    assert got.decode_layers <= 3
    assert "\x00" not in got.normalized


@given(st.text(alphabet="%0123456789abcdefABCDEF<>&;'\"/*-#\x00 ", max_size=500))
@settings(max_examples=400, deadline=None)
def test_normalize_on_encoding_alphabet(value):
    """Focused fuzz over the characters that drive decoding paths."""
    got = normalize(value)
    assert "\x00" not in got.normalized
    assert isinstance(got.comment_free, str)
