"""Framing admission tests, including the h11-vs-httptools divergence."""

from __future__ import annotations

import pytest

from csf.framing import FramingLimits, Rejection, check_framing


def H(*pairs: tuple[str, str]) -> list[tuple[bytes, bytes]]:
    return [(k.encode(), v.encode()) for k, v in pairs]


@pytest.mark.parametrize(
    ("name", "headers"),
    [
        ("simple", H(("host", "h"))),
        ("with_cl", H(("host", "h"), ("content-length", "0"))),
        ("chunked_only", H(("host", "h"), ("transfer-encoding", "chunked"))),
        ("normal", H(("host", "h"), ("user-agent", "Mozilla/5.0"),
                     ("accept", "application/json"), ("x-request-id", "abc-123"))),
        ("cl_large", H(("host", "h"), ("content-length", "1048576"))),
    ],
)
def test_well_formed_requests_accepted(name, headers):
    assert check_framing("GET", "/api/items", headers) is Rejection.OK


@pytest.mark.parametrize(
    ("name", "method", "path", "headers", "want"),
    [
        ("cl_and_te", "POST", "/", H(("content-length", "6"), ("transfer-encoding", "chunked")),
         Rejection.CL_AND_TE),
        ("cl_and_te_reversed", "POST", "/", H(("transfer-encoding", "chunked"), ("content-length", "6")),
         Rejection.CL_AND_TE),
        ("duplicate_cl_same", "POST", "/", H(("content-length", "6"), ("content-length", "6")),
         Rejection.DUPLICATE_CL),
        ("conflicting_cl", "POST", "/", H(("content-length", "6"), ("content-length", "7")),
         Rejection.CONFLICTING_CL),
        ("cl_comma_list", "POST", "/", H(("content-length", "6, 6")), Rejection.DUPLICATE_CL),
        ("negative_cl", "POST", "/", H(("content-length", "-1")), Rejection.INVALID_CL),
        ("plus_prefixed_cl", "POST", "/", H(("content-length", "+5")), Rejection.INVALID_CL),
        ("hex_cl", "POST", "/", H(("content-length", "0x5")), Rejection.INVALID_CL),
        ("non_numeric_cl", "POST", "/", H(("content-length", "6abc")), Rejection.INVALID_CL),
        ("obfuscated_te", "POST", "/", H(("transfer-encoding", "xchunked")), Rejection.UNSUPPORTED_TE),
        ("te_identity_chunked", "POST", "/", H(("transfer-encoding", "identity, chunked")),
         Rejection.UNSUPPORTED_TE),
        ("header_crlf", "GET", "/", H(("x-evil", "a\r\nInjected: yes")), Rejection.HEADER_CRLF),
        ("header_bare_lf", "GET", "/", H(("x-evil", "a\nInjected: yes")), Rejection.HEADER_CRLF),
        ("bad_header_name", "GET", "/", H(("x bad name", "v")), Rejection.BAD_HEADER_NAME),
        ("duplicate_host", "GET", "/", H(("host", "a"), ("host", "b")), Rejection.DUPLICATE_HOST),
        ("bad_method", "GET\rX", "/", H(("host", "h")), Rejection.BAD_METHOD),
        ("path_crlf", "GET", "/a\r\nX: y", H(("host", "h")), Rejection.BAD_PATH),
        ("path_null", "GET", "/a\x00b", H(("host", "h")), Rejection.BAD_PATH),
    ],
)
def test_smuggling_primitives_rejected(name, method, path, headers, want):
    got = check_framing(method, path, headers)
    assert got is not Rejection.OK, f"SECURITY FAILURE: {name} accepted"
    assert got is want, f"{name}: rejected as {got!r}, want {want!r}"


def test_oversized_header_value():
    headers = H(("host", "h"), ("x-big", "A" * 9000))
    assert check_framing("GET", "/", headers) is Rejection.HEADER_TOO_LARGE


def test_too_many_headers():
    headers = H(*[(f"x-h-{i}", "v") for i in range(150)])
    assert check_framing("GET", "/", headers) is Rejection.TOO_MANY_HEADERS


def test_total_header_size_cap():
    headers = H(*[(f"x-pad-{i}", "A" * 7000) for i in range(20)])
    assert check_framing("GET", "/", headers, FramingLimits()) is Rejection.HEADER_TOO_LARGE


def test_parser_is_observable_at_startup():
    """Which parser is installed changes our framing coverage, so it must be
    reportable rather than discovered during an incident."""
    from csf.framing import PARSER_BLIND_SPOTS, http_parser_in_use, parser_warnings

    parser = http_parser_in_use()
    assert parser in PARSER_BLIND_SPOTS

    warnings = parser_warnings()
    if PARSER_BLIND_SPOTS[parser]:
        assert warnings, f"{parser} has blind spots but produced no warning"
        assert "httptools" in warnings[0]
    else:
        assert not warnings


def test_httptools_is_the_installed_parser():
    """Measured: h11 accepts CL+TE (200 OK) and obs-fold; httptools rejects
    both. Our own check covers CL+TE either way, but obs-fold is only caught
    by httptools, so the strict parser is the supported configuration."""
    from csf.framing import http_parser_in_use

    assert http_parser_in_use() == "httptools", (
        "uvicorn[standard] should be installed so httptools is used; "
        "see csf/framing.py for the measured parser comparison"
    )
