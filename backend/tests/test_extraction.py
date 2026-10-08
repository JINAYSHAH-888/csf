"""Extraction tests: provenance, bounds, and no-silent-drop guarantees."""

from __future__ import annotations

import json

import pytest

from csf.extraction import ExtractionLimits, Location, extract


def H(*pairs):
    return [(k.encode(), v.encode()) for k, v in pairs]


def find(result, location, parameter):
    for c in result.candidates:
        if c.location is location and c.parameter == parameter:
            return c
    pytest.fail(
        f"no candidate at {location}/{parameter}; have "
        f"{[(str(c.location), c.parameter) for c in result.candidates]}"
    )


def test_extracts_query_with_provenance():
    res = extract("GET", "/api/search", b"q=hello+world&page=2", H(), b"")
    q = find(res, Location.QUERY, "q")
    assert q.normalized == "hello world"
    assert q.endpoint == "/api/search"
    assert q.method == "GET"
    find(res, Location.QUERY, "page")


def test_malformed_query_pairs_are_not_silently_dropped():
    """parse_qs drops pairs it dislikes; the backend might not (T3)."""
    from urllib.parse import parse_qs

    qs = b"good=1&bad%zz=2&novalue&q=%27+OR+1%3D1"
    stdlib_count = len(parse_qs(qs.decode(), keep_blank_values=True))
    res = extract("GET", "/api", qs, H(), b"")
    ours = [c for c in res.candidates if c.location is Location.QUERY]

    assert len(ours) == 4, f"extracted {len(ours)}, want 4 (stdlib got {stdlib_count})"
    assert find(res, Location.QUERY, "q").normalized == "' OR 1=1"


def test_extracts_nested_json_leaves():
    body = json.dumps(
        {"user": {"name": "alice", "tags": ["a", "b"], "age": 30,
                  "admin": False, "meta": None}}
    ).encode()
    res = extract("POST", "/api/users", b"", H(("content-type", "application/json")), body)

    for path, value, ctype in [
        ("$.user.name", "alice", "string"),
        ("$.user.tags[0]", "a", "string"),
        ("$.user.tags[1]", "b", "string"),
        ("$.user.age", "30", "number"),
        ("$.user.admin", "false", "bool"),
        ("$.user.meta", "", "null"),
    ]:
        c = find(res, Location.JSON_BODY, path)
        assert c.normalized == value, f"{path} = {c.normalized!r}"
        assert c.content_type == ctype, f"{path} type = {c.content_type!r}"

    assert res.body == body, "body must be preserved for upstream forwarding"


def test_bool_is_not_classified_as_number():
    """bool is a subclass of int in Python; order of isinstance checks matters."""
    body = json.dumps({"flag": True, "count": 1}).encode()
    res = extract("POST", "/", b"", H(("content-type", "application/json")), body)
    assert find(res, Location.JSON_BODY, "$.flag").content_type == "bool"
    assert find(res, Location.JSON_BODY, "$.count").content_type == "number"


def test_json_depth_is_capped():
    deep = ('{"a":' * 60) + '"x"' + ("}" * 60)
    res = extract("POST", "/", b"", H(("content-type", "application/json")),
                  deep.encode(), ExtractionLimits(max_json_depth=10))
    assert res.truncation.json_depth_cap_hit
    assert res.truncation.any


def test_candidate_cap_is_enforced():
    qs = "&".join(f"p{i}=v{i}" for i in range(500)).encode()
    res = extract("GET", "/", qs, H(), b"", ExtractionLimits(max_candidates=50))
    assert len(res.candidates) <= 50
    assert res.truncation.candidate_cap_hit


def test_body_cap_is_enforced():
    res = extract("POST", "/", b"", H(("content-type", "text/plain")),
                  b"A" * 5000, ExtractionLimits(max_body_bytes=1000))
    assert res.truncation.body_cap_hit
    assert len(res.body) == 1000


def test_unknown_content_type_body_still_inspected():
    """Declaring a weird type is the cheapest possible WAF bypass."""
    res = extract("POST", "/", b"", H(("content-type", "application/x-invented")),
                  b"' OR 1=1--")
    assert "OR 1=1" in find(res, Location.JSON_BODY, "$body").normalized


def test_unparseable_json_still_inspected():
    res = extract("POST", "/", b"", H(("content-type", "application/json")),
                  b'{"a": \'" OR 1=1')
    assert res.truncation.body_unparseable
    find(res, Location.JSON_BODY, "$raw")


def test_form_path_and_header_extraction():
    res = extract("POST", "/api/v1/users/42", b"",
                  H(("content-type", "application/x-www-form-urlencoded"),
                    ("user-agent", "curl/8"), ("referer", "https://example.com")),
                  b"name=bob&bio=%3Cscript%3E")
    assert find(res, Location.FORM, "bio").normalized == "<script>"
    find(res, Location.FORM, "name")
    find(res, Location.HEADER, "user-agent")
    find(res, Location.HEADER, "referer")
    segments = [c for c in res.candidates if c.location is Location.PATH]
    assert len(segments) == 4


def test_cookies_only_when_enabled():
    headers = H(("cookie", "session=abc; theme=dark"))
    off = extract("GET", "/", b"", headers, b"")
    assert not [c for c in off.candidates if c.location is Location.COOKIE]

    on = extract("GET", "/", b"", headers, b"", ExtractionLimits(inspect_cookies=True))
    assert find(on, Location.COOKIE, "session").normalized == "abc"
    assert find(on, Location.COOKIE, "theme").normalized == "dark"


def test_model_input_includes_full_provenance():
    res = extract("GET", "/api/search", b"q=test", H(), b"")
    got = find(res, Location.QUERY, "q").model_input()
    for fragment in ["[ENDPOINT] /api/search", "[METHOD] GET", "[LOCATION] query",
                     "[PARAM] q", "[TYPE] string", "[VALUE] test"]:
        assert fragment in got, f"missing {fragment!r} in {got!r}"


def test_suspicious_propagates_from_normalization():
    res = extract("GET", "/", b"q=%2525%2527", H(), b"")
    assert find(res, Location.QUERY, "q").suspicious


def test_benign_request_produces_no_suspicious_candidates():
    body = json.dumps({"query": "desk lamp", "filters": {"price_max": 100},
                       "sort": "relevance"}).encode()
    res = extract("POST", "/api/v2/products/search", b"",
                  H(("content-type", "application/json"),
                    ("user-agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)")),
                  body)
    for c in res.candidates:
        assert not c.suspicious, f"benign {c.location}/{c.parameter} flagged: {c.flags}"
    assert not res.truncation.any


def test_request_meta_preserves_duplicate_headers():
    """Downstream stages rebuild the request from request_meta instead of
    re-parsing raw HTTP, so duplicates must survive (T3)."""
    headers = H(("host", "h"), ("x-dup", "a"), ("x-dup", "b"))
    res = extract("POST", "/api/x", b"q=1", headers, b"body")
    meta = res.request_meta
    assert meta["method"] == "POST"
    assert meta["path"] == "/api/x"
    assert meta["query"] == "q=1"
    assert meta["headers"]["x-dup"] == ["a", "b"]
