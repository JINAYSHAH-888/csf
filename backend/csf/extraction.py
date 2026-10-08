"""Extract inspectable values from an HTTP request, with provenance.

Why provenance matters
----------------------
Detection stages are far more accurate when they know where a value came from.
``1 OR 1=1`` in a free-text search box is plausibly a user typing an
expression; the same string in a parameter that is always a small integer is
not. WADBERT's finding that parameter-level modelling beats flat request text
is the empirical form of this argument, and S3's input representation depends
on it.

Train/serve skew
----------------
:meth:`Candidate.model_input` is the single definition of how a candidate is
serialised for the model. The training pipeline imports *this function*. That
is the main reason the backend is one language (ADR-0006): if serving and
training serialised candidates differently, the model would be fed inputs it
was never trained on and the failure would be silent.

Bounds
------
Every traversal is bounded. An attacker controls body shape, parameter count
and nesting depth, so each is capped and exceeding a cap is recorded rather
than silently truncated (threat model T4).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any
from urllib.parse import unquote_plus

from csf.normalization import Flag, normalize
from csf.normalization import Limits as NormLimits

__all__ = [
    "Candidate",
    "ExtractionLimits",
    "Location",
    "Result",
    "Truncation",
    "extract",
]


class Location(StrEnum):
    QUERY = "query"
    FORM = "form"
    JSON_BODY = "json_body"
    MULTIPART = "multipart"
    COOKIE = "cookie"
    HEADER = "header"
    PATH = "path"


#: Flags that make a candidate suspicious on structural grounds alone.
_SUSPICIOUS = frozenset(
    {Flag.DEPTH_CAP_HIT, Flag.NULL_BYTE, Flag.MULTI_LAYER_ENCODING, Flag.INVALID_UTF8}
)


@dataclass(slots=True)
class Candidate:
    """One inspectable value plus everything needed to judge it in context."""

    endpoint: str
    method: str
    location: Location
    parameter: str
    #: The inferred shape ("string", "number", "bool", "null") — not the HTTP
    #: Content-Type header.
    content_type: str
    original: str
    normalized: str
    comment_free: str = ""
    flags: list[Flag] = field(default_factory=list)

    @property
    def suspicious(self) -> bool:
        return any(f in _SUSPICIOUS for f in self.flags)

    def model_input(self) -> str:
        """Render in the provenance-tagged form S3 consumes.

        The training pipeline MUST import this rather than reimplementing it.
        """
        return (
            f"[ENDPOINT] {self.endpoint} [METHOD] {self.method} "
            f"[LOCATION] {self.location} [PARAM] {self.parameter} "
            f"[TYPE] {self.content_type} [VALUE] {self.normalized}"
        )


#: Headers worth inspecting. Most headers are infrastructure noise; these are
#: the ones applications routinely read and pass into queries or templates.
DEFAULT_INSPECT_HEADERS = (
    "user-agent",
    "referer",
    "x-forwarded-for",
    "x-real-ip",
    "x-requested-with",
    "origin",
    "accept-language",
)


@dataclass(frozen=True, slots=True)
class ExtractionLimits:
    max_candidates: int = 256
    max_body_bytes: int = 1 << 20
    max_json_depth: int = 20
    max_header_value: int = 8192
    inspect_cookies: bool = False
    inspect_headers: tuple[str, ...] = DEFAULT_INSPECT_HEADERS
    normalization: NormLimits = field(default_factory=NormLimits)


@dataclass(slots=True)
class Truncation:
    """Records that extraction stopped early. Like a normalisation cap, this
    is a signal: a request with 500 parameters is not ordinary traffic."""

    candidate_cap_hit: bool = False
    json_depth_cap_hit: bool = False
    body_cap_hit: bool = False
    body_unparseable: bool = False

    @property
    def any(self) -> bool:
        return (
            self.candidate_cap_hit
            or self.json_depth_cap_hit
            or self.body_cap_hit
            or self.body_unparseable
        )

    def describe(self) -> str:
        """Which caps fired, for the audit reason string."""
        hit = [name for name, on in (
            ("candidates", self.candidate_cap_hit),
            ("json_depth", self.json_depth_cap_hit),
            ("body", self.body_cap_hit),
            ("body_unparseable", self.body_unparseable),
        ) if on]
        return ",".join(hit) if hit else "none"


@dataclass(slots=True)
class Result:
    candidates: list[Candidate] = field(default_factory=list)
    truncation: Truncation = field(default_factory=Truncation)
    #: The body bytes read during extraction. Callers forwarding upstream must
    #: use this, because the ASGI receive stream has been consumed.
    body: bytes = b""
    #: The request as S0 parsed it: method, path, query, headers, request_id.
    #: Downstream stages reconstruct the request from THIS rather than
    #: re-parsing raw HTTP, so the gateway and its stages cannot disagree
    #: about what the request was (threat model T3).
    request_meta: dict[str, Any] = field(default_factory=dict)


class _Collector:
    __slots__ = ("endpoint", "limits", "method", "result")

    def __init__(self, endpoint: str, method: str, limits: ExtractionLimits) -> None:
        self.endpoint = endpoint
        self.method = method
        self.limits = limits
        self.result = Result()

    def add(self, location: Location, parameter: str, ctype: str, raw: str) -> None:
        if len(self.result.candidates) >= self.limits.max_candidates:
            self.result.truncation.candidate_cap_hit = True
            return
        norm = normalize(raw, self.limits.normalization)
        self.result.candidates.append(
            Candidate(
                endpoint=self.endpoint,
                method=self.method,
                location=location,
                parameter=parameter,
                content_type=ctype,
                original=norm.original,
                normalized=norm.normalized,
                comment_free=norm.comment_free,
                flags=list(norm.flags),
            )
        )

    def walk_json(self, body: bytes) -> None:
        try:
            doc = json.loads(body)
        except (json.JSONDecodeError, UnicodeDecodeError):
            self.result.truncation.body_unparseable = True
            # Unparseable JSON is still inspected as an opaque string: the
            # backend's parser may be more lenient than ours.
            self.add(Location.JSON_BODY, "$raw", "string", _safe_decode(body))
            return
        self.walk_value("$", doc, 0)

    def walk_value(self, path: str, value: Any, depth: int) -> None:
        if depth > self.limits.max_json_depth:
            self.result.truncation.json_depth_cap_hit = True
            return
        if isinstance(value, dict):
            for key, child in value.items():
                self.walk_value(f"{path}.{key}", child, depth + 1)
        elif isinstance(value, list):
            for index, child in enumerate(value):
                self.walk_value(f"{path}[{index}]", child, depth + 1)
        elif isinstance(value, str):
            self.add(Location.JSON_BODY, path, "string", value)
        elif isinstance(value, bool):
            # Checked before int: bool is a subclass of int in Python.
            self.add(Location.JSON_BODY, path, "bool", str(value).lower())
        elif isinstance(value, int | float):
            # Numbers cannot carry injection, but they are recorded so S3 and
            # any learned schema see the full parameter shape of the request.
            self.add(Location.JSON_BODY, path, "number", repr(value))
        elif value is None:
            self.add(Location.JSON_BODY, path, "null", "")


def _safe_decode(data: bytes) -> str:
    return data.decode("utf-8", errors="replace")


def _parse_pairs(blob: str) -> list[tuple[str, str]]:
    """Parse a urlencoded pair list WITHOUT discarding malformed pairs.

    ``urllib.parse.parse_qs`` silently drops pairs it dislikes. The backend
    might not, and a dropped pair is a free bypass (threat model T3). Keys are
    decoded leniently; values are left raw so normalisation can observe their
    encoding depth.
    """
    pairs: list[tuple[str, str]] = []
    for chunk in blob.split("&"):
        if not chunk:
            continue
        key, sep, value = chunk.partition("=")
        if not sep:
            value = ""
        pairs.append((unquote_plus(key), value))
    return pairs


def extract(
    method: str,
    path: str,
    query_string: bytes,
    raw_headers: list[tuple[bytes, bytes]],
    body: bytes,
    limits: ExtractionLimits | None = None,
) -> Result:
    """Extract all inspectable values from a request."""
    lim = limits or ExtractionLimits()
    collector = _Collector(path, method, lim)
    grouped: dict[str, list[str]] = {}
    for raw_name, raw_value in raw_headers:
        grouped.setdefault(
            raw_name.decode("latin-1"), []
        ).append(raw_value.decode("latin-1"))
    collector.result.request_meta = {
        "method": method,
        "path": path,
        "query": query_string.decode("latin-1"),
        "headers": grouped,
    }

    # Path segments: many APIs put identifiers here, and traversal lives here.
    for segment in path.strip("/").split("/"):
        if segment:
            collector.add(Location.PATH, "segment", "string", segment)

    for key, value in _parse_pairs(query_string.decode("latin-1")):
        collector.add(Location.QUERY, key, "string", value)

    header_map: dict[str, str] = {}
    cookie_header = ""
    for raw_name, raw_value in raw_headers:
        name = raw_name.decode("latin-1").lower()
        value = raw_value.decode("latin-1")
        if name == "cookie":
            cookie_header = value
        header_map.setdefault(name, value)

    for name in lim.inspect_headers:
        header_value = header_map.get(name)
        if header_value:
            collector.add(
                Location.HEADER, name, "string", header_value[: lim.max_header_value]
            )

    if lim.inspect_cookies and cookie_header:
        for chunk in cookie_header.split(";"):
            key, sep, value = chunk.strip().partition("=")
            if sep:
                collector.add(Location.COOKIE, key, "string", value)

    if len(body) > lim.max_body_bytes:
        collector.result.truncation.body_cap_hit = True
        body = body[: lim.max_body_bytes]
    collector.result.body = body

    if not body:
        return collector.result

    media_type = header_map.get("content-type", "").split(";")[0].strip().lower()
    if media_type == "application/json" or media_type.endswith("+json"):
        collector.walk_json(body)
    elif media_type == "application/x-www-form-urlencoded":
        for key, value in _parse_pairs(_safe_decode(body)):
            collector.add(Location.FORM, key, "string", value)
    else:
        # An unknown Content-Type must not make the body invisible: declaring
        # a weird type is the cheapest possible WAF bypass.
        collector.add(Location.JSON_BODY, "$body", "string", _safe_decode(body))

    return collector.result
