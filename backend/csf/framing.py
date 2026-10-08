"""Strict HTTP framing admission for S0.

Governing principle: **reject, never normalise.** If a request is ambiguous —
if two conforming parsers could disagree about where it ends or what it
contains — we refuse it. Normalising an ambiguous request means choosing an
interpretation, and if the backend chooses differently we have created exactly
the parser differential of threat model T3. Refusing costs a tiny number of
malformed-but-innocent requests and closes an entire bypass class.

Why this module is not redundant with the ASGI server
-----------------------------------------------------
Measured 2026-10-01 against uvicorn 0.54.0, sending raw bytes over TCP:

==========================  ====================  ==================
Request                     httptools (default)   h11 (fallback)
==========================  ====================  ==================
Content-Length + T-E        400 Bad Request       **200 OK**
Duplicate Content-Length    400                   400
Space before colon          400                   400
Obsolete line folding       400                   **200 OK**
Unsupported T-E             400                   400
==========================  ====================  ==================

``uvicorn[standard]`` installs httptools and ``http="auto"`` prefers it. A
deployment that installs plain ``uvicorn``, or sets ``http="h11"``, silently
gets the permissive parser. **The gateway must not depend on which parser the
operator happened to install.**

The good news, and the reason this is simpler than the equivalent Go code:
ASGI's ``scope["headers"]`` is a list of ``(name, value)`` byte pairs that
preserves duplicates and original order. The evidence survives. Go's
``net/http`` destroys it before a handler runs, which required a connection
sniffer in the Go prototype (see ADR-0006).
"""

from __future__ import annotations

from enum import StrEnum

__all__ = ["FramingLimits", "Rejection", "check_framing"]


class Rejection(StrEnum):
    """Protocol-level refusals. Not detection verdicts."""

    OK = ""
    #: Both Content-Length and Transfer-Encoding: the classic smuggling
    #: primitive. Two intermediaries disagree about which frames the message.
    CL_AND_TE = "content_length_and_transfer_encoding"
    DUPLICATE_CL = "duplicate_content_length"
    CONFLICTING_CL = "conflicting_content_length"
    INVALID_CL = "invalid_content_length"
    UNSUPPORTED_TE = "unsupported_transfer_encoding"
    DUPLICATE_HOST = "duplicate_host"
    BAD_HEADER_NAME = "malformed_header_name"
    HEADER_CRLF = "header_value_contains_crlf"
    TOO_MANY_HEADERS = "too_many_headers"
    HEADER_TOO_LARGE = "header_too_large"
    BAD_METHOD = "malformed_method"
    BAD_PATH = "malformed_path"


class FramingLimits:
    """Bounds header-level resources."""

    __slots__ = ("max_header_bytes", "max_headers", "max_total_header_bytes")

    def __init__(
        self,
        max_headers: int = 100,
        max_header_bytes: int = 8192,
        max_total_header_bytes: int = 64 * 1024,
    ) -> None:
        self.max_headers = max_headers
        self.max_header_bytes = max_header_bytes
        self.max_total_header_bytes = max_total_header_bytes


#: RFC 9110 "tchar" production.
_TCHAR = frozenset(
    "abcdefghijklmnopqrstuvwxyz"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "0123456789"
    "!#$%&'*+-.^_`|~"
)


def _is_token(value: str) -> bool:
    return bool(value) and all(c in _TCHAR for c in value)


def check_framing(
    method: str,
    path: str,
    raw_headers: list[tuple[bytes, bytes]],
    limits: FramingLimits | None = None,
) -> Rejection:
    """Validate request framing from the ASGI raw header list.

    ``raw_headers`` must be ``scope["headers"]`` — the unmodified list,
    including duplicates. Passing a deduplicated mapping defeats the point.
    """
    lim = limits or FramingLimits()

    if not _is_token(method):
        return Rejection.BAD_METHOD
    if "\r" in path or "\n" in path or "\x00" in path:
        return Rejection.BAD_PATH

    if len(raw_headers) > lim.max_headers:
        return Rejection.TOO_MANY_HEADERS

    content_lengths: list[str] = []
    transfer_encodings: list[str] = []
    host_count = 0
    total = 0

    for raw_name, raw_value in raw_headers:
        try:
            name = raw_name.decode("ascii")
            value = raw_value.decode("latin-1")
        except UnicodeDecodeError:
            return Rejection.BAD_HEADER_NAME

        # ASGI servers lowercase names, but a non-token character surviving
        # means the parser accepted something it should not have.
        if not _is_token(name):
            return Rejection.BAD_HEADER_NAME
        if len(value) > lim.max_header_bytes:
            return Rejection.HEADER_TOO_LARGE
        if "\r" in value or "\n" in value:
            return Rejection.HEADER_CRLF

        total += len(name) + len(value) + 4
        if total > lim.max_total_header_bytes:
            return Rejection.HEADER_TOO_LARGE

        lowered = name.lower()
        if lowered == "content-length":
            content_lengths.append(value)
        elif lowered == "transfer-encoding":
            transfer_encodings.append(value)
        elif lowered == "host":
            host_count += 1

    if host_count > 1:
        return Rejection.DUPLICATE_HOST

    if transfer_encodings:
        for header_value in transfer_encodings:
            for part in header_value.split(","):
                if part.strip().lower() != "chunked":
                    return Rejection.UNSUPPORTED_TE

    if content_lengths:
        # A single header carrying "5, 5" is as ambiguous as two headers:
        # some parsers take the first value, some the last.
        if len(content_lengths) > 1:
            if len({v.strip() for v in content_lengths}) > 1:
                return Rejection.CONFLICTING_CL
            return Rejection.DUPLICATE_CL
        raw_cl = content_lengths[0]
        if "," in raw_cl:
            return Rejection.DUPLICATE_CL
        stripped = raw_cl.strip()
        if not stripped.isdigit():
            # isdigit() also rejects "+5", "-1", "0x5" and unicode digits,
            # all of which different parsers interpret differently.
            return Rejection.INVALID_CL
        # The ambiguity that makes smuggling work.
        if transfer_encodings:
            return Rejection.CL_AND_TE

    return Rejection.OK


def http_parser_in_use() -> str:
    """Return the HTTP parser uvicorn will select under ``http="auto"``.

    uvicorn prefers httptools when it is importable and falls back to h11
    otherwise. Which one is installed changes the gateway's security posture
    (see the table above), so this must be observable at startup rather than
    discovered during an incident.
    """
    try:
        import httptools  # noqa: F401
    except ImportError:
        return "h11"
    return "httptools"


#: Framing violations the application-level check CANNOT detect, by parser.
#: h11 rewrites an obs-fold continuation into a single folded value before the
#: ASGI scope is built, so the evidence is destroyed — the same class of
#: problem the Go prototype hit with CL+TE (ADR-0006).
PARSER_BLIND_SPOTS: dict[str, tuple[str, ...]] = {
    "httptools": (),
    "h11": ("obsolete_line_folding",),
}


def parser_warnings() -> list[str]:
    """Return human-readable warnings about the active parser's blind spots."""
    parser = http_parser_in_use()
    blind = PARSER_BLIND_SPOTS.get(parser, ())
    if not blind:
        return []
    return [
        f"HTTP parser is {parser!r}, which cannot be checked for: "
        f"{', '.join(blind)}. httptools rejects these at the parser level. "
        f"Install uvicorn[standard] (which provides httptools) for full "
        f"framing coverage."
    ]
