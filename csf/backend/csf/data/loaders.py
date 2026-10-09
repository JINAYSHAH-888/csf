"""Parsers for the public corpora.

Each loader returns :class:`~csf.data.corpus.Request` objects tagged with
their source, so split boundaries and cross-corpus evaluation can respect
provenance.
"""

from __future__ import annotations

import re
from pathlib import Path
from urllib.parse import urlsplit

from csf.data.corpus import AttackClass, Request

__all__ = ["load_csic", "load_ecml_pkdd", "load_payload_list"]

_REQUEST_LINE = re.compile(r"^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+(\S+)\s+HTTP/")


def _parse_csic_block(lines: list[str], label: AttackClass, origin: str) -> Request | None:
    """Parse one CSIC request block.

    The CSIC format is a raw HTTP request per block, blocks separated by blank
    lines. A POST body follows the headers after a blank line — which means
    the naive "split on blank line" approach loses every POST body, and with
    it most of the attack payloads. We therefore track the header/body
    boundary explicitly.
    """
    if not lines:
        return None
    match = _REQUEST_LINE.match(lines[0])
    if not match:
        return None
    method, url = match.group(1), match.group(2)
    parts = urlsplit(url)

    headers: dict[str, list[str]] = {}
    body = ""
    in_body = False
    body_lines: list[str] = []
    for line in lines[1:]:
        if in_body:
            body_lines.append(line)
            continue
        if not line.strip():
            in_body = True
            continue
        name, sep, value = line.partition(":")
        if sep:
            headers.setdefault(name.strip().lower(), []).append(value.strip())
    body = "\n".join(body_lines).strip()

    return Request(
        method=method,
        path=parts.path,
        query=parts.query,
        headers=headers,
        body=body,
        label=label,
        source="csic2010",
        origin=origin,
    )


def load_csic(path: Path, label: AttackClass, limit: int | None = None) -> list[Request]:
    """Load a CSIC 2010 traffic file.

    CSIC labels its anomalous file as a single bucket; it mixes SQLi, XSS,
    CRLF injection, path traversal, parameter tampering and others. We tag it
    ``OTHER`` rather than guessing a class per request, because mislabelling
    would corrupt per-class recall — the metric that stops a weak class
    hiding behind a strong one.
    """
    requests: list[Request] = []
    block: list[str] = []
    blank_run = 0

    with path.open(encoding="latin-1") as handle:
        for lineno, raw in enumerate(handle, 1):
            line = raw.rstrip("\n")
            if not line.strip():
                blank_run += 1
                # Two consecutive blanks end a block; one may be the
                # header/body separator.
                if blank_run >= 2 and block:
                    parsed = _parse_csic_block(block, label, f"{path.name}:{lineno}")
                    if parsed is not None:
                        requests.append(parsed)
                        if limit and len(requests) >= limit:
                            return requests
                    block = []
                    blank_run = 0
                    continue
                if block:
                    block.append(line)
                continue
            if _REQUEST_LINE.match(line) and block:
                parsed = _parse_csic_block(block, label, f"{path.name}:{lineno}")
                if parsed is not None:
                    requests.append(parsed)
                    if limit and len(requests) >= limit:
                        return requests
                block = []
            blank_run = 0
            block.append(line)

    if block:
        parsed = _parse_csic_block(block, label, f"{path.name}:end")
        if parsed is not None:
            requests.append(parsed)
    return requests


#: A request shape sampled from benign traffic: (method, path, param, headers).
RequestShape = tuple[str, str, str, dict[str, list[str]]]


def benign_request_shapes(rows: list[Request], limit: int = 500) -> list[RequestShape]:
    """Extract realistic request shapes from benign traffic.

    Used to embed payload-list attacks in requests that look like the
    application's own, rather than at a synthetic endpoint.
    """
    shapes: list[RequestShape] = []
    seen: set[tuple[str, str, str]] = set()
    for r in rows:
        params = [kv.split("=", 1)[0] for kv in r.query.split("&") if "=" in kv]
        for param in params or ["q"]:
            key = (r.method, r.path, param)
            if key in seen:
                continue
            seen.add(key)
            shapes.append((r.method, r.path, param, dict(r.headers)))
            if len(shapes) >= limit:
                return shapes
    return shapes


def load_payload_list(
    path: Path, label: AttackClass, source: str,
    endpoint: str = "/api/search", param: str = "q",
    limit: int | None = None,
    shapes: list[RequestShape] | None = None,
    seed: int = 20261006,
) -> list[Request]:
    """Load a newline-delimited payload list into requests.

    These corpora are payloads, not requests, so the surrounding request must
    be constructed. **How it is constructed decides whether the corpus is
    usable.**

    Measured failure of the naive approach: placing every payload at a fixed
    synthetic endpoint (``/api/search?q=``) made that endpoint **100%
    attack** — 1,711 rows, never appearing in benign traffic. A classifier
    then separates the classes perfectly from the endpoint alone, learning
    nothing about payloads. It scored 100% recall at 0.18% FPR on the tuned
    corpus and **100% FPR** on an unseen one, because "not CSIC-shaped" had
    become its definition of an attack.

    Passing ``shapes`` (from :func:`benign_request_shapes`) embeds each
    payload in a request shape drawn from real benign traffic, so endpoint
    and parameter name carry no label information and the only signal left
    is the payload itself.
    """
    import random
    from urllib.parse import quote

    rng = random.Random(seed)  # noqa: S311 - reproducible corpus construction
    requests: list[Request] = []
    with path.open(encoding="utf-8", errors="replace") as handle:
        for lineno, raw in enumerate(handle, 1):
            payload = raw.rstrip("\n")
            if not payload.strip() or payload.lstrip().startswith("#"):
                continue
            if shapes:
                method, shape_path, shape_param, headers = rng.choice(shapes)
            else:
                method, shape_path, shape_param = "GET", endpoint, param
                headers = {"host": ["app.local"], "user-agent": ["Mozilla/5.0"]}
            requests.append(Request(
                method=method,
                path=shape_path,
                query=f"{shape_param}={quote(payload, safe='')}",
                headers=dict(headers),
                label=label,
                source=source,
                origin=f"{path.name}:{lineno}",
            ))
            if limit and len(requests) >= limit:
                break
    return requests


#: ECML/PKDD 2007 class names mapped onto CSF's attack classes.
#:
#: Ldap/XPath injection and SSI are real attacks but are not classes CSF
#: claims to cover, so they are tagged OTHER rather than folded into a class
#: we report recall for. Inflating a claimed class with attacks we never
#: designed for would be the same mistake as CSIC's single "anomalous" bucket.
ECML_CLASS_MAP = {
    "Valid": AttackClass.BENIGN,
    "SqlInjection": AttackClass.SQLI,
    "XSS": AttackClass.XSS,
    "OsCommanding": AttackClass.CMDI,
    "PathTransversal": AttackClass.TRAVERSAL,
    "LdapInjection": AttackClass.OTHER,
    "XPathInjection": AttackClass.OTHER,
    "SSI": AttackClass.OTHER,
}

_ECML_START = re.compile(r"^Start - Id:\s*(\S+)")
_ECML_CLASS = re.compile(r"^class:\s*(\S+)")
_ECML_END = re.compile(r"^End - Id:")


#: Headers that make an ECML/PKDD request protocol-malformed rather than
#: malicious. Measured on the distributed corpus: 100% of sampled "Valid"
#: requests carry BOTH Content-Length and Transfer-Encoding (a request
#: smuggling primitive), and CSF's own S0 framing check rejects 94.5% of the
#: entire corpus before any detection stage runs.
#:
#: Dropping these isolates the question we actually want to answer — does
#: INJECTION detection transfer across corpora — from the question the corpus
#: accidentally asks, which is whether a WAF notices malformed framing.
_ECML_PROTOCOL_NOISE = frozenset({
    "transfer-encoding", "content-length", "expect", "range", "if-range",
    "if-match", "if-none-match", "if-modified-since", "if-unmodified-since",
    "max-forwards", "proxy-authorization", "cookie2", "etag", "mime-version",
    "connection", "accept-charset", "pragma", "cache-control", "date", "from",
})


def load_ecml_pkdd(
    path: Path, limit: int | None = None,
    per_class_limit: int | None = None,
    protocol_normalize: bool = False,
) -> list[Request]:
    """Load the ECML/PKDD 2007 challenge dataset.

    Format is ``Start - Id: N`` / ``class: X`` / raw HTTP request /
    ``End - Id: N``.

    This corpus is the cross-corpus counterpart to CSIC 2010 and is well
    suited to the role: the challenge organisers randomised hostnames, paths,
    parameter names and header values, so nothing can be learned about the
    host application. A detector that scores well on CSIC by memorising
    ``/tienda1/`` templates gets no help here.

    ``protocol_normalize=True`` drops the randomised headers that make the
    requests protocol-malformed (see ``_ECML_PROTOCOL_NOISE``). Use it when
    measuring injection detection; leave it off when the protocol layer is
    what you are testing. **Which setting was used must be reported with any
    number derived from this corpus**, because it changes the result
    completely.
    """
    requests: list[Request] = []
    per_class: dict[AttackClass, int] = {}

    label: AttackClass | None = None
    block: list[str] = []
    in_request = False
    request_id = ""

    def flush() -> None:
        nonlocal label, block, in_request
        if label is not None and block:
            parsed = _parse_csic_block(block, label, f"{path.name}:{request_id}")
            if parsed is not None:
                parsed.source = "ecml_pkdd_2007"
                if protocol_normalize:
                    parsed.headers = {
                        k: v for k, v in parsed.headers.items()
                        if k.lower() not in _ECML_PROTOCOL_NOISE
                    }
                    parsed.source = "ecml_pkdd_2007_normalized"
                keep = True
                if per_class_limit is not None:
                    count = per_class.get(parsed.label, 0)
                    if count >= per_class_limit:
                        keep = False
                    else:
                        per_class[parsed.label] = count + 1
                if keep:
                    requests.append(parsed)
        label = None
        block = []
        in_request = False

    with path.open(encoding="latin-1") as handle:
        for raw in handle:
            line = raw.rstrip("\n")
            if _ECML_START.match(line):
                flush()
                request_id = _ECML_START.match(line).group(1)  # type: ignore[union-attr]
                continue
            match = _ECML_CLASS.match(line)
            if match and not in_request:
                raw_class = match.group(1)
                label = ECML_CLASS_MAP.get(raw_class)
                if label is None:
                    label = AttackClass.OTHER
                continue
            if _ECML_END.match(line):
                flush()
                if limit and len(requests) >= limit:
                    return requests
                continue
            if label is not None:
                in_request = True
                block.append(line)

    flush()
    return requests
