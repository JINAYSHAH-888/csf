#!/usr/bin/env python3
"""Phase 11: parser-differential fuzzing (threat model T3).

T3 is the bypass the threat model calls the most likely real one: CSF frames a
request one way, the backend another, and a payload invisible to CSF is live to
the backend. The threat model makes this test "required, not optional."

The property under test
-----------------------
CSF sits behind the ASGI server's parser (httptools under uvicorn), so it sees
httptools's framing, not raw bytes. A backend may use a different parser. If
two independent parsers frame a request DIFFERENTLY, CSF cannot know which the
backend will follow, so it must REJECT rather than forward. This fuzzer looks
for the failure: a request httptools accepts, h11 frames differently (or
rejects), and CSF nonetheless accepts.

Method
------
For each generated raw request:
  1. Parse with httptools. If it rejects, uvicorn would 400 and the request
     never reaches CSF — safe, and not CSF's call to make.
  2. If httptools accepts, parse with h11 too and compare the FRAMING that
     matters for smuggling: did both see the same body length and the same
     terminal state?
  3. When the two parsers disagree, build the ASGI header list httptools
     produced and run CSF's check_framing on it. If CSF returns OK on a request
     the two parsers framed differently, that is a T3 finding.

This is a differential test (two references), not a correctness oracle for one.
It cannot prove CSF rejects every smuggling vector — only that it rejects the
ones where these two parsers visibly disagree. Stated in the report.
"""
from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import h11  # noqa: E402
import httptools  # noqa: E402

from csf.framing import Rejection, check_framing  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent.parent


@dataclass
class ParseView:
    accepted: bool
    body_len: int | None = None
    error: str = ""
    headers: list[tuple[bytes, bytes]] | None = None


class _HttptoolsTarget:
    def __init__(self) -> None:
        self.headers: list[tuple[bytes, bytes]] = []
        self.body = b""
        self.complete = False

    def on_header(self, name: bytes, value: bytes) -> None:
        self.headers.append((name.lower(), value))

    def on_body(self, data: bytes) -> None:
        self.body += data

    def on_message_complete(self) -> None:
        self.complete = True


def parse_httptools(raw: bytes) -> ParseView:
    tgt = _HttptoolsTarget()
    parser = httptools.HttpRequestParser(tgt)
    try:
        parser.feed_data(raw)
    except Exception as exc:  # noqa: BLE001 - any parser error == rejection
        return ParseView(accepted=False, error=type(exc).__name__)
    if not tgt.complete:
        return ParseView(accepted=False, error="incomplete")
    return ParseView(accepted=True, body_len=len(tgt.body), headers=tgt.headers)


def parse_h11(raw: bytes) -> ParseView:
    conn = h11.Connection(h11.SERVER)
    try:
        conn.receive_data(raw)
        body = b""
        while True:
            ev = conn.next_event()
            if ev is h11.NEED_DATA or isinstance(ev, h11.PAUSED):
                return ParseView(accepted=False, error="incomplete")
            if isinstance(ev, h11.Data):
                body += ev.data
            elif isinstance(ev, h11.EndOfMessage):
                return ParseView(accepted=True, body_len=len(body))
    except Exception as exc:  # noqa: BLE001
        return ParseView(accepted=False, error=type(exc).__name__)


# --- generators: the classic smuggling / desync constructs ----------------
#
# Curated rather than random: pure byte-fuzzing mostly yields garbage both
# parsers reject, which measures nothing. These are the vectors T3 names.

def _req(headers: list[tuple[str, str]], body: bytes = b"") -> bytes:
    head = "GET / HTTP/1.1\r\n" + "".join(f"{k}: {v}\r\n" for k, v in headers)
    # utf-8: headers are bytes on the wire; a client can send non-latin-1
    # bytes (e.g. the utf-8 of a non-ascii digit), and both parsers see them.
    return head.encode("utf-8") + b"\r\n" + body


def generate() -> list[tuple[str, bytes]]:
    out: list[tuple[str, bytes]] = []
    # CL + TE (classic CL.TE / TE.CL smuggling).
    out.append(("cl+te", _req([("Host", "x"), ("Content-Length", "6"),
                               ("Transfer-Encoding", "chunked")], b"0\r\n\r\n")))
    # Duplicate, conflicting Content-Length.
    out.append(("dup_cl_conflict", _req([("Host", "x"), ("Content-Length", "5"),
                                        ("Content-Length", "6")], b"hello")))
    # Duplicate, agreeing Content-Length.
    out.append(("dup_cl_agree", _req([("Host", "x"), ("Content-Length", "5"),
                                      ("Content-Length", "5")], b"hello")))
    # Transfer-Encoding with an obfuscated token.
    out.append(("te_obfuscated", _req([("Host", "x"),
                                       ("Transfer-Encoding", "chunked ")],
                                      b"0\r\n\r\n")))
    out.append(("te_xchunked", _req([("Host", "x"),
                                     ("Transfer-Encoding", "xchunked")], b"")))
    out.append(("te_identity_chunked", _req([("Host", "x"),
                ("Transfer-Encoding", "identity, chunked")], b"0\r\n\r\n")))
    # Space before the colon (obsolete, ambiguous).
    out.append(("space_before_colon", _req([("Host", "x"),
                                            ("Content-Length ", "5")], b"hello")))
    # Tab in the Content-Length value.
    out.append(("tab_in_cl", _req([("Host", "x"), ("Content-Length", "5\t")],
                                  b"hello")))
    # Negative / plus-prefixed / hex content length.
    for odd in ("+5", "-5", "0x5", "5 ", " 5", "05"):
        out.append((f"cl_odd_{odd.strip() or 'sp'}",
                    _req([("Host", "x"), ("Content-Length", odd)], b"hello")))
    # Duplicate Host.
    out.append(("dup_host", _req([("Host", "a"), ("Host", "b"),
                                 ("Content-Length", "0")])))
    # Chunk size with extension / leading zeros / non-hex.
    out.append(("chunk_ext", _req([("Host", "x"),
                ("Transfer-Encoding", "chunked")], b"5;x=1\r\nhello\r\n0\r\n\r\n")))
    # Bare LF line endings (no CR).
    out.append(("bare_lf", b"GET / HTTP/1.1\nHost: x\nContent-Length: 5\n\nhello"))
    # Double Transfer-Encoding across two header lines.
    out.append(("double_te", _req([("Host", "x"), ("Transfer-Encoding", "chunked"),
                ("Transfer-Encoding", "identity")], b"0\r\n\r\n")))
    # TE then CL (TE.CL smuggling shape).
    out.append(("te_then_cl", _req([("Host", "x"),
                ("Transfer-Encoding", "chunked"), ("Content-Length", "6")],
                b"0\r\n\r\n")))
    # Vertical tab / form feed inside the CL value.
    out.append(("cl_vtab", _req([("Host", "x"), ("Content-Length", "5\x0b")],
                                b"hello")))
    out.append(("cl_formfeed", _req([("Host", "x"), ("Content-Length", "5\x0c")],
                                    b"hello")))
    # Unicode digit that .isdigit() accepts but int() may not frame as ascii.
    out.append(("cl_unicode_digit", _req([("Host", "x"),
                ("Content-Length", "\u0665")], b"hello")))  # arabic-indic 5
    # Chunked with a non-hex size.
    out.append(("chunk_nonhex", _req([("Host", "x"),
                ("Transfer-Encoding", "chunked")], b"z\r\nhello\r\n0\r\n\r\n")))
    # A clean request as a control: both parsers must agree, CSF must accept.
    out.append(("clean", _req([("Host", "x"), ("Content-Length", "5")], b"hello")))
    return out


def main() -> int:
    cases = generate()
    findings: list[dict] = []
    rows: list[dict] = []

    for name, raw in cases:
        ht = parse_httptools(raw)
        h = parse_h11(raw)

        # If httptools rejects, uvicorn 400s it; it never reaches CSF.
        if not ht.accepted:
            rows.append({"case": name, "httptools": "reject",
                         "h11": "accept" if h.accepted else "reject",
                         "verdict": "httptools-rejected (never reaches CSF)"})
            continue

        # httptools accepted. Do the parsers agree on framing?
        agree = h.accepted and h.body_len == ht.body_len
        csf = check_framing("GET", "/", ht.headers or [])
        csf_ok = csf is Rejection.OK

        if agree:
            rows.append({"case": name, "httptools": f"accept(body={ht.body_len})",
                         "h11": f"accept(body={h.body_len})",
                         "csf": csf.value or "OK",
                         "verdict": "parsers agree"})
            continue

        # The dangerous case: httptools accepted, h11 disagrees.
        h11_desc = "reject" if not h.accepted else f"accept(body={h.body_len})"
        row = {"case": name, "httptools": f"accept(body={ht.body_len})",
               "h11": h11_desc, "csf": csf.value or "OK",
               "verdict": "DIFFERENTIAL -> CSF must reject"}
        rows.append(row)
        if csf_ok:
            findings.append(row)

    print(f"=== differential fuzz: {len(cases)} cases ===\n")
    print(f"  {'case':<22} {'httptools':<20} {'h11':<18} {'CSF':<24}")
    print("  " + "-" * 86)
    for r in rows:
        print(f"  {r['case']:<22} {r['httptools']:<20} {r['h11']:<18} "
              f"{r.get('csf', '-'):<24}")

    print(f"\n  parser disagreements where CSF FAILED to reject: {len(findings)}")
    for f in findings:
        print(f"    !! {f['case']}: httptools={f['httptools']} h11={f['h11']} "
              f"CSF={f['csf']}")

    out = ROOT / "docs" / "benchmarks" / "differential-fuzz.json"
    out.write_text(json.dumps({"cases": len(cases), "rows": rows,
                               "findings": findings}, indent=2, sort_keys=True))
    print(f"\nwrote {out}")
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
