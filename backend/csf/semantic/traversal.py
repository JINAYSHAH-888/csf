"""Path-traversal analysis by normalisation, not pattern matching.

The mechanism
-------------
Resolve the candidate as a path and ask one question: **does it escape the
root it was supposed to stay under?**

That is a property of the resolved path, not of the characters used to build
it. ``../``, ``..%2f``, ``....//``, ``..\\`` and ``%2e%2e%2f`` are all
different strings and the same attack; after decoding and normalisation they
all resolve above the root. A regex needs a case for each; normalisation
needs none.

Why it was missing
------------------
S2 originally shipped with SQL, XSS and shell analysers and no traversal
analyser at all. Measured consequence: 3.3% recall on ECML's PathTransversal
class, which is 25% of that corpus's claimed attacks. The gap was invisible
until a corpus with a dedicated traversal label was used — which is itself an
argument for per-class measurement.
"""

from __future__ import annotations

import posixpath
import re
from dataclasses import dataclass, field
from urllib.parse import unquote

__all__ = ["TraversalFinding", "TraversalVerdict", "analyze_traversal"]

#: Absolute paths that are never a legitimate user-supplied value.
SENSITIVE_ABSOLUTE = (
    "/etc/", "/proc/", "/sys/", "/root/", "/var/log/", "/var/run/",
    "/boot/", "/dev/", "/home/", "/.ssh/", "/.aws/", "/.git/",
    "c:\\windows", "c:\\winnt", "\\windows\\system32", "/windows/system32",
)

#: Files worth naming explicitly: reading any of them is the goal of most
#: traversal attempts.
SENSITIVE_FILES = (
    "passwd", "shadow", "hosts", "sam", "ntds.dit", "id_rsa", "authorized_keys",
    "web.config", ".htpasswd", ".env", "boot.ini", "win.ini", "credentials",
)

#: A traversal segment in any of its common encodings. Used only as a cheap
#: pre-filter; the decision is made by normalisation below.
_DOTDOT_HINT = re.compile(r"\.\.|%2e|%252e|\.%2e|%2e\.", re.IGNORECASE)

#: Null byte truncation, historically used to cut off an appended extension.
_NULL_TRUNCATION = re.compile(r"%00|\x00")

#: Backslash escaping of the path itself: ``\.\.\/\.\.\/etc\/passwd``.
#:
#: A measured gap. The payload arrives already escaped the way a JSON or
#: JavaScript string literal would be, so percent-decoding leaves it untouched
#: and ``_escapes_root`` sees ``\.\.`` as an ordinary filename rather than a
#: dot segment. 89 missed traversal requests on an unseen application had this
#: single shape. Dropping a backslash before a non-word character recovers the
#: path the receiving parser will see.
_BACKSLASH_ESCAPE = re.compile(r"\\([^\w\s])")

#: Residue of a byte sequence that was not valid UTF-8.
#:
#: Decoding replaces such bytes with U+FFFD, so an invalidly-encoded path
#: separator survives only as a replacement character: ``..\ufffd..`` was
#: ``..<some encoding of />..`` on the wire. The separator is the whole point of
#: the payload, and the reason to send invalid bytes at all is that different
#: parsers resolve them differently. Treating the residue as a candidate
#: separator recovers the dot-segment structure.
_DECODE_RESIDUE = re.compile("\ufffd+")

#: URL schemes that make a file-reading parameter read something else entirely.
#:
#: These are not traversal in the ``../`` sense but they are the same bug class
#: and the same parameter: a value the application resolves as a location.
#: ``file://`` reads the local filesystem, the PHP stream wrappers read source
#: or wrap filters, and ``gopher``/``dict``/``expect`` turn a file read into an
#: outbound request or a command.
DANGEROUS_SCHEMES = (
    "file:", "php:", "phar:", "zip:", "glob:", "data:", "expect:",
    "gopher:", "dict:", "ldap:", "netdoc:", "jar:", "ogg:", "compress.zlib:",
)

#: A scheme is only meaningful at the very start of the value: a URL embedded
#: mid-string is a different question and a far noisier signal.
_SCHEME_AT_START = re.compile(r"^\s*([a-z][a-z0-9.+-]*:)", re.IGNORECASE)


@dataclass(slots=True)
class TraversalFinding:
    marker: str
    weight: float
    detail: str

    def __str__(self) -> str:
        return f"{self.marker}(+{self.weight:g}): {self.detail}"


@dataclass(slots=True)
class TraversalVerdict:
    score: float = 0.0
    findings: list[TraversalFinding] = field(default_factory=list)
    inert: bool = True

    def add(self, marker: str, weight: float, detail: str) -> None:
        for existing in self.findings:
            if existing.marker == marker:
                if weight > existing.weight:
                    self.score += weight - existing.weight
                    existing.weight = weight
                    existing.detail = detail
                return
        self.findings.append(TraversalFinding(marker, weight, detail))
        self.score += weight
        self.inert = False

    def explain(self) -> str:
        if not self.findings:
            return "resolves within its root"
        return "; ".join(str(f) for f in self.findings)


def _decode(value: str, depth: int = 3) -> str:
    """Bounded iterative percent-decoding.

    Bounded for the same reason normalisation is bounded elsewhere: repeated
    decoding of crafted input is a CPU amplification vector (threat model T4).
    """
    current = value
    for _ in range(depth):
        decoded = unquote(current)
        if decoded == current:
            break
        current = decoded
    return current


def _parser_views(value: str) -> list[tuple[str, str]]:
    """The distinct strings a receiving parser might see. Returns (how, text).

    One decoded view is not enough. The same bytes mean different things to
    different parsers, and an attacker picks an encoding precisely because of
    that disagreement, so each plausible reading is normalised separately
    rather than being folded into one canonical string.
    """
    decoded = _decode(value)
    views = [("", decoded)]
    unescaped = _BACKSLASH_ESCAPE.sub(r"\1", decoded)
    if unescaped != decoded:
        views.append(("after removing backslash escapes", unescaped))
    for how, text in list(views):
        if _DECODE_RESIDUE.search(text):
            views.append((
                (how + ", " if how else "")
                + "reading undecodable bytes as a path separator",
                _DECODE_RESIDUE.sub("/", text)))
    return views


def _escapes_root(path: str) -> tuple[bool, int]:
    """Does this path resolve above its root? Returns (escaped, depth)."""
    unified = path.replace("\\", "/")
    # posixpath.normpath collapses ".." the way a filesystem would.
    resolved = posixpath.normpath(posixpath.join("/__root__", unified))
    if not resolved.startswith("/__root__"):
        # Count how far above the root it climbed.
        depth = 0
        probe = resolved
        while probe.startswith("../"):
            depth += 1
            probe = probe[3:]
        return True, max(depth, 1)
    return False, 0


def analyze_traversal(value: str) -> TraversalVerdict:
    """Analyse a candidate value for path traversal."""
    verdict = TraversalVerdict()
    if len(value) < 4:
        return verdict

    decoded = _decode(value)
    lowered = decoded.lower()

    if _NULL_TRUNCATION.search(value):
        verdict.add("null_truncation", 4.0,
                    "value contains a NUL, historically used to truncate an "
                    "appended file extension")

    # --- escape above the root -------------------------------------------
    views = _parser_views(value)
    if _DOTDOT_HINT.search(value) or any(".." in v for _, v in views):
        for how, view in views:
            escaped, depth = _escapes_root(view)
            if escaped:
                suffix = f", {how}" if how else ""
                verdict.add("root_escape", 5.0,
                            f"after decoding and normalisation{suffix} the "
                            f"path resolves {depth} level(s) above its root")
                break
        else:
            if ".." in decoded:
                # Contains ".." but stays within the root once resolved, e.g.
                # "a/../b". Not an escape, but unusual in user input.
                verdict.add("dot_segment", 1.0,
                            "value contains '..' segments that normalise away")

    # --- a scheme that reads something other than a file -----------------
    scheme_match = _SCHEME_AT_START.match(decoded)
    if scheme_match is not None:
        scheme = scheme_match.group(1).lower()
        if scheme.startswith(DANGEROUS_SCHEMES):
            verdict.add("dangerous_scheme", 4.0,
                        f"value opens with the {scheme!r} scheme, which makes "
                        "a location parameter read the local filesystem or "
                        "issue its own request")

    # --- absolute path to a sensitive location ---------------------------
    for prefix in SENSITIVE_ABSOLUTE:
        if prefix in lowered:
            verdict.add("sensitive_absolute_path", 4.0,
                        f"value references {prefix!r}, a location user input "
                        "should never name")
            break

    # --- sensitive filename, only with path structure --------------------
    # "passwd" alone is a word; "../../passwd" and "/etc/passwd" are attacks.
    if "/" in decoded or "\\" in decoded:
        for name in SENSITIVE_FILES:
            if lowered.endswith(name) or f"/{name}" in lowered:
                verdict.add("sensitive_file", 3.0,
                            f"path targets {name!r}")
                break

    return verdict
