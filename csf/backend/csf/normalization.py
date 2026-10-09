"""Decode attacker-controlled values into a canonical form for detection.

Why this is security-critical
-----------------------------
Two opposing risks meet here.

**Under-normalising loses detections.** A payload encoded as
``%2527%20OR%201%3D1`` is invisible to a rule or parser that only sees raw
bytes, because the backend decodes it before the database does.

**Over-normalising creates two problems.** First, CPU amplification:
unbounded iterative decoding of crafted input is a denial-of-service vector
(threat model T4). Second, parser differential: decoding more aggressively
than the backend does means we may "see" an attack the backend never executes
(false positive), or normalise away a distinction the backend treats as
meaningful (false negative).

The resolution
--------------
* Every decoding loop is bounded by an explicit depth cap, every input by a
  size cap, and all work is accounted.
* Hitting a cap is **never silent**. It is recorded in :attr:`Result.flags`
  and is itself a detection signal — legitimate traffic does not arrive
  triple-encoded.
* Both the original and the normalised value are retained. Downstream stages
  see both and decide which view is authoritative for their own purpose,
  rather than being handed a lossy rewrite.

See threat model T3 (parser differential) and T4 (resource exhaustion).
"""

from __future__ import annotations

import html
import re
import unicodedata
from dataclasses import dataclass, field
from enum import StrEnum
from urllib.parse import unquote_plus

__all__ = ["Flag", "Limits", "Result", "normalize"]


class Flag(StrEnum):
    """A notable observation made while normalising. These are signals."""

    MULTI_LAYER_ENCODING = "multi_layer_encoding"
    DEPTH_CAP_HIT = "decode_depth_cap_hit"
    SIZE_CAP_HIT = "size_cap_hit"
    INVALID_UTF8 = "invalid_utf8"
    NULL_BYTE = "null_byte"
    UNICODE_CHANGED = "unicode_normalisation_changed"
    CONTROL_CHARS = "control_characters"
    COMMENT_STRIPPED = "comment_stripped"


DEFAULT_MAX_DECODE_DEPTH = 3
DEFAULT_MAX_VALUE_BYTES = 64 * 1024


@dataclass(frozen=True, slots=True)
class Limits:
    """Bounds all normalisation work."""

    max_decode_depth: int = DEFAULT_MAX_DECODE_DEPTH
    max_value_bytes: int = DEFAULT_MAX_VALUE_BYTES


#: Flags that justify escalation on structural grounds alone, independent of
#: content. Legitimate application traffic does not contain these.
_SUSPICIOUS_FLAGS = frozenset(
    {
        Flag.DEPTH_CAP_HIT,
        Flag.NULL_BYTE,
        Flag.MULTI_LAYER_ENCODING,
        Flag.INVALID_UTF8,
    }
)


@dataclass(slots=True)
class Result:
    """The outcome of normalising one value. Both views are retained."""

    #: The value as received, after size capping only.
    original: str
    #: Decoded and Unicode-normalised.
    normalized: str = ""
    #: :attr:`normalized` with SQL and HTML comment syntax removed. Some
    #: grammars need this view; others must not use it, because comment
    #: removal can itself change meaning.
    comment_free: str = ""
    #: How many decoding passes changed the value.
    decode_layers: int = 0
    flags: list[Flag] = field(default_factory=list)

    def has_flag(self, flag: Flag) -> bool:
        return flag in self.flags

    def add_flag(self, flag: Flag) -> None:
        if flag not in self.flags:
            self.flags.append(flag)

    @property
    def suspicious(self) -> bool:
        """Whether normalisation alone justifies escalation."""
        return any(f in _SUSPICIOUS_FLAGS for f in self.flags)


def _has_control_chars(value: str) -> bool:
    return any(
        (ord(c) < 0x20 or 0x7F <= ord(c) <= 0x9F) and c not in "\t\n\r" for c in value
    )


# Matches MySQL ``-- `` line comments: the double dash REQUIRES trailing
# whitespace or end-of-input. Without that rule, legitimate values such as
# part numbers ("part--123") would be corrupted.
_SQL_LINE_COMMENT = re.compile(r"--(?=[ \t\n\r]|$).*?(?=[\n\r]|$)", re.DOTALL)
_SQL_HASH_COMMENT = re.compile(r"#.*?(?=[\n\r]|$)", re.DOTALL)
_SQL_BLOCK_COMMENT = re.compile(r"/\*.*?(?:\*/|$)", re.DOTALL)
_HTML_COMMENT = re.compile(r"<!--.*?(?:-->|$)", re.DOTALL)


def _strip_comments(value: str, result: Result) -> str:
    """Remove SQL and HTML comment syntax to form a secondary view.

    Comment insertion (``SEL/**/ECT``) is a standard evasion. This is
    deliberately a SEPARATE view: a stage treating the comment-free form as
    authoritative would false-positive on legitimate values containing "--",
    which is common in free text.
    """
    out = value
    for pattern in (
        _SQL_BLOCK_COMMENT,
        _HTML_COMMENT,
        _SQL_LINE_COMMENT,
        _SQL_HASH_COMMENT,
    ):
        out = pattern.sub("", out)
    if out != value:
        result.add_flag(Flag.COMMENT_STRIPPED)
    return out


def normalize(value: str, limits: Limits | None = None) -> Result:
    """Canonicalise a single candidate value under ``limits``.

    Pipeline: size cap -> bounded iterative URL decode -> HTML entity decode
    -> Unicode NFKC -> inspection. Comment stripping produces a separate view
    rather than mutating the primary one.
    """
    lim = limits or Limits()
    result = Result(original=value)

    if len(value) > lim.max_value_bytes:
        value = value[: lim.max_value_bytes]
        result.original = value
        result.add_flag(Flag.SIZE_CAP_HIT)

    current = value
    layers = 0
    for _ in range(lim.max_decode_depth):
        decoded = unquote_plus(current)
        if decoded == current:
            break
        current = decoded
        layers += 1

    # If a further pass would still change the value, we stopped at the cap
    # rather than at a fixed point: the value may remain encoded.
    if layers == lim.max_decode_depth and unquote_plus(current) != current:
        result.add_flag(Flag.DEPTH_CAP_HIT)

    result.decode_layers = layers
    if layers > 1:
        result.add_flag(Flag.MULTI_LAYER_ENCODING)

    # Single-pass HTML entity decoding. Multi-pass is not performed because no
    # mainstream renderer does it, and doing so would manufacture a parser
    # differential of our own making.
    unescaped = html.unescape(current)
    if unescaped != current:
        current = unescaped

    # Python strings are already valid Unicode, but lone surrogates can arrive
    # from percent-decoded bytes and are not encodable.
    try:
        current.encode("utf-8")
    except UnicodeEncodeError:
        result.add_flag(Flag.INVALID_UTF8)
        current = current.encode("utf-8", errors="replace").decode("utf-8")

    # NFKC folds compatibility forms: fullwidth characters, ligatures and
    # lookalikes used to evade naive string matching.
    folded = unicodedata.normalize("NFKC", current)
    if folded != current:
        result.add_flag(Flag.UNICODE_CHANGED)
        current = folded

    if "\x00" in current:
        result.add_flag(Flag.NULL_BYTE)
        current = current.replace("\x00", "")

    if _has_control_chars(current):
        result.add_flag(Flag.CONTROL_CHARS)

    result.normalized = current
    result.comment_free = _strip_comments(current, result)
    return result
