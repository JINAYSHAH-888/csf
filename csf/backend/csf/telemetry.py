"""Structured logging, redaction, and operating modes.

Redaction is a security control, not a courtesy
------------------------------------------------
Every value this gateway logs came from an attacker or a legitimate user, and
both are sensitive for different reasons. Attacker payloads are the evidence
we need; user data is a liability we must not accumulate (threat model T8).

Two rules are enforced here rather than left to call sites:

* Raw JWTs are **never** logged — only a truncated hash.
* Parameters whose names suggest secrets are redacted by value.
"""

from __future__ import annotations

import json
import logging
import sys
from enum import StrEnum
from typing import Any

__all__ = ["Mode", "REDACTED", "configure_logging", "is_sensitive", "redact"]


class Mode(StrEnum):
    """The gateway's enforcement posture."""

    SHADOW = "shadow"
    MONITOR = "monitor"
    ENFORCE = "enforce"
    EMERGENCY = "emergency"


REDACTED = "[REDACTED]"

#: Written WITHOUT separators: names are stripped of "-", "_", "." and " "
#: before comparison. Without that, "X-Api-Key" would not match "api_key" and
#: an API key would be logged in cleartext — a real bug the Go prototype had.
_SENSITIVE_NAMES = (
    "password", "passwd", "pwd", "secret", "token", "authorization", "auth",
    "apikey", "accesskey", "privatekey", "credential", "bearer",
    "session", "cookie", "csrf", "xsrf", "otp", "pin", "ssn",
    "card", "cvv", "cvc", "iban", "passport",
)

_SEPARATORS = str.maketrans("", "", "-_. ")


def redact(name: str, value: str) -> str:
    """Return a value safe to log for the given parameter name."""
    normalized = name.lower().translate(_SEPARATORS)
    if any(s in normalized for s in _SENSITIVE_NAMES):
        return REDACTED
    return value


def is_sensitive(name: str) -> bool:
    return redact(name, "x") == REDACTED


class JSONFormatter(logging.Formatter):
    """Emits one JSON object per line."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"),
            "level": record.levelname.lower(),
            "msg": record.getMessage(),
        }
        extra = getattr(record, "fields", None)
        if isinstance(extra, dict):
            payload.update(extra)
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str)


def configure_logging(level: str = "info", json_output: bool = True) -> logging.Logger:
    logger = logging.getLogger("csf")
    logger.handlers.clear()
    handler = logging.StreamHandler(sys.stdout)
    if json_output:
        handler.setFormatter(JSONFormatter())
    else:
        handler.setFormatter(
            logging.Formatter("%(asctime)s %(levelname)s %(message)s %(fields)s")
        )
    logger.addHandler(handler)
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    logger.propagate = False
    return logger
