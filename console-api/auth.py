"""Authentication and session management module.

Handles:
- Argon2id password hashing and constant-time verification.
- Persistent cryptographically secure secret management.
- HttpOnly JWT session cookie generation and validation.
- User input validation.
"""

from __future__ import annotations

import os
import re
import secrets
import time
from pathlib import Path
from typing import Any

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

DEFAULT_SECRET_PATH = Path(__file__).resolve().parent / ".runtime" / "auth_secret.key"

# Argon2id hasher with standard recommended security parameters
_HASHER = PasswordHasher(
    time_cost=3,
    memory_cost=65536,  # 64 MiB
    parallelism=4,
    hash_len=32,
    salt_len=16,
)

EMAIL_REGEX = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
COOKIE_NAME = "csf_session"
SESSION_DURATION_SECONDS = 7200  # 2 hours


def get_auth_secret() -> str:
    """Retrieve or securely generate and persist the authentication secret.

    Does not fall back to an insecure or ephemeral secret if initialization fails.
    """
    env_secret = os.environ.get("CSF_AUTH_SECRET")
    if env_secret:
        if len(env_secret.strip()) < 32:
            raise RuntimeError("CSF_AUTH_SECRET must be at least 32 characters long.")
        return env_secret.strip()

    secret_file = DEFAULT_SECRET_PATH
    try:
        secret_file.parent.mkdir(parents=True, exist_ok=True)
        if secret_file.exists():
            content = secret_file.read_text(encoding="utf-8").strip()
            if len(content) >= 32:
                return content
            raise RuntimeError("Corrupt or truncated secret in auth_secret.key file.")

        # Generate a 256-bit secure random secret and persist it
        new_secret = secrets.token_hex(32)
        secret_file.write_text(new_secret, encoding="utf-8")
        try:
            os.chmod(secret_file, 0o600)
        except OSError:
            pass  # Windows may not support strict POSIX permissions
        return new_secret
    except Exception as exc:
        raise RuntimeError(
            f"Failed to securely initialize authentication secret: {exc}"
        ) from exc


def hash_password(password: str) -> str:
    """Hash password using Argon2id."""
    if not password:
        raise ValueError("Password cannot be empty.")
    return _HASHER.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    """Verify password against Argon2id hash in constant time."""
    try:
        return _HASHER.verify(password_hash, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def validate_signup_input(
    name: str,
    email: str,
    password: str,
    confirm_password: str,
) -> str | None:
    """Validate sign up inputs. Returns error message or None if valid."""
    if not name or not name.strip():
        return "Name is required."
    if not email or not email.strip():
        return "Email is required."
    if not EMAIL_REGEX.match(email.strip()):
        return "Please enter a valid email address."
    if not password:
        return "Password is required."
    if len(password) < 8:
        return "Password must be at least 8 characters long."
    if password != confirm_password:
        return "Passwords do not match."
    return None


def validate_login_input(email: str, password: str) -> str | None:
    """Validate login inputs. Returns error message or None if valid."""
    if not email or not email.strip():
        return "Email is required."
    if not password:
        return "Password is required."
    return None


def create_session_token(user: dict[str, Any]) -> str:
    """Create a signed JWT session token for the user."""
    secret = get_auth_secret()
    now = int(time.time())
    payload = {
        "sub": str(user["id"]),
        "email": str(user["email"]),
        "name": str(user["name"]),
        "iat": now,
        "exp": now + SESSION_DURATION_SECONDS,
    }
    return jwt.encode(payload, secret, algorithm="HS256")


def verify_session_token(token: str) -> dict[str, Any] | None:
    """Verify and decode a session token. Returns payload or None if invalid/expired."""
    try:
        secret = get_auth_secret()
        payload = jwt.decode(token, secret, algorithms=["HS256"])
        return payload
    except (jwt.PyJWTError, Exception):
        return None
