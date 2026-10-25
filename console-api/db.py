"""SQLite database management and user store for the CSF demo.

Uses Python's standard library sqlite3 with WAL mode for concurrency and durability.
"""

from __future__ import annotations

import os
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

DEFAULT_DB_PATH = Path(__file__).resolve().parent / ".runtime" / "users.db"


def get_db_path() -> Path:
    env_path = os.environ.get("CSF_DB_PATH")
    if env_path:
        return Path(env_path).resolve()
    return DEFAULT_DB_PATH


def get_db_connection(db_path: Path | None = None) -> sqlite3.Connection:
    path = db_path or get_db_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path), timeout=10.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA foreign_keys=ON;")
    return conn


def init_db(db_path: Path | None = None) -> None:
    """Initialize the SQLite database and create the users table if not exists."""
    conn = get_db_connection(db_path)
    try:
        with conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id TEXT PRIMARY KEY,
                    email TEXT NOT NULL UNIQUE,
                    password_hash TEXT NOT NULL,
                    name TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                """
            )
            conn.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email ON users(email);"
            )
    finally:
        conn.close()


def create_user(
    name: str,
    email: str,
    password_hash: str,
    db_path: Path | None = None,
) -> dict[str, Any]:
    """Create a new user in the database.

    Raises sqlite3.IntegrityError if the email already exists.
    """
    conn = get_db_connection(db_path)
    user_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()
    norm_email = email.strip().lower()
    norm_name = name.strip()

    try:
        with conn:
            conn.execute(
                """
                INSERT INTO users (id, email, password_hash, name, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?);
                """,
                (user_id, norm_email, password_hash, norm_name, now, now),
            )
        return {
            "id": user_id,
            "email": norm_email,
            "name": norm_name,
            "created_at": now,
            "updated_at": now,
        }
    finally:
        conn.close()


def get_user_by_email(
    email: str,
    db_path: Path | None = None,
) -> dict[str, Any] | None:
    """Retrieve user record including password_hash for authentication verification."""
    conn = get_db_connection(db_path)
    norm_email = email.strip().lower()
    try:
        cursor = conn.execute(
            "SELECT id, email, password_hash, name, created_at, updated_at FROM users WHERE email = ?;",
            (norm_email,),
        )
        row = cursor.fetchone()
        if not row:
            return None
        return dict(row)
    finally:
        conn.close()


def get_user_by_id(
    user_id: str,
    db_path: Path | None = None,
) -> dict[str, Any] | None:
    """Retrieve public user record excluding password_hash."""
    conn = get_db_connection(db_path)
    try:
        cursor = conn.execute(
            "SELECT id, email, name, created_at, updated_at FROM users WHERE id = ?;",
            (user_id,),
        )
        row = cursor.fetchone()
        if not row:
            return None
        return dict(row)
    finally:
        conn.close()
