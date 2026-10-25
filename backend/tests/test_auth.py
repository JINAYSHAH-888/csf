"""Automated unit and integration tests for authentication and the users database."""

from __future__ import annotations

import sqlite3
import sys
from pathlib import Path

import httpx
import pytest

# Ensure console-api is on sys.path
CONSOLE_DIR = Path(__file__).resolve().parent.parent.parent / "console-api"
if str(CONSOLE_DIR) not in sys.path:
    sys.path.insert(0, str(CONSOLE_DIR))

import auth  # noqa: E402
import db  # noqa: E402
from server import console_app  # noqa: E402


@pytest.fixture(autouse=True)
def isolated_db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Isolate database and secret to a temporary directory for each test."""
    test_db = tmp_path / "test_users.db"
    test_secret_file = tmp_path / "test_auth_secret.key"
    monkeypatch.setattr(db, "DEFAULT_DB_PATH", test_db)
    monkeypatch.setattr(auth, "DEFAULT_SECRET_PATH", test_secret_file)
    monkeypatch.delenv("CSF_DB_PATH", raising=False)
    monkeypatch.delenv("CSF_AUTH_SECRET", raising=False)
    db.init_db(test_db)
    return test_db


def test_users_table_schema(isolated_db: Path) -> None:
    """Verify users table structure, column types, and unique index."""
    conn = sqlite3.connect(str(isolated_db))
    try:
        cursor = conn.execute("PRAGMA table_info(users);")
        columns = {row[1]: row[2] for row in cursor.fetchall()}
        assert "id" in columns
        assert "email" in columns
        assert "password_hash" in columns
        assert "name" in columns
        assert "created_at" in columns
        assert "updated_at" in columns

        cursor = conn.execute("PRAGMA index_list(users);")
        indexes = cursor.fetchall()
        assert any(idx[1] == "idx_users_email" and idx[2] == 1 for idx in indexes)
    finally:
        conn.close()


def test_argon2id_password_hashing() -> None:
    """Verify password hashing produces Argon2id hashes and verifies correctly."""
    pwd = "CorrectHorseBatteryStaple99!"
    hashed = auth.hash_password(pwd)

    # Argon2id identifier prefix
    assert hashed.startswith("$argon2id$")
    # Non-reversibility: hash is not equal to plaintext
    assert hashed != pwd

    # Constant-time verification
    assert auth.verify_password(pwd, hashed) is True
    assert auth.verify_password("WrongPassword123", hashed) is False
    assert auth.verify_password("", hashed) is False


def test_database_user_crud(isolated_db: Path) -> None:
    """Test user creation, retrieval, and unique email constraint."""
    pwd_hash = auth.hash_password("super-secret-password")
    user = db.create_user("Alice Wonderland", "Alice@Example.com", pwd_hash)

    assert user["name"] == "Alice Wonderland"
    assert user["email"] == "alice@example.com"  # Normalized lowercase
    assert "password_hash" not in user
    assert len(user["id"]) == 36  # UUID v4

    # Duplicate email rejection
    with pytest.raises(sqlite3.IntegrityError):
        db.create_user("Alice Clone", "alice@example.com", pwd_hash)

    # Retrieval
    full_user = db.get_user_by_email("alice@example.com")
    assert full_user is not None
    assert full_user["password_hash"] == pwd_hash

    public_user = db.get_user_by_id(user["id"])
    assert public_user is not None
    assert "password_hash" not in public_user
    assert public_user["name"] == "Alice Wonderland"


def test_persistent_secret_stable(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify the auth secret is persistent across calls and not ephemeral."""
    secret_file = tmp_path / "persistent.key"
    monkeypatch.setattr(auth, "DEFAULT_SECRET_PATH", secret_file)

    secret1 = auth.get_auth_secret()
    assert len(secret1) >= 32
    assert secret_file.exists()

    secret2 = auth.get_auth_secret()
    assert secret1 == secret2  # Must be identical across calls


@pytest.mark.asyncio
async def test_api_signup_flow() -> None:
    """Test /api/auth/signup endpoint happy path and validations."""
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=console_app), base_url="http://localhost:5173"
    ) as client:
        # Successful signup
        res = await client.post(
            "/api/auth/signup",
            json={
                "name": "Bob Builder",
                "email": "bob@example.com",
                "password": "StrongPassword123",
                "confirm_password": "StrongPassword123",
            },
        )
        assert res.status_code == 201
        data = res.json()
        assert "user" in data
        assert data["user"]["email"] == "bob@example.com"
        assert "password_hash" not in data["user"]
        assert auth.COOKIE_NAME in res.cookies

        # Duplicate email registration -> 409 Conflict
        res_dup = await client.post(
            "/api/auth/signup",
            json={
                "name": "Bob Imposter",
                "email": "bob@example.com",
                "password": "StrongPassword123",
                "confirm_password": "StrongPassword123",
            },
        )
        assert res_dup.status_code == 409
        assert "already registered" in res_dup.json()["error"]

        # Password mismatch -> 400 Bad Request
        res_mismatch = await client.post(
            "/api/auth/signup",
            json={
                "name": "Charlie",
                "email": "charlie@example.com",
                "password": "StrongPassword123",
                "confirm_password": "DifferentPassword456",
            },
        )
        assert res_mismatch.status_code == 400
        assert "do not match" in res_mismatch.json()["error"]


@pytest.mark.asyncio
async def test_api_login_and_me_flow() -> None:
    """Test /api/auth/login, /api/auth/me, and /api/auth/logout endpoints."""
    # Pre-register a user
    pwd_hash = auth.hash_password("MySecretPass123!")
    db.create_user("Diana Prince", "diana@themyscira.io", pwd_hash)

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=console_app), base_url="http://localhost:5173"
    ) as client:
        # Invalid password -> 401 Unauthorized
        res_bad = await client.post(
            "/api/auth/login",
            json={"email": "diana@themyscira.io", "password": "WrongPassword"},
        )
        assert res_bad.status_code == 401
        assert res_bad.json()["error"] == "Invalid email or password."

        # Non-existent user -> 401 Unauthorized
        res_none = await client.post(
            "/api/auth/login",
            json={"email": "nobody@example.com", "password": "MySecretPass123!"},
        )
        assert res_none.status_code == 401
        assert res_none.json()["error"] == "Invalid email or password."

        # Successful login -> 200 OK
        res_ok = await client.post(
            "/api/auth/login",
            json={"email": "diana@themyscira.io", "password": "MySecretPass123!"},
        )
        assert res_ok.status_code == 200
        assert res_ok.json()["user"]["name"] == "Diana Prince"
        assert auth.COOKIE_NAME in res_ok.cookies

        # Access /api/auth/me with session cookie
        res_me = await client.get("/api/auth/me")
        assert res_me.status_code == 200
        assert res_me.json()["user"]["email"] == "diana@themyscira.io"

        # Logout -> 200 OK
        res_logout = await client.post("/api/auth/logout")
        assert res_logout.status_code == 200

        # After logout, accessing /api/auth/me should fail with 401
        res_me_after = await client.get("/api/auth/me")
        assert res_me_after.status_code == 401
