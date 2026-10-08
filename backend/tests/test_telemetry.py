import pytest

from csf.telemetry import REDACTED, is_sensitive, redact


@pytest.mark.parametrize("name", [
    "password", "Password", "user_password", "PASSWD", "pwd",
    "api_key", "apiKey", "X-Api-Key", "x-api-key", "api.key", "API KEY",
    "authorization", "Authorization", "access_token", "refresh_token",
    "session_id", "Cookie", "Set-Cookie", "csrf_token", "X-CSRF-Token",
    "client_secret", "private_key", "Private-Key", "access-key",
    "card_number", "cvv", "ssn", "X-Auth-Token",
])
def test_sensitive_names_are_redacted(name):
    assert redact(name, "hunter2") == REDACTED, f"{name} leaked"
    assert is_sensitive(name)


@pytest.mark.parametrize("name", [
    "q", "page", "name", "email", "sort", "filter", "id", "query",
    "category", "description", "title", "url", "limit", "offset",
])
def test_ordinary_names_are_not_redacted(name):
    assert redact(name, "value") == "value", f"{name} over-redacted"
