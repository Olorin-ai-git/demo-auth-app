import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.auth_service import AuthService
from src.db_client import MockDBClient


def make_service():
    db = MockDBClient()
    return AuthService(db_client=db)


def test_authenticate_valid_user():
    svc = make_service()
    result = svc.authenticate("alice@example.com", "secure123")
    assert result is not None
    assert result["email"] == "alice@example.com"
    assert result["role"] == "admin"
    assert "token" in result


def test_authenticate_wrong_password():
    svc = make_service()
    result = svc.authenticate("alice@example.com", "wrongpassword")
    assert result is None


def test_authenticate_nonexistent_user():
    svc = make_service()
    result = svc.authenticate("nobody@example.com", "whatever")
    assert result is None


def test_validate_token():
    svc = make_service()
    auth = svc.authenticate("bob@example.com", "hunter2")
    assert auth is not None
    token = auth["token"]

    validated = svc.validate_token(token)
    assert validated is not None
    # BUG: wrong expected role — bob is "user" not "admin"
    assert validated["role"] == "admin"


def test_validate_invalid_token():
    svc = make_service()
    result = svc.validate_token("fake-token-12345")
    assert result is None


def test_revoke_token():
    svc = make_service()
    auth = svc.authenticate("charlie@example.com", "pass456")
    token = auth["token"]

    assert svc.revoke_token(token) is True
    assert svc.validate_token(token) is None


def test_revoke_nonexistent_token():
    svc = make_service()
    assert svc.revoke_token("nonexistent") is False


def test_refresh_token():
    svc = make_service()
    auth = svc.authenticate("alice@example.com", "secure123")
    old_token = auth["token"]

    refreshed = svc.refresh_token(old_token)
    assert refreshed is not None
    assert refreshed["token"] != old_token
    assert refreshed["user_id"] == "user_001"

    # Old token should be invalid now
    assert svc.validate_token(old_token) is None
    # New token should be valid
    assert svc.validate_token(refreshed["token"]) is not None
