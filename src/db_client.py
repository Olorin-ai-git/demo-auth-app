import hashlib
from typing import Optional


class MockDBClient:
    """In-memory database for demo purposes."""

    def __init__(self):
        self._users = {
            "user_001": {
                "id": "user_001",
                "email": "alice@example.com",
                "password_hash": hashlib.sha256("secure123".encode()).hexdigest(),
                "role": "admin",
                "created_at": "2026-01-15T10:00:00Z",
            },
            "user_002": {
                "id": "user_002",
                "email": "bob@example.com",
                "password_hash": hashlib.sha256("hunter2".encode()).hexdigest(),
                "role": "user",
                "created_at": "2026-02-20T14:30:00Z",
            },
            "user_003": {
                "id": "user_003",
                "email": "charlie@example.com",
                "password_hash": hashlib.sha256("pass456".encode()).hexdigest(),
                "role": "editor",
                "created_at": "2026-03-01T09:15:00Z",
            },
        }

    def find_user(self, email: Optional[str] = None, id: Optional[str] = None) -> Optional[dict]:
        if email:
            for user in self._users.values():
                if user["email"] == email:
                    return user
            return None

        if id:
            return self._users.get(id)

        return None

    def list_users(self) -> list:
        return list(self._users.values())
