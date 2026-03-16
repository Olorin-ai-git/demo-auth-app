from datetime import datetime, timedelta
from typing import Optional
import hashlib
import secrets


class AuthService:
    def __init__(self, db_client, token_expiry_hours: int = 24):
        self.db = db_client
        self.token_expiry = timedelta(hours=token_expiry_hours)
        self._active_sessions = {}

    def authenticate(self, email: str, password: str) -> Optional[dict]:
        user = self.db.find_user(email=email)
        if not user:
            return None

        hashed = hashlib.sha256(password.encode()).hexdigest()
        if user["password_hash"] != hashed:
            return None

        token = self._generate_token(user["id"])
        return {
            "user_id": user["id"],
            "email": user["email"],
            "token": token,
            "expires_at": (datetime.utcnow() + self.token_expiry).isoformat(),
            "role": user.get("role", "user"),
        }

    def validate_token(self, token: str) -> Optional[dict]:
        session = self._active_sessions.get(token)
        if not session:
            return None

        if datetime.utcnow() > session["expires_at"]:
            del self._active_sessions[token]
            return None

        return {"user_id": session["user_id"], "role": session["role"]}

    def revoke_token(self, token: str) -> bool:
        if token in self._active_sessions:
            del self._active_sessions[token]
            return True
        return False

    def refresh_token(self, old_token: str) -> Optional[dict]:
        session = self._active_sessions.get(old_token)
        if not session:
            return None

        if datetime.utcnow() > session["expires_at"]:
            del self._active_sessions[old_token]
            return None

        del self._active_sessions[old_token]
        new_token = self._generate_token(session["user_id"])
        return {
            "user_id": session["user_id"],
            "token": new_token,
            "expires_at": (datetime.utcnow() + self.token_expiry).isoformat(),
            "role": session["role"],
        }

    def _generate_token(self, user_id: str) -> str:
        token = secrets.token_urlsafe(32)
        self._active_sessions[token] = {
            "user_id": user_id,
            "role": self.db.find_user(id=user_id).get("role", "user"),
            "expires_at": datetime.utcnow() + self.token_expiry,
        }
        return token
