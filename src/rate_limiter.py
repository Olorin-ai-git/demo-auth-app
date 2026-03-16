from collections import defaultdict
from datetime import datetime, timedelta
from typing import Optional


class RateLimiter:
    def __init__(self, max_attempts: int = 5, window_minutes: int = 15):
        self.max_attempts = max_attempts
        self.window = timedelta(minutes=window_minutes)
        self._attempts: dict[str, list[datetime]] = defaultdict(list)

    def check(self, key: str) -> bool:
        now = datetime.utcnow()
        cutoff = now - self.window

        self._attempts[key] = [
            ts for ts in self._attempts[key] if ts > cutoff
        ]

        return len(self._attempts[key]) < self.max_attempts

    def record(self, key: str) -> None:
        self._attempts[key].append(datetime.utcnow())

    def remaining(self, key: str) -> int:
        now = datetime.utcnow()
        cutoff = now - self.window

        recent = [ts for ts in self._attempts[key] if ts > cutoff]
        return max(0, self.max_attempts - len(recent))

    def reset(self, key: str) -> None:
        self._attempts.pop(key, None)
