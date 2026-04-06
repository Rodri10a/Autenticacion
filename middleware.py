import secrets
import time
from collections import defaultdict


# --- CSRF (Double Submit Cookie) ---


def generate_csrf_token() -> str:
    return secrets.token_hex(32)


def validate_csrf_token(request_token: str | None, cookie_token: str | None) -> bool:
    if not request_token or not cookie_token:
        return False
    return secrets.compare_digest(request_token, cookie_token)


# --- Rate Limiting ---


class RateLimiter:
    def __init__(self, max_attempts: int = 5, lockout_minutes: int = 15):
        self.max_attempts = max_attempts
        self.lockout_seconds = lockout_minutes * 60
        self.attempts: dict = defaultdict(
            lambda: {"count": 0, "locked_until": 0.0}
        )

    def is_locked(self, key: str) -> bool:
        entry = self.attempts[key]
        if entry["locked_until"] > time.time():
            return True
        if entry["locked_until"] != 0 and entry["locked_until"] <= time.time():
            self.attempts[key] = {"count": 0, "locked_until": 0.0}
        return False

    def record_failure(self, key: str):
        entry = self.attempts[key]
        entry["count"] += 1
        if entry["count"] >= self.max_attempts:
            entry["locked_until"] = time.time() + self.lockout_seconds

    def record_success(self, key: str):
        self.attempts[key] = {"count": 0, "locked_until": 0.0}

    def get_remaining_lockout(self, key: str) -> int:
        entry = self.attempts[key]
        if entry["locked_until"] > time.time():
            return int(entry["locked_until"] - time.time())
        return 0


rate_limiter = RateLimiter()
