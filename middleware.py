import secrets


# --- CSRF (Double Submit Cookie) ---


def generate_csrf_token() -> str:
    return secrets.token_hex(32)


def validate_csrf_token(request_token: str | None, cookie_token: str | None) -> bool:
    if not request_token or not cookie_token:
        return False
    return secrets.compare_digest(request_token, cookie_token)
