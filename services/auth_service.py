from datetime import datetime, timedelta, timezone

import bleach
from fastapi import HTTPException

from auth import (
    SESSION_EXPIRY_HOURS,
    create_jwt,
    create_session_id,
    hash_password,
    verify_password,
)
from middleware import rate_limiter


def signup(db, email: str, password: str) -> dict:
    clean_email = bleach.clean(email).lower().strip()

    existing = db.execute(
        "SELECT id FROM users WHERE email = ?", (clean_email,)
    ).fetchone()
    if existing:
        raise HTTPException(status_code=400, detail="El email ya esta registrado")

    db.execute(
        "INSERT INTO users (email, hashed_password, role) VALUES (?, ?, ?)",
        (clean_email, hash_password(password), "user"),
    )
    db.commit()

    user = db.execute(
        "SELECT * FROM users WHERE email = ?", (clean_email,)
    ).fetchone()
    return dict(user)


def login(db, email: str, password: str, session_type: str, client_ip: str) -> dict:
    if rate_limiter.is_locked(client_ip):
        remaining = rate_limiter.get_remaining_lockout(client_ip)
        raise HTTPException(
            status_code=429,
            detail=f"Demasiados intentos. Intenta de nuevo en {remaining} segundos",
        )

    clean_email = bleach.clean(email).lower().strip()

    user = db.execute(
        "SELECT * FROM users WHERE email = ?", (clean_email,)
    ).fetchone()

    if not user or not verify_password(password, user["hashed_password"]):
        rate_limiter.record_failure(client_ip)
        db.execute(
            "INSERT INTO login_attempts (email, ip_address, success) VALUES (?, ?, 0)",
            (clean_email, client_ip),
        )
        db.commit()
        raise HTTPException(status_code=401, detail="Credenciales invalidas")

    if not user["is_active"]:
        raise HTTPException(status_code=403, detail="Cuenta desactivada")

    rate_limiter.record_success(client_ip)
    db.execute(
        "INSERT INTO login_attempts (email, ip_address, success) VALUES (?, ?, 1)",
        (clean_email, client_ip),
    )
    db.commit()

    if session_type == "cookie":
        session_id = create_session_id()
        expires_at = datetime.now(timezone.utc) + timedelta(hours=SESSION_EXPIRY_HOURS)
        db.execute(
            "INSERT INTO sessions (session_id, user_id, expires_at) VALUES (?, ?, ?)",
            (session_id, user["id"], expires_at.isoformat()),
        )
        db.commit()
        return {
            "message": "Login exitoso",
            "auth_type": "cookie",
            "role": user["role"],
            "session_id": session_id,
        }

    token = create_jwt(
        {"sub": user["id"], "email": user["email"], "role": user["role"]}
    )
    return {
        "access_token": token,
        "token_type": "bearer",
        "auth_type": "jwt",
        "role": user["role"],
    }


def logout(db, session_id: str | None):
    if session_id:
        db.execute("DELETE FROM sessions WHERE session_id = ?", (session_id,))
        db.commit()
