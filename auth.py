import os
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from dotenv import load_dotenv
from fastapi import Depends, HTTPException, Request
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy.orm import Session as DBSession

import models
from database import get_db

load_dotenv()

SECRET_KEY = os.getenv("SECRET_KEY", "change-me-in-production")
ALGORITHM = "HS256"
JWT_EXPIRY_MINUTES = 30
SESSION_EXPIRY_HOURS = 24

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def create_jwt(data: dict, expires_delta: timedelta | None = None) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (
        expires_delta or timedelta(minutes=JWT_EXPIRY_MINUTES)
    )
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def decode_jwt(token: str) -> dict | None:
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError:
        return None


def create_session_id() -> str:
    return str(uuid4())


async def get_current_user(
    request: Request, db: DBSession = Depends(get_db)
) -> models.User:
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header.split(" ")[1]
        payload = decode_jwt(token)
        if payload:
            user = (
                db.query(models.User)
                .filter(models.User.id == payload.get("sub"))
                .first()
            )
            if user and user.is_active:
                return user

    session_id = request.cookies.get("session_id")
    if session_id:
        session = (
            db.query(models.Session)
            .filter(
                models.Session.session_id == session_id,
                models.Session.expires_at > datetime.now(timezone.utc),
            )
            .first()
        )
        if session:
            user = (
                db.query(models.User)
                .filter(models.User.id == session.user_id)
                .first()
            )
            if user and user.is_active:
                return user

    raise HTTPException(status_code=401, detail="No autenticado")


def require_role(role: str):
    async def role_checker(user: models.User = Depends(get_current_user)):
        if user.role != role:
            raise HTTPException(status_code=403, detail="Permisos insuficientes")
        return user

    return role_checker
