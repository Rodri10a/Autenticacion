from contextlib import asynccontextmanager

import bleach
from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import Session as DBSession

from datetime import datetime, timedelta, timezone

from auth import (
    SESSION_EXPIRY_HOURS,
    create_jwt,
    create_session_id,
    get_current_user,
    hash_password,
    verify_password,
)
from database import Base, SessionLocal, engine, get_db
from middleware import generate_csrf_token, rate_limiter, validate_csrf_token
from models import LoginAttempt, Session, User
from schemas import LoginRequest, UserCreate, UserResponse


@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        admin = db.query(User).filter(User.role == "admin").first()
        if not admin:
            admin = User(
                email="admin@passport.com",
                hashed_password=hash_password("Admin123!"),
                role="admin",
            )
            db.add(admin)
            db.commit()
    finally:
        db.close()
    yield


app = FastAPI(title="PassPort Auth", lifespan=lifespan)


@app.get("/")
async def login_page():
    return FileResponse("static/index.html")


@app.get("/signup")
async def signup_page():
    return FileResponse("static/signup.html")


@app.get("/dashboard")
async def dashboard_page():
    return FileResponse("static/dashboard.html")


@app.get("/admin")
async def admin_page():
    return FileResponse("static/admin.html")


@app.get("/api/csrf-token")
async def get_csrf_token(response: Response):
    token = generate_csrf_token()
    response.set_cookie(
        key="csrf_token",
        value=token,
        httponly=False,
        samesite="strict",
        secure=False,
    )
    return {"csrf_token": token}


@app.post("/api/signup", response_model=UserResponse)
async def signup(
    user_data: UserCreate, request: Request, db: DBSession = Depends(get_db)
):
    csrf_cookie = request.cookies.get("csrf_token")
    csrf_header = request.headers.get("X-CSRF-Token")
    if not validate_csrf_token(csrf_header, csrf_cookie):
        raise HTTPException(status_code=403, detail="Token CSRF invalido")

    clean_email = bleach.clean(user_data.email).lower().strip()

    existing = db.query(User).filter(User.email == clean_email).first()
    if existing:
        raise HTTPException(status_code=400, detail="El email ya esta registrado")

    new_user = User(
        email=clean_email,
        hashed_password=hash_password(user_data.password),
        role="user",
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user


@app.post("/api/login")
async def login(
    login_data: LoginRequest,
    request: Request,
    response: Response,
    db: DBSession = Depends(get_db),
):
    csrf_cookie = request.cookies.get("csrf_token")
    csrf_header = request.headers.get("X-CSRF-Token")
    if not validate_csrf_token(csrf_header, csrf_cookie):
        raise HTTPException(status_code=403, detail="Token CSRF invalido")

    client_ip = request.client.host

    if rate_limiter.is_locked(client_ip):
        remaining = rate_limiter.get_remaining_lockout(client_ip)
        raise HTTPException(
            status_code=429,
            detail=f"Demasiados intentos. Intenta de nuevo en {remaining} segundos",
        )

    clean_email = bleach.clean(login_data.email).lower().strip()

    user = db.query(User).filter(User.email == clean_email).first()
    if not user or not verify_password(login_data.password, user.hashed_password):
        rate_limiter.record_failure(client_ip)
        db.add(
            LoginAttempt(email=clean_email, ip_address=client_ip, success=False)
        )
        db.commit()
        raise HTTPException(status_code=401, detail="Credenciales invalidas")

    if not user.is_active:
        raise HTTPException(status_code=403, detail="Cuenta desactivada")

    rate_limiter.record_success(client_ip)
    db.add(LoginAttempt(email=clean_email, ip_address=client_ip, success=True))
    db.commit()

    if login_data.session_type == "cookie":
        session_id = create_session_id()
        new_session = Session(
            session_id=session_id,
            user_id=user.id,
            expires_at=datetime.now(timezone.utc)
            + timedelta(hours=SESSION_EXPIRY_HOURS),
        )
        db.add(new_session)
        db.commit()

        response.set_cookie(
            key="session_id",
            value=session_id,
            httponly=True,
            secure=False,
            samesite="lax",
            max_age=SESSION_EXPIRY_HOURS * 3600,
        )
        return {"message": "Login exitoso", "auth_type": "cookie", "role": user.role}

    token = create_jwt({"sub": user.id, "email": user.email, "role": user.role})
    return {
        "access_token": token,
        "token_type": "bearer",
        "auth_type": "jwt",
        "role": user.role,
    }


@app.post("/api/logout")
async def logout(
    request: Request, response: Response, db: DBSession = Depends(get_db)
):
    session_id = request.cookies.get("session_id")
    if session_id:
        session = (
            db.query(Session).filter(Session.session_id == session_id).first()
        )
        if session:
            db.delete(session)
            db.commit()

    response.delete_cookie("session_id")
    return {"message": "Sesion cerrada"}


@app.get("/api/me", response_model=UserResponse)
async def get_me(user: User = Depends(get_current_user)):
    return user


app.mount("/static", StaticFiles(directory="static"), name="static")
