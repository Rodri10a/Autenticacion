from contextlib import asynccontextmanager

import bleach
from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import Session as DBSession

from auth import hash_password
from database import Base, SessionLocal, engine, get_db
from middleware import generate_csrf_token, validate_csrf_token
from models import User
from schemas import UserCreate, UserResponse


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


app.mount("/static", StaticFiles(directory="static"), name="static")
