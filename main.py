import sqlite3
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from auth import SESSION_EXPIRY_HOURS, get_current_user, hash_password, require_role
from database import DATABASE_PATH, get_db, init_db
from middleware import generate_csrf_token, validate_csrf_token
from schemas import LoginRequest, UserCreate, UserResponse
from services import auth_service, user_service


def verify_csrf(request: Request):
    csrf_cookie = request.cookies.get("csrf_token")
    csrf_header = request.headers.get("X-CSRF-Token")
    if not validate_csrf_token(csrf_header, csrf_cookie):
        raise HTTPException(status_code=403, detail="Token CSRF invalido")


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    conn = sqlite3.connect(DATABASE_PATH)
    try:
        admin = conn.execute(
            "SELECT id FROM users WHERE role = 'admin'"
        ).fetchone()
        if not admin:
            conn.execute(
                "INSERT INTO users (email, hashed_password, role) VALUES (?, ?, ?)",
                ("admin@passport.com", hash_password("Admin123!"), "admin"),
            )
            conn.commit()
    finally:
        conn.close()
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


@app.post("/api/signup")
async def signup(user_data: UserCreate, request: Request, db=Depends(get_db)):
    verify_csrf(request)
    user = auth_service.signup(db, user_data.email, user_data.password)
    return UserResponse(**user)


@app.post("/api/login")
async def login(
    login_data: LoginRequest,
    request: Request,
    response: Response,
    db=Depends(get_db),
):
    verify_csrf(request)
    result = auth_service.login(
        db,
        login_data.email,
        login_data.password,
        login_data.session_type,
        request.client.host,
    )

    if "session_id" in result:
        response.set_cookie(
            key="session_id",
            value=result.pop("session_id"),
            httponly=True,
            secure=False,
            samesite="lax",
            max_age=SESSION_EXPIRY_HOURS * 3600,
        )

    return result


@app.post("/api/logout")
async def logout(request: Request, response: Response, db=Depends(get_db)):
    auth_service.logout(db, request.cookies.get("session_id"))
    response.delete_cookie("session_id")
    return {"message": "Sesion cerrada"}


@app.get("/api/me")
async def get_me(user=Depends(get_current_user)):
    return UserResponse(**dict(user))


@app.get("/api/admin/users")
async def list_users(user=Depends(require_role("admin")), db=Depends(get_db)):
    return user_service.list_users(db)


@app.delete("/api/admin/users/{user_id}")
async def delete_user(
    user_id: int,
    request: Request,
    user=Depends(require_role("admin")),
    db=Depends(get_db),
):
    verify_csrf(request)
    return user_service.delete_user(db, user_id, user["id"])


@app.get("/api/admin/login-attempts")
async def get_login_attempts(
    user=Depends(require_role("admin")), db=Depends(get_db)
):
    return user_service.get_login_attempts(db)


app.mount("/static", StaticFiles(directory="static"), name="static")
