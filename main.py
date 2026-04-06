from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from auth import hash_password
from database import Base, SessionLocal, engine
from models import User


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


app.mount("/static", StaticFiles(directory="static"), name="static")
