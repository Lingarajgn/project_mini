from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

import app.models  # noqa: F401
from app.auth.router import router as auth_router
from app.dashboard.router import router as dashboard_router
from app.database.database import Base, engine
from app.routers.health import router as health_router
from app.routines.router import router as routines_router
from app.tasks.router import router as tasks_router

app = FastAPI(title="Routine Hub API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:5500",
        "http://127.0.0.1:5500",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def startup_event() -> None:
    Base.metadata.create_all(bind=engine)


app.include_router(health_router)
app.include_router(auth_router)
app.include_router(tasks_router)
app.include_router(routines_router)
app.include_router(dashboard_router)


@app.get("/")
def read_root() -> dict[str, str]:
    return {"message": "Routine Hub backend is running."}
