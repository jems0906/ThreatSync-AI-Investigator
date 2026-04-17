import os
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from api.alerts import router as alerts_router
from api.audit import router as audit_router
from api.approvals import router as approvals_router
from api.investigations import router as investigations_router
from api.websocket import router as ws_router
from config import settings
from db.database import init_db
from mock_data.seed import seed_initial_data
from services.cache import cache_service
from services.llm_service import llm_service  # noqa: F401 – imported to warm up
from services.rag_pipeline import rag_pipeline


# ── Application lifecycle ─────────────────────────────────────────────────────


@asynccontextmanager
async def lifespan(app: FastAPI):
    print(f"\n{'='*55}")
    print(f"  {settings.APP_NAME}")
    print(f"{'='*55}")

    # Database
    await init_db()
    print("[OK] Database tables created / verified")

    # Redis (optional — app degrades gracefully without it)
    try:
        await cache_service.connect()
        print("[OK] Redis connected")
    except Exception as exc:
        print(f"[WARN] Redis unavailable ({exc}) — caching disabled")

    # RAG pipeline (requires OPENAI_API_KEY)
    try:
        await rag_pipeline.initialize()
        print("[OK] RAG pipeline initialised (ChromaDB + embeddings)")
    except Exception as exc:
        print(f"[WARN] RAG pipeline init failed ({exc}) — retrieval disabled")

    # Seed mock data
    await seed_initial_data()

    print(f"{'='*55}")
    print(f"  Ready -> http://localhost:8000\n")
    yield

    # Shutdown
    await cache_service.disconnect()
    print("[OK] Shutdown complete")


# ── App factory ───────────────────────────────────────────────────────────────

app = FastAPI(
    title=settings.APP_NAME,
    description=(
        "AI-powered SOC threat investigation platform. "
        "Ingests security alerts, runs a RAG + LLM pipeline to generate "
        "investigation reports, and streams results in real time via WebSocket."
    ),
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/api/docs",
    redoc_url="/api/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Routers ───────────────────────────────────────────────────────────────────

app.include_router(alerts_router)
app.include_router(investigations_router)
app.include_router(approvals_router)
app.include_router(audit_router)
app.include_router(ws_router)

# ── Frontend static files ─────────────────────────────────────────────────────

_frontend_dir = os.path.join(os.path.dirname(__file__), "..", "frontend")
if os.path.isdir(_frontend_dir):
    app.mount("/static", StaticFiles(directory=_frontend_dir), name="static")

    @app.get("/", include_in_schema=False)
    async def serve_frontend():
        return FileResponse(os.path.join(_frontend_dir, "index.html"))


# ── Health check ──────────────────────────────────────────────────────────────


@app.get("/health", tags=["ops"])
async def health_check():
    redis_ok = await cache_service.health_check()
    rag_ok = rag_pipeline._initialized
    return {
        "status": "healthy",
        "services": {
            "database": "connected",
            "redis": "connected" if redis_ok else "degraded",
            "rag_pipeline": "ready" if rag_ok else "degraded",
        },
    }
