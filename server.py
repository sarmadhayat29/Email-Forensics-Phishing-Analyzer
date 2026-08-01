"""FastAPI REST API Backend for Email Forensics & Phishing Analyzer.

Exposes REST endpoints for uploading email files (.eml, .msg), executing
forensic analysis pipelines, user authentication (signup/login), persistent analysis history,
retrieving finding JSON data, and downloading HTML/JSON/PDF reports.
"""

import os
import sys

# Insert src directory to Python path BEFORE importing routes
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), 'src')))

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from contextlib import asynccontextmanager

from api.routes import auth, analysis, history, reports
from api.exceptions import register_exception_handlers
from config import ALLOWED_ORIGINS
from db import init_db
from logger import get_logger

logger = get_logger(__name__)

@asynccontextmanager
async def lifespan(application: FastAPI):
    """Initialize database schema on startup."""
    logger.info("Initializing database schema...")
    init_db()
    logger.info("Database schema ready.")
    yield

app = FastAPI(
    title="Email Forensics & Phishing Analyzer API",
    description="REST API for email forensic investigation, user authentication, and persistent analysis history.",
    version="2.0.0",
    lifespan=lifespan,
)

# Enable CORS for web frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)

# Register global exception handlers
register_exception_handlers(app)

@app.get("/api/health")
def health_check():
    return {"status": "ok", "service": "Email Forensics API", "version": "2.0.0"}

# Include routers
app.include_router(auth.router, prefix="/api/auth", tags=["auth"])
app.include_router(analysis.router, prefix="/api", tags=["analysis"])
app.include_router(history.router, prefix="/api/analyses", tags=["history"])
app.include_router(reports.router, prefix="/api/report", tags=["reports"])

# ---------------------------------------------------------------------------
# SPA static hosting (React + Vite + React Router BrowserRouter)
#
# Production serves frontend/dist from this same process (see Procfile).
# Client-side routes like /dashboard and /analysis/:id are not real files on
# disk. StaticFiles(html=True) only serves index.html for directories / missing
# 404.html — it does NOT fall back to index.html for arbitrary paths, so a
# browser refresh on a deep link returned 404. The catch-all below serves
# real dist assets when they exist, otherwise index.html so React Router can
# resolve the path. API routers registered above always take precedence.
# ---------------------------------------------------------------------------
DIST_DIR = os.path.join(os.path.dirname(__file__), "frontend", "dist")


def resolve_spa_file(dist_dir: str, full_path: str) -> str:
    """Return the filesystem path to serve for a browser request.

    Real files under ``dist_dir`` (favicon, SVG, etc.) are returned as-is.
    Everything else — including React Router paths like ``dashboard`` or
    ``analysis/123`` — resolves to ``index.html`` so the SPA can boot.
    """
    index_path = os.path.join(dist_dir, "index.html")
    if not full_path or full_path in {".", "/"}:
        return index_path

    safe_root = os.path.abspath(dist_dir)
    candidate = os.path.abspath(os.path.join(dist_dir, full_path))
    if candidate.startswith(safe_root + os.sep) and os.path.isfile(candidate):
        return candidate
    return index_path


def _serve_spa_index() -> FileResponse:
    index_path = os.path.join(DIST_DIR, "index.html")
    if not os.path.isfile(index_path):
        raise HTTPException(
            status_code=404,
            detail="Frontend build not found. Run npm run build in frontend/.",
        )
    return FileResponse(index_path)


if os.path.isdir(DIST_DIR):
    assets_dir = os.path.join(DIST_DIR, "assets")
    if os.path.isdir(assets_dir):
        app.mount("/assets", StaticFiles(directory=assets_dir), name="assets")

    @app.get("/")
    async def spa_root():
        return _serve_spa_index()

    @app.get("/{full_path:path}")
    async def spa_fallback(full_path: str):
        # Never shadow API with the SPA shell.
        if full_path == "api" or full_path.startswith("api/"):
            raise HTTPException(status_code=404, detail="Not Found")

        target = resolve_spa_file(DIST_DIR, full_path)
        if not os.path.isfile(target):
            raise HTTPException(
                status_code=404,
                detail="Frontend build not found. Run npm run build in frontend/.",
            )
        return FileResponse(target)
else:
    logger.warning(
        "frontend/dist not found — API-only mode. "
        "Build the SPA with: cd frontend && npm run build"
    )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("server:app", host="127.0.0.1", port=8000, reload=True)
