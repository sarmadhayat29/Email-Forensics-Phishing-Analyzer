"""FastAPI REST API Backend for Email Forensics & Phishing Analyzer.

Exposes REST endpoints for uploading email files (.eml, .msg), executing
forensic analysis pipelines, user authentication (signup/login), persistent analysis history,
retrieving finding JSON data, and downloading HTML/JSON/PDF reports.
"""

import os
import sys

# Insert src directory to Python path BEFORE importing routes
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), 'src')))

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
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

# Serve frontend static files if dist directory exists
dist_dir = os.path.join(os.path.dirname(__file__), "frontend", "dist")
if os.path.exists(dist_dir):
    app.mount("/", StaticFiles(directory=dist_dir, html=True), name="static")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("server:app", host="127.0.0.1", port=8000, reload=True)
