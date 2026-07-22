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

from api.routes import auth, analysis, history, reports
from logger import get_logger

logger = get_logger(__name__)

app = FastAPI(
    title="Email Forensics & Phishing Analyzer API",
    description="REST API for email forensic investigation, user authentication, and persistent analysis history.",
    version="2.0.0"
)

# Parse ALLOWED_ORIGINS from environment, default to strict localhost for dev
allowed_origins_env = os.environ.get("ALLOWED_ORIGINS", "http://localhost:5173,http://127.0.0.1:8000,http://localhost:8000")
allowed_origins = [origin.strip() for origin in allowed_origins_env.split(",") if origin.strip()]

# Enable CORS for web frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)

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
