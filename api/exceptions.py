from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
import traceback
from logger import get_logger

logger = get_logger(__name__)

def register_exception_handlers(app: FastAPI):
    @app.exception_handler(Exception)
    async def global_exception_handler(request: Request, exc: Exception):
        logger.error(f"Unhandled server error: {exc}")
        logger.error(traceback.format_exc())
        return JSONResponse(
            status_code=500,
            content={"detail": "An unexpected internal server error occurred."}
        )
