from typing import Optional
from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy.orm import Session
from pydantic import BaseModel

from db import get_db, User
from auth import (
    hash_password, verify_password, create_access_token,
    get_current_user
)
from logger import get_logger

logger = get_logger(__name__)
router = APIRouter()

class AuthRequest(BaseModel):
    email: str
    password: str

def format_iso(dt):
    if dt is None:
        from datetime import datetime, timezone
        return datetime.now(timezone.utc).isoformat()
    if hasattr(dt, 'isoformat'):
        return dt.isoformat()
    return str(dt)

@router.post("/signup")
def signup(req: AuthRequest, db: Session = Depends(get_db)):
    try:
        email = req.email.strip().lower()
        if not email or "@" not in email:
            raise HTTPException(status_code=400, detail="Invalid email address.")
        if not req.password or len(req.password) < 6:
            raise HTTPException(status_code=400, detail="Password must be at least 6 characters.")

        existing = db.query(User).filter(User.email == email).first()
        if existing:
            raise HTTPException(status_code=400, detail="An account with this email already exists.")

        new_user = User(
            email=email,
            password_hash=hash_password(req.password)
        )
        db.add(new_user)
        db.commit()
        db.refresh(new_user)

        token = create_access_token({"sub": new_user.id, "email": new_user.email})
        return {
            "access_token": token,
            "token_type": "bearer",
            "user": {
                "id": new_user.id,
                "email": new_user.email,
                "created_at": format_iso(new_user.created_at)
            }
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Signup error: {e}")
        raise HTTPException(status_code=500, detail="Registration failed due to an internal server error.")

from api.security import login_limiter

@router.post("/login", dependencies=[Depends(login_limiter)])
def login(req: AuthRequest, db: Session = Depends(get_db)):
    try:
        email = req.email.strip().lower()
        user = db.query(User).filter(User.email == email).first()

        if not user or not verify_password(req.password, user.password_hash):
            raise HTTPException(status_code=400, detail="Invalid email or password.")

        token = create_access_token({"sub": user.id, "email": user.email})
        return {
            "access_token": token,
            "token_type": "bearer",
            "user": {
                "id": user.id,
                "email": user.email,
                "created_at": format_iso(user.created_at)
            }
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Login error: {e}")
        raise HTTPException(status_code=500, detail="Login failed due to an internal server error.")

@router.get("/me")
def get_me(user: Optional[User] = Depends(get_current_user)):
    if not user:
        return {"authenticated": False, "user": None}
    return {
        "authenticated": True,
        "user": {
            "id": user.id,
            "email": user.email,
            "created_at": format_iso(user.created_at)
        }
    }
