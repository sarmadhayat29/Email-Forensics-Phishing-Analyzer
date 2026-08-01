from typing import Optional
from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy.orm import Session
from pydantic import BaseModel, Field

from db import User
from auth import hash_password, verify_password
from api.dependencies import create_access_token, get_current_user, get_db
from api.utils import format_iso
from logger import get_logger
from api.security import login_limiter

logger = get_logger(__name__)
router = APIRouter()


class AuthRequest(BaseModel):
    email: str
    password: str
    full_name: Optional[str] = Field(default=None, max_length=255)


def _user_payload(user: User) -> dict:
    return {
        "id": user.id,
        "email": user.email,
        "full_name": getattr(user, "full_name", None),
        "created_at": format_iso(user.created_at),
    }


@router.post("/signup")
def signup(req: AuthRequest, db: Session = Depends(get_db)):
    try:
        email = req.email.strip().lower()
        if not email or "@" not in email:
            raise HTTPException(status_code=400, detail="Invalid email address.")
        if not req.password or len(req.password) < 8:
            raise HTTPException(status_code=400, detail="Password must be at least 8 characters.")
        if req.password != req.password.strip():
            raise HTTPException(status_code=400, detail="Password cannot start or end with spaces.")

        full_name = (req.full_name or "").strip() or None
        if not full_name:
            raise HTTPException(status_code=400, detail="Full name is required.")
        if len(full_name) < 2:
            raise HTTPException(status_code=400, detail="Full name must be at least 2 characters.")

        existing = db.query(User).filter(User.email == email).first()
        if existing:
            raise HTTPException(status_code=400, detail="An account with this email already exists.")

        new_user = User(
            email=email,
            password_hash=hash_password(req.password),
            full_name=full_name,
        )
        db.add(new_user)
        db.commit()
        db.refresh(new_user)

        token = create_access_token({"sub": new_user.id, "email": new_user.email})
        return {
            "access_token": token,
            "token_type": "bearer",
            "user": _user_payload(new_user),
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Signup error: {e}")
        raise HTTPException(status_code=500, detail="Registration failed due to an internal server error.")


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
            "user": _user_payload(user),
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
        "user": _user_payload(user),
    }
