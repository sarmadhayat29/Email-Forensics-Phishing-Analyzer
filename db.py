"""Database Schema & Database Connection Layer.

Supports SQLAlchemy ORM mapped to Supabase PostgreSQL.
"""

import uuid
from datetime import datetime, timezone
from sqlalchemy import create_engine, Column, String, Integer, DateTime, ForeignKey, Index
from sqlalchemy.orm import declarative_base, sessionmaker, relationship
from sqlalchemy.dialects.postgresql import JSONB

from config import DATABASE_URL

engine = create_engine(
    DATABASE_URL,
    pool_pre_ping=True,
    pool_recycle=300,
    pool_size=10,
    max_overflow=20,
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


class User(Base):
    __tablename__ = "users"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    email = Column(String(255), unique=True, index=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    full_name = Column(String(255), nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    analyses = relationship("AnalysisRecord", back_populates="owner", cascade="all, delete-orphan")


class AnalysisRecord(Base):
    __tablename__ = "analysis_records"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    filename = Column(String(255), nullable=False)
    risk_score = Column(Integer, nullable=False, default=0, index=True)
    verdict = Column(String(50), nullable=False, default="Low", index=True)
    report_path = Column(String(500), nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    
    finding_json = Column(JSONB, nullable=False)

    owner = relationship("User", back_populates="analyses")

    # Composite index for the primary history query pattern
    __table_args__ = (
        Index("idx_user_created", "user_id", "created_at"),
    )


def init_db():
    Base.metadata.create_all(bind=engine)
    _ensure_user_full_name_column()


def _ensure_user_full_name_column():
    """Add users.full_name on existing databases created before the column existed."""
    from sqlalchemy import text, inspect

    try:
        inspector = inspect(engine)
        if "users" not in inspector.get_table_names():
            return
        columns = {col["name"] for col in inspector.get_columns("users")}
        if "full_name" in columns:
            return
        with engine.begin() as conn:
            conn.execute(text("ALTER TABLE users ADD COLUMN full_name VARCHAR(255)"))
    except Exception:
        # Best-effort migration; signup still works if the column already exists
        # or the platform forbids ALTER (create_all covers new installs).
        pass

