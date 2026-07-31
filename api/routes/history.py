import os
import json
import shutil
from typing import Optional
from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy.orm import Session

from config import UPLOAD_DIR, REPORTS_DIR
from db import AnalysisRecord, User
from api.dependencies import get_db, require_current_user
from scoring import to_display_score

router = APIRouter()


def _display_score(record: AnalysisRecord, finding_data: dict) -> int:
    """Return the record's score on the 0-100 scale.

    Records written before the switch to a normalised score stored the raw
    weight total (which can exceed 100) and have no ``raw_score`` key, so they
    are mapped through the same monotone function on read.
    """
    score = record.risk_score or 0
    if "raw_score" not in (finding_data or {}) and score > 100:
        return to_display_score(score)
    return score

@router.get("")
def list_analyses(
    search: str = None,
    sort: str = "date_desc",
    risk_level: str = "All",
    limit: int = 50,
    offset: int = 0,
    current_user: User = Depends(require_current_user),
    db: Session = Depends(get_db)
):
    # Clamp limit to a safe maximum to prevent memory exhaustion
    limit = min(max(1, limit), 100)

    user_id = current_user.id
    query = db.query(AnalysisRecord).filter(AnalysisRecord.user_id == user_id)

    if risk_level and risk_level != "All":
        if risk_level == "Safe":
            query = query.filter(AnalysisRecord.verdict == "Low")
        else:
            query = query.filter(AnalysisRecord.verdict == risk_level)

    if search:
        search_fmt = f"%{search.strip().lower()}%"
        # Using native JSONB query
        query = query.filter(
            (AnalysisRecord.filename.ilike(search_fmt)) |
            (AnalysisRecord.finding_json['subject'].astext.ilike(search_fmt)) |
            (AnalysisRecord.finding_json['from_addr'].astext.ilike(search_fmt))
        )

    if sort == "date_asc":
        query = query.order_by(AnalysisRecord.created_at.asc())
    elif sort == "score_desc":
        query = query.order_by(AnalysisRecord.risk_score.desc())
    elif sort == "score_asc":
        query = query.order_by(AnalysisRecord.risk_score.asc())
    elif sort == "filename":
        query = query.order_by(AnalysisRecord.filename.asc())
    else:
        query = query.order_by(AnalysisRecord.created_at.desc())

    total = query.count()
    records = query.offset(offset).limit(limit).all()
    results = []
    for r in records:
        finding_data = r.finding_json
        results.append({
            "id": r.id,
            "filename": r.filename,
            "subject": finding_data.get("subject") or "(No Subject)",
            "from_addr": finding_data.get("from_addr") or "-",
            "score": _display_score(r, finding_data),
            "risk_level": r.verdict,
            "date": r.created_at.isoformat().split("T")[0],
            "created_at": r.created_at.isoformat()
        })

    return {"count": len(results), "total": total, "offset": offset, "limit": limit, "analyses": results}

@router.get("/{id}")
def get_analysis_record(
    id: str, 
    current_user: User = Depends(require_current_user),
    db: Session = Depends(get_db)
):
    record = db.query(AnalysisRecord).filter(AnalysisRecord.id == id, AnalysisRecord.user_id == current_user.id).first()
    if not record:
        raise HTTPException(status_code=404, detail="Analysis record not found.")

    finding_data = record.finding_json
    return {"file_id": record.id, "finding": finding_data}

@router.delete("/{id}")
def delete_analysis_record(
    id: str,
    current_user: User = Depends(require_current_user),
    db: Session = Depends(get_db)
):
    user_id = current_user.id
    record = db.query(AnalysisRecord).filter(AnalysisRecord.id == id, AnalysisRecord.user_id == user_id).first()
    if not record:
        raise HTTPException(status_code=404, detail="Analysis record not found or unauthorized.")

    file_dir = os.path.join(UPLOAD_DIR, id)
    report_dir = os.path.join(REPORTS_DIR, id)
    
    try:
        if os.path.exists(file_dir):
            shutil.rmtree(file_dir)
        if os.path.exists(report_dir):
            shutil.rmtree(report_dir)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to delete analysis files from disk: {str(e)}")

    db.delete(record)
    db.commit()

    return {"status": "deleted", "id": id}
