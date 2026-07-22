import os
import json
import shutil
from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy.orm import Session

from api.config import UPLOAD_DIR, REPORTS_DIR
from db import get_db, User, AnalysisRecord
from auth import require_current_user

router = APIRouter()

@router.get("")
def list_analyses(
    search: str = None,
    sort: str = "date_desc",
    risk_level: str = "All",
    current_user: User = Depends(require_current_user),
    db: Session = Depends(get_db)
):
    user_id = current_user.id
    query = db.query(AnalysisRecord).filter(AnalysisRecord.user_id == user_id)

    if risk_level and risk_level != "All":
        if risk_level == "Safe":
            query = query.filter(AnalysisRecord.verdict == "Low")
        else:
            query = query.filter(AnalysisRecord.verdict == risk_level)

    if search:
        search_fmt = f"%{search.strip().lower()}%"
        # We can only search by filename in the DB now since subject/from_addr are in JSON
        # For a production app we'd use a JSONB query, but for compatibility we'll use filename
        query = query.filter(AnalysisRecord.filename.ilike(search_fmt))

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

    records = query.all()
    results = []
    for r in records:
        finding_data = json.loads(r.finding_json)
        results.append({
            "id": r.id,
            "filename": r.filename,
            "subject": finding_data.get("subject") or "(No Subject)",
            "from_addr": finding_data.get("from_addr") or "-",
            "score": r.risk_score,
            "risk_level": r.verdict,
            "date": r.created_at.isoformat().split("T")[0],
            "created_at": r.created_at.isoformat()
        })

    return {"count": len(results), "analyses": results}

@router.get("/{id}")
def get_analysis_record(
    id: str, 
    current_user: User = Depends(require_current_user),
    db: Session = Depends(get_db)
):
    record = db.query(AnalysisRecord).filter(AnalysisRecord.id == id, AnalysisRecord.user_id == current_user.id).first()
    if not record:
        raise HTTPException(status_code=404, detail="Analysis record not found.")

    finding_data = json.loads(record.finding_json)
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

    db.delete(record)
    db.commit()

    file_dir = os.path.join(UPLOAD_DIR, id)
    report_dir = os.path.join(REPORTS_DIR, id)
    if os.path.exists(file_dir):
        shutil.rmtree(file_dir, ignore_errors=True)
    if os.path.exists(report_dir):
        shutil.rmtree(report_dir, ignore_errors=True)

    return {"status": "deleted", "id": id}
