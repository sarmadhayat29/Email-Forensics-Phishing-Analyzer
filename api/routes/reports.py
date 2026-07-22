import os
import json
from fastapi import APIRouter, HTTPException, Depends
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from api.config import REPORTS_DIR
from db import get_db, AnalysisRecord, User
from auth import require_current_user

router = APIRouter()

def verify_ownership(file_id: str, db: Session, user: User):
    record = db.query(AnalysisRecord).filter(AnalysisRecord.id == file_id, AnalysisRecord.user_id == user.id).first()
    if not record:
        raise HTTPException(status_code=404, detail="Report not found or unauthorized.")
    return record

@router.get("/{file_id}")
def get_report(
    file_id: str, 
    db: Session = Depends(get_db),
    current_user: User = Depends(require_current_user)
):
    verify_ownership(file_id, db, current_user)
    
    json_path = os.path.join(REPORTS_DIR, file_id, "report.json")
    if not os.path.exists(json_path):
        record = db.query(AnalysisRecord).filter(AnalysisRecord.id == file_id).first()
        if record:
            return {"file_id": file_id, "finding": json.loads(record.finding_json)}
        raise HTTPException(status_code=404, detail="Report data not found.")

    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    return {"file_id": file_id, "finding": data}

@router.get("/{file_id}/download/html")
def download_html_report(
    file_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_current_user)
):
    verify_ownership(file_id, db, current_user)
    
    html_path = os.path.join(REPORTS_DIR, file_id, "report.html")
    if not os.path.exists(html_path):
        raise HTTPException(status_code=404, detail="HTML report not found.")

    return FileResponse(
        path=html_path,
        filename=f"investigation_{file_id[:8]}.report.html",
        media_type="text/html"
    )

@router.get("/{file_id}/download/json")
def download_json_report(
    file_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_current_user)
):
    verify_ownership(file_id, db, current_user)

    json_path = os.path.join(REPORTS_DIR, file_id, "report.json")
    if not os.path.exists(json_path):
        raise HTTPException(status_code=404, detail="JSON report not found.")

    return FileResponse(
        path=json_path,
        filename=f"investigation_{file_id[:8]}.report.json",
        media_type="application/json"
    )

@router.get("/{file_id}/download/pdf")
def download_pdf_report(
    file_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_current_user)
):
    verify_ownership(file_id, db, current_user)

    pdf_path = os.path.join(REPORTS_DIR, file_id, "report.pdf")
    if not os.path.exists(pdf_path):
        raise HTTPException(status_code=404, detail="PDF report not found.")

    return FileResponse(
        path=pdf_path,
        filename=f"investigation_{file_id[:8]}.report.pdf",
        media_type="application/pdf"
    )
