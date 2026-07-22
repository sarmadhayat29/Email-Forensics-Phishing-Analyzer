import os
import shutil
import uuid
import dataclasses
import json
import re
from fastapi import APIRouter, File, UploadFile, HTTPException, Depends
from sqlalchemy.orm import Session

from api.config import UPLOAD_DIR, REPORTS_DIR
from main import AnalyzerPipeline
from report import write_html_report, write_json_report, write_pdf_report
from models import Finding
from logger import get_logger
from db import get_db, AnalysisRecord, User
from auth import require_current_user

logger = get_logger(__name__)
router = APIRouter()

MAX_UPLOAD_SIZE = 15 * 1024 * 1024  # 15 MB

def sanitize_filename(filename: str) -> str:
    base = os.path.basename(filename)
    safe = re.sub(r'[^a-zA-Z0-9_\-\.]', '', base)
    if not safe:
        safe = "uploaded_message.eml"
    return safe

from api.security import upload_limiter

@router.post("/upload", dependencies=[Depends(upload_limiter)])
async def upload_email(
    file: UploadFile = File(...),
    current_user: User = Depends(require_current_user)
):
    raw_name = file.filename or "uploaded_message.eml"
    filename = sanitize_filename(raw_name)
    ext = filename.rsplit(".", 1)[-1].lower()

    if ext not in {"eml", "msg"}:
        raise HTTPException(status_code=400, detail="Invalid file type. Only .eml and .msg files are supported.")

    file_id = str(uuid.uuid4())
    file_dir = os.path.join(UPLOAD_DIR, file_id)
    os.makedirs(file_dir, exist_ok=True)

    target_path = os.path.join(file_dir, filename)
    bytes_written = 0
    try:
        with open(target_path, "wb") as buffer:
            while chunk := await file.read(8192):
                bytes_written += len(chunk)
                if bytes_written > MAX_UPLOAD_SIZE:
                    raise HTTPException(status_code=413, detail="Payload Too Large. Max file size is 15MB.")
                buffer.write(chunk)
    except Exception as e:
        shutil.rmtree(file_dir, ignore_errors=True)
        if isinstance(e, HTTPException):
            raise
        logger.error(f"Upload failed: {e}")
        raise HTTPException(status_code=500, detail="Internal server error during upload.")

    logger.info(f"Uploaded email file '{filename}' with ID '{file_id}' by user '{current_user.id}'")

    return {
        "file_id": file_id,
        "filename": filename,
        "size_bytes": bytes_written,
        "message": "File uploaded successfully"
    }

@router.post("/analyze/{file_id}")
def analyze_email(
    file_id: str, 
    db: Session = Depends(get_db),
    current_user: User = Depends(require_current_user)
):
    file_dir = os.path.join(UPLOAD_DIR, file_id)
    if not os.path.exists(file_dir):
        raise HTTPException(status_code=404, detail="File ID not found. Upload file first.")

    files = [f for f in os.listdir(file_dir) if f.endswith((".eml", ".msg"))]
    if not files:
        raise HTTPException(status_code=404, detail="No email file found for specified file ID.")

    target_path = os.path.join(file_dir, files[0])
    out_dir = os.path.join(REPORTS_DIR, file_id)
    os.makedirs(out_dir, exist_ok=True)

    success = False
    try:
        pipeline = AnalyzerPipeline(output_dir=out_dir)
        finding: Finding = pipeline.analyse_one(target_path)

        html_out = os.path.join(out_dir, "report.html")
        json_out = os.path.join(out_dir, "report.json")
        pdf_out = os.path.join(out_dir, "report.pdf")

        write_html_report(finding, html_out)
        write_json_report(finding, json_out)
        write_pdf_report(finding, pdf_out)

        finding_dict = dataclasses.asdict(finding)

        record = db.query(AnalysisRecord).filter(AnalysisRecord.id == file_id).first()
        if not record:
            record = AnalysisRecord(
                id=file_id,
                user_id=current_user.id,
                filename=finding.file,
                risk_score=finding.score,
                verdict=finding.risk_level,
                finding_json=json.dumps(finding_dict, default=str),
                report_path=html_out
            )
            db.add(record)
            db.commit()

        success = True
        return {
            "file_id": file_id,
            "status": "completed",
            "finding": finding_dict
        }
    except Exception as e:
        logger.error(f"Analysis failed for file_id '{file_id}': {str(e)}")
        raise HTTPException(status_code=500, detail="The forensic pipeline encountered an unexpected internal error.")
    finally:
        if not success:
            shutil.rmtree(file_dir, ignore_errors=True)
            shutil.rmtree(out_dir, ignore_errors=True)
