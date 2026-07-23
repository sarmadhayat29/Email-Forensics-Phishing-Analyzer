import os
import shutil
import uuid
import dataclasses
from fastapi import APIRouter, File, UploadFile, HTTPException, Depends
from fastapi.concurrency import run_in_threadpool
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError

from config import UPLOAD_DIR, REPORTS_DIR, MAX_UPLOAD_SIZE
from main import AnalyzerPipeline
from report import write_html_report, write_json_report, write_pdf_report
from models import Finding
from logger import get_logger
from db import AnalysisRecord, User
from api.dependencies import get_db, require_current_user
from api.utils import sanitize_filename
from api.security import upload_limiter

logger = get_logger(__name__)
router = APIRouter()

@router.post("/upload", dependencies=[Depends(upload_limiter)])
async def upload_email(
    file: UploadFile = File(...),
    current_user: User = Depends(require_current_user),
    db: Session = Depends(get_db)
):
    raw_name = file.filename or "uploaded_message.eml"
    filename = sanitize_filename(raw_name)
    ext = filename.rsplit(".", 1)[-1].lower()

    if ext not in {"eml", "msg"}:
        raise HTTPException(status_code=400, detail="Invalid file type. Only .eml and .msg files are supported.")

    file_id = str(uuid.uuid4())
    file_dir = os.path.join(UPLOAD_DIR, file_id)

    # Offload blocking disk I/O to a thread pool to avoid blocking the event loop
    def _save_file():
        os.makedirs(file_dir, exist_ok=True)
        return file_dir

    await run_in_threadpool(_save_file)

    target_path = os.path.join(file_dir, filename)
    bytes_written = 0
    try:
        def _write_chunk(data: bytes):
            with open(target_path, "ab") as buffer:
                buffer.write(data)

        while chunk := await file.read(8192):
            bytes_written += len(chunk)
            if bytes_written > MAX_UPLOAD_SIZE:
                await run_in_threadpool(shutil.rmtree, file_dir, True)
                raise HTTPException(status_code=413, detail="Payload Too Large. Max file size is 15MB.")
            await run_in_threadpool(_write_chunk, chunk)
    except Exception as e:
        await run_in_threadpool(shutil.rmtree, file_dir, True)
        if isinstance(e, HTTPException):
            raise
        logger.error(f"Upload failed: {e}")
        raise HTTPException(status_code=500, detail="Internal server error during upload.")

    # Record ownership in DB immediately on upload to prevent IDOR on /analyze
    try:
        stub = AnalysisRecord(
            id=file_id,
            user_id=current_user.id,
            filename=filename,
            risk_score=0,
            verdict="Pending",
            finding_json={},
        )
        db.add(stub)
        db.commit()
    except IntegrityError:
        db.rollback()

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
    # CRIT-2: Enforce ownership — only the uploading user may analyze their file
    record = db.query(AnalysisRecord).filter(
        AnalysisRecord.id == file_id,
        AnalysisRecord.user_id == current_user.id
    ).first()
    if not record:
        raise HTTPException(status_code=404, detail="File ID not found or unauthorized.")

    file_dir = os.path.join(UPLOAD_DIR, file_id)

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

        # Update the existing stub record created at upload time
        record.filename = finding.file
        record.risk_score = finding.score
        record.verdict = finding.risk_level
        record.finding_json = finding_dict
        record.report_path = html_out
        try:
            db.commit()
        except IntegrityError:
            db.rollback()
            raise HTTPException(status_code=409, detail="Analysis record conflict.")

        success = True
        return {
            "file_id": file_id,
            "status": "completed",
            "finding": finding_dict
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Analysis failed for file_id '{file_id}': {str(e)}")
        raise HTTPException(status_code=500, detail="The forensic pipeline encountered an unexpected internal error.")
    finally:
        if not success:
            shutil.rmtree(file_dir, ignore_errors=True)
            shutil.rmtree(out_dir, ignore_errors=True)
