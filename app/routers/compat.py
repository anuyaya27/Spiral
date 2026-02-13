import json
import logging
import os
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.security import encrypt_text
from app.db.session import get_db
from app.models.job import Job
from app.models.message import Message
from app.models.participant import Participant
from app.models.report import Report
from app.models.upload import Upload
from app.services.parsing.chat_parser import parse_chat_file
from app.services.storage import ensure_upload_dir
from app.services.analysis.runner import analyze_upload_and_store
from app.schemas.llm_report import LLMReport

router = APIRouter(prefix="/compat", tags=["compat"])
logger = logging.getLogger(__name__)


@router.post("/upload", status_code=status.HTTP_201_CREATED)
async def compat_upload(
    file: UploadFile = File(...),
    platform: str | None = Form(default=None),
    timezone_name: str = Form(default="UTC"),
    db: Session = Depends(get_db),
) -> dict:
    raw_bytes = await file.read()
    if not raw_bytes:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Uploaded file is empty.")

    ext = Path(file.filename or "").suffix.lower()
    if not ext:
        ext = ".txt"
    upload_fs_id = str(uuid.uuid4())
    root = ensure_upload_dir()
    saved_path = root / f"{upload_fs_id}{ext}"
    try:
        saved_path.write_bytes(raw_bytes)
    except OSError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Unable to store uploaded file.") from exc
    finally:
        await file.close()

    if os.getenv("DEBUG_PARSE") == "1":
        logger.info(
            "compat_upload_debug",
            extra={
                "filename": file.filename,
                "content_type": file.content_type,
                "headers": dict(file.headers),
                "raw_preview": raw_bytes[:1024].decode("utf-8", errors="replace"),
            },
        )

    retention_until = datetime.now(timezone.utc) + timedelta(days=get_settings().retention_days)
    upload = Upload(
        owner_id=None,
        platform=(platform or _platform_from_filename(file.filename or "") or "generic").lower(),
        timezone=timezone_name,
        status="uploaded",
        file_path=str(saved_path),
        retention_until=retention_until,
        parsing_summary={
            "filename": file.filename or "",
            "content_type": file.content_type or "",
            "stored_bytes": len(raw_bytes),
            "parser": "deferred",
        },
    )
    db.add(upload)
    db.commit()
    db.refresh(upload)
    return {"upload_id": upload.id}


@router.post("/uploads/{upload_id}/analyze")
async def compat_analyze(upload_id: str, request: Request, db: Session = Depends(get_db)) -> dict:
    raw_body = await request.body()
    parsed_body = None
    if raw_body:
        try:
            parsed_body = json.loads(raw_body.decode("utf-8"))
        except json.JSONDecodeError as exc:
            logger.warning("compat_analyze_invalid_json", extra={"upload_id": upload_id, "error": str(exc)})
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid JSON body.") from exc
        if not isinstance(parsed_body, dict):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Request body must be a JSON object.")

    if os.getenv("DEBUG_PARSE") == "1":
        logger.info(
            "compat_analyze_request",
            extra={
                "upload_id": upload_id,
                "headers": dict(request.headers),
                "body": parsed_body if parsed_body is not None else raw_body.decode("utf-8", errors="replace"),
            },
        )

    upload = db.scalar(select(Upload).where(Upload.id == upload_id))
    if not upload:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Upload not found")

    # Rebuild parsed message rows from raw upload on each analyze request.
    db.query(Message).filter(Message.upload_id == upload.id).delete()
    db.query(Participant).filter(Participant.upload_id == upload.id).delete()
    db.commit()

    try:
        parsed = parse_chat_file(upload.file_path, upload.timezone or "UTC")
    except OSError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Stored upload file is unreadable.") from exc

    if os.getenv("DEBUG_PARSE") == "1":
        logger.info(
            "compat_analyze_parse_debug",
            extra={
                "upload_id": upload.id,
                "headers": dict(request.headers),
                "file_path": upload.file_path,
                "parse_stats": {
                    "total_lines": parsed.total_lines,
                    "matched_lines": parsed.matched_lines,
                    "inferred_lines": parsed.inferred_lines,
                },
                "unmatched_preview": parsed.unmatched_lines[:5],
            },
        )

    if not parsed.messages:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={
                "message": "Could not parse any messages from the uploaded file.",
                "first_10_lines": parsed.first_lines,
                "counts": {
                    "total_lines": parsed.total_lines,
                    "matched_lines": parsed.matched_lines,
                    "inferred_lines": parsed.inferred_lines,
                },
            },
        )

    participants_by_name: dict[str, Participant] = {}
    base_ts = datetime.now(timezone.utc)
    for idx, row in enumerate(parsed.messages):
        sender_name = (row.sender or "Unknown").strip() or "Unknown"
        participant = participants_by_name.get(sender_name)
        if participant is None:
            participant = Participant(upload_id=upload.id, display_name=sender_name, normalized_id=sender_name.lower().strip())
            db.add(participant)
            db.flush()
            participants_by_name[sender_name] = participant

        msg_ts = row.ts.astimezone(timezone.utc) if row.ts else (base_ts + timedelta(seconds=idx))
        db.add(
            Message(
                upload_id=upload.id,
                ts=msg_ts,
                sender_id=participant.id,
                encrypted_text=encrypt_text(row.text),
                metadata_json={"inferred": bool(row.inferred)},
            )
        )
    upload.status = "parsed"
    upload.parsing_summary = {
        "message_count": len(parsed.messages),
        "participant_count": len(participants_by_name),
        "matched_lines": parsed.matched_lines,
        "inferred_lines": parsed.inferred_lines,
        "total_lines": parsed.total_lines,
    }
    db.add(upload)
    db.commit()

    message_count = db.scalar(select(func.count(Message.id)).where(Message.upload_id == upload.id)) or 0
    logger.info(
        "compat_analyze_storage_lookup",
        extra={
            "upload_id": upload.id,
            "upload_status": upload.status,
            "file_path": upload.file_path,
            "stored_message_count": int(message_count),
        },
    )

    try:
        report_payload = analyze_upload_and_store(db, upload.id)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    except Exception as exc:  # noqa: BLE001
        logger.exception("compat_analyze_failed", extra={"upload_id": upload.id})
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail="Analysis failed. Please retry.") from exc
    result = LLMReport.model_validate(report_payload).model_dump(mode="json")
    sample_messages = [
        {
            "ts": (row.ts.astimezone(timezone.utc).isoformat() if row.ts else None),
            "sender": row.sender or "Unknown",
            "text": row.text,
        }
        for row in parsed.messages[:3]
    ]
    return {
        "status": "succeeded",
        "message_count": len(parsed.messages),
        "participants": sorted(participants_by_name.keys()),
        "sample_messages": sample_messages,
        **result,
    }


@router.get("/jobs/{job_id}")
def compat_job(job_id: str, db: Session = Depends(get_db)) -> dict:
    job = db.scalar(select(Job).where(Job.id == job_id))
    if not job:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Job not found")
    return {"job_id": job.id, "status": job.status, "progress": job.progress, "error": job.error}


@router.get("/reports/{upload_id}")
def compat_report(upload_id: str, db: Session = Depends(get_db)) -> dict:
    report = db.scalar(select(Report).where(Report.upload_id == upload_id))
    if not report:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report not found")
    return report.report_json


def _platform_from_filename(filename: str) -> str:
    lowered = filename.lower()
    if lowered.endswith(".txt"):
        return "whatsapp"
    if lowered.endswith(".json"):
        return "generic"
    return ""
