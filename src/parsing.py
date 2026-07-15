"""Stage 2 — Parsing.

Splits a raw message into a structured dict: headers, plain/HTML body,
and attachments (with hashes and true-type sniffing).
"""

from email.message import Message
from email.utils import getaddresses

from utils import hash_bytes, sniff_true_type, file_extension


def parse_message(msg: Message) -> dict:
    headers = {}
    for key in msg.keys():
        # Multiple headers with the same name (e.g. multiple Received:)
        # are collected into a list; single ones stay as a plain string.
        values = msg.get_all(key)
        headers[key] = values if len(values) > 1 else values[0]

    body_plain, body_html = _extract_body(msg)
    attachments = _extract_attachments(msg)

    return {
        "headers": headers,
        "from_raw": msg.get("From", ""),
        "to_raw": msg.get("To", ""),
        "subject": msg.get("Subject", ""),
        "reply_to_raw": msg.get("Reply-To", ""),
        "return_path_raw": msg.get("Return-Path", ""),
        "message_id": msg.get("Message-ID", ""),
        "date": msg.get("Date", ""),
        "received_chain": msg.get_all("Received") or [],
        "authentication_results": msg.get_all("Authentication-Results") or [],
        "body_plain": body_plain,
        "body_html": body_html,
        "attachments": attachments,
    }


def _extract_body(msg: Message) -> tuple[str, str]:
    plain, html = "", ""
    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            disp = str(part.get("Content-Disposition") or "")
            if "attachment" in disp:
                continue
            if content_type == "text/plain" and not plain:
                plain = _decode_part(part)
            elif content_type == "text/html" and not html:
                html = _decode_part(part)
    else:
        content_type = msg.get_content_type()
        if content_type == "text/html":
            html = _decode_part(msg)
        else:
            plain = _decode_part(msg)
    return plain, html


def _decode_part(part: Message) -> str:
    try:
        payload = part.get_payload(decode=True)
        if payload is None:
            return part.get_payload() or ""
        charset = part.get_content_charset() or "utf-8"
        return payload.decode(charset, errors="replace")
    except Exception:
        return ""


def _extract_attachments(msg: Message) -> list[dict]:
    attachments = []
    if not msg.is_multipart():
        return attachments
    for part in msg.walk():
        disp = str(part.get("Content-Disposition") or "")
        filename = part.get_filename()
        if "attachment" not in disp and not filename:
            continue
        if part.get_content_maintype() == "multipart":
            continue
        payload = part.get_payload(decode=True) or b""
        filename = filename or "unnamed"
        attachments.append({
            "filename": filename,
            "declared_extension": file_extension(filename),
            "true_type": sniff_true_type(payload),
            "size_bytes": len(payload),
            "hashes": hash_bytes(payload) if payload else {},
        })
    return attachments
