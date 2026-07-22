"""Stage 2 — Parsing.

Splits a raw message into a structured ParsedMessage: headers, plain/HTML body,
and attachments (with hashes and true-type sniffing).
"""

from email.message import Message

from utils import hash_bytes, sniff_true_type, file_extension
from models import ParsedMessage, Attachment
from exceptions import ParsingError
from logger import get_logger

logger = get_logger(__name__)


def parse_message(msg: Message) -> ParsedMessage:
    logger.debug("Parsing email message structure.")
    try:
        headers: dict[str, str | list[str]] = {}
        for key in msg.keys():
            values = msg.get_all(key) or []
            headers[key] = values if len(values) > 1 else values[0]

        body_plain, body_html = _extract_body(msg)
        attachments, embedded_images = _extract_attachments(msg)
        mime_structure = _build_mime_structure(msg)

        return ParsedMessage(
            headers=headers,
            from_raw=str(msg.get("From", "")),
            to_raw=str(msg.get("To", "")),
            sender_raw=str(msg.get("Sender", "")),
            cc_raw=str(msg.get("Cc", "")),
            bcc_raw=str(msg.get("Bcc", "")),
            subject=str(msg.get("Subject", "")),
            reply_to_raw=str(msg.get("Reply-To", "")),
            return_path_raw=str(msg.get("Return-Path", "")),
            message_id=str(msg.get("Message-ID", "")),
            date=str(msg.get("Date", "")),
            received_chain=msg.get_all("Received") or [],
            authentication_results=msg.get_all("Authentication-Results") or [],
            body_plain=body_plain,
            body_html=body_html,
            mime_structure=mime_structure,
            attachments=attachments,
            embedded_images=embedded_images,
        )
    except Exception as e:
        logger.error(f"Failed to parse message: {e}")
        raise ParsingError(f"Failed to parse message structure: {e}") from e


def _build_mime_structure(msg: Message, level: int = 0) -> str:
    indent = "  " * level
    structure = f"{indent}- {msg.get_content_type()}"
    if msg.is_multipart():
        for part in msg.get_payload():
            if isinstance(part, Message):
                structure += "\n" + _build_mime_structure(part, level + 1)
    return structure


def _extract_body(msg: Message) -> tuple[str, str]:
    plain, html = "", ""
    if msg.is_multipart():
        for part in msg.walk():
            # Skip multiparts themselves and attachments
            if part.get_content_maintype() == "multipart":
                continue
            
            disp = str(part.get("Content-Disposition", "") or "")
            if "attachment" in disp.lower():
                continue

            content_type = part.get_content_type()
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
            raw_payload = part.get_payload()
            return str(raw_payload) if raw_payload is not None else ""
        
        charset = part.get_content_charset() or "utf-8"
        return payload.decode(charset, errors="replace")
    except Exception as e:
        logger.warning(f"Failed to decode body part: {e}")
        return ""


def _extract_attachments(msg: Message) -> tuple[list[Attachment], list[Attachment]]:
    attachments: list[Attachment] = []
    embedded_images: list[Attachment] = []
    if not msg.is_multipart():
        return attachments, embedded_images
        
    for part in msg.walk():
        if part.get_content_maintype() == "multipart":
            continue
            
        disp = str(part.get("Content-Disposition", "") or "").lower()
        filename = part.get_filename()
        content_id = part.get("Content-ID")
        
        # Determine if this part is an attachment or inline image
        is_attachment = "attachment" in disp or bool(filename)
        is_inline = "inline" in disp or bool(content_id)
        
        if not is_attachment and not is_inline:
            continue

        try:
            payload = part.get_payload(decode=True) or b""
        except Exception as e:
            logger.warning(f"Failed to decode attachment {filename}: {e}")
            payload = b""
            
        filename = filename or "unnamed"
        att = Attachment(
            filename=filename,
            declared_extension=file_extension(filename),
            true_type=sniff_true_type(payload),
            size_bytes=len(payload),
            hashes=hash_bytes(payload) if payload else {},
            content_id=str(content_id) if content_id else None
        )
        
        if is_inline and (part.get_content_maintype() == "image" or content_id):
            embedded_images.append(att)
        else:
            attachments.append(att)
        
    return attachments, embedded_images


