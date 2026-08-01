"""Stage 1 — Ingestion.

Loads raw message files from disk. .eml files are read with the standard
library using modern policies. .msg (Outlook) support is stubbed behind an optional dependency.
"""

import email
from email import policy
import os
from email.message import Message
from email.parser import HeaderParser

from exceptions import IngestionError, MalformedEmailError
from logger import get_logger

logger = get_logger(__name__)

#: Attribute under which the pristine source bytes are stashed on the parsed
#: Message. DKIM verification hashes the message byte-for-byte, so it needs the
#: original octets rather than a re-serialised copy.
RAW_BYTES_ATTR = "_raw_source_bytes"


def load_eml(path: str) -> Message:
    logger.debug(f"Loading .eml file: {path}")
    try:
        with open(path, "rb") as f:
            raw = f.read()
        msg = email.message_from_bytes(raw, policy=policy.default)
        if not msg:
            raise MalformedEmailError(f"File {path} is empty or unparsable.")
        try:
            setattr(msg, RAW_BYTES_ATTR, raw)
        except Exception:  # pragma: no cover - Message always accepts attributes
            logger.debug("Could not attach raw source bytes; DKIM re-verification will be skipped.")
        return msg
    except OSError as e:
        logger.error(f"Failed to read file {path}: {e}")
        raise IngestionError(f"Cannot read file {path}: {e}") from e
    except Exception as e:
        logger.error(f"Malformed .eml content in {path}: {e}")
        raise MalformedEmailError(f"Malformed .eml content in {path}") from e


def load_msg(path: str) -> Message:
    """Load an Outlook .msg file and normalise it into an email.Message."""
    logger.debug(f"Loading .msg file: {path}")
    try:
        import extract_msg  # type: ignore
    except ImportError as exc:
        raise IngestionError(
            "extract-msg is not installed — .msg support is disabled. "
            "Run: pip install extract-msg --break-system-packages"
        ) from exc

    try:
        msg = extract_msg.Message(path)
        eml = email.message.EmailMessage(policy=policy.default)
        
        # 1. Map headers natively if available, otherwise reconstruct them
        if getattr(msg, "header", None):
            hp = HeaderParser(policy=policy.default)
            parsed_headers = hp.parsestr(str(msg.header))
            for k, v in parsed_headers.items():
                eml[k] = v
        else:
            eml["From"] = msg.sender or ""
            eml["To"] = msg.to or ""
            eml["Cc"] = msg.cc or ""
            eml["Bcc"] = msg.bcc or ""
            eml["Subject"] = msg.subject or ""
            eml["Date"] = msg.date or ""
            if msg.messageId:
                eml["Message-ID"] = msg.messageId

        # 2. Reconstruct Body (Plain / HTML)
        html_body = getattr(msg, "htmlBody", None)
        if html_body:
            eml.set_content(msg.body or "")
            html_text = html_body.decode('utf-8', errors='replace') if isinstance(html_body, bytes) else str(html_body)
            eml.add_alternative(html_text, subtype='html')
        else:
            eml.set_content(msg.body or "")

        # 3. Reconstruct Attachments & Embedded Images
        for att in msg.attachments:
            filename = (
                getattr(att, "longFilename", None)
                or getattr(att, "shortFilename", None)
                or "unnamed"
            )
            data = getattr(att, "data", b"")
            eml.add_attachment(data, maintype="application", subtype="octet-stream", filename=filename)
            
            # If it's an embedded image, it will have a Content-ID
            cid = getattr(att, "cid", None)
            if cid:
                # Get the last added part and append the CID
                payload = eml.get_payload()
                if isinstance(payload, list) and len(payload) > 0:
                    payload[-1].add_header('Content-ID', f"<{cid}>")
                    payload[-1].replace_header('Content-Disposition', 'inline')

        return eml
    except Exception as e:
        logger.error(f"Failed to parse .msg file {path}: {e}")
        raise IngestionError(f"Failed to parse .msg file {path}: {e}") from e


def load_message(path: str) -> Message:
    ext = os.path.splitext(path)[1].lower()
    if ext == ".eml":
        return load_eml(path)
    if ext == ".msg":
        return load_msg(path)
    raise IngestionError(f"Unsupported file type: {ext} (expected .eml or .msg)")


def discover_messages(input_path: str) -> list[str]:
    """Return a list of message file paths from a file or folder input."""
    if os.path.isfile(input_path):
        return [input_path]
    if os.path.isdir(input_path):
        found = []
        for root, _dirs, files in os.walk(input_path):
            for name in files:
                if name.lower().endswith((".eml", ".msg")):
                    found.append(os.path.join(root, name))
        return sorted(found)
    raise IngestionError(f"Input path not found: {input_path}")

