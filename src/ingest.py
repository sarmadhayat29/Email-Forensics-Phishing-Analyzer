"""Stage 1 — Ingestion.

Loads raw message files from disk. .eml files are read with the standard
library. .msg (Outlook) support is stubbed behind an optional dependency
(extract-msg) so the tool still runs without it installed.
"""

import email
import os
from email.message import Message


class IngestError(Exception):
    pass


def load_eml(path: str) -> Message:
    with open(path, "rb") as f:
        return email.message_from_binary_file(f)


def load_msg(path: str) -> Message:
    """Load an Outlook .msg file and normalise it into an email.Message.

    Requires the optional `extract-msg` package. Raises IngestError with a
    clear message if it isn't installed, rather than crashing the whole run.
    """
    try:
        import extract_msg  # type: ignore
    except ImportError as exc:
        raise IngestError(
            "extract-msg is not installed — .msg support is disabled. "
            "Run: pip install extract-msg --break-system-packages"
        ) from exc

    msg = extract_msg.Message(path)
    # Build a minimal RFC822-style message so the rest of the pipeline
    # (which expects an email.message.Message) can treat it uniformly.
    eml = email.message.EmailMessage()
    eml["From"] = msg.sender or ""
    eml["To"] = msg.to or ""
    eml["Subject"] = msg.subject or ""
    eml["Date"] = str(msg.date) if msg.date else ""
    eml.set_content(msg.body or "")
    return eml


def load_message(path: str) -> Message:
    ext = os.path.splitext(path)[1].lower()
    if ext == ".eml":
        return load_eml(path)
    if ext == ".msg":
        return load_msg(path)
    raise IngestError(f"Unsupported file type: {ext} (expected .eml or .msg)")


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
    raise IngestError(f"Input path not found: {input_path}")
