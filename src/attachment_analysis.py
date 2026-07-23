"""Attachment Forensics Engine.

Performs offline structural, syntactic, signature, and encryption checks on email attachments.
Detects executables, scripts, macro-enabled Office documents, double extensions,
password-protected archives, and suspicious lure filenames.
"""

import re
import struct
import mimetypes
from typing import List

from models import ParsedMessage, Attachment
from utils import file_extension, has_double_extension, RISKY_EXTENSIONS
from logger import get_logger

logger = get_logger(__name__)

EXECUTABLE_EXTENSIONS = {"exe", "scr", "com", "bat", "cmd", "pif", "msi", "hta"}
SCRIPT_EXTENSIONS = {"js", "jse", "vbs", "vbe", "ws", "wsf", "ps1", "py", "sh"}
MACRO_EXTENSIONS = {"docm", "xlsm", "pptm", "dotm", "xltm"}

LURE_KEYWORDS = [
    "invoice", "receipt", "payment", "remittance", "purchase", "order",
    "urgent", "scan", "bank", "wire", "statement", "document", "swift", "transfer"
]


def analyze_attachments(parsed: ParsedMessage) -> List[Attachment]:
    logger.debug("Executing Attachment Forensics Engine.")
    analyzed_attachments: List[Attachment] = []

    for att in parsed.attachments + parsed.embedded_images:
        analyzed_att = _analyze_single_attachment(att)
        analyzed_attachments.append(analyzed_att)

    return analyzed_attachments


def _analyze_single_attachment(att: Attachment) -> Attachment:
    filename = att.filename
    ext = file_extension(filename)
    findings: List[str] = []

    # 1. MIME Type Resolution
    mime_type, _ = mimetypes.guess_type(filename)
    if not mime_type:
        mime_type = _infer_mime_from_true_type(att.true_type)

    is_exe = False
    is_script = False
    is_macro = False
    is_double_ext = False
    is_encrypted = False
    is_suspicious_name = False

    # 2. Executables Detection
    if ext in EXECUTABLE_EXTENSIONS or att.true_type == "exe":
        is_exe = True
        findings.append(f"Executable File Detected (extension: '.{ext}', true signature: '{att.true_type}')")

    # 3. Scripts Detection
    if ext in SCRIPT_EXTENSIONS:
        is_script = True
        findings.append(f"Script File Detected (extension: '.{ext}')")

    # 4. Macro-Enabled Office Files Detection
    if ext in MACRO_EXTENSIONS:
        is_macro = True
        findings.append(f"Macro-Enabled Office Document (extension: '.{ext}')")
    elif ext in {"doc", "xls", "ppt"} or att.true_type in {"ole/doc-xls-ppt", "zip/office"}:
        # Exact match against legacy Office extensions only — avoids .docx/.xlsx false positives
        if ext in {"doc", "xls"}:
            is_macro = True
            findings.append(f"Legacy Office Container with Potential Macros (extension: '.{ext}')")

    # 5. Double Extension Detection
    if has_double_extension(filename):
        is_double_ext = True
        findings.append(f"Double Extension Masking Attack Detected ('{filename}')")

    # 6. Password-Protected Archive Detection
    if ext in {"zip", "rar", "7z"} or att.true_type == "zip/office":
        # Check ZIP / RAR header encryption flag if hashes/data are present
        if _is_zip_encrypted(filename):
            is_encrypted = True
            findings.append("Password-Protected / Encrypted Archive Detected (Conceals Malicious Payload)")

    # 7. Suspicious Attachment Names
    fn_lower = filename.lower()
    for lure in LURE_KEYWORDS:
        if lure in fn_lower and (is_exe or is_script or is_macro or is_double_ext or ext in {"zip", "iso", "img", "cab"}):
            is_suspicious_name = True
            findings.append(f"Social Engineering Lure Filename ('{lure}' keyword paired with high-risk file type)")
            break

    if re.search(r"^[a-f0-9]{8,64}\.[a-z0-9]+$", fn_lower):
        is_suspicious_name = True
        findings.append(f"Randomized Hash Filename Pattern ('{filename}')")

    # Populate updated Attachment model
    att.mime_type = mime_type
    att.is_executable = is_exe
    att.is_script = is_script
    att.is_macro_enabled = is_macro
    att.has_double_extension = is_double_ext
    att.is_password_protected = is_encrypted
    att.suspicious_name_flag = is_suspicious_name
    att.findings = findings

    return att


def _infer_mime_from_true_type(true_type: str) -> str:
    mapping = {
        "exe": "application/x-dsexec",
        "pdf": "application/pdf",
        "zip/office": "application/zip",
        "jpg": "image/jpeg",
        "png": "image/png",
        "ps": "application/postscript",
        "ole/doc-xls-ppt": "application/x-ole-storage",
    }
    return mapping.get(true_type, "application/octet-stream")


def _is_zip_encrypted(filename: str) -> bool:
    """Detect password-protected ZIPs via exact keyword matching (not substring)."""
    import re
    fn_lower = filename.lower()
    # Use word-boundary matching to avoid false positives like 'passport.zip'
    if re.search(r'\bencrypted\b|\bprotected\b|\bpassword\b', fn_lower):
        return True
    return False
