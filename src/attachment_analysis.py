"""Attachment Forensics Engine.

Performs offline structural, syntactic, signature, and encryption checks on email attachments.
Detects executables, scripts, macro-enabled Office documents, double extensions,
password-protected archives, and suspicious lure filenames.

When the attachment's bytes survived parsing, the engine reads the container
itself (:mod:`attachment_content`) rather than trusting the filename: ZIP
encryption comes from the general-purpose bit flag, macro presence from a VBA
stream or ``vbaProject.bin`` entry, and PDF risk from the document's own action
objects. Name-based heuristics remain as the fallback for the case where no
bytes are available, so behaviour never regresses when content is missing.
"""

import re
import mimetypes
from typing import List

from models import ParsedMessage, Attachment, attachment_content
from attachment_content import (
    ARCHIVE_CONTAINS_EXECUTABLE, ARCHIVE_DOUBLE_EXTENSION_ENTRY, ARCHIVE_ENCRYPTED,
    ARCHIVE_NESTED, LEGACY_OFFICE_NO_MACRO, OFFICE_ENCRYPTED, OFFICE_VBA_MACRO,
    TYPE_MISMATCH, ArchiveInspection, OleInspection, PdfInspection,
    declared_type_mismatch, inspect_archive, inspect_ole, inspect_pdf,
)
from utils import file_extension, has_double_extension
from logger import get_logger

logger = get_logger(__name__)

EXECUTABLE_EXTENSIONS = {"exe", "scr", "com", "bat", "cmd", "pif", "msi", "hta"}
SCRIPT_EXTENSIONS = {"js", "jse", "vbs", "vbe", "ws", "wsf", "ps1", "py", "sh"}
MACRO_EXTENSIONS = {"docm", "xlsm", "pptm", "dotm", "xltm"}
LEGACY_OFFICE_EXTENSIONS = {"doc", "xls"}

#: Container formats whose contents a name-only check cannot see into.
ARCHIVE_EXTENSIONS = {"zip", "rar", "7z"}

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
    features: List[str] = []

    # 1. MIME Type Resolution
    mime_type, _ = mimetypes.guess_type(filename)
    if not mime_type:
        mime_type = _infer_mime_from_true_type(att.true_type)

    # 1b. Content inspection. Each inspector returns an "uninspected" result for
    # a file it does not recognise, and never raises, so a missing, truncated or
    # corrupt payload simply leaves the name-based checks below in charge.
    data = attachment_content(att)
    archive, ole, pdf = _inspect_content(filename, data)
    content_inspected = archive.inspected or ole.inspected or pdf.inspected

    is_exe = False
    is_script = False
    is_macro = False
    is_double_ext = False
    is_encrypted = False
    is_suspicious_name = False

    # 2. Executables Detection
    if ext in EXECUTABLE_EXTENSIONS or att.true_type in {"exe", "elf"}:
        is_exe = True
        findings.append(f"Executable File Detected (extension: '.{ext}', true signature: '{att.true_type}')")

    # 3. Scripts Detection
    if ext in SCRIPT_EXTENSIONS:
        is_script = True
        findings.append(f"Script File Detected (extension: '.{ext}')")
    elif ext == "lnk" or att.true_type == "lnk":
        # A shortcut is not itself code, but it carries an arbitrary command
        # line and is a mainstream delivery vector for exactly that reason.
        is_script = True
        findings.append("Windows Shortcut (.lnk) Detected — Launches an Arbitrary Command Line")

    # 4. Macro-Enabled Office Files Detection
    if archive.has_vba_project or ole.has_macros:
        # Content-verified: a VBA project is physically present.
        is_macro = True
        features.append(OFFICE_VBA_MACRO)
        evidence = ", ".join(ole.macro_streams) if ole.macro_streams else "vbaProject.bin"
        findings.append(f"VBA Macro Project Found Inside Document (stream/entry: {evidence})")
    elif ext in MACRO_EXTENSIONS:
        is_macro = True
        findings.append(f"Macro-Enabled Office Document (extension: '.{ext}')")
    elif ext in LEGACY_OFFICE_EXTENSIONS:
        if ole.inspected:
            # The container was read and holds no VBA project, so the old
            # "legacy Office means macros" assumption is measurably wrong here.
            features.append(LEGACY_OFFICE_NO_MACRO)
            findings.append(
                f"Legacy Office Container Inspected — No VBA Macro Project Present (extension: '.{ext}')"
            )
        else:
            is_macro = True
            findings.append(f"Legacy Office Container with Potential Macros (extension: '.{ext}')")

    # 5. Double Extension Detection
    if has_double_extension(filename):
        is_double_ext = True
        findings.append(f"Double Extension Masking Attack Detected ('{filename}')")

    # 6. Encryption Detection — read from the container when possible.
    if archive.inspected and archive.encrypted:
        is_encrypted = True
        features.append(ARCHIVE_ENCRYPTED)
        sample = ", ".join(archive.encrypted_entries[:3]) or "unnamed entry"
        findings.append(
            "Password-Protected / Encrypted Archive Confirmed via ZIP Encryption Flag "
            f"(entries: {sample}) — Contents Cannot Be Scanned"
        )
    elif ole.encrypted:
        is_encrypted = True
        features.append(OFFICE_ENCRYPTED)
        findings.append(
            "Password-Protected Office Document Confirmed (OLE 'EncryptedPackage' stream) "
            "— Contents Cannot Be Scanned"
        )
    elif not archive.inspected and ext in ARCHIVE_EXTENSIONS and _is_zip_encrypted(filename):
        # Fallback only: the container could not be read, so the filename is
        # the sole (weak) indication. Never applied to an archive whose flags
        # were actually read, which is what keeps 'passport_protected.zip'
        # style names from overriding evidence.
        is_encrypted = True
        findings.append("Password-Protected / Encrypted Archive Suggested by Filename (unverified)")

    # 6b. What the archive actually carries.
    if archive.risky_entries:
        features.append(ARCHIVE_CONTAINS_EXECUTABLE)
        findings.append(
            "Archive Contains Executable / Script Payload "
            f"({', '.join(archive.risky_entries[:4])})"
        )
    if archive.double_extension_entries:
        features.append(ARCHIVE_DOUBLE_EXTENSION_ENTRY)
        findings.append(
            "Archive Entry Uses Double Extension Masking "
            f"({', '.join(archive.double_extension_entries[:4])})"
        )
    if archive.nested_archives:
        features.append(ARCHIVE_NESTED)
        findings.append(
            f"Nested Archive Inside Archive ({', '.join(archive.nested_archives[:4])}) "
            "— Common Gateway-Evasion Layering"
        )

    # 6c. PDF documents that carry active content.
    for key, detail in zip(pdf.features, pdf.details):
        features.append(key)
        findings.append(f"PDF Risky Feature: {detail}")

    # 6d. Extension contradicting the file's own signature.
    mismatch = declared_type_mismatch(filename, att.true_type)
    if mismatch:
        features.append(TYPE_MISMATCH)
        findings.append(f"File Type Mismatch: {mismatch}")

    # 7. Suspicious Attachment Names
    fn_lower = filename.lower()
    high_risk_context = (
        is_exe or is_script or is_macro or is_double_ext
        or ext in {"zip", "iso", "img", "cab"}
        or bool(features)
    )
    for lure in LURE_KEYWORDS:
        if lure in fn_lower and high_risk_context:
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
    att.content_inspected = content_inspected
    att.risky_features = features

    return att


def _inspect_content(filename: str, data: bytes) -> tuple[ArchiveInspection, OleInspection, PdfInspection]:
    """Run the byte-level inspectors, tolerating any failure inside them.

    The inspectors are already written not to raise; this is the belt-and-braces
    guarantee that a malformed attachment can never abort an analysis.
    """
    if not data:
        return ArchiveInspection(), OleInspection(), PdfInspection()
    try:
        return inspect_archive(data), inspect_ole(data), inspect_pdf(data)
    except Exception as exc:  # defensive: content checks must never break analysis
        logger.warning(f"Content inspection of '{filename}' failed and was skipped: {exc}")
        return ArchiveInspection(), OleInspection(), PdfInspection()


def _infer_mime_from_true_type(true_type: str) -> str:
    mapping = {
        "exe": "application/x-dsexec",
        "elf": "application/x-executable",
        "pdf": "application/pdf",
        "zip/office": "application/zip",
        "jpg": "image/jpeg",
        "png": "image/png",
        "gif": "image/gif",
        "ps": "application/postscript",
        "ole/doc-xls-ppt": "application/x-ole-storage",
        "rtf": "application/rtf",
        "7z": "application/x-7z-compressed",
        "rar": "application/vnd.rar",
        "cab": "application/vnd.ms-cab-compressed",
        "lnk": "application/x-ms-shortcut",
    }
    return mapping.get(true_type, "application/octet-stream")


def _is_zip_encrypted(filename: str) -> bool:
    """Detect password-protected ZIPs via keyword matching with delimiter boundaries."""
    fn_lower = filename.lower()
    # Match encrypted/protected/password bounded by non-alphanumeric chars or underscores (e.g. passport.zip won't match 'pass')
    if re.search(r'(?:^|[_\W])(?:encrypted|protected|password)(?:[_\W]|$)', fn_lower):
        return True
    return False
