"""Byte-level attachment content inspection.

Filename and extension heuristics are the easiest part of an attachment to
forge: an attacker renames ``payload.js`` to ``invoice_2026.zip`` and a
name-only engine is blind. The inspectors here read the bytes instead:

* **Archives** — the ZIP general-purpose bit flag says whether an entry is
  encrypted, and the entry names say what the archive actually carries. Both
  are read from the container itself, so ``quote.zip`` holding ``quote.pdf.lnk``
  is caught while an ordinary ``.docx`` (also a PK zip) is not mistaken for an
  encrypted archive.
* **Office documents** — a VBA project is a named stream (legacy OLE) or a zip
  entry (OOXML). Presence of that stream is macro *evidence*, as opposed to the
  extension-based guess that every legacy ``.doc`` carries macros.
* **PDFs** — the risky feature set (embedded JavaScript, automatic actions,
  ``/Launch``, embedded files) appears as PDF name objects in the file body.

Three rules hold throughout, mirroring :mod:`domain_age` and :mod:`live_auth`:

1. **Never raise.** Every inspector returns a result object; a truncated,
   corrupt or unsupported file yields "not inspected", which scoring reads as
   "no information" rather than as an accusation.
2. **Bounded work.** Entry counts and scan windows are capped so a zip bomb or
   a 15 MB PDF cannot stall an analysis.
3. **No hard new dependency.** ``olefile`` is used when importable (it usually
   is, as a transitive dependency of ``extract-msg``) and a UTF-16 directory
   scan of the raw container is used when it is not.
"""

import io
import re
import struct
import zipfile
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

from utils import RISKY_EXTENSIONS, file_extension, has_double_extension
from logger import get_logger

logger = get_logger(__name__)

#: A hostile archive can declare tens of thousands of entries; only the first
#: few hundred are ever needed to decide whether it is dangerous.
MAX_ARCHIVE_ENTRIES = 300

#: Upper bound on the bytes any string/regex scan reads. Large enough to cover
#: the trailer of a normal document, small enough to keep the worst case cheap.
MAX_SCAN_BYTES = 4 * 1024 * 1024

_LOCAL_FILE_HEADER = b"PK\x03\x04"
_OOXML_MARKER = "[content_types].xml"

#: Archive extensions that are themselves containers. One archive nested inside
#: another is a long-standing way to slip a payload past scanning gateways.
NESTED_ARCHIVE_EXTENSIONS = {"zip", "rar", "7z", "gz", "bz2", "xz", "tar", "cab",
                            "iso", "img", "arj", "lzh", "ace"}

# Machine keys for content-verified observations. Scoring maps these onto
# weights; reports render the human-readable finding text instead.
ARCHIVE_ENCRYPTED = "archive_encrypted"
ARCHIVE_CONTAINS_EXECUTABLE = "archive_contains_executable"
ARCHIVE_NESTED = "archive_nested"
ARCHIVE_DOUBLE_EXTENSION_ENTRY = "archive_double_extension_entry"
OFFICE_VBA_MACRO = "office_vba_macro"
OFFICE_ENCRYPTED = "office_encrypted"
PDF_JAVASCRIPT = "pdf_javascript"
PDF_OPEN_ACTION = "pdf_open_action"
PDF_LAUNCH_ACTION = "pdf_launch_action"
PDF_EMBEDDED_FILE = "pdf_embedded_file"
TYPE_MISMATCH = "type_mismatch"
LEGACY_OFFICE_NO_MACRO = "legacy_office_no_macro"


# --------------------------------------------------------------------------- #
# Archives (the ZIP family, which includes every OOXML Office document)
# --------------------------------------------------------------------------- #


@dataclass
class ArchiveInspection:
    """What the bytes of a PK-zip container actually contain."""

    is_zip: bool = False
    #: True when at least one entry could be read, by either strategy.
    inspected: bool = False
    #: True when an entry sets a general-purpose encryption bit flag.
    encrypted: bool = False
    encrypted_entries: List[str] = field(default_factory=list)
    entry_names: List[str] = field(default_factory=list)
    #: True for Office Open XML packages (docx/xlsx/pptx and their macro
    #: variants), which are zips but must never be read as user archives.
    is_ooxml: bool = False
    has_vba_project: bool = False
    risky_entries: List[str] = field(default_factory=list)
    nested_archives: List[str] = field(default_factory=list)
    double_extension_entries: List[str] = field(default_factory=list)
    #: How the container was read: "central-directory", "local-headers" or "".
    source: str = ""
    detail: str = ""


def inspect_archive(data: bytes) -> ArchiveInspection:
    """Read encryption flags and entry names out of a PK-zip container."""
    result = ArchiveInspection()
    if not data or not data.startswith(b"PK"):
        return result
    result.is_zip = True

    entries = _entries_from_central_directory(data)
    if entries:
        result.source = "central-directory"
    else:
        # A mail-truncated or subtly corrupt archive defeats zipfile entirely,
        # so fall back to walking the local file headers by hand: the flag word
        # sits at a fixed offset in every header, which is all that encryption
        # detection needs.
        entries = _entries_from_local_headers(data)
        if entries:
            result.source = "local-headers"

    if not entries:
        result.detail = ("The archive could not be read (truncated, corrupt, "
                         "or an unsupported variant).")
        return result

    result.inspected = True
    for name, flags in entries:
        result.entry_names.append(name)
        lowered = name.lower()
        if lowered.endswith(_OOXML_MARKER):
            result.is_ooxml = True
        if lowered.endswith("vbaproject.bin"):
            result.has_vba_project = True
        # Bit 0 marks a password-protected entry; bit 6 marks the strong /
        # AES-encrypted variants. Directory entries never set either.
        if flags & 0x1 or flags & 0x40:
            result.encrypted = True
            if name and name not in result.encrypted_entries:
                result.encrypted_entries.append(name)

    _classify_entries(result)
    return result


def _classify_entries(result: ArchiveInspection) -> None:
    """Sort entry names into the risky / nested / masked buckets.

    Skipped for OOXML packages: the parts of a ``.docx`` are internal plumbing,
    not files a user was sent, and naming rules there differ entirely.
    """
    if result.is_ooxml:
        return

    for name in result.entry_names:
        base = name.replace("\\", "/").rsplit("/", 1)[-1]
        if not base:
            continue  # directory entry
        extension = file_extension(base)
        if extension in RISKY_EXTENSIONS and base not in result.risky_entries:
            result.risky_entries.append(base)
        if extension in NESTED_ARCHIVE_EXTENSIONS and base not in result.nested_archives:
            result.nested_archives.append(base)
        if has_double_extension(base) and base not in result.double_extension_entries:
            result.double_extension_entries.append(base)


def _entries_from_central_directory(data: bytes) -> List[Tuple[str, int]]:
    """``(name, flag_bits)`` per entry, read through :mod:`zipfile`."""
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            return [
                (info.filename or "", int(getattr(info, "flag_bits", 0) or 0))
                for info in archive.infolist()[:MAX_ARCHIVE_ENTRIES]
            ]
    except Exception as exc:  # BadZipFile, truncation, unsupported variant, ...
        logger.debug(f"ZIP central directory unreadable: {type(exc).__name__}: {exc}")
        return []


def _entries_from_local_headers(data: bytes) -> List[Tuple[str, int]]:
    """``(name, flag_bits)`` per entry, by scanning local file headers.

    Only used when the central directory is unreadable. Headers with an
    implausible filename are skipped rather than guessed at, so a ``PK\\x03\\x04``
    byte sequence inside stored data does not invent an entry.
    """
    entries: List[Tuple[str, int]] = []
    offset = data.find(_LOCAL_FILE_HEADER)
    while offset != -1 and len(entries) < MAX_ARCHIVE_ENTRIES:
        if offset + 30 > len(data):
            break
        try:
            flags = struct.unpack_from("<H", data, offset + 6)[0]
            name_length = struct.unpack_from("<H", data, offset + 26)[0]
        except struct.error:
            break
        name = ""
        if 0 < name_length <= 512 and offset + 30 + name_length <= len(data):
            raw_name = data[offset + 30:offset + 30 + name_length]
            try:
                name = raw_name.decode("utf-8")
            except UnicodeDecodeError:
                name = raw_name.decode("latin-1", errors="replace")
        if name and name.isprintable():
            entries.append((name, int(flags)))
        offset = data.find(_LOCAL_FILE_HEADER, offset + 4)
    return entries


# --------------------------------------------------------------------------- #
# Legacy Office (OLE / Compound File Binary) containers
# --------------------------------------------------------------------------- #


@dataclass
class OleInspection:
    """Macro and encryption evidence from an OLE compound-file container."""

    is_ole: bool = False
    inspected: bool = False
    has_macros: bool = False
    #: True for an OOXML package wrapped in OLE encryption (``EncryptedPackage``),
    #: which is how a password-protected .docx/.xlsx is actually stored.
    encrypted: bool = False
    macro_streams: List[str] = field(default_factory=list)
    #: "olefile" or "raw-directory-scan".
    source: str = ""
    detail: str = ""


_OLE_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"

#: Directory-entry names that only exist when a VBA project is stored. Matched
#: against the entry names ``olefile`` reports, which are authoritative.
_VBA_STREAM_NAMES = ("VBA", "_VBA_PROJECT", "_VBA_PROJECT_CUR", "Macros", "vbaProject.bin")

#: The subset safe to search for in the raw container. Names in a compound file
#: are UTF-16LE — and so is the *text* of a Word document, so a bare "Macros" or
#: "VBA" would match a document merely discussing them. Only names too
#: distinctive to occur in prose are used here.
_VBA_RAW_MARKERS = ("_VBA_PROJECT", "_VBA_PROJECT_CUR", "vbaProject.bin")

#: Present only when the real payload is an encrypted OOXML package.
_ENCRYPTED_PACKAGE_NAMES = ("EncryptedPackage", "EncryptionInfo")

#: Streams every ordinary Office document has. Finding one proves the container's
#: directory was legible, which is what lets "no VBA project here" be reported as
#: a finding rather than as an unknown.
_OFFICE_STREAM_NAMES = ("WordDocument", "Workbook", "PowerPoint Document",
                        "SummaryInformation", "1Table")


def inspect_ole(data: bytes) -> OleInspection:
    """Look for a VBA project (or OLE-wrapped encryption) inside a CFB file."""
    result = OleInspection()
    if not data or not data.startswith(_OLE_MAGIC[:4]):
        return result
    result.is_ole = True

    names = _ole_names_via_olefile(data)
    if names is not None:
        result.source = "olefile"
    else:
        names = _ole_names_via_raw_scan(data)
        if names:
            result.source = "raw-directory-scan"

    if not names:
        result.detail = ("The OLE container's directory could not be read, so macro "
                         "presence is unknown.")
        return result

    result.inspected = True
    lowered = {name.lower(): name for name in names}
    for candidate in _VBA_STREAM_NAMES:
        match = lowered.get(candidate.lower())
        if match and match not in result.macro_streams:
            result.macro_streams.append(match)
    result.has_macros = bool(result.macro_streams)
    result.encrypted = any(candidate.lower() in lowered for candidate in _ENCRYPTED_PACKAGE_NAMES)
    return result


def _ole_names_via_olefile(data: bytes) -> Optional[List[str]]:
    """Directory entry names via ``olefile``, or ``None`` when unavailable.

    ``None`` distinguishes "the library is missing or gave up" from "the
    container genuinely holds no entries", so the caller can fall back.
    """
    try:
        import olefile  # type: ignore
    except Exception:  # not installed, or a broken install
        return None

    try:
        with olefile.OleFileIO(io.BytesIO(data)) as container:
            names: List[str] = []
            for entry in container.listdir(streams=True, storages=True):
                names.extend(str(part) for part in entry if part)
            return names or None
    except Exception as exc:  # not an OLE file after all, truncated, ...
        logger.debug(f"olefile could not read container: {type(exc).__name__}: {exc}")
        return None


def _ole_names_via_raw_scan(data: bytes) -> List[str]:
    """Names found by searching the raw container for UTF-16LE stream names."""
    window = data[:MAX_SCAN_BYTES]
    found: List[str] = []
    for name in _VBA_RAW_MARKERS + _ENCRYPTED_PACKAGE_NAMES + _OFFICE_STREAM_NAMES:
        if name.encode("utf-16-le") in window:
            found.append(name)
    return found


# --------------------------------------------------------------------------- #
# PDF risky features
# --------------------------------------------------------------------------- #


@dataclass
class PdfInspection:
    is_pdf: bool = False
    inspected: bool = False
    #: Machine keys of the risky features present, e.g. ``pdf_javascript``.
    features: List[str] = field(default_factory=list)
    #: Human-readable one-liner per feature, in the same order.
    details: List[str] = field(default_factory=list)


# Each pattern anchors on a PDF *name object*, and the delimiter class after
# the token is what keeps false positives down: '/JS' is only accepted when a
# value follows it (a dictionary, string, array or indirect reference), so the
# letters "/JS" inside a compressed stream or a font name are ignored.
_PDF_FEATURE_PATTERNS = [
    (PDF_JAVASCRIPT, re.compile(rb"/JavaScript[\s/<\[(\]>]|/JS\s*[<\[(/\d]"),
     "Embedded JavaScript (/JS or /JavaScript action)"),
    (PDF_OPEN_ACTION, re.compile(rb"/OpenAction[\s/<\[(\d]"),
     "Automatic action on open (/OpenAction)"),
    (PDF_LAUNCH_ACTION, re.compile(rb"/Launch[\s/<\[(\d]"),
     "External program launch action (/Launch)"),
    (PDF_EMBEDDED_FILE, re.compile(rb"/EmbeddedFile[s]?[\s/<\[(\d]"),
     "Embedded file payload (/EmbeddedFile)"),
]


def inspect_pdf(data: bytes) -> PdfInspection:
    """Scan PDF bytes for the features malicious documents rely on."""
    result = PdfInspection()
    if not data:
        return result
    header_window = data[:1024]
    if not (data.startswith(b"%PDF") or b"%PDF-" in header_window):
        return result

    result.is_pdf = True
    result.inspected = True
    window = data[:MAX_SCAN_BYTES]
    for key, pattern, description in _PDF_FEATURE_PATTERNS:
        match = pattern.search(window)
        if match:
            result.features.append(key)
            result.details.append(description)
    return result


# --------------------------------------------------------------------------- #
# Declared type vs. actual signature
# --------------------------------------------------------------------------- #


#: Signatures an extension is allowed to carry. An extension absent from the
#: table is never checked, and ``unknown`` (no signature matched) is always
#: allowed, so only a *contradiction* between name and bytes is reported.
EXPECTED_SIGNATURES: dict[str, set[str]] = {
    "pdf": {"pdf"},
    "docx": {"zip/office"},
    "xlsx": {"zip/office"},
    "pptx": {"zip/office"},
    "docm": {"zip/office"},
    "xlsm": {"zip/office"},
    "pptm": {"zip/office"},
    "doc": {"ole/doc-xls-ppt", "rtf", "zip/office"},
    "xls": {"ole/doc-xls-ppt", "zip/office"},
    "ppt": {"ole/doc-xls-ppt", "zip/office"},
    "rtf": {"rtf", "ole/doc-xls-ppt"},
    "jpg": {"jpg"},
    "jpeg": {"jpg"},
    "png": {"png"},
    "gif": {"gif"},
    "zip": {"zip/office"},
    "7z": {"7z"},
    "rar": {"rar"},
}


def declared_type_mismatch(filename: str, true_type: str) -> Optional[str]:
    """Explain a contradiction between an extension and the file's signature.

    Returns ``None`` when the extension is unlisted, when no signature could be
    read, or when the signature is one the extension legitimately carries.
    """
    extension = file_extension(filename or "")
    allowed = EXPECTED_SIGNATURES.get(extension)
    if not allowed:
        return None
    if not true_type or true_type == "unknown":
        return None
    if true_type in allowed:
        return None
    return (f"Declared as '.{extension}' but the file signature is '{true_type}' "
            f"— the extension misrepresents the real file type.")
