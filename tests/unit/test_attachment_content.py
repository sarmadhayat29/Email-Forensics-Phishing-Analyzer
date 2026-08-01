"""Byte-level attachment inspection.

Every fixture is synthesised in memory from a few dozen bytes: real archives
built with :mod:`zipfile`, minimal PDF bodies, and OLE containers reduced to the
magic number plus the stream names that matter. No binary sample files.
"""

import io
import os
import sys
import unittest
import zipfile

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../../src')))

from attachment_content import (
    PDF_EMBEDDED_FILE, PDF_JAVASCRIPT, PDF_LAUNCH_ACTION, PDF_OPEN_ACTION,
    declared_type_mismatch, inspect_archive, inspect_ole, inspect_pdf,
)

OLE_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"


def zip_bytes(entries) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, payload in entries:
            archive.writestr(name, payload)
    return buffer.getvalue()


def mark_encrypted(data: bytes) -> bytes:
    """Set the general-purpose encryption bit, as a password-protected zip does.

    The flag word sits at offset 6 of a local file header and offset 8 of a
    central-directory header.
    """
    out = bytearray(data)
    for signature, flag_offset in ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8)):
        index = out.find(signature)
        while index != -1:
            out[index + flag_offset] |= 0x01
            index = out.find(signature, index + 4)
    return bytes(out)


def ooxml_bytes(extra_entries=()) -> bytes:
    entries = [
        ("[Content_Types].xml", '<?xml version="1.0"?><Types/>'),
        ("_rels/.rels", "<Relationships/>"),
        ("word/document.xml", "<document>Quarterly report</document>"),
    ]
    entries.extend(extra_entries)
    return zip_bytes(entries)


def ole_bytes(*stream_names: str) -> bytes:
    """A stub compound file: the real magic plus UTF-16LE directory names."""
    body = b"".join(name.encode("utf-16-le") + b"\x00\x00" for name in stream_names)
    return OLE_MAGIC + b"\x00" * 24 + body + b"\x00" * 16


class TestArchiveInspection(unittest.TestCase):

    def test_plain_archive_is_not_reported_as_encrypted(self):
        result = inspect_archive(zip_bytes([("notes.txt", "hello")]))
        self.assertTrue(result.is_zip)
        self.assertTrue(result.inspected)
        self.assertFalse(result.encrypted)
        self.assertEqual(result.entry_names, ["notes.txt"])
        self.assertEqual(result.source, "central-directory")

    def test_encryption_flag_is_read_from_the_container(self):
        result = inspect_archive(mark_encrypted(zip_bytes([("payload.bin", "x" * 64)])))
        self.assertTrue(result.encrypted)
        self.assertEqual(result.encrypted_entries, ["payload.bin"])

    def test_ooxml_document_is_not_mistaken_for_an_encrypted_archive(self):
        """A .docx is a PK zip; it must never read as a protected archive."""
        result = inspect_archive(ooxml_bytes())
        self.assertTrue(result.is_ooxml)
        self.assertFalse(result.encrypted)
        self.assertFalse(result.has_vba_project)
        self.assertEqual(result.risky_entries, [])
        self.assertEqual(result.nested_archives, [])

    def test_ooxml_internals_are_never_treated_as_user_files(self):
        """Office parts are plumbing, so they are not classified as payloads."""
        result = inspect_archive(ooxml_bytes([("word/embeddings/oleObject1.bin", "x")]))
        self.assertTrue(result.is_ooxml)
        self.assertEqual(result.risky_entries, [])

    def test_vba_project_entry_is_detected(self):
        result = inspect_archive(ooxml_bytes([("word/vbaProject.bin", "\x00\x01macro")]))
        self.assertTrue(result.has_vba_project)

    def test_executable_entry_is_detected_by_name_inside_the_archive(self):
        result = inspect_archive(zip_bytes([("readme.txt", "hi"), ("invoice.pdf.exe", "MZ")]))
        self.assertIn("invoice.pdf.exe", result.risky_entries)
        self.assertIn("invoice.pdf.exe", result.double_extension_entries)

    def test_shortcut_entry_is_detected(self):
        result = inspect_archive(zip_bytes([("Quote_2026.lnk", "x")]))
        self.assertEqual(result.risky_entries, ["Quote_2026.lnk"])

    def test_nested_archive_is_detected(self):
        result = inspect_archive(zip_bytes([("documents.zip", "PK\x03\x04")]))
        self.assertEqual(result.nested_archives, ["documents.zip"])

    def test_entries_in_subdirectories_are_classified_by_basename(self):
        result = inspect_archive(zip_bytes([("attachments/run.js", "alert(1)")]))
        self.assertEqual(result.risky_entries, ["run.js"])

    def test_truncated_archive_falls_back_to_local_headers(self):
        """Mail truncation destroys the central directory, not the flags."""
        data = mark_encrypted(zip_bytes([("payload.exe", "MZ" + "x" * 200)]))
        truncated = data[:len(data) // 2]
        result = inspect_archive(truncated)
        self.assertEqual(result.source, "local-headers")
        self.assertTrue(result.inspected)
        self.assertTrue(result.encrypted)
        self.assertIn("payload.exe", result.risky_entries)

    def test_unreadable_container_reports_nothing_rather_than_guessing(self):
        result = inspect_archive(b"PK" + os.urandom(48))
        self.assertTrue(result.is_zip)
        self.assertFalse(result.inspected)
        self.assertFalse(result.encrypted)
        self.assertIn("could not be read", result.detail)

    def test_non_zip_input_is_ignored(self):
        for data in (b"", b"%PDF-1.4", OLE_MAGIC):
            result = inspect_archive(data)
            self.assertFalse(result.is_zip)
            self.assertFalse(result.inspected)


class TestOleInspection(unittest.TestCase):

    def test_vba_project_stream_means_macros(self):
        result = inspect_ole(ole_bytes("WordDocument", "_VBA_PROJECT"))
        self.assertTrue(result.is_ole)
        self.assertTrue(result.inspected)
        self.assertTrue(result.has_macros)
        self.assertIn("_VBA_PROJECT", result.macro_streams)

    def test_ordinary_document_reports_no_macros(self):
        result = inspect_ole(ole_bytes("WordDocument", "1Table", "SummaryInformation"))
        self.assertTrue(result.inspected)
        self.assertFalse(result.has_macros)

    def test_document_merely_discussing_macros_is_not_flagged(self):
        """Word stores body text as UTF-16 too, so prose must not match."""
        prose = "Please enable Macros and VBA support before running the report."
        result = inspect_ole(ole_bytes("WordDocument") + prose.encode("utf-16-le"))
        self.assertTrue(result.inspected)
        self.assertFalse(result.has_macros)

    def test_encrypted_office_package_is_detected(self):
        result = inspect_ole(ole_bytes("EncryptionInfo", "EncryptedPackage"))
        self.assertTrue(result.encrypted)

    def test_unreadable_container_is_reported_as_unknown(self):
        result = inspect_ole(OLE_MAGIC + b"\x00" * 64)
        self.assertTrue(result.is_ole)
        self.assertFalse(result.inspected)
        self.assertFalse(result.has_macros)

    def test_non_ole_input_is_ignored(self):
        for data in (b"", b"%PDF-1.4", b"PK\x03\x04"):
            self.assertFalse(inspect_ole(data).is_ole)


class TestPdfInspection(unittest.TestCase):

    def test_javascript_and_open_action_are_detected(self):
        data = (b"%PDF-1.7\n1 0 obj<< /Type /Catalog /OpenAction 2 0 R >>endobj\n"
                b"2 0 obj<< /S /JavaScript /JS (app.alert\\(1\\)) >>endobj\n%%EOF")
        result = inspect_pdf(data)
        self.assertTrue(result.inspected)
        self.assertIn(PDF_JAVASCRIPT, result.features)
        self.assertIn(PDF_OPEN_ACTION, result.features)

    def test_launch_and_embedded_file_are_detected(self):
        data = (b"%PDF-1.4\n3 0 obj<< /S /Launch /F (cmd.exe) >>endobj\n"
                b"4 0 obj<< /Type /Filespec /EF << /F 5 0 R >> /EmbeddedFile >>endobj\n%%EOF")
        result = inspect_pdf(data)
        self.assertIn(PDF_LAUNCH_ACTION, result.features)
        self.assertIn(PDF_EMBEDDED_FILE, result.features)

    def test_ordinary_pdf_reports_no_risky_features(self):
        data = (b"%PDF-1.5\n1 0 obj<< /Type /Page /Subtype /Type1 /Font 2 0 R >>endobj\n"
                b"trailer<< /Root 1 0 R >>\n%%EOF")
        result = inspect_pdf(data)
        self.assertTrue(result.inspected)
        self.assertEqual(result.features, [])

    def test_js_prefix_inside_another_name_does_not_match(self):
        """'/JSubtype' or '/JScriptless' are not JavaScript actions."""
        data = b"%PDF-1.5\n1 0 obj<< /JSubtype /None /JScriptless true >>endobj\n%%EOF"
        self.assertEqual(inspect_pdf(data).features, [])

    def test_non_pdf_input_is_ignored(self):
        for data in (b"", b"PK\x03\x04", b"/JavaScript /OpenAction /Launch"):
            result = inspect_pdf(data)
            self.assertFalse(result.is_pdf)
            self.assertEqual(result.features, [])


class TestDeclaredTypeMismatch(unittest.TestCase):

    def test_extension_contradicting_the_signature_is_reported(self):
        reason = declared_type_mismatch("invoice.pdf", "exe")
        self.assertIsNotNone(reason)
        self.assertIn("exe", reason)

    def test_legitimate_combinations_are_silent(self):
        for filename, true_type in (
            ("report.docx", "zip/office"),
            ("report.doc", "ole/doc-xls-ppt"),
            ("legacy.doc", "rtf"),          # Word opens RTF saved as .doc
            ("scan.pdf", "pdf"),
            ("photo.jpeg", "jpg"),
            ("archive.zip", "zip/office"),
        ):
            self.assertIsNone(declared_type_mismatch(filename, true_type), filename)

    def test_unknown_signature_is_never_a_mismatch(self):
        self.assertIsNone(declared_type_mismatch("scan.pdf", "unknown"))
        self.assertIsNone(declared_type_mismatch("scan.pdf", ""))

    def test_unlisted_extension_is_not_checked(self):
        self.assertIsNone(declared_type_mismatch("payload.bin", "exe"))


if __name__ == "__main__":
    unittest.main()
