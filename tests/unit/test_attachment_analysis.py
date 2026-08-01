import unittest
import sys
import os
from email.message import EmailMessage

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../../src')))

from models import (
    Attachment, AuthVerdict, ParsedMessage, RoutingVerdict, set_attachment_content,
)
from attachment_analysis import analyze_attachments
from parsing import parse_message
from scoring import score_message
from attachment_content import (
    ARCHIVE_CONTAINS_EXECUTABLE, ARCHIVE_DOUBLE_EXTENSION_ENTRY, ARCHIVE_ENCRYPTED,
    ARCHIVE_NESTED, LEGACY_OFFICE_NO_MACRO, OFFICE_ENCRYPTED, OFFICE_VBA_MACRO,
    PDF_JAVASCRIPT, PDF_LAUNCH_ACTION, TYPE_MISMATCH,
)
from utils import file_extension, sniff_true_type

from test_attachment_content import mark_encrypted, ole_bytes, ooxml_bytes, zip_bytes


def analyse_one(filename: str, content: bytes = b"", true_type: str = None) -> Attachment:
    """Run the engine over a single attachment, with optional real bytes."""
    att = Attachment(
        filename=filename,
        declared_extension=file_extension(filename),
        true_type=true_type if true_type is not None else sniff_true_type(content),
        size_bytes=len(content),
    )
    if content:
        set_attachment_content(att, content)
    return analyze_attachments(ParsedMessage(attachments=[att]))[0]


class TestAttachmentAnalysis(unittest.TestCase):

    def test_executable_and_double_extension(self):
        att = Attachment(
            filename="invoice.pdf.exe",
            declared_extension="exe",
            true_type="exe",
            size_bytes=1024
        )
        parsed = ParsedMessage(attachments=[att])
        analyzed = analyze_attachments(parsed)
        self.assertEqual(len(analyzed), 1)
        res = analyzed[0]
        self.assertTrue(res.is_executable)
        self.assertTrue(res.has_double_extension)
        self.assertTrue(res.suspicious_name_flag)

    def test_macro_office_document(self):
        att = Attachment(
            filename="financial_report.xlsm",
            declared_extension="xlsm",
            true_type="zip/office",
            size_bytes=4096
        )
        parsed = ParsedMessage(attachments=[att])
        analyzed = analyze_attachments(parsed)
        res = analyzed[0]
        self.assertTrue(res.is_macro_enabled)

    def test_password_protected_archive(self):
        att = Attachment(
            filename="urgent_payment_encrypted.zip",
            declared_extension="zip",
            true_type="zip/office",
            size_bytes=2048
        )
        parsed = ParsedMessage(attachments=[att])
        analyzed = analyze_attachments(parsed)
        res = analyzed[0]
        self.assertTrue(res.is_password_protected)

    def test_windows_shortcut_is_flagged_as_a_launcher(self):
        res = analyse_one("Quote_2026.lnk", b"\x4c\x00\x00\x00\x01\x14\x02\x00" + b"\x00" * 32)
        self.assertTrue(res.is_script)
        self.assertIn("Shortcut", " ".join(res.findings))


class TestContentVerifiedArchives(unittest.TestCase):
    """Encryption and payload claims are read from the container, not the name."""

    def test_encrypted_archive_is_confirmed_from_the_encryption_flag(self):
        res = analyse_one("statement.zip", mark_encrypted(zip_bytes([("statement.pdf", "x" * 64)])))
        self.assertTrue(res.content_inspected)
        self.assertTrue(res.is_password_protected)
        self.assertIn(ARCHIVE_ENCRYPTED, res.risky_features)

    def test_filename_keyword_does_not_override_a_readable_archive(self):
        """'encrypted' in the name is not evidence once the flags are legible."""
        res = analyse_one("invoice_encrypted.zip", zip_bytes([("invoice.pdf", "x" * 64)]))
        self.assertTrue(res.content_inspected)
        self.assertFalse(res.is_password_protected)
        self.assertNotIn(ARCHIVE_ENCRYPTED, res.risky_features)

    def test_filename_heuristic_still_applies_without_bytes(self):
        res = analyse_one("invoice_encrypted.zip", b"", true_type="zip/office")
        self.assertFalse(res.content_inspected)
        self.assertTrue(res.is_password_protected)

    def test_archive_carrying_an_executable_is_flagged(self):
        res = analyse_one("invoice_2026.zip", zip_bytes([("quote.pdf.exe", "MZ" + "x" * 64)]))
        self.assertIn(ARCHIVE_CONTAINS_EXECUTABLE, res.risky_features)
        self.assertIn(ARCHIVE_DOUBLE_EXTENSION_ENTRY, res.risky_features)
        self.assertTrue(res.suspicious_name_flag)

    def test_nested_archive_is_flagged(self):
        res = analyse_one("files.zip", zip_bytes([("inner.zip", "PK\x03\x04")]))
        self.assertIn(ARCHIVE_NESTED, res.risky_features)

    def test_benign_archive_is_clean(self):
        res = analyse_one("photos.zip", zip_bytes([("holiday.jpg", "\xff\xd8\xff"), ("notes.txt", "hi")]))
        self.assertTrue(res.content_inspected)
        self.assertEqual(res.risky_features, [])
        self.assertFalse(res.is_password_protected)


class TestContentVerifiedOfficeDocuments(unittest.TestCase):

    def test_ordinary_docx_is_not_flagged(self):
        res = analyse_one("quarterly_report.docx", ooxml_bytes())
        self.assertTrue(res.content_inspected)
        self.assertFalse(res.is_macro_enabled)
        self.assertFalse(res.is_password_protected)
        self.assertEqual(res.risky_features, [])

    def test_vba_project_inside_ooxml_is_detected(self):
        res = analyse_one("payroll.docx", ooxml_bytes([("word/vbaProject.bin", "\x00macro")]))
        self.assertTrue(res.is_macro_enabled)
        self.assertIn(OFFICE_VBA_MACRO, res.risky_features)

    def test_legacy_document_with_a_vba_stream_is_detected(self):
        res = analyse_one("remittance.doc", ole_bytes("WordDocument", "_VBA_PROJECT"))
        self.assertTrue(res.is_macro_enabled)
        self.assertIn(OFFICE_VBA_MACRO, res.risky_features)

    def test_legacy_document_without_macros_is_no_longer_assumed_to_have_them(self):
        res = analyse_one("minutes.doc", ole_bytes("WordDocument", "1Table", "SummaryInformation"))
        self.assertTrue(res.content_inspected)
        self.assertFalse(res.is_macro_enabled)
        self.assertIn(LEGACY_OFFICE_NO_MACRO, res.risky_features)

    def test_legacy_extension_heuristic_survives_without_bytes(self):
        res = analyse_one("minutes.doc", b"", true_type="ole/doc-xls-ppt")
        self.assertFalse(res.content_inspected)
        self.assertTrue(res.is_macro_enabled)

    def test_password_protected_office_document_is_detected(self):
        res = analyse_one("payment_advice.xls", ole_bytes("EncryptionInfo", "EncryptedPackage"))
        self.assertTrue(res.is_password_protected)
        self.assertIn(OFFICE_ENCRYPTED, res.risky_features)


class TestContentVerifiedPdfs(unittest.TestCase):

    def test_pdf_with_javascript_is_flagged(self):
        data = b"%PDF-1.7\n1 0 obj<< /S /JavaScript /JS (app.alert\\(1\\)) >>endobj\n%%EOF"
        res = analyse_one("receipt.pdf", data)
        self.assertTrue(res.content_inspected)
        self.assertIn(PDF_JAVASCRIPT, res.risky_features)

    def test_pdf_with_launch_action_is_flagged(self):
        data = b"%PDF-1.4\n1 0 obj<< /S /Launch /F (cmd.exe) >>endobj\n%%EOF"
        res = analyse_one("scan.pdf", data)
        self.assertIn(PDF_LAUNCH_ACTION, res.risky_features)

    def test_ordinary_pdf_is_clean(self):
        data = b"%PDF-1.5\n1 0 obj<< /Type /Page /Subtype /Type1 >>endobj\ntrailer<<>>\n%%EOF"
        res = analyse_one("agenda.pdf", data)
        self.assertTrue(res.content_inspected)
        self.assertEqual(res.risky_features, [])


class TestDeclaredTypeMismatch(unittest.TestCase):

    def test_executable_masquerading_as_a_pdf(self):
        res = analyse_one("invoice.pdf", b"MZ\x90\x00" + b"\x00" * 64)
        self.assertIn(TYPE_MISMATCH, res.risky_features)
        self.assertTrue(res.is_executable)

    def test_matching_signature_is_silent(self):
        res = analyse_one("report.docx", ooxml_bytes())
        self.assertNotIn(TYPE_MISMATCH, res.risky_features)


class TestEndToEndThroughParsing(unittest.TestCase):
    """The decoded bytes must survive parsing and reach scoring as evidence."""

    def _message_with_attachment(self, filename, payload):
        message = EmailMessage()
        message["From"] = "Accounts <billing@vendor-example.com>"
        message["To"] = "ap@ourcompany.com"
        message["Subject"] = "Invoice attached"
        message.set_content("Please find the invoice attached.")
        message.add_attachment(payload, maintype="application", subtype="octet-stream",
                               filename=filename)
        return message

    def _analyse(self, filename, payload):
        parsed = parse_message(self._message_with_attachment(filename, payload))
        parsed.attachments = analyze_attachments(parsed)
        verdict = score_message(
            parsed,
            AuthVerdict(raw="", source="", spf="pass", dkim="pass", dmarc="pass"),
            RoutingVerdict(hop_count=2),
        )
        return parsed.attachments[0], verdict

    def test_encrypted_archive_reaches_scoring_as_verified_evidence(self):
        payload = mark_encrypted(zip_bytes([("invoice.pdf", "x" * 128)]))
        att, verdict = self._analyse("invoice_2026.zip", payload)
        self.assertTrue(att.content_inspected)
        self.assertIn(ARCHIVE_ENCRYPTED, att.risky_features)
        signal = next(s for s in verdict.signals if "Attachment" in s.indicator)
        self.assertGreaterEqual(signal.weight, 25)
        self.assertIn("encryption flag", signal.evidence)

    def test_benign_attachment_produces_no_attachment_signal(self):
        att, verdict = self._analyse("holiday_photos.zip", zip_bytes([("beach.jpg", "\xff\xd8\xff")]))
        self.assertTrue(att.content_inspected)
        self.assertEqual(att.risky_features, [])
        self.assertEqual([s for s in verdict.signals if "Attachment" in s.indicator], [])


class TestGracefulDegradation(unittest.TestCase):
    """Content inspection must never turn a bad attachment into an exception."""

    def test_truncated_and_corrupt_payloads_are_survivable(self):
        payloads = [
            b"",
            b"PK",
            b"PK\x03\x04" + os.urandom(24),
            b"%PDF-1.4" + os.urandom(64),
            b"\xd0\xcf\x11\xe0" + os.urandom(64),
            os.urandom(128),
        ]
        for payload in payloads:
            res = analyse_one("mystery.dat", payload, true_type="unknown")
            self.assertIsInstance(res.findings, list)
            self.assertIsInstance(res.risky_features, list)

    def test_content_bytes_never_leak_into_the_serialised_model(self):
        import dataclasses
        res = analyse_one("report.docx", ooxml_bytes())
        payload = dataclasses.asdict(res)
        self.assertNotIn("_content_bytes", payload)
        for value in payload.values():
            self.assertNotIsInstance(value, bytes)


if __name__ == '__main__':
    unittest.main()
