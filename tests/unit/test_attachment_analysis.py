import unittest
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../../src')))

from models import ParsedMessage, Attachment
from attachment_analysis import analyze_attachments


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


if __name__ == '__main__':
    unittest.main()
