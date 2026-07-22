import unittest
from email.message import EmailMessage
from email import policy

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../../src')))

from parsing import parse_message
from models import ParsedMessage


class TestParsing(unittest.TestCase):
    def test_parse_simple_text_message(self):
        msg = EmailMessage(policy=policy.default)
        msg['Subject'] = 'Test Subject'
        msg['From'] = 'sender@example.com'
        msg['To'] = 'receiver@example.com'
        msg['Cc'] = 'cc@example.com'
        msg['Bcc'] = 'bcc@example.com'
        msg['Sender'] = 'real-sender@example.com'
        msg.set_content("Hello World")

        parsed = parse_message(msg)

        self.assertIsInstance(parsed, ParsedMessage)
        self.assertEqual(parsed.subject, "Test Subject")
        self.assertEqual(parsed.from_raw, "sender@example.com")
        self.assertEqual(parsed.cc_raw, "cc@example.com")
        self.assertEqual(parsed.bcc_raw, "bcc@example.com")
        self.assertEqual(parsed.sender_raw, "real-sender@example.com")
        self.assertEqual(parsed.body_plain.strip(), "Hello World")
        self.assertEqual(parsed.body_html, "")
        self.assertEqual(len(parsed.attachments), 0)
        self.assertEqual(len(parsed.embedded_images), 0)
        self.assertIn("text/plain", parsed.mime_structure)

    def test_parse_multipart_with_attachment_and_inline_image(self):
        msg = EmailMessage(policy=policy.default)
        msg['Subject'] = 'Test Attachment'
        msg['From'] = 'sender@example.com'
        msg['To'] = 'receiver@example.com'
        msg.set_content("Body content")
        
        # Add a fake PDF attachment
        msg.add_attachment(b"%PDF-1.4...", maintype='application', subtype='pdf', filename='test.pdf')
        
        # Add a fake inline image
        msg.add_attachment(b"\x89PNG...", maintype='image', subtype='png', filename='image.png')
        payload = msg.get_payload()
        payload[-1].add_header('Content-ID', '<img123>')
        payload[-1].replace_header('Content-Disposition', 'inline; filename="image.png"')

        parsed = parse_message(msg)

        self.assertEqual(parsed.body_plain.strip(), "Body content")
        
        self.assertEqual(len(parsed.attachments), 1)
        att = parsed.attachments[0]
        self.assertEqual(att.filename, "test.pdf")
        self.assertEqual(att.declared_extension, "pdf")
        self.assertEqual(att.true_type, "pdf")
        
        self.assertEqual(len(parsed.embedded_images), 1)
        img = parsed.embedded_images[0]
        self.assertEqual(img.filename, "image.png")
        self.assertEqual(img.content_id, "<img123>")
        self.assertEqual(img.true_type, "png")

if __name__ == '__main__':
    unittest.main()

