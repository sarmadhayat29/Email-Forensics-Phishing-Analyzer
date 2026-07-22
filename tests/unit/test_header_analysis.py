import unittest
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../../src')))

from models import ParsedMessage
from header_analysis import analyze_headers


class TestHeaderAnalysis(unittest.TestCase):

    def test_clean_headers_no_findings(self):
        parsed = ParsedMessage(
            from_raw="John Doe <john@company.com>",
            to_raw="jane@company.com",
            subject="Meeting Agenda",
            date="Wed, 22 Jul 2026 10:00:00 +0000",
            message_id="<msg12345@company.com>",
            headers={
                "From": "John Doe <john@company.com>",
                "To": "jane@company.com",
                "Subject": "Meeting Agenda",
                "Date": "Wed, 22 Jul 2026 10:00:00 +0000",
                "Message-ID": "<msg12345@company.com>"
            }
        )
        verdict = analyze_headers(parsed)
        self.assertEqual(len(verdict.findings), 0)

    def test_display_name_spoofing(self):
        parsed = ParsedMessage(
            from_raw="PayPal Support <hacker@evil-domain.com>",
            to_raw="victim@company.com",
            subject="Account Suspended",
            date="Wed, 22 Jul 2026 10:00:00 +0000",
            message_id="<msg999@evil-domain.com>",
            headers={
                "From": "PayPal Support <hacker@evil-domain.com>",
                "To": "victim@company.com",
                "Subject": "Account Suspended",
                "Date": "Wed, 22 Jul 2026 10:00:00 +0000",
                "Message-ID": "<msg999@evil-domain.com>"
            }
        )
        verdict = analyze_headers(parsed)
        titles = [f.title for f in verdict.findings]
        self.assertIn("Display Name Brand Impersonation", titles)

    def test_from_vs_reply_to_mismatch(self):
        parsed = ParsedMessage(
            from_raw="CEO <ceo@company.com>",
            reply_to_raw="attacker@phish.com",
            subject="Urgent Transfer",
            date="Wed, 22 Jul 2026 10:00:00 +0000",
            message_id="<msg555@company.com>",
            headers={
                "From": "CEO <ceo@company.com>",
                "Reply-To": "attacker@phish.com",
                "Subject": "Urgent Transfer",
                "Date": "Wed, 22 Jul 2026 10:00:00 +0000",
                "Message-ID": "<msg555@company.com>"
            }
        )
        verdict = analyze_headers(parsed)
        titles = [f.title for f in verdict.findings]
        self.assertIn("From vs. Reply-To Mismatch", titles)

    def test_missing_message_id_and_mandatory_headers(self):
        parsed = ParsedMessage(
            from_raw="spammer@bad.com",
            headers={
                "From": "spammer@bad.com"
            }
        )
        verdict = analyze_headers(parsed)
        titles = [f.title for f in verdict.findings]
        self.assertIn("Missing Message-ID Header", titles)
        self.assertIn("Missing Mandatory Email Headers", titles)

    def test_suspicious_message_id_format(self):
        parsed = ParsedMessage(
            from_raw="sender@test.com",
            subject="Hello",
            date="Wed, 22 Jul 2026 10:00:00 +0000",
            message_id="invalid-message-id-format",
            headers={
                "From": "sender@test.com",
                "Subject": "Hello",
                "Date": "Wed, 22 Jul 2026 10:00:00 +0000",
                "Message-ID": "invalid-message-id-format"
            }
        )
        verdict = analyze_headers(parsed)
        titles = [f.title for f in verdict.findings]
        self.assertIn("Suspicious Message-ID Format", titles)

    def test_suspicious_x_header(self):
        parsed = ParsedMessage(
            from_raw="sender@test.com",
            subject="Hello",
            date="Wed, 22 Jul 2026 10:00:00 +0000",
            message_id="<123@test.com>",
            headers={
                "From": "sender@test.com",
                "Subject": "Hello",
                "Date": "Wed, 22 Jul 2026 10:00:00 +0000",
                "Message-ID": "<123@test.com>",
                "X-Mailer": "PHPMailer 5.2",
                "X-PHP-Originating-Script": "1000:evil.php"
            }
        )
        verdict = analyze_headers(parsed)
        titles = [f.title for f in verdict.findings]
        self.assertIn("Suspicious X-Headers Detected", titles)

    def test_high_risk_tld(self):
        parsed = ParsedMessage(
            from_raw="spammer@cheap-deals.xyz",
            subject="Buy now",
            date="Wed, 22 Jul 2026 10:00:00 +0000",
            message_id="<123@cheap-deals.xyz>",
            headers={
                "From": "spammer@cheap-deals.xyz",
                "Subject": "Buy now",
                "Date": "Wed, 22 Jul 2026 10:00:00 +0000",
                "Message-ID": "<123@cheap-deals.xyz>"
            }
        )
        verdict = analyze_headers(parsed)
        titles = [f.title for f in verdict.findings]
        self.assertIn("High-Risk Top-Level Domain (TLD)", titles)


if __name__ == '__main__':
    unittest.main()
