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

    def test_from_vs_reply_to_unrelated_is_difference_not_high(self):
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
        by_title = {f.title: f for f in verdict.findings}
        self.assertIn("From vs. Reply-To Domain Difference", by_title)
        self.assertEqual(by_title["From vs. Reply-To Domain Difference"].risk_level, "Medium")

    def test_same_org_reply_to_not_flagged(self):
        parsed = ParsedMessage(
            from_raw="noreply@company.com",
            reply_to_raw="support@company.com",
            message_id="<m@company.com>",
            headers={"From": "noreply@company.com", "Reply-To": "support@company.com",
                     "Message-ID": "<m@company.com>"},
        )
        titles = [f.title for f in analyze_headers(parsed).findings]
        self.assertTrue(all("Reply-To" not in t for t in titles))

    def test_subdomain_org_reply_to_not_flagged(self):
        parsed = ParsedMessage(
            from_raw="admissions@giki.edu.pk",
            reply_to_raw="studentservices@portal.giki.edu.pk",
            message_id="<m@giki.edu.pk>",
            headers={"From": "admissions@giki.edu.pk",
                     "Reply-To": "studentservices@portal.giki.edu.pk",
                     "Message-ID": "<m@giki.edu.pk>"},
        )
        titles = [f.title for f in analyze_headers(parsed).findings]
        self.assertTrue(all("Reply-To" not in t for t in titles))

    def test_zendesk_esp_reply_to_not_flagged(self):
        parsed = ParsedMessage(
            from_raw="noreply@company.com",
            reply_to_raw="support@company.zendesk.com",
            message_id="<m@company.com>",
            headers={"From": "noreply@company.com",
                     "Reply-To": "support@company.zendesk.com",
                     "Message-ID": "<m@company.com>"},
        )
        titles = [f.title for f in analyze_headers(parsed).findings]
        self.assertTrue(all("Reply-To" not in t for t in titles))

    def test_brand_to_gmail_reply_to_is_high(self):
        parsed = ParsedMessage(
            from_raw="security@paypal.com",
            reply_to_raw="random@gmail.com",
            message_id="<m@paypal.com>",
            headers={"From": "security@paypal.com", "Reply-To": "random@gmail.com",
                     "Message-ID": "<m@paypal.com>"},
        )
        by_title = {f.title: f for f in analyze_headers(parsed).findings}
        self.assertIn("Suspicious Reply-To Destination", by_title)
        self.assertEqual(by_title["Suspicious Reply-To Destination"].risk_level, "High")

    def test_brand_to_high_risk_tld_reply_to_is_high(self):
        parsed = ParsedMessage(
            from_raw="account@microsoft.com",
            reply_to_raw="help@account-security.xyz",
            message_id="<m@microsoft.com>",
            headers={"From": "account@microsoft.com",
                     "Reply-To": "help@account-security.xyz",
                     "Message-ID": "<m@microsoft.com>"},
        )
        by_title = {f.title: f for f in analyze_headers(parsed).findings}
        self.assertIn("Suspicious Reply-To Destination", by_title)
        self.assertEqual(by_title["Suspicious Reply-To Destination"].risk_level, "High")

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

    def test_pineapple_display_name_is_not_apple_impersonation(self):
        parsed = ParsedMessage(
            from_raw="Pineapple Corp <sales@fruit.example>",
            message_id="<m@fruit.example>",
            headers={"From": "Pineapple Corp <sales@fruit.example>", "Message-ID": "<m@fruit.example>"},
        )
        titles = [f.title for f in analyze_headers(parsed).findings]
        self.assertNotIn("Display Name Brand Impersonation", titles)


class TestAuthenticationResultsAttribution(unittest.TestCase):
    """The authserv-id is corroborated against the Received chain rather than
    matched against a list of MTA brand names."""

    def _parsed(self, auth_results, received_chain):
        return ParsedMessage(
            from_raw="sender@corp.example",
            to_raw="user@example.com",
            subject="Hello",
            date="Wed, 22 Jul 2026 10:00:00 +0000",
            message_id="<abc@corp.example>",
            authentication_results=auth_results,
            received_chain=received_chain,
            headers={"From": "sender@corp.example"},
        )

    def test_authserv_id_matching_receiving_hop_is_clean(self):
        parsed = self._parsed(
            ["mta1234.randomisp.net; spf=pass smtp.mailfrom=corp.example"],
            ["from out.corp.example ([1.2.3.4]) by mta1234.randomisp.net with ESMTP id x;"
             " Wed, 22 Jul 2026 10:00:00 +0000"],
        )
        self.assertEqual(analyze_headers(parsed).findings, [])

    def test_authserv_id_matching_by_registrable_domain_is_clean(self):
        parsed = self._parsed(
            ["mx.example.com; spf=pass"],
            ["from a.b ([1.2.3.4]) by inbound-smtp.example.com with ESMTP id x;"
             " Wed, 22 Jul 2026 10:00:00 +0000"],
        )
        self.assertEqual(analyze_headers(parsed).findings, [])

    def test_unattributed_authserv_id_is_flagged_as_medium(self):
        parsed = self._parsed(
            ["attacker-controlled.tk; spf=pass"],
            ["from evil ([1.2.3.4]) by mx.victim.com with ESMTP id y;"
             " Wed, 22 Jul 2026 10:00:00 +0000"],
        )
        findings = {f.title: f.risk_level for f in analyze_headers(parsed).findings}
        self.assertIn("Unattributed Authentication-Results Header", findings)
        self.assertEqual(findings["Unattributed Authentication-Results Header"], "Medium")

    def test_missing_authserv_id_is_flagged(self):
        parsed = self._parsed(
            ["spf=pass dkim=pass"],
            ["from evil ([1.2.3.4]) by mx.victim.com with ESMTP id y;"
             " Wed, 22 Jul 2026 10:00:00 +0000"],
        )
        titles = [f.title for f in analyze_headers(parsed).findings]
        self.assertIn("Authentication-Results Missing Authserv-ID", titles)

    def test_no_received_chain_is_not_flagged_here(self):
        """Routing analysis already reports a missing chain; do not double-report."""
        parsed = self._parsed(["mx.somewhere.net; spf=pass"], [])
        titles = [f.title for f in analyze_headers(parsed).findings]
        self.assertNotIn("Unattributed Authentication-Results Header", titles)


if __name__ == '__main__':
    unittest.main()
