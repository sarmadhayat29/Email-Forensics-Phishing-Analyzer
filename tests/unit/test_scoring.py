import unittest
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../../src')))

from scoring import score_message
from models import ParsedMessage, AuthVerdict, RoutingVerdict
from url_analysis import analyze_urls


class TestScoring(unittest.TestCase):
    def test_clean_message_scores_zero(self):
        parsed = ParsedMessage(from_raw="sender@legit.com")
        auth = AuthVerdict(raw="", source="", spf="pass", dkim="pass", dmarc="pass")
        routing = RoutingVerdict(hop_count=3)
        
        verdict = score_message(parsed, auth, routing)
        self.assertEqual(verdict.total_score, 0)
        self.assertEqual(verdict.risk_level, "Low")
        self.assertEqual(len(verdict.signals), 0)

    def test_spf_failure(self):
        parsed = ParsedMessage(from_raw="sender@legit.com")
        auth = AuthVerdict(raw="", source="", spf="fail", dkim="pass", dmarc="pass")
        routing = RoutingVerdict(hop_count=3)
        
        verdict = score_message(parsed, auth, routing)
        self.assertGreaterEqual(verdict.total_score, 30)
        self.assertEqual(verdict.risk_level, "Medium")
        indicators = [s.indicator for s in verdict.signals]
        self.assertIn("SPF Authentication Failure", indicators)

    def test_credential_harvesting_and_urgency(self):
        parsed = ParsedMessage(
            from_raw="security@bank.xyz",
            subject="URGENT: Immediate action required",
            body_plain="Please confirm your password within 24 hours to restore account access."
        )
        auth = AuthVerdict(raw="", source="", spf="pass", dkim="pass", dmarc="pass")
        routing = RoutingVerdict(hop_count=2)

        verdict = score_message(parsed, auth, routing)
        indicators = [s.indicator for s in verdict.signals]
        self.assertIn("High-Risk Top-Level Domain (TLD)", indicators)
        self.assertIn("Credential Harvesting Language", indicators)
        self.assertIn("Urgent Pressure Tactics", indicators)

    def test_ip_based_url_and_open_redirect(self):
        body_html = '<a href="http://192.168.1.1/login?redirect=https://evil.com">Click Here</a>'
        parsed = ParsedMessage(
            from_raw="support@company.com",
            body_html=body_html
        )
        auth = AuthVerdict(raw="", source="", spf="pass", dkim="pass", dmarc="pass")
        routing = RoutingVerdict(hop_count=2)

        # Extract URL verdict so URL-based signals are evaluated in scoring
        url_verdict = analyze_urls(parsed)
        verdict = score_message(parsed, auth, routing, url_verdict=url_verdict)
        indicators = [s.indicator for s in verdict.signals]
        self.assertIn("IP-Based Link Target", indicators)
        self.assertIn("Multiple / Open Redirect Link Parameter", indicators)

    def test_fake_invoice_and_financial_scam(self):
        parsed = ParsedMessage(
            from_raw="billing@vendor-update.com",
            subject="Invoice #49204 Payment Overdue",
            body_plain="Please process wire transfer for attached invoice #49204 immediately."
        )
        auth = AuthVerdict(raw="", source="", spf="pass", dkim="pass", dmarc="pass")
        routing = RoutingVerdict(hop_count=2)

        verdict = score_message(parsed, auth, routing)
        indicators = [s.indicator for s in verdict.signals]
        self.assertIn("Financial Scam Language", indicators)
        self.assertIn("Fake Invoice / BEC Indicators", indicators)

    def test_punycode_domain(self):
        parsed = ParsedMessage(
            from_raw="admin@xn--paypa-4ve.com"
        )
        auth = AuthVerdict(raw="", source="", spf="pass", dkim="pass", dmarc="pass")
        routing = RoutingVerdict(hop_count=2)

        verdict = score_message(parsed, auth, routing)
        indicators = [s.indicator for s in verdict.signals]
        self.assertIn("Punycode / Unicode Domain", indicators)


if __name__ == '__main__':
    unittest.main()

