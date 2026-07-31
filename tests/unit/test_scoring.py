import unittest
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../../src')))

from scoring import score_message, to_display_score, _bucket
from models import ParsedMessage, AuthVerdict, RoutingVerdict, HeaderAnalysisVerdict
from url_analysis import analyze_urls


def _pass_auth():
    return AuthVerdict(raw="", source="", spf="pass", dkim="pass", dmarc="pass")


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

    def test_confidential_keyword_no_longer_flags(self):
        """Corporate disclaimers must not trigger the suspicious keyword signal."""
        parsed = ParsedMessage(
            from_raw="hr@company.com",
            subject="Q3 planning notes",
            body_plain="This email and any attachments are confidential and privileged."
        )
        verdict = score_message(parsed, _pass_auth(), RoutingVerdict(hop_count=3))
        self.assertEqual(verdict.total_score, 0)
        self.assertEqual(verdict.risk_level, "Low")

    def test_keywords_found_through_html_obfuscation(self):
        parsed = ParsedMessage(
            from_raw="alerts@company.com",
            body_html="<p>Please conf&#8203;irm your pass<b>word</b> immediately.</p>"
        )
        verdict = score_message(parsed, _pass_auth(), RoutingVerdict(hop_count=3))
        self.assertIn("Credential Harvesting Language", [s.indicator for s in verdict.signals])


class TestAuthenticationWeighting(unittest.TestCase):

    def _score(self, **kwargs):
        parsed = ParsedMessage(from_raw="news@smallbiz.com", body_plain="Monthly newsletter.")
        return score_message(parsed, AuthVerdict(raw="", source="", **kwargs), RoutingVerdict(hop_count=3))

    def test_hard_failures_dominate(self):
        verdict = self._score(spf="fail", dkim="fail", dmarc="fail")
        indicators = [s.indicator for s in verdict.signals]
        self.assertIn("SPF Authentication Failure", indicators)
        self.assertIn("DKIM Signature Failure", indicators)
        self.assertIn("DMARC Policy Violation", indicators)
        self.assertIn(verdict.risk_level, {"High", "Critical"})

    def test_unsigned_legitimate_mail_stays_low(self):
        """spf/dkim/dmarc = none must not push ordinary unsigned mail out of Low."""
        verdict = self._score(spf="none", dkim="none", dmarc="none")
        self.assertEqual(verdict.risk_level, "Low")
        self.assertGreater(verdict.total_score, 0)

    def test_absent_auth_headers_stay_low(self):
        verdict = self._score()
        self.assertEqual(verdict.risk_level, "Low")

    def test_softfail_weighs_less_than_hard_fail(self):
        soft = self._score(spf="softfail", dkim="pass", dmarc="pass").total_score
        hard = self._score(spf="fail", dkim="pass", dmarc="pass").total_score
        self.assertLess(soft, hard)
        self.assertGreater(soft, 0)


class TestRoutingFlagScoring(unittest.TestCase):

    def test_routing_anomalies_are_scored(self):
        routing = RoutingVerdict(hop_count=3, flags=[
            "Hop #2 occurred 400s BEFORE Hop #1 (time travel anomaly / forged header).",
            "Hop #2 contains private IP (10.0.0.5) appearing after public WAN transit.",
        ])
        verdict = score_message(ParsedMessage(from_raw="a@b.com"), _pass_auth(), routing)
        indicators = [s.indicator for s in verdict.signals]
        self.assertIn("Routing Forensics: Impossible Routing Sequence", indicators)
        self.assertIn("Routing Forensics: Private IP After Public Transit", indicators)

    def test_repeated_flags_are_collapsed_and_capped(self):
        """Many flags of one kind score once, and the total stays bounded."""
        routing = RoutingVerdict(hop_count=6, flags=[
            f"Discontinuity between Hop #{i} (by 'a') and Hop #{i+1} (from 'b') — possible missing intermediate relay hop."
            for i in range(1, 6)
        ] + [
            "Hop #3 has an unparseable timestamp format.",
            "Hop #4 experienced excessive transit delay (~30 hours).",
            "Hop #2 has a future timestamp (2030-01-01) — clock skew or forged header.",
        ])
        verdict = score_message(ParsedMessage(from_raw="a@b.com"), _pass_auth(), routing)
        routing_signals = [s for s in verdict.signals if s.indicator.startswith("Routing Forensics:")]
        self.assertEqual(len(routing_signals), 3)
        self.assertEqual(len([s for s in routing_signals if "Discontinuity" in s.indicator]), 1)
        self.assertLessEqual(sum(s.weight for s in routing_signals), 45)

    def test_no_flags_scores_nothing(self):
        verdict = score_message(ParsedMessage(from_raw="a@b.com"), _pass_auth(), RoutingVerdict(hop_count=3))
        self.assertEqual(verdict.total_score, 0)


class TestSenderIdentityDeduplication(unittest.TestCase):

    def _parsed(self):
        return ParsedMessage(
            from_raw="PayPal Support <security@paypa1-secure.tk>",
            reply_to_raw="attacker@elsewhere.tk",
        )

    def test_scored_standalone_without_header_verdict(self):
        verdict = score_message(self._parsed(), _pass_auth(), RoutingVerdict(hop_count=3))
        indicators = [s.indicator for s in verdict.signals]
        self.assertIn("Display Name Impersonation", indicators)
        self.assertIn("Lookalike / Typosquatted Domain", indicators)
        self.assertIn("High-Risk Top-Level Domain (TLD)", indicators)
        self.assertIn("Mismatched Sender Domains", indicators)

    def test_not_double_scored_when_header_forensics_supplied(self):
        """Header forensics owns these categories once it is in play."""
        verdict = score_message(
            self._parsed(), _pass_auth(), RoutingVerdict(hop_count=3),
            header_verdict=HeaderAnalysisVerdict(findings=[]),
        )
        indicators = [s.indicator for s in verdict.signals]
        for duplicated in (
            "Display Name Impersonation",
            "Lookalike / Typosquatted Domain",
            "High-Risk Top-Level Domain (TLD)",
            "Mismatched Sender Domains",
        ):
            self.assertNotIn(duplicated, indicators)


class TestDisplayScoreScale(unittest.TestCase):

    def test_anchors(self):
        self.assertEqual(to_display_score(0), 0)
        self.assertEqual(to_display_score(30), 30)
        self.assertEqual(to_display_score(70), 70)
        self.assertEqual(to_display_score(150), 90)

    def test_clamped_and_never_negative(self):
        self.assertEqual(to_display_score(-50), 0)
        self.assertLessEqual(to_display_score(10 ** 6), 100)

    def test_monotone_so_ranking_is_preserved(self):
        previous = -1
        for raw in range(0, 2001):
            current = to_display_score(raw)
            self.assertGreaterEqual(current, previous)
            self.assertTrue(0 <= current <= 100)
            previous = current

    def test_buckets_align_with_frontend_thresholds(self):
        self.assertEqual(_bucket(0), "Low")
        self.assertEqual(_bucket(29), "Low")
        self.assertEqual(_bucket(30), "Medium")
        self.assertEqual(_bucket(69), "Medium")
        self.assertEqual(_bucket(70), "High")
        self.assertEqual(_bucket(89), "High")
        self.assertEqual(_bucket(90), "Critical")

    def test_verdict_exposes_both_scales(self):
        parsed = ParsedMessage(from_raw="a@b.com")
        verdict = score_message(parsed, AuthVerdict(raw="", source="", spf="fail", dkim="fail", dmarc="fail"),
                                RoutingVerdict(hop_count=3))
        self.assertEqual(verdict.display_score, to_display_score(verdict.total_score))
        self.assertLessEqual(verdict.display_score, 100)


class TestConfidence(unittest.TestCase):

    def test_confidence_reported_when_evidence_exists(self):
        parsed = ParsedMessage(from_raw="a@b.com", body_plain="Hello there.")
        verdict = score_message(parsed, _pass_auth(), RoutingVerdict(hop_count=3))
        self.assertIsNotNone(verdict.confidence)
        self.assertTrue(0 < verdict.confidence <= 90)
        self.assertIn("Confidence", verdict.confidence_label)

    def test_confidence_is_none_without_any_evidence(self):
        """No auth results, no routing chain, no body: do not claim confidence."""
        parsed = ParsedMessage(from_raw="a@b.com")
        verdict = score_message(parsed, AuthVerdict(raw="", source=""), RoutingVerdict(hop_count=0))
        self.assertIsNone(verdict.confidence)
        self.assertEqual(verdict.confidence_label, "Insufficient evidence")


if __name__ == '__main__':
    unittest.main()

