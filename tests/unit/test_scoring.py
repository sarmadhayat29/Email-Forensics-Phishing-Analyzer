import unittest
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../../src')))

from scoring import (
    FAMILY_SCORE_CAPS, score_message, to_display_score, _bucket, _signal_family,
)
from models import (
    Attachment, ParsedMessage, AuthVerdict, RoutingVerdict, HeaderAnalysisVerdict,
    HeaderFinding,
)
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
        # Auth alone saturates High band by raw score but the corroboration gate
        # keeps the verdict at Medium without a second evidence family.
        self.assertEqual(verdict.risk_level, "Medium")
        self.assertGreaterEqual(verdict.display_score, 70)

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


class TestConfidenceWithLiveVerification(unittest.TestCase):
    """Independently re-verified authentication is stronger evidence than a claim."""

    def _score(self, **auth_kwargs):
        parsed = ParsedMessage(from_raw="a@b.com", body_plain="Hello there.")
        auth = AuthVerdict(raw="", source="", spf="pass", dkim="pass", dmarc="pass", **auth_kwargs)
        return score_message(parsed, auth, RoutingVerdict(hop_count=3))

    def test_live_verified_beats_header_only(self):
        live = self._score(live_attempted=True, live_verified=True)
        header_only = self._score()
        self.assertGreaterEqual(live.confidence, header_only.confidence)

    def test_failed_live_attempt_lowers_confidence(self):
        failed = self._score(live_attempted=True, live_verified=False)
        header_only = self._score()
        self.assertLess(failed.confidence, header_only.confidence)
        self.assertIn("independently re-verified authentication", failed.confidence_label)

    def test_confidence_stays_within_bounds(self):
        for kwargs in ({}, {"live_attempted": True, "live_verified": True},
                       {"live_attempted": True, "live_verified": False}):
            verdict = self._score(**kwargs)
            self.assertTrue(0 < verdict.confidence <= 90)

    def test_offline_deployment_is_not_penalised(self):
        """live_attempted=False (air-gapped) must score as it always has."""
        self.assertEqual(self._score().confidence, 90)


class TestFamilyCaps(unittest.TestCase):
    """Each evidence family saturates, so one stage cannot decide a verdict.

    Correlated evidence within a family (five header findings about one forged
    From, thirty links tripping one detector) must not accumulate its way to
    Critical. Capping changes what a signal contributes, never whether the
    analyst sees it.
    """

    def _family_weight(self, verdict, family):
        return sum(s.weight for s in verdict.signals if _signal_family(s.indicator) == family)

    def _family_signals(self, verdict, family):
        return [s for s in verdict.signals if _signal_family(s.indicator) == family]

    def test_authentication_saturates(self):
        auth = AuthVerdict(
            raw="", source="", spf="fail", dkim="fail", dmarc="fail",
            inconsistencies=[f"Conflicting authentication header #{i}" for i in range(8)],
        )
        verdict = score_message(ParsedMessage(from_raw="a@b.com"), auth, RoutingVerdict(hop_count=3))
        self.assertEqual(self._family_weight(verdict, "authentication"),
                         FAMILY_SCORE_CAPS["authentication"])
        # Every observation is still reported, capped or not.
        self.assertEqual(len(self._family_signals(verdict, "authentication")), 11)

    def test_hard_auth_failures_alone_stay_medium(self):
        """Authentication failures alone must not produce High without corroboration."""
        auth = AuthVerdict(raw="", source="", spf="fail", dkim="fail", dmarc="fail")
        verdict = score_message(ParsedMessage(from_raw="a@b.com"), auth, RoutingVerdict(hop_count=3))
        self.assertEqual(verdict.risk_level, "Medium")
        self.assertIn("authentication failures alone", verdict.classification_reason.lower())

    def test_hard_auth_failures_with_impersonation_reach_high(self):
        auth = AuthVerdict(raw="", source="", spf="fail", dkim="fail", dmarc="fail")
        findings = [
            HeaderFinding(title="Lookalike Brand Domain (Typosquatting)", description="d",
                          risk_level="High", evidence="e", recommendation="r"),
        ]
        verdict = score_message(
            ParsedMessage(from_raw="PayPal <security@paypa1-secure.tk>"),
            auth, RoutingVerdict(hop_count=3),
            header_verdict=HeaderAnalysisVerdict(findings=findings),
        )
        self.assertIn(verdict.risk_level, {"High", "Critical"})

    def test_link_forensics_saturates(self):
        anchors = "".join(
            f'<a href="http://10.0.0.{i}/login?redirect=https://evil{i}.tk">paypal.com</a>'
            for i in range(1, 13)
        )
        parsed = ParsedMessage(from_raw="a@b.com", body_html=anchors)
        verdict = score_message(parsed, _pass_auth(), RoutingVerdict(hop_count=3),
                                url_verdict=analyze_urls(parsed))
        self.assertEqual(self._family_weight(verdict, "link forensics"),
                         FAMILY_SCORE_CAPS["link forensics"])

    def test_message_content_saturates_but_keeps_every_indicator(self):
        parsed = ParsedMessage(
            from_raw="a@b.com",
            subject="Urgent notice: action required",
            body_plain=(
                "Security alert: suspicious activity. Please confirm your password. "
                "Respond immediately or your account will be suspended. "
                "Complete the wire transfer for the attached invoice #4021. "
                "Your password expired, reset password now."
            ),
        )
        verdict = score_message(parsed, _pass_auth(), RoutingVerdict(hop_count=3))
        indicators = {s.indicator for s in self._family_signals(verdict, "message content")}
        for expected in ("Suspicious Keywords", "Credential Harvesting Language",
                         "Urgent Pressure Tactics", "Financial Scam Language",
                         "Fake Invoice / BEC Indicators", "Password Reset Scam Language"):
            self.assertIn(expected, indicators)
        self.assertEqual(self._family_weight(verdict, "message content"),
                         FAMILY_SCORE_CAPS["message content"])

    def test_header_forensics_saturates(self):
        findings = [
            HeaderFinding(title=f"Forged Header #{i}", description="d", risk_level="Critical",
                          evidence="e", recommendation="r")
            for i in range(6)
        ]
        verdict = score_message(ParsedMessage(from_raw="a@b.com"), _pass_auth(),
                                RoutingVerdict(hop_count=3),
                                header_verdict=HeaderAnalysisVerdict(findings=findings))
        self.assertEqual(self._family_weight(verdict, "header forensics"),
                         FAMILY_SCORE_CAPS["header forensics"])

    def test_attachment_forensics_saturates(self):
        attachments = [
            Attachment(filename=f"invoice_{i}.pdf.exe", declared_extension="exe",
                       true_type="exe", size_bytes=1024, is_executable=True,
                       has_double_extension=True)
            for i in range(5)
        ]
        verdict = score_message(ParsedMessage(from_raw="a@b.com", attachments=attachments),
                                _pass_auth(), RoutingVerdict(hop_count=3))
        self.assertEqual(self._family_weight(verdict, "attachment forensics"),
                         FAMILY_SCORE_CAPS["attachment forensics"])
        self.assertEqual(len(self._family_signals(verdict, "attachment forensics")), 5)

    def test_no_single_family_can_reach_critical_alone(self):
        for cap in FAMILY_SCORE_CAPS.values():
            self.assertLess(to_display_score(cap), 90)

    def test_evidence_below_a_cap_is_untouched(self):
        """Ordinary messages keep the exact weights they always had."""
        auth = AuthVerdict(raw="", source="", spf="fail", dkim="pass", dmarc="pass")
        verdict = score_message(ParsedMessage(from_raw="a@b.com"), auth, RoutingVerdict(hop_count=3))
        self.assertEqual(verdict.total_score, 30)

    def test_strongest_evidence_in_a_family_is_what_scores(self):
        """Budget goes to the severe finding, not to whichever came first."""
        findings = [
            HeaderFinding(title="Minor note", description="d", risk_level="Low",
                          evidence="e", recommendation="r"),
        ] * 20 + [
            HeaderFinding(title="Forged From", description="d", risk_level="Critical",
                          evidence="e", recommendation="r"),
        ]
        verdict = score_message(ParsedMessage(from_raw="a@b.com"), _pass_auth(),
                                RoutingVerdict(hop_count=3),
                                header_verdict=HeaderAnalysisVerdict(findings=findings))
        critical = next(s for s in verdict.signals if s.indicator.endswith("Forged From"))
        self.assertEqual(critical.weight, 35)


if __name__ == '__main__':
    unittest.main()

