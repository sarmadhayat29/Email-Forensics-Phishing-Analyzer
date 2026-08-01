"""Regression tests: legitimate mail must not be High; real threats must be."""

import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../src")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from header_analysis import analyze_headers
from models import ParsedMessage, AuthVerdict, RoutingVerdict, Attachment
from scoring import (
    score_message, is_trusted_authenticated_sender, _apply_high_risk_gate, _make_signal,
)
from url_analysis import analyze_urls
from tests.validation.corpus import build_validation_corpus
from tests.validation.evaluate import evaluate, POSITIVE


class TestValidationCorpusAccuracy(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = evaluate()

    def test_zero_false_positives(self):
        self.assertEqual(self.report["metrics"]["false_positives"], 0)

    def test_zero_false_negatives(self):
        self.assertEqual(self.report["metrics"]["false_negatives"], 0)

    def test_perfect_precision_and_recall(self):
        m = self.report["metrics"]
        self.assertEqual(m["precision"], 1.0)
        self.assertEqual(m["recall"], 1.0)
        self.assertEqual(m["f1"], 1.0)
        self.assertEqual(m["accuracy"], 1.0)

    def test_every_benign_case_stays_below_high(self):
        for row in self.report["cases"]:
            if row["label"] != "benign":
                continue
            self.assertNotIn(
                row["risk_level"], POSITIVE,
                msg=f"FP: {row['id']} scored {row['risk_level']} ({row['display_score']})",
            )

    def test_every_malicious_case_reaches_high(self):
        for row in self.report["cases"]:
            if row["label"] != "malicious":
                continue
            self.assertIn(
                row["risk_level"], POSITIVE,
                msg=f"FN: {row['id']} scored {row['risk_level']} ({row['display_score']})",
            )


class TestTrustedSenderDampening(unittest.TestCase):
    def test_google_security_alert_is_low(self):
        parsed = ParsedMessage(
            from_raw="Google <no-reply@accounts.google.com>",
            subject="Security alert",
            body_plain="Reset password here if this was not you: https://accounts.google.com/",
            message_id="<1@x>", date="Sat, 01 Aug 2026 12:00:00 +0000", to_raw="u@x.com",
        )
        auth = AuthVerdict(raw="", source="", spf="pass", dkim="pass", dmarc="pass")
        self.assertTrue(is_trusted_authenticated_sender("accounts.google.com", auth))
        v = score_message(parsed, auth, RoutingVerdict(hop_count=3),
                          header_verdict=analyze_headers(parsed),
                          url_verdict=analyze_urls(parsed))
        self.assertEqual(v.risk_level, "Low")
        self.assertTrue(v.trusted_sender)

    def test_urgency_alone_never_high(self):
        parsed = ParsedMessage(
            from_raw="boss@company.com",
            subject="Immediate action required",
            body_plain="Please respond immediately within 24 hours. Final warning.",
            message_id="<1@x>", date="Sat, 01 Aug 2026 12:00:00 +0000", to_raw="u@x.com",
        )
        v = score_message(
            parsed,
            AuthVerdict(raw="", source="", spf="pass", dkim="pass", dmarc="pass"),
            RoutingVerdict(hop_count=3),
            header_verdict=analyze_headers(parsed),
        )
        self.assertNotIn(v.risk_level, POSITIVE)

    def test_payment_confirmation_not_financial_scam(self):
        parsed = ParsedMessage(
            from_raw="shop@unknown-merchant.example",
            subject="Order update",
            body_plain="Your payment confirmation for order 99 is ready. Bank deposit posted.",
            message_id="<1@x>", date="Sat, 01 Aug 2026 12:00:00 +0000", to_raw="u@x.com",
        )
        v = score_message(
            parsed,
            AuthVerdict(raw="", source="", spf="pass", dkim="pass", dmarc="pass"),
            RoutingVerdict(hop_count=3),
            header_verdict=analyze_headers(parsed),
        )
        indicators = [s.indicator for s in v.signals if s.weight > 0]
        self.assertNotIn("Financial Scam Language", indicators)


class TestHighRiskCorroborationGate(unittest.TestCase):
    def test_weak_only_signals_demoted_from_high(self):
        weak_pile = [
            _make_signal("Urgent Pressure Tactics", 25, "e", "x", strength="weak"),
            _make_signal("Suspicious Keywords", 25, "e", "x", strength="weak"),
            _make_signal("No SPF Record Published", 20, "e", "x", strength="weak"),
        ]
        # Raw display would be High (70) but gate must demote.
        level, reason, _ = _apply_high_risk_gate(70, weak_pile)
        self.assertEqual(level, "Medium")
        self.assertIn("Demoted", reason)

    def test_two_strong_families_keep_high(self):
        signals = [
            _make_signal("SPF Authentication Failure", 30, "e", "x", strength="strong"),
            _make_signal("Lookalike / Typosquatted Domain", 25, "e", "x", strength="strong"),
        ]
        level, reason, _ = _apply_high_risk_gate(70, signals)
        self.assertEqual(level, "High")
        self.assertIn("strong evidence", reason.lower())

    def test_explainability_fields_populated(self):
        parsed = ParsedMessage(
            from_raw="PayPal Security <no-reply@paypa1-secure.com>",
            subject="Verify your account",
            body_plain="Confirm your password now.",
            message_id="<1@x>", date="Sat, 01 Aug 2026 12:00:00 +0000", to_raw="u@x.com",
        )
        v = score_message(
            parsed,
            AuthVerdict(raw="", source="", spf="fail", dkim="fail", dmarc="fail"),
            RoutingVerdict(hop_count=3),
            header_verdict=analyze_headers(parsed),
        )
        self.assertTrue(v.rationale)
        self.assertTrue(v.classification_reason)
        self.assertGreater(v.strong_signal_count, 0)
        for s in v.signals:
            if s.weight > 0:
                self.assertTrue(s.family)
                self.assertIn(s.strength, {"strong", "weak"})


class TestMalwareStillDetected(unittest.TestCase):
    def test_double_extension_with_bec_is_high(self):
        parsed = ParsedMessage(
            from_raw="Billing <invoices@vendor-secure.tk>",
            subject="Invoice attached - payment overdue",
            body_plain="Complete the wire transfer for invoice #4401.",
            message_id="<1@x>", date="Sat, 01 Aug 2026 12:00:00 +0000", to_raw="u@x.com",
            attachments=[
                Attachment(
                    filename="Invoice_4401.pdf.exe",
                    declared_extension="exe",
                    true_type="exe",
                    size_bytes=4096,
                    is_executable=True,
                    has_double_extension=True,
                )
            ],
        )
        v = score_message(
            parsed,
            AuthVerdict(raw="", source="", spf="none", dkim="none", dmarc="none"),
            RoutingVerdict(hop_count=3),
            header_verdict=analyze_headers(parsed),
        )
        self.assertIn(v.risk_level, POSITIVE)


if __name__ == "__main__":
    unittest.main()
