"""Sender-history baselining and its (conservative) contribution to scoring.

No database is involved anywhere: prior senders are supplied as plain lists, and
the DB-backed loader the API installs is represented by a callable, including a
callable that fails.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../../src')))

from models import AuthVerdict, ParsedMessage, RoutingVerdict, SenderHistory
from scoring import (
    FIRST_CONTACT_ADDRESS_WEIGHT, FIRST_CONTACT_DOMAIN_WEIGHT,
    FIRST_CONTACT_WITH_PAYMENT_WEIGHT, MAX_SENDER_HISTORY_SCORE, score_message,
)
from sender_history import (
    MIN_PRIOR_MESSAGES, build_history, history_provider, senders_from_records,
)


def known_senders(count=8, address="ap@vendor-supplies.com"):
    """A believable correspondent set of at least the minimum baseline size."""
    others = [f"colleague{i}@ourcompany.com" for i in range(count - 1)]
    return [address] + others


class TestBuildHistory(unittest.TestCase):

    def test_first_contact_domain_is_reported(self):
        history = build_history("Accounts <billing@brand-new-vendor.com>", known_senders())
        self.assertTrue(history.available)
        self.assertTrue(history.first_time_domain)
        self.assertTrue(history.first_time_address)
        self.assertEqual(history.domain, "brand-new-vendor.com")

    def test_established_correspondent_is_not_first_contact(self):
        history = build_history("ap@vendor-supplies.com", known_senders())
        self.assertTrue(history.available)
        self.assertFalse(history.first_time_domain)
        self.assertFalse(history.first_time_address)
        self.assertEqual(history.address_count, 1)

    def test_new_address_at_a_known_domain(self):
        history = build_history("newhire@vendor-supplies.com", known_senders())
        self.assertTrue(history.first_time_address)
        self.assertFalse(history.first_time_domain)

    def test_subdomain_of_a_known_domain_is_the_same_correspondent(self):
        """Ordinary ESP/subdomain variation must not read as a first contact."""
        history = build_history("billing@mail.vendor-supplies.com", known_senders())
        self.assertFalse(history.first_time_domain)

    def test_history_is_unavailable_below_the_minimum_baseline(self):
        history = build_history("billing@somewhere.com", ["a@b.com", "c@d.com"])
        self.assertFalse(history.available)
        self.assertEqual(history.prior_messages, 2)
        self.assertIn(str(MIN_PRIOR_MESSAGES), history.detail)

    def test_no_prior_messages_at_all(self):
        history = build_history("billing@somewhere.com", [])
        self.assertFalse(history.available)
        self.assertEqual(history.prior_messages, 0)

    def test_unparseable_prior_entries_are_ignored_not_counted(self):
        history = build_history("billing@somewhere.com",
                                known_senders() + ["", None, "not an address", "<>"])
        self.assertEqual(history.prior_messages, len(known_senders()))

    def test_missing_sender_yields_no_baseline(self):
        for from_raw in ("", "no address here", None):
            history = build_history(from_raw, known_senders())
            self.assertFalse(history.available)

    def test_display_name_spoofing_cannot_fake_a_known_domain(self):
        """The real address in angle brackets decides, not the display name."""
        history = build_history('"ap@vendor-supplies.com" <thief@evil.tk>', known_senders())
        self.assertTrue(history.first_time_domain)
        self.assertEqual(history.domain, "evil.tk")


class TestHistoryProvider(unittest.TestCase):

    def test_provider_returns_a_history_for_the_parsed_message(self):
        provider = history_provider(lambda: known_senders())
        history = provider(ParsedMessage(from_raw="billing@brand-new-vendor.com"))
        self.assertTrue(history.available)
        self.assertTrue(history.first_time_domain)

    def test_failing_loader_degrades_to_no_history(self):
        def broken_loader():
            raise RuntimeError("database is unreachable")

        provider = history_provider(broken_loader)
        self.assertIsNone(provider(ParsedMessage(from_raw="billing@brand-new-vendor.com")))

    def test_records_are_read_in_every_shape_a_caller_might_supply(self):
        records = [
            "raw@header.com",
            ("tuple@row.com",),
            {"from_addr": "Dict Row <dict@row.com>"},
            None,
            ("",),
        ]
        self.assertEqual(
            senders_from_records(records),
            ["raw@header.com", "tuple@row.com", "Dict Row <dict@row.com>"],
        )

    def test_orm_style_records_are_read_from_finding_json(self):
        class Record:
            def __init__(self, from_addr):
                self.finding_json = {"from_addr": from_addr}

        self.assertEqual(senders_from_records([Record("a@b.com"), Record("")]), ["a@b.com"])


def _score(parsed, sender_history=None):
    return score_message(
        parsed,
        AuthVerdict(raw="", source="", spf="pass", dkim="pass", dmarc="pass"),
        RoutingVerdict(hop_count=3),
        sender_history=sender_history,
    )


def _history_signals(verdict):
    return [s for s in verdict.signals if s.indicator.startswith("Sender History:")]


class TestSenderHistoryScoring(unittest.TestCase):

    def _invoice_message(self):
        return ParsedMessage(
            from_raw="Accounts <billing@brand-new-vendor.com>",
            subject="Updated remittance details",
            body_plain="Please see the attached invoice #88213 and note our new bank deposit details.",
        )

    def _ordinary_message(self):
        return ParsedMessage(
            from_raw="Accounts <billing@brand-new-vendor.com>",
            subject="Nice to meet you at the conference",
            body_plain="Great speaking today — here is the deck we discussed.",
        )

    def _first_contact(self):
        return build_history("billing@brand-new-vendor.com", known_senders())

    def test_first_contact_plus_payment_language_scores_the_combination(self):
        verdict = _score(self._invoice_message(), self._first_contact())
        signals = _history_signals(verdict)
        self.assertEqual(len(signals), 1)
        self.assertEqual(signals[0].weight, FIRST_CONTACT_WITH_PAYMENT_WEIGHT)
        self.assertIn("Fake Invoice / BEC Indicators", signals[0].evidence)

    def test_first_contact_alone_is_only_context(self):
        verdict = _score(self._ordinary_message(), self._first_contact())
        signals = _history_signals(verdict)
        self.assertEqual(len(signals), 1)
        self.assertEqual(signals[0].weight, FIRST_CONTACT_DOMAIN_WEIGHT)
        self.assertEqual(verdict.risk_level, "Low")

    def test_new_address_at_a_known_domain_scores_least(self):
        history = build_history("newhire@vendor-supplies.com", known_senders())
        parsed = ParsedMessage(from_raw="newhire@vendor-supplies.com", body_plain="Hello team.")
        signals = _history_signals(_score(parsed, history))
        self.assertEqual([s.weight for s in signals], [FIRST_CONTACT_ADDRESS_WEIGHT])

    def test_known_correspondent_scores_nothing(self):
        history = build_history("ap@vendor-supplies.com", known_senders())
        parsed = ParsedMessage(from_raw="ap@vendor-supplies.com",
                               body_plain="Attached invoice #88213 as agreed.")
        self.assertEqual(_history_signals(_score(parsed, history)), [])

    def test_unavailable_history_scores_nothing(self):
        thin = build_history("billing@brand-new-vendor.com", ["only@one.com"])
        self.assertEqual(_history_signals(_score(self._invoice_message(), thin)), [])
        self.assertEqual(_history_signals(_score(self._invoice_message(), SenderHistory())), [])

    def test_cli_path_without_history_is_scored_exactly_as_before(self):
        parsed = self._invoice_message()
        without = _score(parsed)
        with_none = _score(parsed, None)
        self.assertEqual(without.total_score, with_none.total_score)
        self.assertEqual(_history_signals(without), [])

    def test_history_never_carries_a_verdict_on_its_own(self):
        parsed = ParsedMessage(from_raw="billing@brand-new-vendor.com",
                               body_plain="Please wire transfer the overdue payment today.")
        verdict = _score(parsed, self._first_contact())
        history_weight = sum(s.weight for s in _history_signals(verdict))
        self.assertLessEqual(history_weight, MAX_SENDER_HISTORY_SCORE)
        self.assertNotEqual(verdict.risk_level, "Critical")

    def test_available_history_raises_evidence_confidence(self):
        parsed = ParsedMessage(from_raw="ap@vendor-supplies.com", body_plain="Hello.")
        known = build_history("ap@vendor-supplies.com", known_senders())
        baseline = score_message(parsed,
                                 AuthVerdict(raw="", source="", spf="pass", dkim="none", dmarc="none"),
                                 RoutingVerdict(hop_count=1))
        with_history = score_message(parsed,
                                     AuthVerdict(raw="", source="", spf="pass", dkim="none", dmarc="none"),
                                     RoutingVerdict(hop_count=1),
                                     sender_history=known)
        self.assertGreater(with_history.confidence, baseline.confidence)
        self.assertLessEqual(with_history.confidence, 90)


if __name__ == "__main__":
    unittest.main()
