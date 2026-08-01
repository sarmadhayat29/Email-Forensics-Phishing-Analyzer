"""Unit tests for WHOIS-backed domain registration-age analysis.

Every test injects a fake WHOIS callable: the suite must never touch the
network. The whole feature is disabled by default in conftest, so each test
class that needs it enables it explicitly and restores the previous value.
"""

import os
import sys
import unittest
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../../src')))

import domain_age
from domain_age import (
    ESTABLISHED, EXEMPT, NEWLY_REGISTERED, UNKNOWN, YOUNG,
    analyse_domain_age, collect_domains, is_exempt, lookup_domain_age,
)
from models import AuthVerdict, DomainAgeFinding, ExtractedURL, ParsedMessage, RoutingVerdict, URLAnalysisVerdict
from scoring import MAX_DOMAIN_AGE_SCORE, score_message


def days_ago(days: int) -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=days)


class FakeWhois:
    """Records every queried domain and replays canned answers."""

    def __init__(self, answers=None, error=None, hang=False):
        self.answers = answers or {}
        self.error = error
        self.hang = hang
        self.queries = []

    def __call__(self, domain):
        self.queries.append(domain)
        if self.hang:
            import time
            time.sleep(5)
        if self.error is not None:
            raise self.error
        if domain not in self.answers:
            raise RuntimeError(f"No WHOIS data for {domain}")
        return self.answers[domain]


class DomainAgeTestCase(unittest.TestCase):
    """Enables the feature for the duration of each test and resets state."""

    enabled = "true"

    def setUp(self):
        self._previous = os.environ.get("DOMAIN_AGE_ENABLED")
        os.environ["DOMAIN_AGE_ENABLED"] = self.enabled
        domain_age.clear_cache()
        domain_age.reset_whois_health()

    def tearDown(self):
        if self._previous is None:
            os.environ.pop("DOMAIN_AGE_ENABLED", None)
        else:
            os.environ["DOMAIN_AGE_ENABLED"] = self._previous
        domain_age.clear_cache()
        domain_age.reset_whois_health()


class TestClassification(DomainAgeTestCase):

    def _lookup(self, created, domain="fresh-domain.tk"):
        whois = FakeWhois({domain: {"creation_date": created, "registrar": "Test Registrar"}})
        return lookup_domain_age(domain, whois_func=whois), whois

    def test_brand_new_domain_is_newly_registered(self):
        finding, _ = self._lookup(days_ago(5))
        self.assertEqual(finding.classification, NEWLY_REGISTERED)
        self.assertEqual(finding.age_days, 5)
        self.assertEqual(finding.source, "whois")
        self.assertEqual(finding.registrar, "Test Registrar")

    def test_medium_age_domain_is_young(self):
        finding, _ = self._lookup(days_ago(45))
        self.assertEqual(finding.classification, YOUNG)
        self.assertEqual(finding.age_days, 45)

    def test_aged_domain_is_established(self):
        finding, _ = self._lookup(days_ago(800))
        self.assertEqual(finding.classification, ESTABLISHED)
        self.assertTrue(finding.resolved)

    def test_boundary_at_thirty_days_is_not_newly_registered(self):
        finding, _ = self._lookup(days_ago(30))
        self.assertEqual(finding.classification, YOUNG)

    def test_string_creation_date_is_parsed(self):
        finding, _ = self._lookup(days_ago(10).strftime("%Y-%m-%d %H:%M:%S"))
        self.assertEqual(finding.classification, NEWLY_REGISTERED)

    def test_list_of_dates_uses_the_earliest(self):
        finding, _ = self._lookup([days_ago(400), days_ago(3)])
        self.assertEqual(finding.age_days, 400)
        self.assertEqual(finding.classification, ESTABLISHED)

    def test_timezone_aware_date_is_normalised(self):
        aware = datetime.now(timezone.utc) - timedelta(days=7)
        finding, _ = self._lookup(aware)
        self.assertEqual(finding.classification, NEWLY_REGISTERED)

    def test_future_creation_date_is_ignored(self):
        finding, _ = self._lookup(datetime.now() + timedelta(days=30))
        self.assertEqual(finding.classification, UNKNOWN)
        self.assertIsNone(finding.age_days)

    def test_thresholds_are_configurable(self):
        os.environ["NRD_DAYS"] = "60"
        try:
            finding, _ = self._lookup(days_ago(45))
            self.assertEqual(finding.classification, NEWLY_REGISTERED)
        finally:
            os.environ.pop("NRD_DAYS", None)


class TestGracefulDegradation(DomainAgeTestCase):

    def test_lookup_failure_yields_unknown_without_raising(self):
        whois = FakeWhois(error=ConnectionRefusedError("port 43 blocked"))
        finding = lookup_domain_age("some-domain.com", whois_func=whois)
        self.assertEqual(finding.classification, UNKNOWN)
        self.assertIsNone(finding.age_days)
        self.assertEqual(finding.source, "error")

    def test_missing_creation_date_yields_unknown(self):
        whois = FakeWhois({"no-date.com": {"registrar": "Anon"}})
        finding = lookup_domain_age("no-date.com", whois_func=whois)
        self.assertEqual(finding.classification, UNKNOWN)
        self.assertIn("no usable creation date", finding.detail)

    def test_timeout_is_bounded_and_reported_as_unknown(self):
        os.environ["WHOIS_TIMEOUT"] = "1"
        try:
            whois = FakeWhois(hang=True)
            started = datetime.now()
            finding = lookup_domain_age("slow-domain.com", whois_func=whois)
            elapsed = (datetime.now() - started).total_seconds()
        finally:
            os.environ.pop("WHOIS_TIMEOUT", None)
        self.assertEqual(finding.classification, UNKNOWN)
        self.assertLess(elapsed, 4, "WHOIS timeout did not bound the lookup")

    def test_missing_dependency_yields_unknown(self):
        original = domain_age._default_whois_func
        domain_age._default_whois_func = lambda: None
        try:
            finding = lookup_domain_age("unresolvable.com")
        finally:
            domain_age._default_whois_func = original
        self.assertEqual(finding.classification, UNKNOWN)
        self.assertIn("python-whois", finding.detail)

    def test_repeated_failures_open_the_circuit_breaker(self):
        whois = FakeWhois(error=OSError("network unreachable"))
        for index in range(domain_age.WHOIS_FAILURE_THRESHOLD):
            lookup_domain_age(f"broken{index}.com", whois_func=whois)
        self.assertFalse(domain_age.whois_available())

        finding = lookup_domain_age("another-domain.com", whois_func=whois)
        self.assertEqual(finding.classification, UNKNOWN)
        self.assertIn("suspended", finding.detail)
        self.assertEqual(len(whois.queries), domain_age.WHOIS_FAILURE_THRESHOLD)

    def test_unparseable_input_is_skipped(self):
        whois = FakeWhois()
        finding = lookup_domain_age("", whois_func=whois)
        self.assertEqual(finding.source, "skipped")
        self.assertEqual(whois.queries, [])


class TestDisabled(DomainAgeTestCase):
    enabled = "false"

    def test_disabled_via_env_performs_no_lookup(self):
        whois = FakeWhois({"evil.tk": {"creation_date": days_ago(2)}})
        finding = lookup_domain_age("evil.tk", whois_func=whois)
        self.assertEqual(finding.classification, UNKNOWN)
        self.assertEqual(finding.source, "disabled")
        self.assertEqual(whois.queries, [])

    def test_pipeline_helper_returns_nothing_when_disabled(self):
        whois = FakeWhois({"evil.tk": {"creation_date": days_ago(2)}})
        parsed = ParsedMessage(from_raw="Billing <billing@evil.tk>")
        self.assertEqual(analyse_domain_age(parsed, whois_func=whois), [])
        self.assertEqual(whois.queries, [])


class TestCaching(DomainAgeTestCase):

    def test_cache_hit_does_not_requery_whois(self):
        whois = FakeWhois({"repeat.com": {"creation_date": days_ago(10)}})
        first = lookup_domain_age("repeat.com", whois_func=whois)
        second = lookup_domain_age("repeat.com", whois_func=whois)

        self.assertEqual(whois.queries, ["repeat.com"])
        self.assertEqual(first.source, "whois")
        self.assertEqual(second.source, "cache")
        self.assertEqual(second.age_days, first.age_days)
        self.assertEqual(second.classification, NEWLY_REGISTERED)

    def test_failures_are_negatively_cached(self):
        whois = FakeWhois(error=RuntimeError("no such domain"))
        lookup_domain_age("gone.com", whois_func=whois)
        second = lookup_domain_age("gone.com", whois_func=whois)
        self.assertEqual(len(whois.queries), 1)
        self.assertEqual(second.classification, UNKNOWN)

    def test_expired_entries_are_refetched(self):
        whois = FakeWhois({"stale.com": {"creation_date": days_ago(10)}})
        lookup_domain_age("stale.com", whois_func=whois)
        domain_age._cache["stale.com"]["expires"] = 0
        lookup_domain_age("stale.com", whois_func=whois)
        self.assertEqual(whois.queries, ["stale.com", "stale.com"])

    def test_subdomains_share_the_registrable_domain_entry(self):
        whois = FakeWhois({"example.co.uk": {"creation_date": days_ago(500)}})
        lookup_domain_age("mail.example.co.uk", whois_func=whois)
        finding = lookup_domain_age("news.example.co.uk", whois_func=whois)
        self.assertEqual(whois.queries, ["example.co.uk"])
        self.assertEqual(finding.domain, "example.co.uk")


class TestExemptions(DomainAgeTestCase):

    def test_brand_owned_domains_are_exempt(self):
        self.assertTrue(is_exempt("paypal.com"))
        self.assertTrue(is_exempt("mail.microsoft.com"))
        self.assertFalse(is_exempt("paypal-secure-login.tk"))

    def test_exempt_domain_is_never_queried(self):
        whois = FakeWhois({"google.com": {"creation_date": days_ago(1)}})
        finding = lookup_domain_age("google.com", whois_func=whois)
        self.assertEqual(finding.classification, EXEMPT)
        self.assertEqual(whois.queries, [])

    def test_exempt_domain_scores_nothing(self):
        findings = [DomainAgeFinding(domain="paypal.com", classification=EXEMPT, origin="sender")]
        verdict = _score(findings)
        self.assertEqual(_domain_age_weight(verdict), 0)


class TestDomainCollection(DomainAgeTestCase):

    def test_sender_comes_first_and_links_are_deduplicated(self):
        parsed = ParsedMessage(from_raw="Support <help@sender-domain.com>")
        url_verdict = URLAnalysisVerdict(urls=[
            ExtractedURL(raw_url="http://a.link-one.com/x", normalized_url="", domain="a.link-one.com"),
            ExtractedURL(raw_url="http://b.link-one.com/y", normalized_url="", domain="b.link-one.com"),
            ExtractedURL(raw_url="http://sender-domain.com/z", normalized_url="", domain="sender-domain.com"),
        ])
        self.assertEqual(
            collect_domains(parsed, url_verdict),
            [("sender-domain.com", "sender"), ("link-one.com", "link")],
        )

    def test_lookup_budget_limits_live_queries(self):
        os.environ["DOMAIN_AGE_MAX_LOOKUPS"] = "2"
        try:
            answers = {f"host{i}.com": {"creation_date": days_ago(3)} for i in range(5)}
            answers["sender.com"] = {"creation_date": days_ago(3)}
            whois = FakeWhois(answers)
            parsed = ParsedMessage(from_raw="a@sender.com")
            url_verdict = URLAnalysisVerdict(urls=[
                ExtractedURL(raw_url=f"http://host{i}.com/", normalized_url="", domain=f"host{i}.com")
                for i in range(5)
            ])
            analyse_domain_age(parsed, url_verdict, whois_func=whois)
        finally:
            os.environ.pop("DOMAIN_AGE_MAX_LOOKUPS", None)
        self.assertEqual(len(whois.queries), 2)

    def test_a_misbehaving_whois_library_cannot_break_analysis(self):
        def exploding(_domain):
            raise KeyboardInterrupt("library raising a BaseException")

        parsed = ParsedMessage(from_raw="a@sender.com")
        self.assertIsInstance(analyse_domain_age(parsed, whois_func=exploding), list)


def _score(domain_age_findings, parsed=None):
    return score_message(
        parsed or ParsedMessage(from_raw="a@sender-domain.com"),
        AuthVerdict(raw="", source="", spf="pass", dkim="pass", dmarc="pass"),
        RoutingVerdict(hop_count=3),
        domain_age_findings=domain_age_findings,
    )


def _domain_age_weight(verdict) -> int:
    return sum(s.weight for s in verdict.signals if s.indicator.startswith("Domain Reputation:"))


class TestScoring(unittest.TestCase):

    def test_newly_registered_sender_scores(self):
        verdict = _score([DomainAgeFinding(domain="evil.tk", classification=NEWLY_REGISTERED,
                                           age_days=3, created="2026-07-01", origin="sender")])
        self.assertEqual(_domain_age_weight(verdict), 25)
        signal = next(s for s in verdict.signals if s.indicator.startswith("Domain Reputation:"))
        self.assertIn("evil.tk", signal.evidence)

    def test_young_sender_scores_less_than_new_sender(self):
        young = _score([DomainAgeFinding(domain="evil.tk", classification=YOUNG,
                                         age_days=60, origin="sender")])
        new = _score([DomainAgeFinding(domain="evil.tk", classification=NEWLY_REGISTERED,
                                       age_days=3, origin="sender")])
        self.assertLess(_domain_age_weight(young), _domain_age_weight(new))

    def test_link_domain_scores_less_than_sender_domain(self):
        link = _score([DomainAgeFinding(domain="evil.tk", classification=NEWLY_REGISTERED,
                                        age_days=3, origin="link")])
        sender = _score([DomainAgeFinding(domain="evil.tk", classification=NEWLY_REGISTERED,
                                          age_days=3, origin="sender")])
        self.assertLess(_domain_age_weight(link), _domain_age_weight(sender))

    def test_established_domain_scores_nothing(self):
        verdict = _score([DomainAgeFinding(domain="old.com", classification=ESTABLISHED,
                                           age_days=4000, origin="sender")])
        self.assertEqual(_domain_age_weight(verdict), 0)

    def test_unknown_lookup_scores_nothing(self):
        verdict = _score([DomainAgeFinding(domain="mystery.com", classification=UNKNOWN,
                                           source="error", origin="sender")])
        self.assertEqual(_domain_age_weight(verdict), 0)

    def test_total_contribution_is_capped(self):
        findings = [DomainAgeFinding(domain=f"evil{i}.tk", classification=NEWLY_REGISTERED,
                                     age_days=1, origin="link") for i in range(10)]
        findings.append(DomainAgeFinding(domain="evil-sender.tk", classification=NEWLY_REGISTERED,
                                         age_days=1, origin="sender"))
        verdict = _score(findings)
        self.assertLessEqual(_domain_age_weight(verdict), MAX_DOMAIN_AGE_SCORE)
        self.assertLessEqual(
            len([s for s in verdict.signals if s.indicator.startswith("Domain Reputation:")]), 2
        )

    def test_new_domain_alone_does_not_reach_critical(self):
        findings = [DomainAgeFinding(domain=f"evil{i}.tk", classification=NEWLY_REGISTERED,
                                     age_days=1, origin="link") for i in range(6)]
        verdict = _score(findings)
        self.assertIn(verdict.risk_level, {"Low", "Medium"})

    def test_no_findings_leaves_scoring_unchanged(self):
        parsed = ParsedMessage(from_raw="a@sender-domain.com")
        auth = AuthVerdict(raw="", source="", spf="pass", dkim="pass", dmarc="pass")
        routing = RoutingVerdict(hop_count=3)
        baseline = score_message(parsed, auth, routing)
        with_empty = score_message(parsed, auth, routing, domain_age_findings=[])
        self.assertEqual(baseline.total_score, with_empty.total_score)
        self.assertEqual(baseline.confidence, with_empty.confidence)

    def test_resolved_age_is_reflected_in_confidence(self):
        parsed = ParsedMessage(from_raw="a@sender-domain.com", body_plain="hello")
        auth = AuthVerdict(raw="", source="", spf="pass", dkim="pass", dmarc="pass")
        routing = RoutingVerdict(hop_count=3)
        resolved = score_message(parsed, auth, routing, domain_age_findings=[
            DomainAgeFinding(domain="old.com", classification=ESTABLISHED, age_days=4000, source="whois")
        ])
        unresolved = score_message(parsed, auth, routing, domain_age_findings=[
            DomainAgeFinding(domain="old.com", classification=UNKNOWN, source="error")
        ])
        self.assertGreater(resolved.confidence, unresolved.confidence)


class TestEndToEnd(DomainAgeTestCase):

    def test_new_sender_domain_flows_through_scoring(self):
        whois = FakeWhois({"brand-new-shop.tk": {"creation_date": days_ago(4),
                                                 "registrar": "Cheap Registrar"}})
        parsed = ParsedMessage(from_raw="Billing <billing@brand-new-shop.tk>")
        findings = analyse_domain_age(parsed, whois_func=whois)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].classification, NEWLY_REGISTERED)

        verdict = _score(findings, parsed)
        self.assertEqual(_domain_age_weight(verdict), 25)


if __name__ == "__main__":
    unittest.main()
