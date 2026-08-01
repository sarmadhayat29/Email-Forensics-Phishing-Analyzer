"""Unit tests for the live SPF/DKIM/DMARC primitives.

Every test injects a fake resolver or a fake DKIM verifier: the suite must never
depend on DNS or the internet.
"""

import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../../src')))

import live_auth
from live_auth import (
    DnsPermanentError, DnsTemporaryError, DkimResult,
    domains_aligned, evaluate_dmarc, evaluate_spf, sending_ip, verify_dkim,
)
from models import ParsedMessage


class FakeDns:
    """Stand-in for :class:`live_auth.DnsClient` backed by dictionaries."""

    def __init__(self, txt=None, a=None, mx=None, temporary=()):
        self.txt_records = txt or {}
        self.a_records = a or {}
        self.mx_records = mx or {}
        self.temporary = set(temporary)
        self.queries = []

    def _guard(self, name):
        self.queries.append(name)
        if name in self.temporary:
            raise DnsTemporaryError(f"Timeout resolving {name}")

    def txt(self, name):
        self._guard(name)
        if name not in self.txt_records:
            raise DnsPermanentError(f"NXDOMAIN {name}")
        return list(self.txt_records[name])

    def a(self, name):
        self._guard(name)
        return list(self.a_records.get(name, []))

    def mx(self, name):
        self._guard(name)
        return list(self.mx_records.get(name, []))


class TestSpfEvaluation(unittest.TestCase):

    def _spf(self, record, ip, domain="example.com", **kwargs):
        txt = {domain: [record]} if record is not None else {}
        txt.update(kwargs.pop("extra_txt", {}))
        dns = FakeDns(txt=txt, **kwargs)
        return evaluate_spf(domain, ip, dns_client=dns)

    def test_authorised_ip_passes(self):
        result = self._spf("v=spf1 ip4:203.0.113.0/24 -all", "203.0.113.10")
        self.assertEqual(result.verdict, "pass")
        self.assertTrue(result.definitive)
        self.assertIn("203.0.113.10", result.detail)

    def test_unauthorised_ip_hard_fails(self):
        result = self._spf("v=spf1 ip4:203.0.113.0/24 -all", "185.220.101.7")
        self.assertEqual(result.verdict, "fail")

    def test_tilde_all_softfails(self):
        self.assertEqual(self._spf("v=spf1 ip4:203.0.113.1 ~all", "8.8.8.8").verdict, "softfail")

    def test_question_all_is_neutral(self):
        self.assertEqual(self._spf("v=spf1 ?all", "8.8.8.8").verdict, "neutral")

    def test_no_matching_mechanism_without_all_is_neutral(self):
        self.assertEqual(self._spf("v=spf1 ip4:203.0.113.1", "8.8.8.8").verdict, "neutral")

    def test_domain_without_spf_record_is_none(self):
        self.assertEqual(self._spf("v=notspf hello", "8.8.8.8").verdict, "none")

    def test_domain_without_txt_records_is_none(self):
        result = evaluate_spf("example.com", "8.8.8.8", dns_client=FakeDns())
        self.assertEqual(result.verdict, "none")

    def test_multiple_spf_records_is_permerror(self):
        dns = FakeDns(txt={"example.com": ["v=spf1 -all", "v=spf1 +all"]})
        self.assertEqual(evaluate_spf("example.com", "8.8.8.8", dns_client=dns).verdict, "permerror")

    def test_resolver_timeout_is_temperror_and_not_definitive(self):
        dns = FakeDns(txt={"example.com": ["v=spf1 -all"]}, temporary={"example.com"})
        result = evaluate_spf("example.com", "8.8.8.8", dns_client=dns)
        self.assertEqual(result.verdict, "temperror")
        self.assertFalse(result.definitive)

    def test_missing_or_unparseable_ip_is_temperror(self):
        dns = FakeDns(txt={"example.com": ["v=spf1 -all"]})
        self.assertEqual(evaluate_spf("example.com", "", dns_client=dns).verdict, "temperror")
        self.assertEqual(evaluate_spf("example.com", "not-an-ip", dns_client=dns).verdict, "temperror")

    def test_missing_domain_is_not_evaluated(self):
        result = evaluate_spf("", "8.8.8.8", dns_client=FakeDns())
        self.assertEqual(result.verdict, "not_present")
        self.assertFalse(result.definitive)

    def test_include_is_followed(self):
        dns = FakeDns(txt={
            "example.com": ["v=spf1 include:_spf.provider.net -all"],
            "_spf.provider.net": ["v=spf1 ip4:198.51.100.0/24 -all"],
        })
        self.assertEqual(evaluate_spf("example.com", "198.51.100.7", dns_client=dns).verdict, "pass")
        self.assertEqual(evaluate_spf("example.com", "203.0.113.7", dns_client=dns).verdict, "fail")

    def test_a_and_mx_mechanisms(self):
        dns = FakeDns(
            txt={"example.com": ["v=spf1 a mx -all"]},
            a={"example.com": ["198.51.100.5"], "mail.example.com": ["203.0.113.9"]},
            mx={"example.com": ["mail.example.com"]},
        )
        self.assertEqual(evaluate_spf("example.com", "198.51.100.5", dns_client=dns).verdict, "pass")
        self.assertEqual(evaluate_spf("example.com", "203.0.113.9", dns_client=dns).verdict, "pass")
        self.assertEqual(evaluate_spf("example.com", "192.0.2.1", dns_client=dns).verdict, "fail")

    def test_a_mechanism_honours_cidr(self):
        dns = FakeDns(txt={"example.com": ["v=spf1 a/24 -all"]}, a={"example.com": ["198.51.100.5"]})
        self.assertEqual(evaluate_spf("example.com", "198.51.100.200", dns_client=dns).verdict, "pass")

    def test_redirect_modifier(self):
        dns = FakeDns(txt={
            "example.com": ["v=spf1 redirect=_spf.example.net"],
            "_spf.example.net": ["v=spf1 ip4:198.51.100.0/24 -all"],
        })
        self.assertEqual(evaluate_spf("example.com", "198.51.100.1", dns_client=dns).verdict, "pass")
        self.assertEqual(evaluate_spf("example.com", "8.8.8.8", dns_client=dns).verdict, "fail")

    def test_lookup_budget_is_enforced(self):
        # A record that includes itself would loop forever without the budget.
        dns = FakeDns(txt={"loop.com": ["v=spf1 include:loop.com -all"]})
        result = evaluate_spf("loop.com", "8.8.8.8", dns_client=dns)
        self.assertEqual(result.verdict, "permerror")
        self.assertLessEqual(len(dns.queries), live_auth.SPF_MAX_DNS_LOOKUPS + 2)

    def test_unexpandable_macros_degrade_to_temperror(self):
        dns = FakeDns(txt={"example.com": ["v=spf1 exists:%{ir}.spf.example.net -all"]})
        self.assertEqual(evaluate_spf("example.com", "8.8.8.8", dns_client=dns).verdict, "temperror")

    def test_unknown_mechanism_is_permerror(self):
        self.assertEqual(self._spf("v=spf1 wat:1 -all", "8.8.8.8").verdict, "permerror")

    def test_ipv6_mechanism(self):
        dns = FakeDns(txt={"example.com": ["v=spf1 ip6:2001:db8::/32 -all"]})
        self.assertEqual(evaluate_spf("example.com", "2001:db8::1", dns_client=dns).verdict, "pass")
        self.assertEqual(evaluate_spf("example.com", "2001:dead::1", dns_client=dns).verdict, "fail")


class TestSendingIp(unittest.TestCase):

    def test_newest_routable_hop_is_used(self):
        parsed = ParsedMessage(received_chain=[
            "from relay.evil.ru ([185.220.101.7]) by mx.example.com; Wed, 15 Jul 2026 09:41:12 +0000",
            "from origin.example ([203.0.113.44]) by relay.evil.ru; Wed, 15 Jul 2026 09:40:02 +0000",
        ])
        self.assertEqual(sending_ip(parsed), "185.220.101.7")

    def test_internal_hops_without_public_ip_are_skipped(self):
        parsed = ParsedMessage(received_chain=[
            "by internal.corp ([10.0.0.5]) with SMTP id 1",
            "from sender.example ([93.184.216.34]) by mx.corp",
        ])
        self.assertEqual(sending_ip(parsed), "93.184.216.34")

    def test_originating_ip_header_is_a_fallback(self):
        parsed = ParsedMessage(headers={"X-Originating-IP": "[93.184.216.34]"})
        self.assertEqual(sending_ip(parsed), "93.184.216.34")

    def test_documentation_ranges_are_not_treated_as_the_sender(self):
        """Synthetic samples must not produce a live verdict from a fake IP."""
        parsed = ParsedMessage(received_chain=["from a.example ([203.0.113.44]) by mx.example.com"])
        self.assertIsNone(sending_ip(parsed))

    def test_no_ip_available(self):
        self.assertIsNone(sending_ip(ParsedMessage(received_chain=["by internal.corp ([127.0.0.1])"])))


SIGNED_MESSAGE = (
    b"DKIM-Signature: v=1; a=rsa-sha256; d=example.com; s=sel1; h=from:subject;\r\n"
    b" b=AAAA\r\n"
    b"From: Sender <someone@example.com>\r\n"
    b"Subject: Hello\r\n"
    b"\r\n"
    b"Body\r\n"
)

UNSIGNED_MESSAGE = b"From: Sender <someone@example.com>\r\nSubject: Hello\r\n\r\nBody\r\n"


class TestDkimVerification(unittest.TestCase):

    def test_missing_raw_bytes_is_not_present(self):
        result = verify_dkim(b"")
        self.assertEqual(result.verdict, "not_present")
        self.assertFalse(result.definitive)

    def test_unsigned_message_is_none(self):
        result = verify_dkim(UNSIGNED_MESSAGE, verifier=lambda raw, idx: True)
        self.assertEqual(result.verdict, "none")
        self.assertTrue(result.definitive)

    def test_valid_signature_passes_and_reports_signing_domain(self):
        result = verify_dkim(SIGNED_MESSAGE, verifier=lambda raw, idx: True)
        self.assertEqual(result.verdict, "pass")
        self.assertEqual(result.passed_domains, ["example.com"])

    def test_invalid_signature_fails(self):
        result = verify_dkim(SIGNED_MESSAGE, verifier=lambda raw, idx: False)
        self.assertEqual(result.verdict, "fail")
        self.assertEqual(result.passed_domains, [])

    def test_validation_exception_is_a_failure(self):
        def boom(raw, idx):
            raise ValueError("body hash mismatch")

        self.assertEqual(verify_dkim(SIGNED_MESSAGE, verifier=boom).verdict, "fail")

    def test_dns_exception_is_temperror_not_a_failure(self):
        def boom(raw, idx):
            raise RuntimeError("DNS timeout while fetching key")

        result = verify_dkim(SIGNED_MESSAGE, verifier=boom)
        self.assertEqual(result.verdict, "temperror")
        self.assertFalse(result.definitive)

    def test_missing_optional_dependency_is_not_present(self):
        with mock.patch.object(live_auth, "_default_dkim_verifier", return_value=None):
            result = verify_dkim(SIGNED_MESSAGE)
        self.assertEqual(result.verdict, "not_present")
        self.assertIn("dkimpy", result.detail)


class TestDmarcEvaluation(unittest.TestCase):

    def _dns(self, record=None, name="_dmarc.example.com", **kwargs):
        txt = {name: [record]} if record else {}
        return FakeDns(txt=txt, **kwargs)

    def _spf_pass(self, domain="example.com"):
        return live_auth.SpfResult(verdict="pass", domain=domain, ip="203.0.113.1")

    def test_no_record_is_none(self):
        result = evaluate_dmarc("example.com", dns_client=self._dns())
        self.assertEqual(result.verdict, "none")
        self.assertIsNone(result.policy)
        self.assertTrue(result.definitive)

    def test_aligned_spf_passes_and_policy_is_captured(self):
        result = evaluate_dmarc(
            "example.com",
            spf=self._spf_pass(),
            mailfrom_domain="example.com",
            dns_client=self._dns("v=DMARC1; p=reject; pct=100"),
        )
        self.assertEqual(result.verdict, "pass")
        self.assertEqual(result.policy, "reject")
        self.assertTrue(result.spf_aligned)

    def test_relaxed_alignment_accepts_subdomain(self):
        result = evaluate_dmarc(
            "example.com",
            spf=self._spf_pass("bounce.example.com"),
            mailfrom_domain="bounce.example.com",
            dns_client=self._dns("v=DMARC1; p=none"),
        )
        self.assertEqual(result.verdict, "pass")

    def test_strict_alignment_rejects_subdomain(self):
        result = evaluate_dmarc(
            "example.com",
            spf=self._spf_pass("bounce.example.com"),
            dkim=DkimResult(verdict="none"),
            mailfrom_domain="bounce.example.com",
            dns_client=self._dns("v=DMARC1; p=quarantine; aspf=s"),
        )
        self.assertEqual(result.verdict, "fail")
        self.assertEqual(result.policy, "quarantine")
        self.assertTrue(result.notes)

    def test_unaligned_spf_pass_fails_dmarc(self):
        result = evaluate_dmarc(
            "example.com",
            spf=self._spf_pass("sketchy-sender.xyz"),
            dkim=DkimResult(verdict="none"),
            mailfrom_domain="sketchy-sender.xyz",
            dns_client=self._dns("v=DMARC1; p=reject"),
        )
        self.assertEqual(result.verdict, "fail")
        self.assertFalse(result.spf_aligned)

    def test_aligned_dkim_passes(self):
        result = evaluate_dmarc(
            "example.com",
            dkim=DkimResult(verdict="pass", passed_domains=["mail.example.com"]),
            dns_client=self._dns("v=DMARC1; p=reject"),
        )
        self.assertEqual(result.verdict, "pass")
        self.assertTrue(result.dkim_aligned)

    def test_organisational_domain_fallback_uses_subdomain_policy(self):
        dns = FakeDns(txt={"_dmarc.example.com": ["v=DMARC1; p=reject; sp=quarantine"]})
        result = evaluate_dmarc(
            "mail.example.com",
            spf=self._spf_pass("sketchy.xyz"),
            dkim=DkimResult(verdict="none"),
            mailfrom_domain="sketchy.xyz",
            dns_client=dns,
        )
        self.assertEqual(result.verdict, "fail")
        self.assertEqual(result.policy, "quarantine")

    def test_resolver_failure_is_temperror(self):
        dns = FakeDns(txt={"_dmarc.example.com": ["v=DMARC1; p=reject"]},
                      temporary={"_dmarc.example.com"})
        result = evaluate_dmarc("example.com", spf=self._spf_pass(), dns_client=dns)
        self.assertEqual(result.verdict, "temperror")
        self.assertFalse(result.definitive)

    def test_record_present_but_nothing_evaluable_is_temperror(self):
        result = evaluate_dmarc("example.com", dns_client=self._dns("v=DMARC1; p=reject"))
        self.assertEqual(result.verdict, "temperror")

    def test_failure_needs_both_mechanisms_to_be_known(self):
        """A missing SPF result must not be turned into a policy violation."""
        result = evaluate_dmarc(
            "example.com",
            dkim=DkimResult(verdict="none"),
            dns_client=self._dns("v=DMARC1; p=reject"),
        )
        self.assertEqual(result.verdict, "temperror")
        self.assertIn("SPF", result.detail)
        self.assertEqual(result.policy, "reject")

    def test_failure_is_declared_once_both_mechanisms_are_known(self):
        result = evaluate_dmarc(
            "example.com",
            spf=live_auth.SpfResult(verdict="fail", domain="example.com"),
            dkim=DkimResult(verdict="none"),
            mailfrom_domain="example.com",
            dns_client=self._dns("v=DMARC1; p=reject"),
        )
        self.assertEqual(result.verdict, "fail")


class TestMissingDnspython(unittest.TestCase):

    def setUp(self):
        live_auth.reset_dns_health()

    def tearDown(self):
        live_auth.reset_dns_health()

    def test_absent_dnspython_degrades_to_temperror(self):
        with mock.patch.dict(sys.modules, {"dns": None, "dns.resolver": None, "dns.exception": None}):
            with self.assertRaises(DnsTemporaryError):
                live_auth.DnsClient(timeout=1.0).txt("example.com")
            result = evaluate_spf("example.com", "185.220.101.7",
                                  dns_client=live_auth.DnsClient(timeout=1.0))
        self.assertEqual(result.verdict, "temperror")
        self.assertFalse(result.definitive)


class TestResolverCircuitBreaker(unittest.TestCase):
    """A host with no resolver must not pay a timeout on every single lookup."""

    def setUp(self):
        live_auth.reset_dns_health()

    def tearDown(self):
        live_auth.reset_dns_health()

    def test_repeated_failures_suspend_live_lookups(self):
        self.assertTrue(live_auth.dns_available())
        for _ in range(live_auth.DNS_FAILURE_THRESHOLD):
            live_auth._record_dns_failure()
        self.assertFalse(live_auth.dns_available())

        with self.assertRaises(DnsTemporaryError):
            live_auth.DnsClient(timeout=1.0)._resolve("example.com", "TXT")

    def test_a_successful_answer_clears_the_failure_count(self):
        live_auth._record_dns_failure()
        live_auth._record_dns_success()
        self.assertTrue(live_auth.dns_available())
        self.assertEqual(live_auth._dns_health["consecutive_failures"], 0)

    def test_spf_degrades_to_temperror_while_suspended(self):
        for _ in range(live_auth.DNS_FAILURE_THRESHOLD):
            live_auth._record_dns_failure()
        result = evaluate_spf("example.com", "185.220.101.7", dns_client=live_auth.DnsClient(timeout=1.0))
        self.assertEqual(result.verdict, "temperror")


class TestAlignmentHelper(unittest.TestCase):

    def test_relaxed_and_strict(self):
        self.assertTrue(domains_aligned("mail.example.com", "example.com"))
        self.assertFalse(domains_aligned("mail.example.com", "example.com", "s"))
        self.assertTrue(domains_aligned("example.com", "example.com", "s"))
        self.assertFalse(domains_aligned("evil.com", "example.com"))
        self.assertFalse(domains_aligned(None, "example.com"))


class TestConfiguration(unittest.TestCase):

    def test_timeout_defaults_and_clamps(self):
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("AUTH_DNS_TIMEOUT", None)
            self.assertEqual(live_auth.dns_timeout(), live_auth.DEFAULT_DNS_TIMEOUT)
        with mock.patch.dict(os.environ, {"AUTH_DNS_TIMEOUT": "2.5"}):
            self.assertEqual(live_auth.dns_timeout(), 2.5)
        with mock.patch.dict(os.environ, {"AUTH_DNS_TIMEOUT": "900"}):
            self.assertEqual(live_auth.dns_timeout(), live_auth.MAX_DNS_TIMEOUT)
        with mock.patch.dict(os.environ, {"AUTH_DNS_TIMEOUT": "nonsense"}):
            self.assertEqual(live_auth.dns_timeout(), live_auth.DEFAULT_DNS_TIMEOUT)

    def test_enable_flag(self):
        for value in ("false", "0", "no", "off"):
            with mock.patch.dict(os.environ, {"LIVE_AUTH_ENABLED": value}):
                self.assertFalse(live_auth.live_auth_enabled())
        for value in ("true", "1", "yes"):
            with mock.patch.dict(os.environ, {"LIVE_AUTH_ENABLED": value}):
                self.assertTrue(live_auth.live_auth_enabled())

    def test_enabled_by_default(self):
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("LIVE_AUTH_ENABLED", None)
            self.assertTrue(live_auth.live_auth_enabled())


if __name__ == '__main__':
    unittest.main()
