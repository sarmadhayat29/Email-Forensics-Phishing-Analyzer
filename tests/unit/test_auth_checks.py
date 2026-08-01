"""Unit tests for header-derived authentication analysis and live re-verification.

The live path is always exercised with an injected fake resolver / fake DKIM
verifier, so these tests never touch DNS or the internet.
"""

import os
import sys
import unittest
from contextlib import ExitStack
from unittest import mock

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../../src')))
sys.path.insert(0, os.path.dirname(__file__))

import auth_checks
import live_auth
from auth_checks import analyse_authentication, dkim_signing_domain, live_reverify
from models import ParsedMessage

from test_live_auth import FakeDns


LIVE_ON = {"LIVE_AUTH_ENABLED": "true"}

SIGNED_MESSAGE = (
    b"DKIM-Signature: v=1; a=rsa-sha256; d=mailer.example.net; s=sel1; h=from;\r\n"
    b" b=AAAA\r\n"
    b"From: Billing <billing@example.com>\r\n"
    b"Subject: Invoice\r\n"
    b"\r\n"
    b"Body\r\n"
)


class TestDkimSigningDomainExtraction(unittest.TestCase):
    """Regression: the signing domain is ``d=``, never ``header.from=``."""

    def test_header_d_is_preferred(self):
        combined = "mx.example.com; dkim=pass header.d=mailer.example.net; dmarc=pass header.from=example.com"
        self.assertEqual(dkim_signing_domain(combined), ("mailer.example.net", "header.d"))

    def test_header_i_is_the_fallback(self):
        combined = "mx.example.com; dkim=pass header.i=@signer.example.net header.s=s1"
        self.assertEqual(dkim_signing_domain(combined), ("signer.example.net", "header.i"))

    def test_header_from_is_never_used_as_the_signing_domain(self):
        combined = "mx.example.com; dkim=pass header.from=example.com"
        self.assertEqual(dkim_signing_domain(combined), (None, None))


class TestHeaderDkimAlignment(unittest.TestCase):

    def _analyse(self, auth_results, from_raw="Billing <billing@example.com>"):
        return analyse_authentication(ParsedMessage(from_raw=from_raw, authentication_results=auth_results))

    def test_misaligned_signing_domain_is_flagged(self):
        """The old regex read header.from= and so compared From with itself."""
        verdict = self._analyse([
            "mx.example.com; spf=pass smtp.mailfrom=example.com; "
            "dkim=pass header.d=evil-signer.xyz; dmarc=pass header.from=example.com"
        ])
        self.assertEqual(verdict.dkim, "pass")
        self.assertIn("header.d=evil-signer.xyz", verdict.dkim_details)
        self.assertTrue(any("DKIM Alignment Warning" in inc for inc in verdict.inconsistencies))

    def test_subdomain_signing_is_aligned_under_relaxed_alignment(self):
        verdict = self._analyse([
            "mx.example.com; dkim=pass header.d=mail.example.com; dmarc=pass header.from=example.com"
        ])
        self.assertFalse(any("DKIM Alignment" in inc for inc in verdict.inconsistencies))

    def test_exact_signing_domain_is_aligned(self):
        verdict = self._analyse([
            "mx.example.com; dkim=pass header.d=example.com; dmarc=pass header.from=example.com"
        ])
        self.assertEqual(verdict.inconsistencies, [])

    def test_header_only_verdict_is_not_marked_live(self):
        verdict = self._analyse(["mx.example.com; spf=pass smtp.mailfrom=example.com"])
        self.assertFalse(verdict.live_attempted)
        self.assertFalse(verdict.live_verified)


UNSIGNED_MESSAGE = b"From: Billing <billing@example.com>\r\nSubject: Invoice\r\n\r\nBody\r\n"


def _phish_parsed(auth_claim="attacker.invalid; spf=pass smtp.mailfrom=example.com; "
                            "dkim=pass header.d=example.com; dmarc=pass header.from=example.com",
                  raw_bytes=UNSIGNED_MESSAGE,
                  received_by="mx.example.com"):
    """A message claiming a full authentication pass, sent from a public IP.

    Default authserv-id is *unattributed* (does not match Received ``by``), so
    live verification may override injected PASS claims. Pass an attributed
    claim explicitly to exercise header-authoritative retention.
    """
    return ParsedMessage(
        from_raw="Billing <billing@example.com>",
        received_chain=[
            f"from relay.evil.ru ([185.220.101.7]) by {received_by} with SMTP; "
            "Wed, 15 Jul 2026 09:41:12 +0000",
        ],
        authentication_results=[auth_claim],
        body_plain="Please pay the attached invoice.",
        raw_bytes=raw_bytes,
    )


def _attributed_pass_claim():
    return (
        "mx.example.com; spf=pass smtp.mailfrom=example.com; "
        "dkim=pass header.d=example.com; dmarc=pass header.from=example.com"
    )


def _dns_saying_fail():
    """SPF authorises a different network; DMARC published with p=reject."""
    return FakeDns(txt={
        "example.com": ["v=spf1 ip4:93.184.216.0/24 -all"],
        "_dmarc.example.com": ["v=DMARC1; p=reject"],
    })


class TestLiveReverify(unittest.TestCase):

    def _run(self, parsed, dns=None, dkim_result=None):
        dns = dns or _dns_saying_fail()
        with ExitStack() as stack:
            stack.enter_context(mock.patch.dict(os.environ, LIVE_ON))
            stack.enter_context(mock.patch.object(live_auth, "DnsClient", lambda *a, **kw: dns))
            if dkim_result is not None:
                stack.enter_context(mock.patch.object(live_auth, "verify_dkim",
                                                      lambda *a, **kw: dkim_result))
            return live_reverify(parsed)

    def test_live_results_override_unattributed_headers(self):
        verdict = self._run(_phish_parsed())
        self.assertTrue(verdict.live_attempted)
        self.assertTrue(verdict.live_verified)
        self.assertTrue(verdict.source.startswith(auth_checks.LIVE_SOURCE_PREFIX))
        self.assertIn("SPF", verdict.source)
        self.assertEqual(verdict.spf, "fail")
        self.assertEqual(verdict.dmarc, "fail")
        self.assertEqual(verdict.dmarc_policy, "reject")
        self.assertIn("185.220.101.7", verdict.note)

    def test_injected_unattributed_pass_does_not_survive_a_live_failure(self):
        verdict = self._run(_phish_parsed())
        contradictions = [inc for inc in verdict.inconsistencies if "Verification mismatch" in inc]
        self.assertTrue(any("spf=pass" in inc and "spf=fail" in inc for inc in contradictions))
        self.assertTrue(any("enforcing policy (p=reject)" in inc for inc in verdict.inconsistencies))

    def test_attributed_header_pass_is_retained_when_live_spf_disagrees(self):
        """Border-MTA Authentication-Results are authoritative for scoring.

        Reconstructing the connecting IP from Received text is unreliable; a
        disagreement becomes a verification mismatch, not a forged-header fail.
        """
        parsed = _phish_parsed(auth_claim=_attributed_pass_claim())
        verdict = self._run(parsed)
        self.assertEqual(verdict.spf, "pass")
        self.assertEqual(verdict.dmarc, "pass")
        self.assertTrue(any("Verification mismatch" in inc and "spf" in inc
                            for inc in verdict.inconsistencies))
        self.assertTrue(any("header-authoritative" in check for check in verdict.live_checks))
        # Must not invent a hard SPF fail that would drive High risk.
        self.assertFalse(any("spf=fail" in check and "live-verified (fail)" in check
                             for check in verdict.live_checks))

    def test_attributed_dkim_pass_retained_when_signature_stripped(self):
        parsed = _phish_parsed(auth_claim=_attributed_pass_claim())
        verdict = self._run(parsed)
        self.assertEqual(verdict.dkim, "pass")
        self.assertFalse([inc for inc in verdict.inconsistencies
                          if "Forged or stale" in inc])

    def test_stripped_dkim_signature_is_not_called_a_forgery(self):
        """Unattributed claimed dkim=pass with no signature is not accused of forgery."""
        verdict = self._run(_phish_parsed())
        self.assertEqual(verdict.dkim, "none")
        self.assertFalse([inc for inc in verdict.inconsistencies
                          if "Forged or stale" in inc and "dkim" in inc])

    def test_live_pass_is_reported_when_the_sender_is_authorised(self):
        dns = FakeDns(txt={
            "example.com": ["v=spf1 ip4:185.220.101.0/24 -all"],
            "_dmarc.example.com": ["v=DMARC1; p=reject"],
        })
        verdict = self._run(_phish_parsed(), dns=dns)
        self.assertEqual(verdict.spf, "pass")
        self.assertEqual(verdict.dmarc, "pass")
        self.assertFalse([inc for inc in verdict.inconsistencies if "Verification mismatch" in inc
                          and "spf=fail" in inc])

    def test_live_dkim_failure_overrides_a_claimed_dkim_pass(self):
        parsed = _phish_parsed(raw_bytes=SIGNED_MESSAGE)
        verdict = self._run(parsed, dkim_result=live_auth.DkimResult(
            verdict="fail", detail="signature #1 failed verification",
            signature_domains=["mailer.example.net"],
        ))
        self.assertEqual(verdict.dkim, "fail")
        self.assertTrue(any("dkim=pass" in inc and "dkim=fail" in inc
                            for inc in verdict.inconsistencies))

    def test_live_dkim_crypto_fail_overrides_even_attributed_header(self):
        parsed = _phish_parsed(auth_claim=_attributed_pass_claim(), raw_bytes=SIGNED_MESSAGE)
        verdict = self._run(parsed, dkim_result=live_auth.DkimResult(
            verdict="fail", detail="signature #1 failed verification",
            signature_domains=["example.com"],
        ))
        self.assertEqual(verdict.dkim, "fail")
        self.assertTrue(any("Verification mismatch" in inc and "dkim" in inc
                            for inc in verdict.inconsistencies))

    def test_live_dkim_misalignment_is_reported(self):
        parsed = _phish_parsed(raw_bytes=SIGNED_MESSAGE)
        verdict = self._run(parsed, dkim_result=live_auth.DkimResult(
            verdict="pass", detail="verified", signature_domains=["mailer.example.net"],
            passed_domains=["mailer.example.net"],
        ))
        self.assertEqual(verdict.dkim, "pass")
        self.assertTrue(any("DKIM Alignment Warning" in inc for inc in verdict.inconsistencies))

    def test_unsigned_message_reports_dkim_none_live(self):
        verdict = self._run(_phish_parsed())
        self.assertEqual(verdict.dkim, "none")
        self.assertTrue(any("DKIM: live-verified (none)" in check for check in verdict.live_checks))

    def test_provenance_is_recorded_per_mechanism(self):
        verdict = self._run(_phish_parsed())
        self.assertEqual(len(verdict.live_checks), 3)
        for mechanism in ("SPF", "DKIM", "DMARC"):
            self.assertTrue(any(check.startswith(f"{mechanism}:")
                                for check in verdict.live_checks), mechanism)

    def test_without_raw_bytes_dkim_stays_header_derived(self):
        verdict = self._run(_phish_parsed(raw_bytes=b""))
        self.assertEqual(verdict.dkim, "pass")
        self.assertTrue(any(check.startswith("DKIM: header-derived") for check in verdict.live_checks))
        # DKIM unknown means DMARC alignment cannot be settled either.
        self.assertTrue(any("DMARC: header-derived" in check for check in verdict.live_checks))

    def test_designated_ip_from_ar_commentary_is_preferred(self):
        claim = (
            "mx.example.com; spf=pass (mx.example.com: domain of newsletter@example.com "
            "designates 185.220.101.7 as permitted sender) smtp.mailfrom=example.com; "
            "dkim=pass header.d=example.com; dmarc=pass header.from=example.com"
        )
        dns = FakeDns(txt={
            "example.com": ["v=spf1 ip4:185.220.101.0/24 -all"],
            "_dmarc.example.com": ["v=DMARC1; p=none"],
        })
        parsed = _phish_parsed(auth_claim=claim)
        verdict = self._run(parsed, dns=dns)
        self.assertEqual(verdict.spf, "pass")
        self.assertIn("185.220.101.7", verdict.note)

class TestLiveReverifyDegradation(unittest.TestCase):

    def test_resolver_failure_falls_back_to_header_results(self):
        dns = FakeDns(temporary={"example.com", "_dmarc.example.com"})
        parsed = _phish_parsed(raw_bytes=b"")  # nothing at all is verifiable
        with mock.patch.dict(os.environ, LIVE_ON), \
             mock.patch.object(live_auth, "DnsClient", lambda *a, **kw: dns):
            verdict = live_reverify(parsed)

        header_verdict = analyse_authentication(parsed)
        self.assertTrue(verdict.live_attempted)
        self.assertFalse(verdict.live_verified)
        self.assertEqual(verdict.spf, header_verdict.spf)
        self.assertEqual(verdict.dkim, header_verdict.dkim)
        self.assertEqual(verdict.dmarc, header_verdict.dmarc)
        self.assertEqual(verdict.source, header_verdict.source)
        self.assertIn("header-derived", verdict.note)

    def test_disabled_by_environment_returns_none(self):
        with mock.patch.dict(os.environ, {"LIVE_AUTH_ENABLED": "false"}):
            self.assertIsNone(live_reverify(_phish_parsed()))

    def test_missing_optional_dependency_returns_none(self):
        """An unimportable live_auth (missing dnspython/dkimpy) must not raise."""
        with mock.patch.dict(os.environ, LIVE_ON), \
             mock.patch.dict(sys.modules, {"live_auth": None}):
            self.assertIsNone(live_reverify(_phish_parsed()))

    def test_unexpected_exception_returns_none(self):
        with mock.patch.dict(os.environ, LIVE_ON), \
             mock.patch.object(live_auth, "sending_ip", side_effect=RuntimeError("boom")):
            self.assertIsNone(live_reverify(_phish_parsed()))

    def test_message_without_received_chain_keeps_header_spf(self):
        parsed = ParsedMessage(
            from_raw="Billing <billing@example.com>",
            authentication_results=["mx.example.com; spf=pass smtp.mailfrom=example.com"],
        )
        dns = FakeDns(txt={"_dmarc.example.com": ["v=DMARC1; p=none"]})
        with mock.patch.dict(os.environ, LIVE_ON), \
             mock.patch.object(live_auth, "DnsClient", lambda *a, **kw: dns):
            verdict = live_reverify(parsed)
        self.assertEqual(verdict.spf, "pass")
        self.assertTrue(any("no routable sending IP" in check for check in verdict.live_checks))


class TestPipelineWiring(unittest.TestCase):
    """``main`` composes the two paths as ``live_reverify(...) or analyse_authentication(...)``."""

    def test_fallback_expression_yields_a_usable_verdict(self):
        parsed = _phish_parsed()
        with mock.patch.dict(os.environ, {"LIVE_AUTH_ENABLED": "false"}):
            verdict = live_reverify(parsed) or analyse_authentication(parsed)
        self.assertEqual(verdict.spf, "pass")
        self.assertFalse(verdict.live_attempted)

    def test_live_verdict_is_truthy_so_it_wins_the_or_expression(self):
        parsed = _phish_parsed()
        dns = _dns_saying_fail()
        with mock.patch.dict(os.environ, LIVE_ON), \
             mock.patch.object(live_auth, "DnsClient", lambda *a, **kw: dns):
            verdict = live_reverify(parsed) or analyse_authentication(parsed)
        self.assertEqual(verdict.spf, "fail")


if __name__ == '__main__':
    unittest.main()
