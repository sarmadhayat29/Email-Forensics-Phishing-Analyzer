import unittest
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../../src')))

from models import ParsedMessage
from url_analysis import analyze_urls


class TestURLAnalysis(unittest.TestCase):

    def test_clean_urls(self):
        parsed = ParsedMessage(
            body_html='<a href="https://company.com/about">About Us</a>',
            body_plain="Visit https://company.com/help"
        )
        verdict = analyze_urls(parsed)
        self.assertEqual(verdict.total_urls, 2)
        self.assertEqual(verdict.suspicious_count, 0)

    def test_mismatched_hyperlink_anchor(self):
        parsed = ParsedMessage(
            body_html='<a href="http://evil-attacker.com/login">https://paypal.com/signin</a>'
        )
        verdict = analyze_urls(parsed)
        self.assertEqual(verdict.total_urls, 1)
        url_obj = verdict.urls[0]
        self.assertTrue(url_obj.is_mismatched_anchor)
        self.assertTrue(any("Mismatched Hyperlink" in f for f in url_obj.findings))

    def test_ip_based_url_and_shortener(self):
        parsed = ParsedMessage(
            body_html='<a href="http://192.168.1.50/admin">Click</a> <a href="http://bit.ly/xyz">Short</a>'
        )
        verdict = analyze_urls(parsed)
        self.assertEqual(verdict.total_urls, 2)
        self.assertTrue(verdict.urls[0].is_ip_based)
        self.assertTrue(verdict.urls[1].is_shortener)

    def test_open_redirect_and_high_risk_tld(self):
        parsed = ParsedMessage(
            body_html='<a href="http://cheap-deals.xyz/gateway?redirect=https://evil.com">Click</a>'
        )
        verdict = analyze_urls(parsed)
        self.assertEqual(verdict.total_urls, 1)
        url_obj = verdict.urls[0]
        self.assertTrue(url_obj.is_suspicious_domain)
        self.assertTrue(any("open-redirect" in f for f in url_obj.findings))


class TestAnchorMismatchPrecision(unittest.TestCase):
    """Anchor text only counts as a domain claim when it plausibly is one."""

    def _mismatched(self, anchor, href="http://links.company.com/track"):
        parsed = ParsedMessage(body_html=f'<a href="{href}">{anchor}</a>')
        return analyze_urls(parsed).urls[0].is_mismatched_anchor

    def test_filenames_and_versions_are_not_domain_claims(self):
        for anchor in ["invoice.pdf", "report.docx", "Release 2.1", "Click here",
                       "Acme Inc.We deliver", "see page 4.2 below"]:
            self.assertFalse(self._mismatched(anchor), anchor)

    def test_real_domain_claims_still_flagged(self):
        self.assertTrue(self._mismatched("www.paypal.com"))
        self.assertTrue(self._mismatched("https://paypal.com/signin"))
        self.assertTrue(self._mismatched("support@paypal.com"))

    def test_same_organisation_subdomains_are_not_mismatched(self):
        self.assertFalse(self._mismatched("company.com", "https://links.company.com/track"))
        self.assertFalse(self._mismatched("https://www.company.com/a", "https://cdn.company.com/b"))

    def test_anchor_matching_target_exactly(self):
        self.assertFalse(self._mismatched("https://company.com/x", "https://company.com/x"))


if __name__ == '__main__':
    unittest.main()
